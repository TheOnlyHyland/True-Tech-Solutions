"""Internal signed journal service for the True Family companion App."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import stat
import threading
from typing import Any, Callable, TypeVar
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout, web


LOGGER = logging.getLogger("true_family_journal")

APP_BASE_SLUG = "true_family_journal"
APP_FULL_SLUG = "8c9c720e_true_family_journal"
APP_HOSTNAME = "8c9c720e-true-family-journal"
APP_VERSION = "0.2.1"
PROTOCOL = "true-family-journal-v1"
DISCOVERY_SERVICE = "true_family"
PORT = 8765

MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_ROOT_BYTES = 3 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
MAX_INTEGER_DIGITS = 128
MAX_GENERATION = (1 << 63) - 1
MAX_REPLAY_ENTRIES = 65_536
MAX_CONCURRENT_AUTHENTICATED_REQUESTS = 16
REQUEST_SLOT_TIMEOUT_SECONDS = 1.0
BODY_READ_TIMEOUT_SECONDS = 5.0
RESPONSE_WRITE_TIMEOUT_SECONDS = 5.0
HANDLER_DRAIN_TIMEOUT_SECONDS = 15.0
MAX_ACCEPTED_CONNECTIONS = 16
MAX_HEADER_BYTES = 8 * 1024
HEADER_READ_TIMEOUT_SECONDS = 2.0
MAX_CONTENT_LENGTH_DIGITS = 10
MAX_RECEIPTS_PER_JOURNAL = 4_096
MAX_RECEIPT_RESPONSE_BYTES = 512

DATABASE_NAME = "true_family_journal.sqlite3"
DISCOVERY_UUID_NAME = "true_family_journal.discovery_uuid"
DATABASE_USER_VERSION = 3
SQLITE_BUSY_TIMEOUT_MS = 5_000

REQUEST_BOOT_HEADER = "X-True-Family-Boot-ID"
REQUEST_ID_HEADER = "X-True-Family-Request-ID"
SIGNATURE_HEADER = "X-True-Family-Signature"
REQUEST_SIGNATURE_DOMAIN = "true-family-journal-request-v1"
RESPONSE_SIGNATURE_DOMAIN = "true-family-journal-response-v1"
COMMIT_TOKEN_DOMAIN = "true-family-journal-commit-v1"
SAVE_REQUEST_ID_DOMAIN = "true-family-journal-save-id-v1"

HEX_32_PATTERN = re.compile(r"^[0-9a-f]{32}$")
HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_PATTERN = re.compile(r"^tfj-[0-9a-f]{32}$")
CONTENT_LENGTH_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)$")
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
DISCOVERY_UUID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

HELLO_CAPABILITIES = (
    "barrier",
    "close",
    "idempotent-save",
    "load",
    "revision-and-generation-cas",
    "durability.sqlite-wal-full-process-crash-cas.v1",
)

POST_PATHS = frozenset(
    {"/v1/hello", "/v1/load", "/v1/save", "/v1/barrier", "/v1/close"}
)

JOURNAL_TABLE_SQL = """
CREATE TABLE journals (
    journal_id TEXT NOT NULL PRIMARY KEY,
    canonical_root BLOB NOT NULL CHECK (
        typeof(canonical_root) = 'blob' AND length(canonical_root) <= 3145728
    ),
    generation INTEGER NOT NULL CHECK (
        typeof(generation) = 'integer'
        AND generation >= 0
        AND generation <= 9223372036854775807
    ),
    revision TEXT NOT NULL CHECK (
        length(revision) = 64 AND revision NOT GLOB '*[^0-9a-f]*'
    ),
    commit_token TEXT NOT NULL CHECK (
        length(commit_token) = 64 AND commit_token NOT GLOB '*[^0-9a-f]*'
    )
) STRICT, WITHOUT ROWID
"""

RECEIPT_TABLE_SQL = """
CREATE TABLE operation_receipts (
    request_id TEXT NOT NULL PRIMARY KEY,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64
        AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    journal_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (
        typeof(generation) = 'integer'
        AND generation >= 0
        AND generation <= 9223372036854775807
    ),
    revision TEXT NOT NULL CHECK (
        length(revision) = 64 AND revision NOT GLOB '*[^0-9a-f]*'
    ),
    commit_token TEXT NOT NULL CHECK (
        length(commit_token) = 64 AND commit_token NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_response BLOB NOT NULL CHECK (
        typeof(canonical_response) = 'blob'
        AND length(canonical_response) <= 512
    ),
    FOREIGN KEY (journal_id) REFERENCES journals(journal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID
"""

JOURNAL_TOKEN_INDEX_SQL = """
CREATE UNIQUE INDEX journals_commit_token
ON journals(commit_token)
"""

RECEIPT_TOKEN_INDEX_SQL = """
CREATE UNIQUE INDEX operation_receipts_commit_token
ON operation_receipts(commit_token)
"""

RECEIPT_VERSION_INDEX_SQL = """
CREATE UNIQUE INDEX operation_receipts_journal_generation
ON operation_receipts(journal_id, generation)
"""

_T = TypeVar("_T")


class ProtocolFailure(Exception):
    """A safe, externally reportable protocol failure."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class DuplicateJsonKey(ValueError):
    """Canonical JSON contained a duplicate object key."""


class JournalStoreError(RuntimeError):
    """Base class for fail-closed journal storage errors."""


class JournalStoreConflict(JournalStoreError):
    """A caller supplied stale or conflicting compare-and-swap evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class JournalStoreCorruption(JournalStoreError):
    """SQLite or a durable application row failed validation."""


class JournalStoreSchemaError(JournalStoreError):
    """The database has an unsupported or unexpected schema."""


class JournalStoreClosed(JournalStoreError):
    """New work was submitted after shutdown began."""


class SupervisorDiscoveryError(RuntimeError):
    """Supervisor discovery replacement failed without exposing its payload."""


@dataclass(frozen=True, slots=True)
class JournalRecord:
    """One validated durable journal row."""

    root: dict[str, Any]
    generation: int
    revision: str
    commit_token: str


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    """One fully verified immutable save receipt."""

    request_id: str
    request_digest: str
    journal_id: str
    generation: int
    revision: str
    commit_token: str
    response: bytes


@dataclass(frozen=True, slots=True)
class SaveOutcome:
    """Exact canonical save response and whether it came from a receipt."""

    response: bytes
    replayed: bool


@dataclass(frozen=True, slots=True)
class AdmittedHeaders:
    """Canonical request headers accepted before any body bytes are buffered."""

    boot_id: str
    request_id: str
    signature: str
    content_length: int


@dataclass(frozen=True, slots=True)
class ProtocolResponse:
    """One canonical protocol response, signed only after authentication."""

    status: int
    body: bytes
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class StrictHttpRequest:
    """One fully framed strict HTTP/1.1 request."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


def _reject_json_constant(_value: str) -> None:
    raise ValueError("Non-finite JSON numbers are not supported.")


def _parse_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds its safety bound.")
    return int(value)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise DuplicateJsonKey("Duplicate JSON object key.")
        output[key] = value
    return output


def _validate_json_tree(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON node count exceeds its safety bound.")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON depth exceeds its safety bound.")

        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise TypeError("JSON object keys must be built-in strings.")
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
            continue
        if type(item) is list:
            stack.extend((child, depth + 1) for child in item)
            continue
        if type(item) is str:
            item.encode("utf-8", "strict")
            continue
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite.")
            continue
        if type(item) in {int, bool} or item is None:
            continue
        raise TypeError("JSON values must use built-in JSON types.")


def canonical_json(value: Any) -> bytes:
    """Return the one canonical JSON byte representation used by the protocol."""

    _validate_json_tree(value)
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError, UnicodeError) as err:
        raise ValueError("Value cannot be represented as canonical JSON.") from err
    return rendered.encode("utf-8")


# The canonical root bytes replace the two-byte ``{}`` placeholder exactly.
MAX_LOAD_RESPONSE_OVERHEAD = len(
    canonical_json(
        {
            "absent": False,
            "generation": MAX_GENERATION,
            "revision": "f" * 64,
            "root": {},
        }
    )
) - 2
if MAX_ROOT_BYTES + MAX_LOAD_RESPONSE_OVERHEAD > MAX_BODY_BYTES:
    raise RuntimeError("The configured root limit cannot fit a load response.")


def parse_canonical_json(raw: bytes) -> dict[str, Any]:
    """Decode a strict built-in root object and require byte-level canonicality."""

    if len(raw) > MAX_BODY_BYTES:
        raise ProtocolFailure(413, "body_too_large")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
            parse_int=_parse_json_integer,
        )
        _validate_json_tree(value)
        encoded = canonical_json(value)
    except (
        DuplicateJsonKey,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as err:
        raise ProtocolFailure(400, "invalid_json") from err
    if type(value) is not dict:
        raise ProtocolFailure(400, "invalid_root")
    if encoded != raw:
        raise ProtocolFailure(400, "noncanonical_json")
    return value


def _exact_envelope(value: dict[str, Any], keys: frozenset[str]) -> None:
    if set(value) != keys:
        raise ProtocolFailure(400, "invalid_envelope")


def _validate_journal_id(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 255
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProtocolFailure(400, "invalid_journal_id")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as err:
        raise ProtocolFailure(400, "invalid_journal_id") from err
    return value


def _validate_client_id(value: Any) -> str:
    if type(value) is not str or not HEX_32_PATTERN.fullmatch(value):
        raise ProtocolFailure(400, "invalid_client_id")
    return value


def _validate_request_id(value: Any) -> str:
    if type(value) is not str or not REQUEST_ID_PATTERN.fullmatch(value):
        raise ProtocolFailure(400, "invalid_request_id")
    return value


def _validate_digest(value: Any, code: str = "invalid_digest") -> str:
    if type(value) is not str or not HEX_64_PATTERN.fullmatch(value):
        raise ProtocolFailure(400, code)
    return value


def _validate_expected_revision(value: Any) -> str | None:
    if value is None:
        return None
    return _validate_digest(value, "invalid_expected_revision")


def _validate_generation(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_GENERATION:
        raise ProtocolFailure(400, "invalid_generation")
    return value


def _validate_root(
    value: Any,
    expected_journal_id: str,
) -> tuple[dict[str, Any], bytes, int]:
    if type(value) is not dict:
        raise ProtocolFailure(400, "invalid_journal_root")
    if "journal_id" not in value or "generation" not in value:
        raise ProtocolFailure(400, "invalid_journal_root")
    root_journal_id = _validate_journal_id(value["journal_id"])
    if root_journal_id != expected_journal_id:
        raise ProtocolFailure(400, "journal_id_mismatch")
    generation = _validate_generation(value["generation"])
    try:
        root_bytes = canonical_json(value)
    except (TypeError, UnicodeError, ValueError) as err:
        raise ProtocolFailure(400, "invalid_journal_root") from err
    if len(root_bytes) > MAX_ROOT_BYTES:
        raise ProtocolFailure(413, "root_too_large")
    return value, root_bytes, generation


def _validate_nonce(value: Any) -> str:
    if type(value) is not str:
        raise ProtocolFailure(400, "invalid_nonce")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as err:
        raise ProtocolFailure(400, "invalid_nonce") from err
    if (
        not encoded
        or len(encoded) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProtocolFailure(400, "invalid_nonce")
    return value


def _request_signature_bytes(
    method: str,
    path: str,
    boot_id: str,
    request_id: str,
    body: bytes,
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return (
        f"{REQUEST_SIGNATURE_DOMAIN}\n{method}\n{path}\n{boot_id}\n"
        f"{request_id}\n{body_digest}"
    ).encode("ascii")


def _response_signature_bytes(
    status: int,
    path: str,
    boot_id: str,
    request_id: str,
    body: bytes,
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return (
        f"{RESPONSE_SIGNATURE_DOMAIN}\n{status}\n{path}\n{boot_id}\n"
        f"{request_id}\n{body_digest}"
    ).encode("ascii")


def sign_request(
    key: bytes,
    method: str,
    path: str,
    boot_id: str,
    request_id: str,
    body: bytes,
) -> str:
    """Sign one request; exported so a future project client can share the spec."""

    return hmac.new(
        key,
        _request_signature_bytes(method, path, boot_id, request_id, body),
        hashlib.sha256,
    ).hexdigest()


def sign_response(
    key: bytes,
    status: int,
    path: str,
    boot_id: str,
    request_id: str,
    body: bytes,
) -> str:
    """Sign one response using the response domain separator."""

    return hmac.new(
        key,
        _response_signature_bytes(status, path, boot_id, request_id, body),
        hashlib.sha256,
    ).hexdigest()


def _commit_token(request_id: str, request_digest: str) -> str:
    material = (
        f"{COMMIT_TOKEN_DOMAIN}\n{request_id}\n{request_digest}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def deterministic_save_request_id(request_digest: str) -> str:
    canonical_digest = _validate_digest(request_digest)
    material = f"{SAVE_REQUEST_ID_DOMAIN}\n{canonical_digest}".encode("ascii")
    return f"tfj-{hashlib.sha256(material).hexdigest()[:32]}"


def _parse_content_length(value: Any) -> int:
    if (
        type(value) is not str
        or len(value) > MAX_CONTENT_LENGTH_DIGITS
        or not CONTENT_LENGTH_PATTERN.fullmatch(value)
    ):
        raise ProtocolFailure(400, "invalid_content_length")
    try:
        content_length = int(value, 10)
    except (TypeError, ValueError, OverflowError) as err:
        raise ProtocolFailure(400, "invalid_content_length") from err
    if content_length > MAX_BODY_BYTES:
        raise ProtocolFailure(413, "body_too_large")
    return content_length


async def _await_worker(future: asyncio.Future[_T]) -> _T:
    """Do not abandon a worker operation when its caller is cancelled."""

    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        while not future.done():
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                continue
        future.result()
        raise


class SQLiteJournalStore:
    """Single-worker SQLite persistence and durable save receipts."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="true-family-journal-sqlite",
        )
        self._connection: sqlite3.Connection | None = None
        self._worker_ident: int | None = None
        self._closing = False
        self._closed = False
        self._close_future: asyncio.Future[None] | None = None

    @classmethod
    async def async_open(cls, data_dir: Path | str) -> SQLiteJournalStore:
        directory = Path(data_dir)
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        store = cls(directory / DATABASE_NAME)
        try:
            await store._submit(store._open_sync)
        except asyncio.CancelledError:
            await store.async_close()
            raise
        except BaseException:
            store._executor.shutdown(wait=True, cancel_futures=False)
            store._closed = True
            raise
        return store

    def _worker_call(self, function: Callable[..., _T], *args: Any) -> _T:
        current_ident = threading.get_ident()
        if self._worker_ident is None:
            self._worker_ident = current_ident
        elif self._worker_ident != current_ident:
            raise JournalStoreError("SQLite escaped its private worker thread.")
        return function(*args)

    async def _submit(self, function: Callable[..., _T], *args: Any) -> _T:
        if self._closing or self._closed:
            raise JournalStoreClosed("Journal store shutdown has begun.")
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(
            self._executor,
            self._worker_call,
            function,
            *args,
        )
        return await _await_worker(future)

    def _open_sync(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
            connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
            journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "wal":
                raise JournalStoreSchemaError("SQLite WAL mode is unavailable.")
            connection.execute("PRAGMA synchronous=FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if synchronous != (2,):
                raise JournalStoreSchemaError("SQLite FULL sync mode is unavailable.")
            connection.execute("PRAGMA foreign_keys=ON")
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
            if foreign_keys != (1,):
                raise JournalStoreSchemaError("SQLite foreign keys are unavailable.")

            self._quick_check(connection)
            version_row = connection.execute("PRAGMA user_version").fetchone()
            if version_row is None or type(version_row[0]) is not int:
                raise JournalStoreSchemaError("SQLite user version is unreadable.")
            version = version_row[0]
            tables = self._application_tables(connection)
            if version == 0:
                if tables:
                    raise JournalStoreSchemaError(
                        "An unversioned journal database is not empty."
                    )
                self._create_schema(connection)
            elif version != DATABASE_USER_VERSION:
                raise JournalStoreSchemaError(
                    "The journal database schema version is unsupported."
                )

            self._validate_pragmas(connection)
            self._validate_schema(connection)
            self._quick_check(connection)
            self._validate_durable_rows(connection)
            self._connection = connection
        except (JournalStoreError, sqlite3.Error) as err:
            if connection is not None:
                connection.close()
            if isinstance(err, JournalStoreError):
                raise
            raise JournalStoreCorruption("SQLite startup validation failed.") from err

    @staticmethod
    def _quick_check(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA quick_check").fetchall()
        if rows != [("ok",)]:
            raise JournalStoreCorruption("SQLite quick_check failed.")

    @staticmethod
    def _application_tables(connection: sqlite3.Connection) -> set[str]:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }

    @staticmethod
    def _normalize_ddl(value: str) -> str:
        return " ".join(value.strip().removesuffix(";").split())

    @classmethod
    def _expected_schema_objects(cls) -> dict[tuple[str, str, str], str]:
        return {
            ("table", "journals", "journals"): cls._normalize_ddl(
                JOURNAL_TABLE_SQL
            ),
            (
                "table",
                "operation_receipts",
                "operation_receipts",
            ): cls._normalize_ddl(RECEIPT_TABLE_SQL),
            (
                "index",
                "journals_commit_token",
                "journals",
            ): cls._normalize_ddl(JOURNAL_TOKEN_INDEX_SQL),
            (
                "index",
                "operation_receipts_commit_token",
                "operation_receipts",
            ): cls._normalize_ddl(RECEIPT_TOKEN_INDEX_SQL),
            (
                "index",
                "operation_receipts_journal_generation",
                "operation_receipts",
            ): cls._normalize_ddl(RECEIPT_VERSION_INDEX_SQL),
        }

    @staticmethod
    def _validate_pragmas(connection: sqlite3.Connection) -> None:
        expected = {
            "busy_timeout": SQLITE_BUSY_TIMEOUT_MS,
            "foreign_keys": 1,
            "journal_mode": "wal",
            "synchronous": 2,
            "user_version": DATABASE_USER_VERSION,
        }
        actual: dict[str, Any] = {}
        for pragma in expected:
            row = connection.execute(f"PRAGMA {pragma}").fetchone()
            if row is None or len(row) != 1:
                raise JournalStoreSchemaError(
                    "A required SQLite pragma is unreadable."
                )
            actual[pragma] = (
                str(row[0]).lower() if pragma == "journal_mode" else row[0]
            )
        if actual != expected:
            raise JournalStoreSchemaError(
                "The SQLite durability pragmas are not exact."
            )

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(JOURNAL_TABLE_SQL)
            connection.execute(RECEIPT_TABLE_SQL)
            connection.execute(JOURNAL_TOKEN_INDEX_SQL)
            connection.execute(RECEIPT_TOKEN_INDEX_SQL)
            connection.execute(RECEIPT_VERSION_INDEX_SQL)
            connection.execute(f"PRAGMA user_version={DATABASE_USER_VERSION}")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _table_columns(
        connection: sqlite3.Connection,
        table: str,
    ) -> tuple[tuple[str, str, int, int], ...]:
        return tuple(
            (row[1], row[2], row[3], row[5])
            for row in connection.execute(f"PRAGMA table_info({table})")
        )

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        schema_rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if any(type(row[3]) is not str for row in schema_rows):
            raise JournalStoreSchemaError("A SQLite schema object has no exact DDL.")
        actual_objects = {
            (row[0], row[1], row[2]): self._normalize_ddl(row[3])
            for row in schema_rows
        }
        if actual_objects != self._expected_schema_objects():
            raise JournalStoreSchemaError(
                "The SQLite schema objects or normalized DDL are unexpected."
            )
        if self._table_columns(connection, "journals") != (
            ("journal_id", "TEXT", 1, 1),
            ("canonical_root", "BLOB", 1, 0),
            ("generation", "INTEGER", 1, 0),
            ("revision", "TEXT", 1, 0),
            ("commit_token", "TEXT", 1, 0),
        ):
            raise JournalStoreSchemaError("The journals table shape is unexpected.")
        if self._table_columns(connection, "operation_receipts") != (
            ("request_id", "TEXT", 1, 1),
            ("request_digest", "TEXT", 1, 0),
            ("journal_id", "TEXT", 1, 0),
            ("generation", "INTEGER", 1, 0),
            ("revision", "TEXT", 1, 0),
            ("commit_token", "TEXT", 1, 0),
            ("canonical_response", "BLOB", 1, 0),
        ):
            raise JournalStoreSchemaError(
                "The operation receipts table shape is unexpected."
            )
        table_flags = {
            row[1]: (row[4], row[5])
            for row in connection.execute("PRAGMA table_list")
            if row[1] in {"journals", "operation_receipts"}
        }
        if table_flags != {
            "journals": (1, 1),
            "operation_receipts": (1, 1),
        }:
            raise JournalStoreSchemaError("Journal tables must be strict and rowless.")
        index_signatures: dict[str, tuple[int, str, int, tuple[str, ...]]] = {}
        for table in ("journals", "operation_receipts"):
            for row in connection.execute(f"PRAGMA index_list({table})"):
                index_signatures[row[1]] = (
                    row[2],
                    row[3],
                    row[4],
                    tuple(
                        column[2]
                        for column in connection.execute(
                            f"PRAGMA index_info({row[1]})"
                        )
                    ),
                )
        if index_signatures != {
            "journals_commit_token": (1, "c", 0, ("commit_token",)),
            "sqlite_autoindex_journals_1": (1, "pk", 0, ("journal_id",)),
            "operation_receipts_commit_token": (
                1,
                "c",
                0,
                ("commit_token",),
            ),
            "operation_receipts_journal_generation": (
                1,
                "c",
                0,
                ("journal_id", "generation"),
            ),
            "sqlite_autoindex_operation_receipts_1": (
                1,
                "pk",
                0,
                ("request_id",),
            ),
        }:
            raise JournalStoreSchemaError("The SQLite index definitions are unexpected.")
        if connection.execute("PRAGMA foreign_key_list(journals)").fetchall():
            raise JournalStoreSchemaError("The journals table has an unexpected key.")
        if connection.execute(
            "PRAGMA foreign_key_list(operation_receipts)"
        ).fetchall() != [
            (
                0,
                0,
                "journals",
                "journal_id",
                "journal_id",
                "RESTRICT",
                "RESTRICT",
                "NONE",
            )
        ]:
            raise JournalStoreSchemaError(
                "The operation receipt foreign key is unexpected."
            )
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise JournalStoreCorruption("SQLite foreign-key validation failed.")

    @staticmethod
    def _decode_durable_root(
        journal_id: Any,
        root_blob: Any,
        generation: Any,
        revision: Any,
        commit_token: Any,
    ) -> JournalRecord:
        try:
            canonical_journal_id = _validate_journal_id(journal_id)
            canonical_generation = _validate_generation(generation)
            canonical_revision = _validate_digest(revision)
            canonical_commit_token = _validate_digest(commit_token)
            if type(root_blob) is not bytes:
                raise ProtocolFailure(400, "invalid_journal_root")
            root = parse_canonical_json(root_blob)
            _root, encoded, root_generation = _validate_root(
                root,
                canonical_journal_id,
            )
        except ProtocolFailure as err:
            raise JournalStoreCorruption("A durable journal row is invalid.") from err
        if root_generation != canonical_generation:
            raise JournalStoreCorruption("A durable journal generation is inconsistent.")
        if hashlib.sha256(encoded).hexdigest() != canonical_revision:
            raise JournalStoreCorruption("A durable journal revision is inconsistent.")
        return JournalRecord(
            root=root,
            generation=canonical_generation,
            revision=canonical_revision,
            commit_token=canonical_commit_token,
        )

    @staticmethod
    def _decode_durable_receipt(
        request_id: Any,
        request_digest: Any,
        journal_id: Any,
        generation: Any,
        revision: Any,
        commit_token: Any,
        response_blob: Any,
    ) -> ReceiptRecord:
        try:
            canonical_request_id = _validate_request_id(request_id)
            canonical_request_digest = _validate_digest(request_digest)
            canonical_journal_id = _validate_journal_id(journal_id)
            canonical_generation = _validate_generation(generation)
            canonical_revision = _validate_digest(revision)
            canonical_token = _validate_digest(commit_token)
            if (
                type(response_blob) is not bytes
                or len(response_blob) > MAX_RECEIPT_RESPONSE_BYTES
            ):
                raise ProtocolFailure(400, "invalid_receipt")
            response = parse_canonical_json(response_blob)
            _exact_envelope(
                response,
                frozenset({"commit_token", "generation", "revision"}),
            )
            if not hmac.compare_digest(
                canonical_token,
                _commit_token(canonical_request_id, canonical_request_digest),
            ):
                raise ProtocolFailure(400, "invalid_receipt")
            if _validate_digest(response["commit_token"]) != canonical_token:
                raise ProtocolFailure(400, "invalid_receipt")
            if _validate_generation(response["generation"]) != canonical_generation:
                raise ProtocolFailure(400, "invalid_receipt")
            if _validate_digest(response["revision"]) != canonical_revision:
                raise ProtocolFailure(400, "invalid_receipt")
        except ProtocolFailure as err:
            raise JournalStoreCorruption("A durable operation receipt is invalid.") from err
        return ReceiptRecord(
            request_id=canonical_request_id,
            request_digest=canonical_request_digest,
            journal_id=canonical_journal_id,
            generation=canonical_generation,
            revision=canonical_revision,
            commit_token=canonical_token,
            response=response_blob,
        )

    @staticmethod
    def _validate_receipt_relationship(
        receipt: ReceiptRecord,
        journal: JournalRecord,
    ) -> None:
        if receipt.generation > journal.generation:
            raise JournalStoreCorruption(
                "A durable receipt is newer than its journal."
            )
        if receipt.generation == journal.generation and (
            not hmac.compare_digest(receipt.revision, journal.revision)
            or not hmac.compare_digest(receipt.commit_token, journal.commit_token)
        ):
            raise JournalStoreCorruption(
                "The current journal does not match its durable receipt."
            )

    def _validate_durable_rows(self, connection: sqlite3.Connection) -> None:
        journals: dict[str, JournalRecord] = {}
        for row in connection.execute(
            "SELECT journal_id, canonical_root, generation, revision, commit_token "
            "FROM journals"
        ):
            record = self._decode_durable_root(*row)
            journals[row[0]] = record

        receipts_by_journal: dict[str, list[ReceiptRecord]] = {
            journal_id: [] for journal_id in journals
        }
        for row in connection.execute(
            "SELECT request_id, request_digest, journal_id, generation, revision, "
            "commit_token, canonical_response "
            "FROM operation_receipts"
        ):
            receipt = self._decode_durable_receipt(*row)
            journal = journals.get(receipt.journal_id)
            if journal is None:
                raise JournalStoreCorruption(
                    "A durable receipt has no journal relationship."
                )
            self._validate_receipt_relationship(receipt, journal)
            receipts_by_journal[receipt.journal_id].append(receipt)
        for journal_id, journal in journals.items():
            receipts = sorted(
                receipts_by_journal[journal_id],
                key=lambda receipt: receipt.generation,
            )
            first_generation = max(
                0,
                journal.generation - MAX_RECEIPTS_PER_JOURNAL + 1,
            )
            expected_count = journal.generation - first_generation + 1
            if len(receipts) != expected_count:
                raise JournalStoreCorruption(
                    "The durable receipt suffix has an unexpected length."
                )
            if any(
                receipt.generation != expected_generation
                for expected_generation, receipt in enumerate(
                    receipts,
                    start=first_generation,
                )
            ):
                raise JournalStoreCorruption(
                    "The durable journal receipt suffix is not contiguous."
                )

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise JournalStoreClosed("The SQLite connection is unavailable.")
        return self._connection

    async def async_load(self, journal_id: str) -> JournalRecord | None:
        canonical_journal_id = _validate_journal_id(journal_id)
        return await self._submit(self._load_sync, canonical_journal_id)

    def _load_sync(self, journal_id: str) -> JournalRecord | None:
        row = self._require_connection().execute(
            "SELECT journal_id, canonical_root, generation, revision, commit_token "
            "FROM journals WHERE journal_id = ?",
            (journal_id,),
        ).fetchone()
        if row is None:
            return None
        return self._decode_durable_root(*row)

    async def async_save(
        self,
        *,
        journal_id: str,
        expected_revision: str | None,
        root: dict[str, Any],
        request_id: str,
        request_digest: str,
    ) -> SaveOutcome:
        canonical_journal_id = _validate_journal_id(journal_id)
        canonical_expected = _validate_expected_revision(expected_revision)
        canonical_request_id = _validate_request_id(request_id)
        canonical_request_digest = _validate_digest(request_digest)
        _root, root_bytes, generation = _validate_root(root, canonical_journal_id)
        return await self._submit(
            self._save_sync,
            canonical_journal_id,
            canonical_expected,
            root_bytes,
            generation,
            canonical_request_id,
            canonical_request_digest,
        )

    def _save_sync(
        self,
        journal_id: str,
        expected_revision: str | None,
        root_bytes: bytes,
        generation: int,
        request_id: str,
        request_digest: str,
    ) -> SaveOutcome:
        connection = self._require_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            receipt = connection.execute(
                "SELECT request_id, request_digest, journal_id, generation, revision, "
                "commit_token, canonical_response "
                "FROM operation_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if receipt is not None:
                verified_receipt = self._decode_durable_receipt(*receipt)
                if verified_receipt.request_digest != request_digest:
                    raise JournalStoreConflict("request_id_conflict")
                if verified_receipt.journal_id != journal_id:
                    raise JournalStoreCorruption(
                        "A replay receipt has the wrong journal relationship."
                    )
                journal_row = connection.execute(
                    "SELECT journal_id, canonical_root, generation, revision, "
                    "commit_token FROM journals WHERE journal_id = ?",
                    (journal_id,),
                ).fetchone()
                if journal_row is None:
                    raise JournalStoreCorruption(
                        "A replay receipt has no durable journal."
                    )
                journal_record = self._decode_durable_root(*journal_row)
                self._validate_receipt_relationship(
                    verified_receipt,
                    journal_record,
                )
                connection.execute("COMMIT")
                return SaveOutcome(response=verified_receipt.response, replayed=True)

            current = connection.execute(
                "SELECT generation, revision FROM journals WHERE journal_id = ?",
                (journal_id,),
            ).fetchone()
            if current is None:
                if generation != 0:
                    raise JournalStoreConflict("stale_generation")
                if expected_revision is not None:
                    raise JournalStoreConflict("stale_revision")
            else:
                current_generation, current_revision = current
                if current_generation >= MAX_GENERATION or generation != (
                    current_generation + 1
                ):
                    raise JournalStoreConflict("stale_generation")
                if expected_revision != current_revision:
                    raise JournalStoreConflict("stale_revision")

            revision = hashlib.sha256(root_bytes).hexdigest()
            commit_token = _commit_token(request_id, request_digest)
            response = canonical_json(
                {
                    "commit_token": commit_token,
                    "generation": generation,
                    "revision": revision,
                }
            )

            if current is None:
                connection.execute(
                    "INSERT INTO journals "
                    "(journal_id, canonical_root, generation, revision, commit_token) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (journal_id, root_bytes, generation, revision, commit_token),
                )
            else:
                cursor = connection.execute(
                    "UPDATE journals SET canonical_root = ?, generation = ?, "
                    "revision = ?, commit_token = ? "
                    "WHERE journal_id = ? AND generation = ? AND revision = ?",
                    (
                        root_bytes,
                        generation,
                        revision,
                        commit_token,
                        journal_id,
                        current[0],
                        current[1],
                    ),
                )
                if cursor.rowcount != 1:
                    raise JournalStoreConflict("cas_conflict")

            connection.execute(
                "INSERT INTO operation_receipts "
                "(request_id, request_digest, journal_id, generation, revision, "
                "commit_token, canonical_response) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    request_digest,
                    journal_id,
                    generation,
                    revision,
                    commit_token,
                    response,
                ),
            )
            first_retained_generation = max(
                0,
                generation - MAX_RECEIPTS_PER_JOURNAL + 1,
            )
            connection.execute(
                "DELETE FROM operation_receipts "
                "WHERE journal_id = ? AND generation < ?",
                (journal_id, first_retained_generation),
            )
            connection.execute("COMMIT")
            return SaveOutcome(response=response, replayed=False)
        except (JournalStoreError, sqlite3.Error) as err:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            if isinstance(err, JournalStoreError):
                raise
            if isinstance(err, sqlite3.IntegrityError):
                raise JournalStoreConflict("cas_conflict") from err
            raise JournalStoreCorruption("SQLite save failed.") from err
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    async def async_barrier(self, journal_id: str, commit_token: str) -> None:
        canonical_journal_id = _validate_journal_id(journal_id)
        canonical_token = _validate_digest(commit_token, "invalid_commit_token")
        await self._submit(
            self._barrier_sync,
            canonical_journal_id,
            canonical_token,
        )

    def _barrier_sync(self, journal_id: str, commit_token: str) -> None:
        connection = self._require_connection()
        row = connection.execute(
            "SELECT request_id, request_digest, journal_id, generation, revision, "
            "commit_token, canonical_response "
            "FROM operation_receipts "
            "WHERE journal_id = ? AND commit_token = ?",
            (journal_id, commit_token),
        ).fetchone()
        if row is None:
            raise JournalStoreConflict("unknown_commit_token")
        receipt = self._decode_durable_receipt(*row)
        if receipt.journal_id != journal_id or not hmac.compare_digest(
            receipt.commit_token,
            commit_token,
        ):
            raise JournalStoreCorruption(
                "The barrier receipt relationship is invalid."
            )
        journal_row = connection.execute(
            "SELECT journal_id, canonical_root, generation, revision, commit_token "
            "FROM journals WHERE journal_id = ?",
            (journal_id,),
        ).fetchone()
        if journal_row is None:
            raise JournalStoreCorruption("The barrier journal is unavailable.")
        self._validate_receipt_relationship(
            receipt,
            self._decode_durable_root(*journal_row),
        )

    def _close_sync(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is None:
            return
        try:
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint != (0, 0, 0):
                raise JournalStoreCorruption("SQLite WAL checkpoint did not complete.")
        finally:
            connection.close()

    async def async_close(self) -> None:
        if self._closed:
            return
        if self._close_future is None:
            self._closing = True
            loop = asyncio.get_running_loop()
            self._close_future = loop.run_in_executor(
                self._executor,
                self._worker_call,
                self._close_sync,
            )
        try:
            await _await_worker(self._close_future)
        except asyncio.CancelledError:
            self._finish_executor_shutdown()
            raise
        except BaseException:
            self._finish_executor_shutdown()
            raise
        self._finish_executor_shutdown()

    def _finish_executor_shutdown(self) -> None:
        if self._closed:
            return
        self._executor.shutdown(wait=True, cancel_futures=False)
        self._closed = True


class ReplayGuard:
    """Bound authenticated request replay state to the current process boot."""

    def __init__(self) -> None:
        self._entries: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def claim(
        self,
        request_id: str,
        path: str,
        request_digest: str,
        *,
        idempotent: bool,
    ) -> None:
        async with self._lock:
            previous = self._entries.get(request_id)
            identity = (path, request_digest)
            if previous is not None:
                if not idempotent or previous != identity:
                    raise ProtocolFailure(409, "request_id_conflict")
                self._entries.move_to_end(request_id)
                return
            self._entries[request_id] = identity
            if len(self._entries) > MAX_REPLAY_ENTRIES:
                self._entries.popitem(last=False)


class JournalServerState:
    """Per-process key, boot identity, replay state, and SQLite owner."""

    def __init__(
        self,
        store: SQLiteJournalStore,
        *,
        key: bytes,
        boot_id: str,
    ) -> None:
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("The process HMAC key must contain exactly 32 bytes.")
        if not HEX_32_PATTERN.fullmatch(boot_id):
            raise ValueError("The process boot ID must be 32 lowercase hex characters.")
        self.store = store
        self._key = key
        self.boot_id = boot_id
        self.replays = ReplayGuard()
        self.request_slots = asyncio.BoundedSemaphore(
            MAX_CONCURRENT_AUTHENTICATED_REQUESTS
        )
        self._closed = False

    @classmethod
    async def async_create(
        cls,
        data_dir: Path | str,
        *,
        key: bytes | None = None,
        boot_id: str | None = None,
    ) -> JournalServerState:
        process_key = secrets.token_bytes(32) if key is None else key
        process_boot_id = secrets.token_hex(16) if boot_id is None else boot_id
        store = await SQLiteJournalStore.async_open(data_dir)
        return cls(store, key=process_key, boot_id=process_boot_id)

    @property
    def key_hex(self) -> str:
        return self._key.hex()

    def verify_request(
        self,
        supplied_signature: str,
        method: str,
        path: str,
        boot_id: str,
        request_id: str,
        body: bytes,
    ) -> bool:
        expected = sign_request(
            self._key,
            method,
            path,
            boot_id,
            request_id,
            body,
        )
        return hmac.compare_digest(expected, supplied_signature)

    def response_signature(
        self,
        status: int,
        path: str,
        request_id: str,
        body: bytes,
    ) -> str:
        return sign_response(
            self._key,
            status,
            path,
            self.boot_id,
            request_id,
            body,
        )

    def discovery_config(self, host: str) -> dict[str, Any]:
        if type(host) is not str or host != APP_HOSTNAME:
            raise SupervisorDiscoveryError("The trusted internal App hostname is required.")
        return {
            "boot_id": self.boot_id,
            "host": host,
            "key": self.key_hex,
            "port": PORT,
            "protocol": PROTOCOL,
        }

    async def async_close(self) -> None:
        if self._closed:
            return
        try:
            await self.store.async_close()
        finally:
            if self.store._closed:
                self._closed = True


STATE_KEY = web.AppKey("true_family_journal_state", JournalServerState)


def _single_header(
    request: web.Request,
    name: str,
    *,
    status: int = 400,
    code: str = "invalid_headers",
) -> str:
    values = request.headers.getall(name, [])
    if len(values) != 1:
        raise ProtocolFailure(status, code)
    return values[0]


def _admit_request_headers(request: web.Request) -> AdmittedHeaders:
    request_id = _single_header(request, REQUEST_ID_HEADER)
    if not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise ProtocolFailure(400, "invalid_request_id")
    boot_id = _single_header(
        request,
        REQUEST_BOOT_HEADER,
        status=401,
        code="authentication_failed",
    )
    signature = _single_header(
        request,
        SIGNATURE_HEADER,
        status=401,
        code="authentication_failed",
    )
    if (
        not HEX_32_PATTERN.fullmatch(boot_id)
        or not HEX_64_PATTERN.fullmatch(signature)
    ):
        raise ProtocolFailure(401, "authentication_failed")
    if request.query_string:
        raise ProtocolFailure(400, "query_not_allowed")

    encodings = request.headers.getall("Content-Encoding", [])
    if encodings and (len(encodings) != 1 or encodings[0].lower() != "identity"):
        raise ProtocolFailure(400, "unsupported_content_encoding")
    content_types = request.headers.getall("Content-Type", [])
    if len(content_types) != 1:
        raise ProtocolFailure(400, "invalid_content_type")
    normalized_type = content_types[0].replace(" ", "").lower()
    if normalized_type not in {"application/json", "application/json;charset=utf-8"}:
        raise ProtocolFailure(400, "invalid_content_type")
    expectations = request.headers.getall("Expect", [])
    if expectations:
        raise ProtocolFailure(400, "expectation_not_supported")

    lengths = request.headers.getall("Content-Length", [])
    transfer_encodings = request.headers.getall("Transfer-Encoding", [])
    if transfer_encodings:
        raise ProtocolFailure(400, "invalid_transfer_encoding")
    if len(lengths) != 1:
        raise ProtocolFailure(400, "invalid_content_length")
    content_length = _parse_content_length(lengths[0])

    return AdmittedHeaders(
        boot_id=boot_id,
        request_id=request_id,
        signature=signature,
        content_length=content_length,
    )


async def _read_request_body(
    request: web.Request,
    content_length: int,
) -> bytes:

    body = bytearray()
    while True:
        chunk = await request.content.read(64 * 1024)
        if not chunk:
            break
        if len(chunk) > MAX_BODY_BYTES - len(body):
            raise ProtocolFailure(413, "body_too_large")
        body.extend(chunk)
    if len(body) != content_length:
        raise ProtocolFailure(400, "invalid_content_length")
    return bytes(body)


def _protocol_error(
    status: int,
    code: str,
    *,
    request_id: str | None = None,
) -> ProtocolResponse:
    return ProtocolResponse(
        status=status,
        body=canonical_json({"error": code}),
        request_id=request_id,
    )


def _signed_response_headers(
    state: JournalServerState,
    path: str,
    response: ProtocolResponse,
) -> dict[str, str]:
    if response.request_id is None:
        return {}
    return {
        REQUEST_BOOT_HEADER: state.boot_id,
        REQUEST_ID_HEADER: response.request_id,
        SIGNATURE_HEADER: state.response_signature(
            response.status,
            path,
            response.request_id,
            response.body,
        ),
    }


def _web_protocol_response(
    state: JournalServerState,
    path: str,
    response: ProtocolResponse,
    *,
    close_connection: bool = False,
) -> web.Response:
    web_response = web.Response(
        status=response.status,
        body=response.body,
        content_type="application/json",
        charset="utf-8",
        headers=_signed_response_headers(state, path, response),
    )
    if close_connection:
        web_response.force_close()
    return web_response


async def _health(_request: web.Request) -> web.Response:
    return web.Response(
        body=canonical_json({"protocol": PROTOCOL, "status": "ok"}),
        content_type="application/json",
        charset="utf-8",
    )


async def _dispatch_authenticated(
    state: JournalServerState,
    path: str,
    envelope: dict[str, Any],
    request_id: str,
    request_digest: str,
) -> bytes:
    if path == "/v1/hello":
        _exact_envelope(envelope, frozenset({"client_id", "nonce"}))
        _validate_client_id(envelope["client_id"])
        nonce = _validate_nonce(envelope["nonce"])
        return canonical_json(
            {
                "capabilities": list(HELLO_CAPABILITIES),
                "nonce": nonce,
            }
        )

    if path == "/v1/load":
        _exact_envelope(envelope, frozenset({"client_id", "journal_id"}))
        _validate_client_id(envelope["client_id"])
        journal_id = _validate_journal_id(envelope["journal_id"])
        record = await state.store.async_load(journal_id)
        if record is None:
            return canonical_json(
                {
                    "absent": True,
                    "generation": None,
                    "revision": None,
                    "root": None,
                }
            )
        return canonical_json(
            {
                "absent": False,
                "generation": record.generation,
                "revision": record.revision,
                "root": record.root,
            }
        )

    if path == "/v1/save":
        _exact_envelope(
            envelope,
            frozenset(
                {"client_id", "expected_revision", "journal_id", "root"}
            ),
        )
        _validate_client_id(envelope["client_id"])
        journal_id = _validate_journal_id(envelope["journal_id"])
        expected_revision = _validate_expected_revision(
            envelope["expected_revision"]
        )
        root, _root_bytes, _generation = _validate_root(
            envelope["root"],
            journal_id,
        )
        outcome = await state.store.async_save(
            journal_id=journal_id,
            expected_revision=expected_revision,
            root=root,
            request_id=request_id,
            request_digest=request_digest,
        )
        return outcome.response

    if path == "/v1/barrier":
        _exact_envelope(
            envelope,
            frozenset({"client_id", "commit_token", "journal_id"}),
        )
        _validate_client_id(envelope["client_id"])
        journal_id = _validate_journal_id(envelope["journal_id"])
        commit_token = _validate_digest(
            envelope["commit_token"],
            "invalid_commit_token",
        )
        await state.store.async_barrier(journal_id, commit_token)
        return canonical_json({"commit_token": commit_token})

    if path == "/v1/close":
        _exact_envelope(envelope, frozenset({"client_id"}))
        _validate_client_id(envelope["client_id"])
        return canonical_json({"closed": True})

    raise ProtocolFailure(404, "unknown_endpoint")


async def _process_signed_request(
    state: JournalServerState,
    *,
    method: str,
    path: str,
    boot_id: str,
    request_id: str,
    signature: str,
    body: bytes,
) -> ProtocolResponse:
    if (
        method != "POST"
        or not HEX_32_PATTERN.fullmatch(boot_id)
        or not REQUEST_ID_PATTERN.fullmatch(request_id)
        or not HEX_64_PATTERN.fullmatch(signature)
        or not hmac.compare_digest(boot_id, state.boot_id)
        or not state.verify_request(
            signature,
            method,
            path,
            boot_id,
            request_id,
            body,
        )
    ):
        return _protocol_error(401, "authentication_failed")

    request_digest = hashlib.sha256(body).hexdigest()
    try:
        if path == "/v1/save" and not hmac.compare_digest(
            request_id,
            deterministic_save_request_id(request_digest),
        ):
            raise ProtocolFailure(400, "invalid_save_request_id")
        envelope = parse_canonical_json(body)
        await state.replays.claim(
            request_id,
            path,
            request_digest,
            idempotent=path in {"/v1/save", "/v1/barrier"},
        )
        response_body = await _dispatch_authenticated(
            state,
            path,
            envelope,
            request_id,
            request_digest,
        )
        return ProtocolResponse(
            status=200,
            body=response_body,
            request_id=request_id,
        )
    except ProtocolFailure as err:
        return _protocol_error(err.status, err.code, request_id=request_id)
    except JournalStoreConflict as err:
        return _protocol_error(409, err.code, request_id=request_id)
    except asyncio.CancelledError:
        raise
    except JournalStoreError:
        LOGGER.exception("The journal store rejected an authenticated operation.")
        return _protocol_error(500, "storage_failure", request_id=request_id)
    except BaseException:
        LOGGER.exception("An authenticated journal operation failed.")
        return _protocol_error(500, "internal_error", request_id=request_id)


async def _authenticated_post(request: web.Request) -> web.Response:
    state = request.app[STATE_KEY]
    try:
        admitted = _admit_request_headers(request)
    except ProtocolFailure as err:
        return _web_protocol_response(
            state,
            request.path,
            _protocol_error(err.status, err.code),
            close_connection=True,
        )

    acquired = False
    try:
        try:
            async with asyncio.timeout(REQUEST_SLOT_TIMEOUT_SECONDS):
                await state.request_slots.acquire()
                acquired = True
        except TimeoutError:
            return _web_protocol_response(
                state,
                request.path,
                _protocol_error(503, "request_busy"),
                close_connection=True,
            )
        try:
            async with asyncio.timeout(BODY_READ_TIMEOUT_SECONDS):
                body = await _read_request_body(
                    request,
                    admitted.content_length,
                )
        except TimeoutError:
            return _web_protocol_response(
                state,
                request.path,
                _protocol_error(408, "request_timeout"),
                close_connection=True,
            )
        response = await _process_signed_request(
            state,
            method=request.method,
            path=request.path,
            boot_id=admitted.boot_id,
            request_id=admitted.request_id,
            signature=admitted.signature,
            body=body,
        )
        return _web_protocol_response(
            state,
            request.path,
            response,
            close_connection=response.request_id is None,
        )
    except ProtocolFailure as err:
        return _web_protocol_response(
            state,
            request.path,
            _protocol_error(err.status, err.code),
            close_connection=True,
        )
    except asyncio.CancelledError:
        raise
    except BaseException:
        LOGGER.exception("The test HTTP adapter failed before authentication.")
        return _web_protocol_response(
            state,
            request.path,
            _protocol_error(500, "internal_error"),
            close_connection=True,
        )
    finally:
        if acquired:
            state.request_slots.release()


async def _cleanup_application(app: web.Application) -> None:
    await app[STATE_KEY].async_close()


def create_web_application(state: JournalServerState) -> web.Application:
    """Create a test adapter around the shared signed protocol processor."""

    application = web.Application(client_max_size=MAX_BODY_BYTES + 1)
    application[STATE_KEY] = state
    application.router.add_get("/healthz", _health, allow_head=False)
    for path in (
        "/v1/hello",
        "/v1/load",
        "/v1/save",
        "/v1/barrier",
        "/v1/close",
    ):
        application.router.add_post(path, _authenticated_post)
    application.on_cleanup.append(_cleanup_application)
    return application


HTTP_REASON = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    408: "Request Timeout",
    413: "Content Too Large",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def _strict_http_bytes(
    state: JournalServerState,
    path: str,
    response: ProtocolResponse,
) -> bytes:
    reason = HTTP_REASON.get(response.status, "Error")
    lines = [
        f"HTTP/1.1 {response.status} {reason}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(response.body)}",
        "Connection: close",
    ]
    lines.extend(
        f"{name}: {value}"
        for name, value in _signed_response_headers(state, path, response).items()
    )
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + response.body


class StrictHttpServer:
    """Bounded production HTTP/1.1 frontend for the signed journal protocol."""

    def __init__(
        self,
        state: JournalServerState,
        *,
        max_connections: int = MAX_ACCEPTED_CONNECTIONS,
        max_header_bytes: int = MAX_HEADER_BYTES,
        header_timeout: float = HEADER_READ_TIMEOUT_SECONDS,
        body_timeout: float = BODY_READ_TIMEOUT_SECONDS,
        connection_started: Callable[[], None] | None = None,
        response_started: Callable[[ProtocolResponse], None] | None = None,
    ) -> None:
        if (
            type(max_connections) is not int
            or max_connections < 1
            or type(max_header_bytes) is not int
            or max_header_bytes < 256
            or type(header_timeout) not in {int, float}
            or not math.isfinite(header_timeout)
            or header_timeout <= 0
            or type(body_timeout) not in {int, float}
            or not math.isfinite(body_timeout)
            or body_timeout <= 0
        ):
            raise ValueError("Strict HTTP bounds must be positive and finite.")
        self.state = state
        self.max_connections = max_connections
        self.max_header_bytes = max_header_bytes
        self.header_timeout = float(header_timeout)
        self.body_timeout = float(body_timeout)
        self._connection_started = connection_started
        self._response_started = response_started
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._task_writers: dict[asyncio.Task[None], asyncio.StreamWriter] = {}
        self._active_connections = 0
        self._closing = False
        self._closed = asyncio.Event()

    @property
    def active_connections(self) -> int:
        return self._active_connections

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("The strict HTTP server is not listening.")
        return int(self._server.sockets[0].getsockname()[1])

    async def async_start(self, host: str, port: int) -> None:
        if self._server is not None or self._closing:
            raise RuntimeError("The strict HTTP server cannot be started twice.")
        self._server = await asyncio.start_server(
            self._accept,
            host=host,
            port=port,
            limit=self.max_header_bytes,
            backlog=self.max_connections,
        )

    def _accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self._closing or self._active_connections >= self.max_connections:
            writer.write(
                _strict_http_bytes(
                    self.state,
                    "/",
                    _protocol_error(503, "request_busy"),
                )
            )
            writer.close()
            return

        self._active_connections += 1
        try:
            if self._connection_started is not None:
                self._connection_started()
        except BaseException:
            self._active_connections -= 1
            writer.close()
            LOGGER.exception("The strict HTTP connection hook failed safely.")
            return
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._tasks.add(task)
        self._task_writers[task] = writer
        task.add_done_callback(self._connection_done)

    def _connection_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        self._task_writers.pop(task, None)
        self._active_connections -= 1
        if task.cancelled():
            return
        try:
            task.result()
        except BaseException:
            LOGGER.exception("A strict HTTP connection failed safely.")

    async def _read_header_block(
        self,
        reader: asyncio.StreamReader,
    ) -> tuple[bytes, bytes]:
        buffered = bytearray()
        async with asyncio.timeout(self.header_timeout):
            while True:
                remaining = self.max_header_bytes + 1 - len(buffered)
                if remaining <= 0:
                    raise ProtocolFailure(431, "headers_too_large")
                chunk = await reader.read(min(1_024, remaining))
                if not chunk:
                    raise ProtocolFailure(400, "invalid_http")
                buffered.extend(chunk)
                marker = buffered.find(b"\r\n\r\n")
                if marker >= 0:
                    header_end = marker + 4
                    if header_end > self.max_header_bytes:
                        raise ProtocolFailure(431, "headers_too_large")
                    return bytes(buffered[:marker]), bytes(buffered[header_end:])
                if len(buffered) >= self.max_header_bytes:
                    raise ProtocolFailure(431, "headers_too_large")

    def _parse_header_block(
        self,
        header_block: bytes,
    ) -> tuple[str, str, dict[str, str]]:
        try:
            text = header_block.decode("ascii", "strict")
        except UnicodeError as err:
            raise ProtocolFailure(400, "invalid_http") from err
        lines = text.split("\r\n")
        if not lines or any(not line for line in lines):
            raise ProtocolFailure(400, "invalid_http")
        request_parts = lines[0].split(" ")
        if (
            len(request_parts) != 3
            or request_parts[0] not in {"GET", "POST"}
            or request_parts[2] != "HTTP/1.1"
        ):
            raise ProtocolFailure(400, "invalid_http")
        method, path, _version = request_parts
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or any(ord(character) < 33 or ord(character) > 126 for character in path)
        ):
            raise ProtocolFailure(400, "invalid_http")

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if line[0] in " \t" or ":" not in line:
                raise ProtocolFailure(400, "invalid_headers")
            name, value = line.split(":", 1)
            if not HEADER_NAME_PATTERN.fullmatch(name):
                raise ProtocolFailure(400, "invalid_headers")
            lowered = name.lower()
            if lowered in headers:
                raise ProtocolFailure(400, "invalid_headers")
            if value.startswith("\t") or value.endswith("\t"):
                raise ProtocolFailure(400, "invalid_headers")
            canonical_value = value.strip(" ")
            if not canonical_value or any(
                ord(character) < 32 or ord(character) > 126
                for character in canonical_value
            ):
                raise ProtocolFailure(400, "invalid_headers")
            headers[lowered] = canonical_value

        if "host" not in headers:
            raise ProtocolFailure(400, "invalid_headers")
        if "transfer-encoding" in headers:
            raise ProtocolFailure(400, "invalid_transfer_encoding")
        if "expect" in headers:
            raise ProtocolFailure(400, "expectation_not_supported")
        encodings = headers.get("content-encoding")
        if encodings is not None and encodings.lower() != "identity":
            raise ProtocolFailure(400, "unsupported_content_encoding")
        return method, path, headers

    def _validate_strict_framing(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
    ) -> int:
        length_value = headers.get("content-length")
        if method == "GET":
            if path != "/healthz":
                raise ProtocolFailure(404, "not_found")
            if length_value not in {None, "0"}:
                raise ProtocolFailure(400, "invalid_content_length")
            return 0

        if length_value is None:
            raise ProtocolFailure(400, "invalid_content_length")
        content_length = _parse_content_length(length_value)
        content_type = headers.get("content-type")
        if content_type is None or content_type.replace(" ", "").lower() not in {
            "application/json",
            "application/json;charset=utf-8",
        }:
            raise ProtocolFailure(400, "invalid_content_type")
        boot_id = headers.get(REQUEST_BOOT_HEADER.lower())
        request_id = headers.get(REQUEST_ID_HEADER.lower())
        signature = headers.get(SIGNATURE_HEADER.lower())
        if (
            boot_id is None
            or request_id is None
            or signature is None
            or not HEX_32_PATTERN.fullmatch(boot_id)
            or not REQUEST_ID_PATTERN.fullmatch(request_id)
            or not HEX_64_PATTERN.fullmatch(signature)
            or not hmac.compare_digest(boot_id, self.state.boot_id)
        ):
            raise ProtocolFailure(401, "authentication_failed")
        return content_length

    async def _read_request(
        self,
        reader: asyncio.StreamReader,
    ) -> StrictHttpRequest:
        header_block, body_prefix = await self._read_header_block(reader)
        method, path, headers = self._parse_header_block(header_block)
        content_length = self._validate_strict_framing(method, path, headers)
        if len(body_prefix) > content_length:
            raise ProtocolFailure(400, "invalid_content_length")
        body = bytearray(body_prefix)
        remaining = content_length - len(body)
        if remaining:
            async with asyncio.timeout(self.body_timeout):
                while remaining:
                    chunk = await reader.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise ProtocolFailure(400, "invalid_content_length")
                    body.extend(chunk)
                    remaining -= len(chunk)
        return StrictHttpRequest(
            method=method,
            path=path,
            headers=headers,
            body=bytes(body),
        )

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        path = "/"
        try:
            try:
                request = await self._read_request(reader)
            except TimeoutError:
                response = _protocol_error(408, "request_timeout")
            except ProtocolFailure as err:
                response = _protocol_error(err.status, err.code)
            else:
                path = request.path
                if request.method == "GET":
                    response = ProtocolResponse(
                        status=200,
                        body=canonical_json({"protocol": PROTOCOL, "status": "ok"}),
                    )
                else:
                    response = await _process_signed_request(
                        self.state,
                        method=request.method,
                        path=request.path,
                        boot_id=request.headers[REQUEST_BOOT_HEADER.lower()],
                        request_id=request.headers[REQUEST_ID_HEADER.lower()],
                        signature=request.headers[SIGNATURE_HEADER.lower()],
                        body=request.body,
                    )
            if self._response_started is not None:
                self._response_started(response)
            try:
                async with asyncio.timeout(RESPONSE_WRITE_TIMEOUT_SECONDS):
                    writer.write(_strict_http_bytes(self.state, path, response))
                    await writer.drain()
            except TimeoutError:
                writer.transport.abort()
        except asyncio.CancelledError:
            raise
        except ConnectionError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def async_close(self) -> None:
        if self._closing:
            await self._closed.wait()
            return
        self._closing = True
        try:
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()
            tasks = set(self._tasks)
            if tasks:
                _done, pending = await asyncio.wait(
                    tasks,
                    timeout=HANDLER_DRAIN_TIMEOUT_SECONDS,
                )
                for task in pending:
                    writer = self._task_writers.get(task)
                    if writer is not None:
                        writer.transport.abort()
                    task.cancel()
                if pending:
                    await asyncio.sleep(0)
        finally:
            self._closed.set()


def _read_discovery_uuid(data_dir: Path) -> str | None:
    path = data_dir / DISCOVERY_UUID_NAME
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise SupervisorDiscoveryError(
            "The prior discovery identity cannot be opened safely."
        ) from err
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256:
            raise SupervisorDiscoveryError(
                "The prior discovery identity is not a bounded regular file."
            )
        raw = os.read(descriptor, 257)
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("ascii").strip()
    except UnicodeError as err:
        raise SupervisorDiscoveryError(
            "The prior discovery identity is malformed."
        ) from err
    if not DISCOVERY_UUID_PATTERN.fullmatch(value):
        raise SupervisorDiscoveryError("The prior discovery identity is malformed.")
    return value


def _write_discovery_uuid(data_dir: Path, discovery_uuid: str) -> None:
    if not DISCOVERY_UUID_PATTERN.fullmatch(discovery_uuid):
        raise SupervisorDiscoveryError("Supervisor returned an invalid discovery ID.")
    final_path = data_dir / DISCOVERY_UUID_NAME
    temporary_path = data_dir / (
        f".{DISCOVERY_UUID_NAME}.{secrets.token_hex(8)}.tmp"
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary_path, flags, 0o600)
    try:
        raw = f"{discovery_uuid}\n".encode("ascii")
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary_path, final_path)
        directory_descriptor = os.open(
            data_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary_path.unlink(missing_ok=True)


async def _bounded_supervisor_json(response: Any) -> dict[str, Any]:
    raw = await response.content.read(65_537)
    if len(raw) > 65_536:
        raise SupervisorDiscoveryError("Supervisor returned an oversized response.")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, ValueError) as err:
        raise SupervisorDiscoveryError(
            "Supervisor returned a malformed discovery response."
        ) from err
    if type(value) is not dict:
        raise SupervisorDiscoveryError(
            "Supervisor returned a malformed discovery response."
        )
    return value


class SupervisorDiscovery:
    """Replace one Supervisor discovery record without logging its secret config."""

    def __init__(
        self,
        data_dir: Path | str,
        *,
        token: str,
        base_url: str = "http://supervisor",
    ) -> None:
        if type(token) is not str or not token:
            raise SupervisorDiscoveryError("The Supervisor token is unavailable.")
        self._data_dir = Path(data_dir)
        self._token = token
        self._base_url = base_url.rstrip("/")

    async def async_replace(self, config: dict[str, Any]) -> str:
        prior_uuid = _read_discovery_uuid(self._data_dir)
        headers = {"Authorization": f"Bearer {self._token}"}
        timeout = ClientTimeout(total=15)
        try:
            async with ClientSession(headers=headers, timeout=timeout) as session:
                if prior_uuid is not None:
                    delete_url = (
                        f"{self._base_url}/discovery/{quote(prior_uuid, safe='')}"
                    )
                    async with session.delete(delete_url) as response:
                        await response.read()
                        if response.status not in {200, 204, 404}:
                            raise SupervisorDiscoveryError(
                                "Supervisor rejected stale discovery cleanup."
                            )

                payload = {"config": config, "service": DISCOVERY_SERVICE}
                async with session.post(
                    f"{self._base_url}/discovery",
                    json=payload,
                ) as response:
                    if not 200 <= response.status < 300:
                        await response.read()
                        raise SupervisorDiscoveryError(
                            "Supervisor rejected discovery registration."
                        )
                    result = await _bounded_supervisor_json(response)
        except SupervisorDiscoveryError:
            raise
        except asyncio.CancelledError:
            raise
        except BaseException as err:
            raise SupervisorDiscoveryError(
                "Supervisor discovery communication failed."
            ) from err

        data = result.get("data", result)
        if type(data) is not dict or type(data.get("uuid")) is not str:
            raise SupervisorDiscoveryError(
                "Supervisor omitted the new discovery identity."
            )
        discovery_uuid = data["uuid"]
        if not DISCOVERY_UUID_PATTERN.fullmatch(discovery_uuid):
            raise SupervisorDiscoveryError("Supervisor returned an invalid discovery ID.")
        _write_discovery_uuid(self._data_dir, discovery_uuid)
        LOGGER.info("Supervisor discovery registration was replaced.")
        return discovery_uuid


async def async_run_service(
    state: JournalServerState,
    listener: StrictHttpServer,
    discovery: Any,
    *,
    internal_host: str,
    bind_host: str,
    port: int,
) -> None:
    """Run listener, discovery, and signal-aware bounded shutdown."""

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    registered_signals: list[signal.Signals] = []
    discovery_task: asyncio.Task[Any] | None = None
    stop_task: asyncio.Task[bool] | None = None
    try:
        await listener.async_start(bind_host, port)
        for process_signal in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(process_signal, stop_event.set)
                registered_signals.append(process_signal)
            except (NotImplementedError, RuntimeError):
                continue
        discovery_task = asyncio.create_task(
            discovery.async_replace(state.discovery_config(internal_host))
        )
        stop_task = asyncio.create_task(stop_event.wait())
        done, _pending = await asyncio.wait(
            {discovery_task, stop_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stop_task in done:
            discovery_task.cancel()
            await asyncio.gather(discovery_task, return_exceptions=True)
            return
        await discovery_task
        LOGGER.info("True Family Journal is listening on its internal port.")
        await stop_task
    finally:
        for task in (discovery_task, stop_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (discovery_task, stop_task) if task is not None),
            return_exceptions=True,
        )
        for process_signal in registered_signals:
            loop.remove_signal_handler(process_signal)
        try:
            await listener.async_close()
        finally:
            await state.async_close()


async def async_serve() -> None:
    """Run the App, listening before publishing its per-boot secret discovery."""

    data_dir = Path("/data")
    state = await JournalServerState.async_create(data_dir)
    listener = StrictHttpServer(state)
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    discovery = SupervisorDiscovery(data_dir, token=token)
    internal_host = os.environ.get("HOSTNAME") or socket.gethostname()
    await async_run_service(
        state,
        listener,
        discovery,
        internal_host=internal_host,
        bind_host="0.0.0.0",
        port=PORT,
    )


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(async_serve())
    except KeyboardInterrupt:
        return 0
    except BaseException as err:
        LOGGER.error("True Family Journal startup failed (%s).", type(err).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
