"""Authenticated remote crash-durable reference journal client.

The remote App is the persistence boundary.  This client deliberately derives
its private Supervisor-network destination from the validated full App slug and
never owns Home Assistant's shared HTTP session.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
from typing import TYPE_CHECKING, Any, Final, Self, TypeVar, cast

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import reference_journal_file as _strict_json

if TYPE_CHECKING:
    from .reference_migration_ha import ReferenceJournalDurabilityProof


PROTOCOL_VERSION: Final = 1
PROTOCOL_ID: Final = "true-family-journal-v1"
REMOTE_JOURNAL_PORT: Final = 8765
MAX_CANONICAL_JSON_BYTES: Final = 4 * 1024 * 1024
MAX_ROOT_JSON_BYTES: Final = 3 * 1024 * 1024
HELLO_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 10.0
MUTATION_TIMEOUT_SECONDS = 30.0
READ_ATTEMPTS: Final = 2

BOOT_ID_HEADER: Final = "X-True-Family-Boot-ID"
REQUEST_ID_HEADER: Final = "X-True-Family-Request-ID"
SIGNATURE_HEADER: Final = "X-True-Family-Signature"

REMOTE_JOURNAL_CAPABILITIES: Final = (
    "barrier",
    "close",
    "idempotent-save",
    "load",
    "revision-and-generation-cas",
    "durability.sqlite-wal-full-process-crash-cas.v1",
)
REMOTE_JOURNAL_DURABILITY_CAPABILITY: Final = (
    "durability.sqlite-wal-full-process-crash-cas.v1"
)

# Trust only the exact App identity derived from the frozen public repository URL.
TRUSTED_REMOTE_JOURNAL_APP_SLUGS: Final = frozenset(
    {"8c9c720e_true_family_journal"}
)

_HELLO_PATH: Final = "/v1/hello"
_LOAD_PATH: Final = "/v1/load"
_SAVE_PATH: Final = "/v1/save"
_BARRIER_PATH: Final = "/v1/barrier"
_REQUEST_SIGNATURE_DOMAIN: Final = "true-family-journal-request-v1"
_RESPONSE_SIGNATURE_DOMAIN: Final = "true-family-journal-response-v1"
_COMMIT_TOKEN_DOMAIN: Final = "true-family-journal-commit-v1"
_SAVE_REQUEST_ID_DOMAIN: Final = "true-family-journal-save-id-v1"
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ID = re.compile(r"^tfj-[0-9a-f]{32}$")
_FULL_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$")
_HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ERROR_CODE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
_MAX_SQLITE_REVISION: Final = (1 << 63) - 1

_T = TypeVar("_T")


class RemoteJournalError(RuntimeError):
    """Base class for fail-closed remote journal errors."""


class RemoteJournalUnavailableError(RemoteJournalError):
    """Raised when the remote journal App is unavailable."""


class RemoteJournalTimeoutError(RemoteJournalUnavailableError):
    """Raised when a bounded remote operation times out."""


class RemoteJournalAuthenticationError(RemoteJournalError):
    """Raised when an authenticated protocol boundary cannot be verified."""


class RemoteJournalProtocolError(RemoteJournalError):
    """Raised when protocol shape, identity, or operation ordering is invalid."""


class RemoteJournalConflictError(RemoteJournalError):
    """Raised when the remote linearizable compare-and-swap fails."""


class RemoteJournalCorruptionError(RemoteJournalError):
    """Raised when bounded canonical JSON or a journal read-back is invalid."""


class RemoteJournalSizeError(RemoteJournalCorruptionError):
    """Raised when a request or response exceeds the protocol byte bound."""


class RemoteJournalResponseSizeError(RemoteJournalSizeError):
    """Raised when a submitted request receives an oversized response."""


class RemoteJournalPoisonedError(RemoteJournalError):
    """Raised after a failed operation makes the current object unusable."""


class RemoteJournalAmbiguousMutationError(RemoteJournalPoisonedError):
    """Raised when a submitted mutation may already have committed."""


class RemoteJournalClosedError(RemoteJournalError):
    """Raised after close has begun."""


class _SignedStatusError(RemoteJournalError):
    """Marker for a verified response that definitively rejected a request."""


class _SignedUnavailableError(RemoteJournalUnavailableError, _SignedStatusError):
    pass


class _SignedAuthenticationError(
    RemoteJournalAuthenticationError,
    _SignedStatusError,
):
    pass


class _SignedProtocolError(RemoteJournalProtocolError, _SignedStatusError):
    pass


@dataclass(frozen=True, slots=True)
class RemoteJournalEndpoint:
    """Strict immutable Supervisor discovery data for one remote App boot."""

    full_slug: str
    boot_id: str
    hmac_key: str = field(repr=False)
    hostname: str = field(init=False)
    port: int = field(init=False, default=REMOTE_JOURNAL_PORT)
    protocol: int = field(init=False, default=PROTOCOL_VERSION)
    protocol_id: str = field(init=False, default=PROTOCOL_ID)
    _key_bytes: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.full_slug) is not str
            or not _FULL_SLUG.fullmatch(self.full_slug)
            or self.full_slug not in TRUSTED_REMOTE_JOURNAL_APP_SLUGS
        ):
            raise ValueError("The trusted full Supervisor App slug is required.")
        hostname = self.full_slug.replace("_", "-")
        if not _HOSTNAME.fullmatch(hostname):
            raise ValueError("The full App slug does not derive a valid hostname.")
        if type(self.boot_id) is not str or not _HEX_32.fullmatch(self.boot_id):
            raise ValueError("The remote journal boot ID must be 32 lowercase hex.")
        if type(self.hmac_key) is not str or not _HEX_64.fullmatch(self.hmac_key):
            raise ValueError("The remote journal HMAC key must be 64 lowercase hex.")
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "_key_bytes", bytes.fromhex(self.hmac_key))


@dataclass(frozen=True, slots=True)
class _SignedRequest:
    path: str
    request_id: str
    body: bytes
    body_digest: str


@dataclass(frozen=True, slots=True)
class _Snapshot:
    generation: int | None
    revision: str | None
    root: bytes | None


@dataclass(frozen=True, slots=True)
class _Commit:
    snapshot: _Snapshot
    commit_token: str


@dataclass(frozen=True, slots=True)
class _PendingSave:
    request: _SignedRequest
    candidate: _Snapshot


def _canonical_encode(value: dict[str, Any]) -> bytes:
    try:
        return _strict_json._canonical_encode(value, MAX_CANONICAL_JSON_BYTES)
    except _strict_json.ReferenceJournalCorruptionError:
        raise RemoteJournalCorruptionError(
            "Remote journal data is not bounded canonical JSON."
        ) from None


def _canonical_decode(raw: bytes) -> dict[str, Any]:
    try:
        return _strict_json._canonical_decode(raw, MAX_CANONICAL_JSON_BYTES)
    except _strict_json.ReferenceJournalCorruptionError:
        raise RemoteJournalCorruptionError(
            "The signed remote journal response is malformed or noncanonical."
        ) from None


def _canonical_root_encode(value: dict[str, Any]) -> bytes:
    """Encode one root within the App's independent 3 MiB payload bound."""

    try:
        return _strict_json._canonical_encode(value, MAX_ROOT_JSON_BYTES)
    except _strict_json.ReferenceJournalCorruptionError:
        try:
            _strict_json._validate_json_tree(value)
        except _strict_json.ReferenceJournalCorruptionError:
            raise RemoteJournalCorruptionError(
                "Remote journal data is not bounded canonical JSON."
            ) from None
        raise RemoteJournalSizeError(
            "The remote journal root exceeds the App payload byte bound."
        ) from None


def _journal_id_is_valid(journal_id: object) -> bool:
    if (
        type(journal_id) is not str
        or not journal_id
        or len(journal_id) > 255
        or journal_id != journal_id.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in journal_id)
    ):
        return False
    try:
        journal_id.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _new_request_id() -> str:
    request_id = f"tfj-{secrets.token_hex(16)}"
    if not _REQUEST_ID.fullmatch(request_id):
        raise AssertionError("The secure request ID generator returned invalid data.")
    return request_id


def _save_request_id(body_digest: str) -> str:
    if type(body_digest) is not str or not _HEX_64.fullmatch(body_digest):
        raise RemoteJournalProtocolError("The remote save body digest is invalid.")
    material = f"{_SAVE_REQUEST_ID_DOMAIN}\n{body_digest}".encode("ascii")
    request_id = f"tfj-{hashlib.sha256(material).hexdigest()[:32]}"
    if not _REQUEST_ID.fullmatch(request_id):
        raise AssertionError("The deterministic save request ID is invalid.")
    return request_id


def _new_nonce() -> str:
    nonce = secrets.token_hex(16)
    if not _HEX_32.fullmatch(nonce):
        raise AssertionError("The secure nonce generator returned invalid data.")
    return nonce


def _request_signature(
    key: bytes,
    *,
    method: str,
    path: str,
    boot_id: str,
    request_id: str,
    body_digest: str,
) -> str:
    canonical = (
        f"{_REQUEST_SIGNATURE_DOMAIN}\n{method}\n{path}\n{boot_id}\n"
        f"{request_id}\n{body_digest}"
    ).encode("ascii")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _response_signature(
    key: bytes,
    *,
    status: int,
    path: str,
    boot_id: str,
    request_id: str,
    body_digest: str,
) -> str:
    canonical = (
        f"{_RESPONSE_SIGNATURE_DOMAIN}\n{status}\n{path}\n{boot_id}\n"
        f"{request_id}\n{body_digest}"
    ).encode("ascii")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _commit_token(request: _SignedRequest) -> str:
    canonical = (
        f"{_COMMIT_TOKEN_DOMAIN}\n{request.request_id}\n{request.body_digest}"
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _exact_mapping(
    value: Any,
    keys: frozenset[str],
    *,
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise RemoteJournalProtocolError(f"The signed {label} shape is invalid.")
    if any(type(key) is not str for key in value):
        raise RemoteJournalProtocolError(f"The signed {label} keys are invalid.")
    return cast(dict[str, Any], value)


def _validate_generation(value: Any, *, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_REVISION:
        raise RemoteJournalProtocolError(f"The signed {label} generation is invalid.")
    return value


def _validate_digest(value: Any, *, label: str) -> str:
    if type(value) is not str or not _HEX_64.fullmatch(value):
        raise RemoteJournalProtocolError(f"The signed {label} digest is invalid.")
    return value


async def _await_owned_task(
    task: asyncio.Future[_T],
) -> tuple[_T, asyncio.CancelledError | None]:
    """Drain accepted I/O even when its caller is cancelled."""

    cancelled: asyncio.CancelledError | None = None
    while True:
        try:
            return await asyncio.shield(task), cancelled
        except asyncio.CancelledError as err:
            if task.cancelled():
                raise
            if cancelled is None:
                cancelled = err


class RemoteReferenceJournalStore:
    """Serialized remote SQLite FULL journal adapter with revision CAS."""

    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        session: aiohttp.ClientSession,
        journal_id: str,
        endpoint: RemoteJournalEndpoint,
    ) -> None:
        self._loop = loop
        self._session = session
        self._journal_id = journal_id
        self._endpoint = endpoint
        self._base_url = f"http://{endpoint.hostname}:{endpoint.port}"
        self._operation_lock = asyncio.Lock()
        self._client_id = _new_nonce()
        self._store_id: str | None = None
        self._capabilities: tuple[str, ...] | None = None
        self._snapshot: _Snapshot | None = None
        self._save_ready = False
        self._commit: _Commit | None = None
        self._pending_save: _PendingSave | None = None
        self._poisoned = False
        self._ambiguous = False
        self._replay_allowed = False
        self._closing = False
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None
        self._durability_proof: ReferenceJournalDurabilityProof | None = None

    @classmethod
    async def async_open(
        cls,
        hass: HomeAssistant,
        *,
        journal_id: str,
        endpoint: RemoteJournalEndpoint,
    ) -> Self:
        """Perform the signed hello and return one owned remote store."""

        if not _journal_id_is_valid(journal_id):
            raise ValueError(
                "Journal ID must be trimmed non-empty text without control characters."
            )
        if type(endpoint) is not RemoteJournalEndpoint:
            raise TypeError("A RemoteJournalEndpoint instance is required.")
        loop = asyncio.get_running_loop()
        store = cls(
            loop=loop,
            session=async_get_clientsession(hass),
            journal_id=journal_id,
            endpoint=endpoint,
        )
        hello_task = loop.create_task(store._async_hello())
        try:
            _result, cancelled = await _await_owned_task(hello_task)
        except BaseException:
            store._closing = True
            store._closed = True
            raise
        if cancelled is not None:
            try:
                await store.async_close()
            except RemoteJournalError:
                pass
            raise cancelled
        return store

    @property
    def endpoint(self) -> RemoteJournalEndpoint:
        """Return the immutable discovery endpoint used for this owned store."""

        return self._endpoint

    @property
    def store_id(self) -> str:
        """Return the hello-bound stable remote store identity."""

        if self._store_id is None:
            raise RemoteJournalProtocolError("The remote journal hello is incomplete.")
        return self._store_id

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return the exact immutable capability tuple accepted at hello."""

        if self._capabilities is None:
            raise RemoteJournalProtocolError("The remote journal hello is incomplete.")
        return self._capabilities

    @property
    def durability_proof(self) -> ReferenceJournalDurabilityProof:
        """Identify the remote SQLite FULL process-crash durability boundary."""

        if self._durability_proof is None:
            from .reference_migration_ha import (
                _issue_remote_reference_journal_durability_proof,
            )

            self._durability_proof = (
                _issue_remote_reference_journal_durability_proof(self)
            )
        return self._durability_proof

    def _require_loop(self) -> None:
        if asyncio.get_running_loop() is not self._loop:
            raise RemoteJournalProtocolError(
                "The remote journal store must remain on its opening event loop."
            )

    def _raise_if_unusable(self) -> None:
        if self._closing or self._closed:
            raise RemoteJournalClosedError(
                "The remote journal store is closing or closed."
            )
        if self._poisoned:
            if self._ambiguous:
                recovery = (
                    "explicitly replay the retained save request, or close, reopen, "
                    "and reconcile."
                    if self._replay_allowed
                    else "close, reopen, and reconcile exact durable state."
                )
                raise RemoteJournalAmbiguousMutationError(
                    f"A remote journal mutation is ambiguous; {recovery}"
                )
            raise RemoteJournalPoisonedError(
                "The remote journal store failed closed and must be reopened."
            )

    def _mark_poisoned(
        self,
        *,
        ambiguous: bool,
        replay_allowed: bool = False,
    ) -> None:
        self._poisoned = True
        self._ambiguous = ambiguous
        self._replay_allowed = replay_allowed

    def _signed_request(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        request_id: str | None = None,
    ) -> _SignedRequest:
        body = _canonical_encode(payload)
        body_digest = hashlib.sha256(body).hexdigest()
        if request_id is None:
            identifier = (
                _save_request_id(body_digest)
                if path == _SAVE_PATH
                else _new_request_id()
            )
        else:
            identifier = request_id
        if type(identifier) is not str or not _REQUEST_ID.fullmatch(identifier):
            raise RemoteJournalProtocolError("The remote request ID is invalid.")
        return _SignedRequest(
            path=path,
            request_id=identifier,
            body=body,
            body_digest=body_digest,
        )

    async def _async_hello(self) -> None:
        nonce = _new_nonce()
        request = self._signed_request(
            _HELLO_PATH,
            {
                "client_id": self._client_id,
                "nonce": nonce,
            },
        )
        response = await self._async_post(
            request,
            timeout=HELLO_TIMEOUT_SECONDS,
            attempts=READ_ATTEMPTS,
            renew_request_id=True,
        )
        hello = _exact_mapping(
            response,
            frozenset({"capabilities", "nonce"}),
            label="hello response",
        )
        if type(hello["nonce"]) is not str or not hmac.compare_digest(
            hello["nonce"], nonce
        ):
            raise RemoteJournalProtocolError(
                "The signed hello nonce reflection is invalid."
            )
        capabilities = hello["capabilities"]
        if (
            type(capabilities) is not list
            or any(type(item) is not str for item in capabilities)
            or tuple(capabilities) != REMOTE_JOURNAL_CAPABILITIES
        ):
            raise RemoteJournalProtocolError(
                "The signed remote journal capabilities are invalid."
            )
        self._store_id = self._client_id
        self._capabilities = tuple(capabilities)

    async def _read_response_body(self, response: aiohttp.ClientResponse) -> bytes:
        body = bytearray()
        while True:
            chunk = await response.content.readany()
            if not chunk:
                break
            if len(body) + len(chunk) > MAX_CANONICAL_JSON_BYTES:
                response.close()
                raise RemoteJournalResponseSizeError(
                    "The remote journal response exceeds the protocol byte bound."
                )
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _one_header(response: aiohttp.ClientResponse, name: str) -> str:
        values = response.headers.getall(name, [])
        if len(values) != 1 or type(values[0]) is not str:
            raise RemoteJournalAuthenticationError(
                "A required signed response header is missing or duplicated."
            )
        return values[0]

    def _verify_response(
        self,
        response: aiohttp.ClientResponse,
        request: _SignedRequest,
        body: bytes,
    ) -> None:
        response_boot_id = self._one_header(response, BOOT_ID_HEADER)
        response_request_id = self._one_header(response, REQUEST_ID_HEADER)
        signature = self._one_header(response, SIGNATURE_HEADER)
        if (
            not _HEX_32.fullmatch(response_boot_id)
            or not _REQUEST_ID.fullmatch(response_request_id)
            or not _HEX_64.fullmatch(signature)
        ):
            raise RemoteJournalAuthenticationError(
                "A signed response header is not canonical."
            )
        body_digest = hashlib.sha256(body).hexdigest()
        expected = _response_signature(
            self._endpoint._key_bytes,
            status=response.status,
            path=request.path,
            boot_id=self._endpoint.boot_id,
            request_id=request.request_id,
            body_digest=body_digest,
        )
        if not hmac.compare_digest(signature, expected):
            raise RemoteJournalAuthenticationError(
                "The remote journal response signature is invalid."
            )
        if not hmac.compare_digest(response_boot_id, self._endpoint.boot_id):
            raise RemoteJournalAuthenticationError(
                "The remote journal App boot identity changed."
            )
        if not hmac.compare_digest(response_request_id, request.request_id):
            raise RemoteJournalProtocolError(
                "The signed response request identity is invalid."
            )
        content_types = response.headers.getall("Content-Type", [])
        if len(content_types) != 1 or content_types[0].replace(" ", "").lower() not in {
            "application/json",
            "application/json;charset=utf-8",
        }:
            raise RemoteJournalProtocolError(
                "The signed response content type is invalid."
            )
        content_encodings = response.headers.getall("Content-Encoding", [])
        if content_encodings and (
            len(content_encodings) != 1
            or content_encodings[0].lower() != "identity"
        ):
            raise RemoteJournalProtocolError(
                "Encoded remote journal responses are not accepted."
            )

    def _raise_signed_status(
        self,
        status: int,
        response: dict[str, Any],
    ) -> None:
        error = _exact_mapping(
            response,
            frozenset({"error"}),
            label="error response",
        )
        code = error["error"]
        if type(code) is not str or not _ERROR_CODE.fullmatch(code):
            raise _SignedProtocolError(
                "The signed remote journal error code is invalid."
            )
        if status == 401:
            raise _SignedAuthenticationError(
                "The remote journal request was not authenticated."
            )
        if status == 409:
            raise RemoteJournalConflictError(
                "The remote journal compare-and-swap conflicted."
            )
        if status == 413:
            raise RemoteJournalSizeError(
                "The remote journal request exceeds the protocol byte bound."
            )
        if status in {408, 429} or 500 <= status <= 599:
            raise _SignedUnavailableError("The remote journal App is unavailable.")
        raise _SignedProtocolError("The remote journal returned an invalid status.")

    async def _async_post_once(
        self,
        request: _SignedRequest,
        *,
        timeout: float,
    ) -> tuple[dict[str, Any], bool]:
        signature = _request_signature(
            self._endpoint._key_bytes,
            method="POST",
            path=request.path,
            boot_id=self._endpoint.boot_id,
            request_id=request.request_id,
            body_digest=request.body_digest,
        )
        response_started = False
        try:
            async with self._session.post(
                f"{self._base_url}{request.path}",
                data=request.body,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Content-Type": "application/json",
                    BOOT_ID_HEADER: self._endpoint.boot_id,
                    REQUEST_ID_HEADER: request.request_id,
                    SIGNATURE_HEADER: signature,
                },
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as response:
                response_started = True
                body = await self._read_response_body(response)
                self._verify_response(response, request, body)
                decoded = _canonical_decode(body)
                if response.status != 200:
                    self._raise_signed_status(response.status, decoded)
                return decoded, response_started
        except RemoteJournalError:
            raise
        except asyncio.TimeoutError:
            timeout_error = RemoteJournalTimeoutError(
                "The remote journal operation timed out."
            )
            setattr(timeout_error, "_response_started", response_started)
            raise timeout_error from None
        except (aiohttp.ClientError, RuntimeError):
            unavailable = RemoteJournalUnavailableError(
                "The remote journal App could not be reached."
            )
            setattr(unavailable, "_response_started", response_started)
            raise unavailable from None

    async def _async_post(
        self,
        request: _SignedRequest,
        *,
        timeout: float,
        attempts: int,
        renew_request_id: bool = False,
    ) -> dict[str, Any]:
        active_request = request
        for attempt in range(attempts):
            try:
                response, _started = await self._async_post_once(
                    active_request,
                    timeout=timeout,
                )
                return response
            except (RemoteJournalTimeoutError, RemoteJournalUnavailableError) as err:
                response_started = bool(getattr(err, "_response_started", True))
                if (
                    isinstance(err, _SignedStatusError)
                    or response_started
                    or attempt + 1 >= attempts
                ):
                    raise
                if renew_request_id:
                    active_request = _SignedRequest(
                        path=request.path,
                        request_id=_new_request_id(),
                        body=request.body,
                        body_digest=request.body_digest,
                    )
        raise AssertionError("The bounded request loop did not return or raise.")

    def _validate_root(
        self,
        root: Any,
        *,
        label: str,
        expected_generation: int | None = None,
    ) -> tuple[bytes, int]:
        if type(root) is not dict:
            raise RemoteJournalCorruptionError(
                f"The signed {label} root is not a built-in mapping."
            )
        journal_id = root.get("journal_id")
        if type(journal_id) is not str or journal_id != self._journal_id:
            raise RemoteJournalCorruptionError(
                f"The signed {label} root journal identity is invalid."
            )
        generation = _validate_generation(root.get("generation"), label=label)
        if expected_generation is not None and generation != expected_generation:
            raise RemoteJournalConflictError(
                "The remote journal save is not exactly the next generation."
            )
        return _canonical_root_encode(cast(dict[str, Any], root)), generation

    def _validate_load_readback(
        self,
        response: dict[str, Any],
        *,
        label: str,
    ) -> _Snapshot:
        readback = _exact_mapping(
            response,
            frozenset({"absent", "generation", "revision", "root"}),
            label=label,
        )
        absent = readback["absent"]
        if type(absent) is not bool:
            raise RemoteJournalProtocolError(
                "The signed load absence marker is invalid."
            )
        if absent:
            if any(
                readback[key] is not None
                for key in ("generation", "revision", "root")
            ):
                raise RemoteJournalCorruptionError(
                    "The signed absent-journal read-back is inconsistent."
                )
            return _Snapshot(generation=None, revision=None, root=None)
        generation = _validate_generation(readback["generation"], label=label)
        revision = _validate_digest(readback["revision"], label=label)
        root_bytes, root_generation = self._validate_root(
            readback["root"],
            label=label,
        )
        if root_generation != generation:
            raise RemoteJournalCorruptionError(
                "The signed load generation does not match its root."
            )
        expected_revision = hashlib.sha256(root_bytes).hexdigest()
        if not hmac.compare_digest(revision, expected_revision):
            raise RemoteJournalCorruptionError(
                "The signed load revision does not match its root."
            )
        return _Snapshot(
            generation=generation,
            revision=revision,
            root=root_bytes,
        )

    async def _run_serialized(self, operation) -> Any:
        self._require_loop()
        async with self._operation_lock:
            self._raise_if_unusable()
            task = self._loop.create_task(operation())
            result, cancelled = await _await_owned_task(task)
            if cancelled is not None:
                raise cancelled
            return result

    async def async_load(self) -> dict[str, Any] | None:
        """Load one exact root and establish the next save revision."""

        return cast(dict[str, Any] | None, await self._run_serialized(self._load))

    async def _load(self) -> dict[str, Any] | None:
        if self._commit is not None:
            raise RemoteJournalProtocolError(
                "A committed save must be barriered before another load."
            )
        request = self._signed_request(
            _LOAD_PATH,
            {
                "client_id": self.store_id,
                "journal_id": self._journal_id,
            },
        )
        try:
            response = await self._async_post(
                request,
                timeout=READ_TIMEOUT_SECONDS,
                attempts=READ_ATTEMPTS,
                renew_request_id=True,
            )
            snapshot = self._validate_load_readback(response, label="load response")
        except RemoteJournalError:
            self._mark_poisoned(ambiguous=False)
            raise
        self._snapshot = snapshot
        self._save_ready = True
        if snapshot.root is None:
            return None
        return cast(dict[str, Any], _canonical_decode(snapshot.root))

    async def async_save(self, data: dict[str, Any]) -> None:
        """Submit one revision-CAS save without any automatic mutation retry."""

        await self._run_serialized(lambda: self._save(data))

    async def _save(self, data: dict[str, Any]) -> None:
        if self._commit is not None:
            raise RemoteJournalProtocolError(
                "A committed save must be barriered before another save."
            )
        if not self._save_ready or self._snapshot is None:
            raise RemoteJournalProtocolError(
                "Remote journal save requires a preceding successful load."
            )
        try:
            if type(data) is not dict:
                raise RemoteJournalCorruptionError(
                    "Remote journal save requires a built-in mapping root."
                )
            expected_generation = (
                0
                if self._snapshot.generation is None
                else self._snapshot.generation + 1
            )
            if expected_generation > _MAX_SQLITE_REVISION:
                raise RemoteJournalConflictError(
                    "The remote journal generation space is exhausted."
                )
            root_bytes, generation = self._validate_root(
                data,
                label="save request",
                expected_generation=expected_generation,
            )
            revision = hashlib.sha256(root_bytes).hexdigest()
            request = self._signed_request(
                _SAVE_PATH,
                {
                    "client_id": self.store_id,
                    "expected_revision": self._snapshot.revision,
                    "journal_id": self._journal_id,
                    "root": _canonical_decode(root_bytes),
                },
            )
            candidate = _Snapshot(
                generation=generation,
                revision=revision,
                root=root_bytes,
            )
        except RemoteJournalError:
            self._mark_poisoned(ambiguous=False)
            raise
        pending = _PendingSave(
            request=request,
            candidate=candidate,
        )
        self._pending_save = pending
        try:
            response = await self._async_post(
                request,
                timeout=MUTATION_TIMEOUT_SECONDS,
                attempts=1,
            )
            commit_token = self._validate_save_response(
                response,
                pending,
                label="save response",
            )
            self._accept_save_response(pending, commit_token)
        except _SignedUnavailableError:
            self._mark_poisoned(ambiguous=True, replay_allowed=True)
            raise
        except RemoteJournalAuthenticationError:
            self._mark_poisoned(ambiguous=True)
            raise
        except _SignedStatusError:
            self._pending_save = None
            self._mark_poisoned(ambiguous=False)
            raise
        except RemoteJournalResponseSizeError:
            self._mark_poisoned(ambiguous=True, replay_allowed=True)
            raise RemoteJournalAmbiguousMutationError(
                "The remote save response exceeded its byte bound after submission; "
                "explicitly replay the retained request or close, reopen, and reconcile."
            ) from None
        except (RemoteJournalConflictError, RemoteJournalSizeError):
            self._pending_save = None
            self._mark_poisoned(ambiguous=False)
            raise
        except RemoteJournalError:
            self._mark_poisoned(ambiguous=True, replay_allowed=True)
            raise RemoteJournalAmbiguousMutationError(
                "The remote save outcome is ambiguous; explicitly replay the retained "
                "request or close, reopen, and reconcile."
            ) from None

    def _validate_save_response(
        self,
        response: dict[str, Any],
        pending: _PendingSave,
        *,
        label: str,
    ) -> str:
        readback = _exact_mapping(
            response,
            frozenset({"commit_token", "generation", "revision"}),
            label=label,
        )
        commit_token = _validate_digest(readback["commit_token"], label=label)
        generation = _validate_generation(readback["generation"], label=label)
        revision = _validate_digest(readback["revision"], label=label)
        if (
            generation != pending.candidate.generation
            or pending.candidate.revision is None
            or not hmac.compare_digest(revision, pending.candidate.revision)
            or not hmac.compare_digest(commit_token, _commit_token(pending.request))
        ):
            raise RemoteJournalCorruptionError(
                "The signed save response does not match the submitted root."
            )
        return commit_token

    def _accept_save_response(
        self,
        pending: _PendingSave,
        commit_token: str,
    ) -> None:
        self._snapshot = pending.candidate
        self._save_ready = False
        self._commit = _Commit(
            snapshot=pending.candidate,
            commit_token=commit_token,
        )
        self._poisoned = False
        self._ambiguous = False
        self._replay_allowed = True

    async def async_replay_save(self) -> None:
        """Explicitly replay the exact retained save ID, digest, and body."""

        self._require_loop()
        async with self._operation_lock:
            if self._closing or self._closed:
                raise RemoteJournalClosedError(
                    "The remote journal store is closing or closed."
                )
            pending = self._pending_save
            if (
                pending is None
                or not self._replay_allowed
                or (self._poisoned and not self._ambiguous)
            ):
                raise RemoteJournalProtocolError(
                    "No replayable remote save request is retained."
                )
            task = self._loop.create_task(self._replay_save(pending))
            _result, cancelled = await _await_owned_task(task)
            if cancelled is not None:
                raise cancelled

    async def _replay_save(self, pending: _PendingSave) -> None:
        try:
            response = await self._async_post(
                pending.request,
                timeout=MUTATION_TIMEOUT_SECONDS,
                attempts=1,
            )
            commit_token = self._validate_save_response(
                response,
                pending,
                label="save replay response",
            )
            self._accept_save_response(pending, commit_token)
        except RemoteJournalResponseSizeError:
            self._mark_poisoned(ambiguous=True, replay_allowed=True)
            raise RemoteJournalAmbiguousMutationError(
                "The remote save replay response exceeded its byte bound; the exact "
                "request remains retained for reconciliation."
            ) from None
        except RemoteJournalError:
            self._mark_poisoned(ambiguous=True, replay_allowed=True)
            raise

    async def async_barrier(self) -> None:
        """Consume exactly one save after a signed durable read-back barrier."""

        await self._run_serialized(self._barrier)

    async def _barrier(self) -> None:
        commit = self._commit
        if commit is None:
            raise RemoteJournalProtocolError(
                "Durability barrier requires one unconsumed preceding save."
            )
        request = self._signed_request(
            _BARRIER_PATH,
            {
                "client_id": self.store_id,
                "commit_token": commit.commit_token,
                "journal_id": self._journal_id,
            },
        )
        try:
            response = await self._async_post(
                request,
                timeout=MUTATION_TIMEOUT_SECONDS,
                attempts=1,
            )
            readback = _exact_mapping(
                response,
                frozenset({"commit_token"}),
                label="barrier response",
            )
            commit_token = _validate_digest(
                readback["commit_token"],
                label="barrier response",
            )
            if not hmac.compare_digest(commit_token, commit.commit_token):
                raise RemoteJournalCorruptionError(
                    "The signed barrier token does not match the committed save."
                )
        except RemoteJournalError:
            self._mark_poisoned(ambiguous=True)
            raise
        self._commit = None
        self._pending_save = None
        self._replay_allowed = False

    async def async_close(self) -> None:
        """Drain accepted work and release the remote owner without closing HTTP."""

        self._require_loop()
        if self._closed:
            return
        if self._close_task is None:
            self._closing = True
            self._close_task = self._loop.create_task(self._finish_close())
        _result, cancelled = await _await_owned_task(self._close_task)
        if cancelled is not None:
            raise cancelled

    async def _finish_close(self) -> None:
        """Wait for accepted local work without contacting the stateless App."""

        try:
            async with self._operation_lock:
                pass
        finally:
            self._closed = True


__all__ = (
    "BOOT_ID_HEADER",
    "MAX_CANONICAL_JSON_BYTES",
    "MAX_ROOT_JSON_BYTES",
    "PROTOCOL_ID",
    "PROTOCOL_VERSION",
    "REMOTE_JOURNAL_CAPABILITIES",
    "REMOTE_JOURNAL_DURABILITY_CAPABILITY",
    "REMOTE_JOURNAL_PORT",
    "REQUEST_ID_HEADER",
    "SIGNATURE_HEADER",
    "TRUSTED_REMOTE_JOURNAL_APP_SLUGS",
    "RemoteJournalAmbiguousMutationError",
    "RemoteJournalAuthenticationError",
    "RemoteJournalClosedError",
    "RemoteJournalConflictError",
    "RemoteJournalCorruptionError",
    "RemoteJournalEndpoint",
    "RemoteJournalError",
    "RemoteJournalPoisonedError",
    "RemoteJournalProtocolError",
    "RemoteJournalResponseSizeError",
    "RemoteJournalSizeError",
    "RemoteJournalTimeoutError",
    "RemoteJournalUnavailableError",
    "RemoteReferenceJournalStore",
)
