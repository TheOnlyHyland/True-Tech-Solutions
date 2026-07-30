"""Authenticated wire and state tests for the remote reference journal client."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable
from dataclasses import FrozenInstanceError, dataclass
import hashlib
import hmac
import importlib.util
import json
import logging
from pathlib import Path
import re
import socket
import sys
from typing import Any, AsyncIterator

import aiohttp
from aiohttp import web
from homeassistant.core import HomeAssistant
import pytest
import pytest_asyncio

from custom_components.true_family import reference_journal_remote as remote
from custom_components.true_family import reference_migration_ha as journal_ha


pytestmark = pytest.mark.enable_socket

APP_SLUG = "8c9c720e_true_family_journal"
APP_HOSTNAME = "8c9c720e-true-family-journal"
BOOT_ID = "0123456789abcdef0123456789abcdef"
HMAC_KEY = "ab" * 32
JOURNAL_ID = "true-family-schema-v4-reference-journal"
PORT = 8765
MAX_BODY = 4 * 1024 * 1024
MAX_ROOT = 3 * 1024 * 1024
CAPABILITIES = (
    "barrier",
    "close",
    "idempotent-save",
    "load",
    "revision-and-generation-cas",
    "durability.sqlite-wal-full-process-crash-cas.v1",
)
REQUEST_ID_PATTERN = re.compile(r"^tfj-[0-9a-f]{32}$")
HEX_32_PATTERN = re.compile(r"^[0-9a-f]{32}$")
HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class DuplicateKey(ValueError):
    pass


class FakeConflict(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def app_encode(value: dict[str, Any]) -> bytes:
    """Canonical encoder independent from the client implementation."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def app_decode(raw: bytes) -> dict[str, Any]:
    """Strict duplicate-rejecting canonical decoder for the fake App."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise DuplicateKey
            output[key] = value
        return output

    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if type(value) is not dict or app_encode(value) != raw:
        raise ValueError
    return value


def request_signature(
    key: bytes,
    path: str,
    boot_id: str,
    request_id: str,
    body: bytes,
) -> str:
    digest = hashlib.sha256(body).hexdigest()
    message = (
        "true-family-journal-request-v1\nPOST\n"
        f"{path}\n{boot_id}\n{request_id}\n{digest}"
    ).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def response_signature(
    key: bytes,
    status: int,
    path: str,
    boot_id: str,
    request_id: str,
    body: bytes,
) -> str:
    digest = hashlib.sha256(body).hexdigest()
    message = (
        "true-family-journal-response-v1\n"
        f"{status}\n{path}\n{boot_id}\n{request_id}\n{digest}"
    ).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def commit_token(request_id: str, request_digest: str) -> str:
    material = (
        f"true-family-journal-commit-v1\n{request_id}\n{request_digest}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def save_request_id(body_digest: str) -> str:
    material = f"true-family-journal-save-id-v1\n{body_digest}".encode("ascii")
    return f"tfj-{hashlib.sha256(material).hexdigest()[:32]}"


def root_for(generation: int, marker: str = "root") -> dict[str, Any]:
    return {
        "content": {"marker": marker},
        "generation": generation,
        "journal_id": JOURNAL_ID,
        "schema": 4,
    }


@dataclass(frozen=True, slots=True)
class ObservedRequest:
    path: str
    request_id: str
    body: bytes
    body_digest: str


class LoopbackResolver(aiohttp.abc.AbstractResolver):
    """Resolve only the slug-derived private hostname to the local fake App."""

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        assert host == APP_HOSTNAME
        assert port == PORT
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        return None


class FakeJournalApp:
    """Independent in-memory implementation of the exact companion App protocol."""

    def __init__(self) -> None:
        self.boot_id = BOOT_ID
        self.key_hex = HMAC_KEY
        self.generation: int | None = None
        self.revision: str | None = None
        self.root: dict[str, Any] | None = None
        self.requests: list[ObservedRequest] = []
        self.failures: list[str] = []
        self.replay_guard: dict[str, tuple[str, str]] = {}
        self.receipts: dict[str, tuple[str, dict[str, Any]]] = {}
        self.commit_tokens: set[str] = set()
        self.disconnects: defaultdict[str, int] = defaultdict(int)
        self.signed_statuses: dict[str, tuple[int, str]] = {}
        self.response_faults: dict[str, str] = {}
        self.response_mutators: dict[
            str, Callable[[dict[str, Any]], dict[str, Any]]
        ] = {}
        self.before_delays: defaultdict[str, float] = defaultdict(float)
        self.after_delays: defaultdict[str, float] = defaultdict(float)
        self.drop_save_before_commit = False
        self.after_gates: dict[str, asyncio.Event] = {}
        self.entered: defaultdict[str, asyncio.Event] = defaultdict(asyncio.Event)
        self.committed = asyncio.Event()
        self.close_count = 0
        self.runner: web.AppRunner | None = None
        self.session: aiohttp.ClientSession | None = None
        self.stores: list[remote.RemoteReferenceJournalStore] = []

    @property
    def key(self) -> bytes:
        return bytes.fromhex(self.key_hex)

    def endpoint(self) -> remote.RemoteJournalEndpoint:
        return remote.RemoteJournalEndpoint(
            full_slug=APP_SLUG,
            boot_id=BOOT_ID,
            hmac_key=HMAC_KEY,
        )

    async def open_store(
        self,
        hass: HomeAssistant,
        *,
        journal_id: str = JOURNAL_ID,
        endpoint: remote.RemoteJournalEndpoint | None = None,
    ) -> remote.RemoteReferenceJournalStore:
        store = await remote.RemoteReferenceJournalStore.async_open(
            hass,
            journal_id=journal_id,
            endpoint=self.endpoint() if endpoint is None else endpoint,
        )
        self.stores.append(store)
        return store

    def path_requests(self, path: str) -> list[ObservedRequest]:
        return [request for request in self.requests if request.path == path]

    def _load_response(self) -> dict[str, Any]:
        if self.root is None:
            return {
                "absent": True,
                "generation": None,
                "revision": None,
                "root": None,
            }
        return {
            "absent": False,
            "generation": self.generation,
            "revision": self.revision,
            "root": self.root,
        }

    async def _response(
        self,
        *,
        path: str,
        request_id: str,
        status: int,
        payload: dict[str, Any],
    ) -> web.Response:
        mutator = self.response_mutators.pop(path, None)
        if mutator is not None:
            payload = mutator(payload)
        body = app_encode(payload)
        fault = self.response_faults.pop(path, None)
        signing_body = body
        response_body = body
        signing_key = self.key
        signing_path = path
        signing_status = status
        signing_boot = self.boot_id
        signing_request_id = request_id
        response_boot = self.boot_id
        response_request_id = request_id
        if fault == "key":
            signing_key = bytes.fromhex("cd" * 32)
        elif fault == "boot":
            signing_boot = "f" * 32
            response_boot = signing_boot
        elif fault == "request":
            signing_request_id = "tfj-" + "e" * 32
            response_request_id = signing_request_id
        elif fault == "path":
            signing_path = "/v1/not-the-requested-path"
        elif fault == "status":
            signing_status = 201
        elif fault == "body":
            response_body = body + b" "
        elif fault == "malformed":
            signing_body = response_body = b'{"nonce":'
        elif fault == "duplicate":
            signing_body = response_body = b'{"nonce":"a","nonce":"a"}'
        elif fault == "oversize":
            signing_body = response_body = b"{" + b"x" * MAX_BODY + b"}"
        signature = response_signature(
            signing_key,
            signing_status,
            signing_path,
            signing_boot,
            signing_request_id,
            signing_body,
        )
        return web.Response(
            status=status,
            body=response_body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-True-Family-Boot-ID": response_boot,
                "X-True-Family-Request-ID": response_request_id,
                "X-True-Family-Signature": signature,
            },
        )

    async def _error(
        self,
        path: str,
        request_id: str,
        status: int,
        code: str,
    ) -> web.Response:
        return await self._response(
            path=path,
            request_id=request_id,
            status=status,
            payload={"error": code},
        )

    def _validate_request(
        self,
        request: web.Request,
        raw: bytes,
    ) -> tuple[str, dict[str, Any]] | None:
        request_id = request.headers.get("X-True-Family-Request-ID", "")
        boot_id = request.headers.get("X-True-Family-Boot-ID", "")
        signature = request.headers.get("X-True-Family-Signature", "")
        if not REQUEST_ID_PATTERN.fullmatch(request_id):
            self.failures.append("request ID")
            return None
        expected = request_signature(
            self.key,
            request.path,
            boot_id,
            request_id,
            raw,
        )
        if (
            request.method != "POST"
            or boot_id != self.boot_id
            or not hmac.compare_digest(signature, expected)
            or request.content_type != "application/json"
            or request.query_string
            or len(raw) > MAX_BODY
        ):
            return None
        try:
            payload = app_decode(raw)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            self.failures.append("canonical request JSON")
            return None
        self.requests.append(
            ObservedRequest(
                path=request.path,
                request_id=request_id,
                body=raw,
                body_digest=hashlib.sha256(raw).hexdigest(),
            )
        )
        return request_id, payload

    @staticmethod
    def _exact(payload: dict[str, Any], keys: set[str]) -> None:
        if type(payload) is not dict or set(payload) != keys:
            raise ValueError

    @staticmethod
    def _client_id(payload: dict[str, Any]) -> str:
        client_id = payload["client_id"]
        if type(client_id) is not str or not HEX_32_PATTERN.fullmatch(client_id):
            raise ValueError
        return client_id

    async def handle(self, request: web.Request) -> web.StreamResponse:
        raw = await request.read()
        validated = self._validate_request(request, raw)
        request_id = request.headers.get(
            "X-True-Family-Request-ID", "tfj-" + "0" * 32
        )
        if validated is None:
            return await self._error(
                request.path,
                request_id,
                401,
                "authentication_failed",
            )
        request_id, payload = validated
        digest = hashlib.sha256(raw).hexdigest()
        identity = (request.path, digest)
        previous = self.replay_guard.get(request_id)
        if previous is not None and (
            request.path not in {"/v1/save", "/v1/barrier"} or previous != identity
        ):
            return await self._error(
                request.path,
                request_id,
                409,
                "request_id_conflict",
            )
        self.replay_guard[request_id] = identity

        if self.disconnects[request.path] > 0:
            self.disconnects[request.path] -= 1
            transport = request.transport
            if transport is not None:
                transport.abort()
            return web.Response(status=500)
        signed_status = self.signed_statuses.pop(request.path, None)
        if signed_status is not None:
            return await self._error(
                request.path,
                request_id,
                signed_status[0],
                signed_status[1],
            )
        delay = self.before_delays[request.path]
        if delay:
            await asyncio.sleep(delay)
        if request.path == "/v1/save" and self.drop_save_before_commit:
            self.drop_save_before_commit = False
            return await self._error(
                request.path,
                request_id,
                503,
                "storage_failure",
            )

        try:
            response_payload = await self._dispatch(
                request.path,
                request_id,
                digest,
                payload,
            )
        except FakeConflict as err:
            return await self._error(request.path, request_id, 409, err.code)
        except (AssertionError, KeyError, TypeError, ValueError):
            self.failures.append(f"shape:{request.path}")
            return await self._error(
                request.path,
                request_id,
                400,
                "invalid_envelope",
            )

        self.entered[request.path].set()
        gate = self.after_gates.get(request.path)
        if gate is not None:
            await gate.wait()
        delay = self.after_delays[request.path]
        if delay:
            await asyncio.sleep(delay)
        return await self._response(
            path=request.path,
            request_id=request_id,
            status=200,
            payload=response_payload,
        )

    async def _dispatch(
        self,
        path: str,
        request_id: str,
        request_digest: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if path == "/v1/hello":
            self._exact(payload, {"client_id", "nonce"})
            self._client_id(payload)
            nonce = payload["nonce"]
            assert type(nonce) is str and 1 <= len(nonce.encode("utf-8")) <= 128
            return {"capabilities": list(CAPABILITIES), "nonce": nonce}
        if path == "/v1/load":
            self._exact(payload, {"client_id", "journal_id"})
            self._client_id(payload)
            assert payload["journal_id"] == JOURNAL_ID
            return self._load_response()
        if path == "/v1/save":
            return self._save(payload, request_id, request_digest)
        if path == "/v1/barrier":
            self._exact(payload, {"client_id", "commit_token", "journal_id"})
            self._client_id(payload)
            assert payload["journal_id"] == JOURNAL_ID
            token = payload["commit_token"]
            assert type(token) is str and HEX_64_PATTERN.fullmatch(token)
            if token not in self.commit_tokens:
                raise FakeConflict("unknown_commit_token")
            return {"commit_token": token}
        if path == "/v1/close":
            self._exact(payload, {"client_id"})
            self._client_id(payload)
            self.close_count += 1
            return {"closed": True}
        raise ValueError

    def _save(
        self,
        payload: dict[str, Any],
        request_id: str,
        request_digest: str,
    ) -> dict[str, Any]:
        self._exact(
            payload,
            {"client_id", "expected_revision", "journal_id", "root"},
        )
        self._client_id(payload)
        assert payload["journal_id"] == JOURNAL_ID
        receipt = self.receipts.get(request_id)
        if receipt is not None:
            if receipt[0] != request_digest:
                raise FakeConflict("request_id_conflict")
            return receipt[1]
        root = payload["root"]
        assert type(root) is dict
        assert root.get("journal_id") == JOURNAL_ID
        generation = root.get("generation")
        assert type(generation) is int and generation >= 0
        if self.root is None:
            if generation != 0:
                raise FakeConflict("stale_generation")
            if payload["expected_revision"] is not None:
                raise FakeConflict("stale_revision")
        else:
            if generation != self.generation + 1:  # type: ignore[operator]
                raise FakeConflict("stale_generation")
            if payload["expected_revision"] != self.revision:
                raise FakeConflict("stale_revision")
        root_bytes = app_encode(root)
        assert len(root_bytes) <= MAX_ROOT
        revision = hashlib.sha256(root_bytes).hexdigest()
        token = commit_token(request_id, request_digest)
        response = {
            "commit_token": token,
            "generation": generation,
            "revision": revision,
        }
        self.root = app_decode(root_bytes)
        self.generation = generation
        self.revision = revision
        self.receipts[request_id] = (request_digest, response)
        self.commit_tokens.add(token)
        self.committed.set()
        return response


@pytest_asyncio.fixture
async def fake_app(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> AsyncIterator[FakeJournalApp]:
    app = FakeJournalApp()
    web_app = web.Application(client_max_size=MAX_BODY + 1)
    for path in ("hello", "load", "save", "barrier", "close"):
        web_app.router.add_post(f"/v1/{path}", app.handle)
    runner = web.AppRunner(web_app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()
    session = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(
            resolver=LoopbackResolver(),
            use_dns_cache=False,
        )
    )
    app.runner = runner
    app.session = session
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    try:
        yield app
    finally:
        for store in reversed(app.stores):
            try:
                await store.async_close()
            except (remote.RemoteJournalError, asyncio.CancelledError):
                pass
        await session.close()
        await runner.cleanup()


def test_endpoint_is_strict_immutable_derived_and_redacted() -> None:
    endpoint = remote.RemoteJournalEndpoint(
        full_slug=APP_SLUG,
        boot_id=BOOT_ID,
        hmac_key=HMAC_KEY,
    )

    assert endpoint.hostname == APP_HOSTNAME
    assert endpoint.port == 8765
    assert endpoint.protocol == 1
    assert endpoint.protocol_id == "true-family-journal-v1"
    assert HMAC_KEY not in repr(endpoint)
    assert "hmac_key" not in repr(endpoint)
    with pytest.raises(FrozenInstanceError):
        endpoint.hostname = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("full_slug", "true_family_journal"),
        ("full_slug", "attacker_true_family_journal"),
        ("full_slug", "repository_true_family_journal"),
        ("full_slug", "local_true_family_journal"),
        ("full_slug", "8c22f541_true_family_journal"),
        ("full_slug", "8c9c720e_true_family_journal_attacker"),
        ("full_slug", "local_other_journal"),
        ("full_slug", "Local_true_family_journal"),
        ("full_slug", "local_true_family_journal/path"),
        ("full_slug", "a_" + "b" * 62),
        ("boot_id", "A" * 32),
        ("boot_id", "0" * 31),
        ("hmac_key", "0" * 63),
        ("hmac_key", "g" * 64),
    ),
)
def test_endpoint_rejects_noncanonical_discovery(field: str, value: str) -> None:
    values = {"full_slug": APP_SLUG, "boot_id": BOOT_ID, "hmac_key": HMAC_KEY}
    values[field] = value
    with pytest.raises(ValueError):
        remote.RemoteJournalEndpoint(**values)


async def test_exact_hello_proof_and_shared_session_lifetime(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)

    assert store.endpoint == fake_app.endpoint()
    assert HEX_32_PATTERN.fullmatch(store.store_id)
    assert store.capabilities == CAPABILITIES
    assert remote.REMOTE_JOURNAL_DURABILITY_CAPABILITY in store.capabilities
    hello = app_decode(fake_app.path_requests("/v1/hello")[0].body)
    assert hello["client_id"] == store.store_id
    assert set(hello) == {"client_id", "nonce"}
    assert store._durability_proof is None
    proof = store.durability_proof
    assert isinstance(proof, journal_ha.ReferenceJournalDurabilityProof)
    assert proof.provider_id == (
        "tf/remote-sqlite-full-process-crash-cas-reference-journal/v1"
    )
    assert proof.guarantee == "sqlite-wal-full-process-crash-cas/v1"
    assert proof.scope is journal_ha.ReferenceJournalDurabilityScope.PROCESS_CRASH_ONLY
    assert APP_SLUG not in proof.provider_id
    assert HMAC_KEY not in proof.provider_id
    await store.async_close()
    await store.async_close()

    assert fake_app.close_count == 0
    assert fake_app.session is not None and not fake_app.session.closed
    assert fake_app.failures == []


async def test_canonical_signed_load_save_barrier_round_trip(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    assert await store.async_load() is None
    root = root_for(0, "round-trip")
    await store.async_save(root)
    await store.async_barrier()
    assert await store.async_load() == root

    assert [request.path for request in fake_app.requests] == [
        "/v1/hello",
        "/v1/load",
        "/v1/save",
        "/v1/barrier",
        "/v1/load",
    ]
    for request in fake_app.requests:
        assert REQUEST_ID_PATTERN.fullmatch(request.request_id)
        assert app_encode(app_decode(request.body)) == request.body
        assert request.body_digest == hashlib.sha256(request.body).hexdigest()
    save = app_decode(fake_app.path_requests("/v1/save")[0].body)
    save_request = fake_app.path_requests("/v1/save")[0]
    assert save_request.request_id == save_request_id(save_request.body_digest)
    assert set(save) == {"client_id", "expected_revision", "journal_id", "root"}
    assert save["expected_revision"] is None
    barrier = app_decode(fake_app.path_requests("/v1/barrier")[0].body)
    assert set(barrier) == {"client_id", "commit_token", "journal_id"}
    assert fake_app.failures == []


@pytest.mark.parametrize("fault", ("key", "boot", "request", "path", "status", "body"))
async def test_wrong_response_key_boot_request_path_status_or_body_is_rejected(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    fault: str,
) -> None:
    fake_app.response_faults["/v1/hello"] = fault
    with pytest.raises(
        (remote.RemoteJournalAuthenticationError, remote.RemoteJournalProtocolError)
    ):
        await fake_app.open_store(hass)


@pytest.mark.parametrize(
    ("fault", "error_type"),
    (
        ("malformed", remote.RemoteJournalCorruptionError),
        ("duplicate", remote.RemoteJournalCorruptionError),
        ("oversize", remote.RemoteJournalSizeError),
    ),
)
async def test_signed_malformed_duplicate_and_oversize_json_are_bounded(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    fault: str,
    error_type: type[BaseException],
) -> None:
    fake_app.response_faults["/v1/hello"] = fault
    with pytest.raises(error_type):
        await fake_app.open_store(hass)


@pytest.mark.parametrize(
    "mutation",
    ("nonce", "capabilities", "missing_durability", "extra", "type"),
)
async def test_hello_requires_exact_nonce_and_capabilities(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    mutation: str,
) -> None:
    def mutate(payload: dict[str, Any]) -> dict[str, Any]:
        changed = dict(payload)
        if mutation == "nonce":
            changed["nonce"] = "wrong-nonce"
        elif mutation == "capabilities":
            changed["capabilities"] = list(reversed(CAPABILITIES))
        elif mutation == "missing_durability":
            changed["capabilities"] = [
                item
                for item in CAPABILITIES
                if item != remote.REMOTE_JOURNAL_DURABILITY_CAPABILITY
            ]
        elif mutation == "extra":
            changed["protocol"] = "true-family-journal-v1"
        else:
            changed["capabilities"] = "load"
        return changed

    fake_app.response_mutators["/v1/hello"] = mutate
    with pytest.raises(
        (remote.RemoteJournalAuthenticationError, remote.RemoteJournalProtocolError)
    ):
        await fake_app.open_store(hass)


async def test_state_machine_requires_load_next_generation_and_one_barrier(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    with pytest.raises(remote.RemoteJournalProtocolError):
        await store.async_save(root_for(0))
    with pytest.raises(remote.RemoteJournalProtocolError):
        await store.async_barrier()
    assert await store.async_load() is None
    with pytest.raises(remote.RemoteJournalConflictError):
        await store.async_save(root_for(1, "future"))
    with pytest.raises(remote.RemoteJournalPoisonedError):
        await store.async_save(root_for(0))

    replacement = await fake_app.open_store(hass)
    assert await replacement.async_load() is None
    await replacement.async_save(root_for(0))
    with pytest.raises(remote.RemoteJournalProtocolError):
        await replacement.async_load()
    with pytest.raises(remote.RemoteJournalProtocolError):
        await replacement.async_save(root_for(1))
    await replacement.async_barrier()
    with pytest.raises(remote.RemoteJournalProtocolError):
        await replacement.async_barrier()
    assert await replacement.async_load() == root_for(0)


async def test_stale_revision_returns_typed_conflict_and_never_overwrites(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    first = await fake_app.open_store(hass)
    second = await fake_app.open_store(hass)
    assert await first.async_load() is None
    assert await second.async_load() is None
    await first.async_save(root_for(0, "first"))
    await first.async_barrier()

    with pytest.raises(remote.RemoteJournalConflictError):
        await second.async_save(root_for(0, "second"))
    with pytest.raises(remote.RemoteJournalPoisonedError):
        await second.async_load()
    assert fake_app.generation == 0
    assert fake_app.root == root_for(0, "first")


async def test_hello_and_load_retry_with_new_ids_only_before_any_response(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    fake_app.disconnects["/v1/hello"] = 1
    store = await fake_app.open_store(hass)
    hello_requests = fake_app.path_requests("/v1/hello")
    assert len(hello_requests) == 2
    assert hello_requests[0].request_id != hello_requests[1].request_id
    assert hello_requests[0].body == hello_requests[1].body

    fake_app.disconnects["/v1/load"] = 1
    assert await store.async_load() is None
    load_requests = fake_app.path_requests("/v1/load")
    assert len(load_requests) == 2
    assert load_requests[0].request_id != load_requests[1].request_id
    assert load_requests[0].body == load_requests[1].body
    assert all(
        request.request_id != save_request_id(request.body_digest)
        for request in (*hello_requests, *load_requests)
    )


@pytest.mark.parametrize(
    ("status", "code", "error_type"),
    (
        (401, "authentication_failed", remote.RemoteJournalAuthenticationError),
        (409, "stale_revision", remote.RemoteJournalConflictError),
        (413, "body_too_large", remote.RemoteJournalSizeError),
        (500, "storage_failure", remote.RemoteJournalUnavailableError),
        (400, "invalid_envelope", remote.RemoteJournalProtocolError),
    ),
)
async def test_signed_http_statuses_map_to_typed_errors_without_retry(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    status: int,
    code: str,
    error_type: type[BaseException],
) -> None:
    store = await fake_app.open_store(hass)
    fake_app.signed_statuses["/v1/load"] = (status, code)
    with pytest.raises(error_type):
        await store.async_load()
    assert len(fake_app.path_requests("/v1/load")) == 1
    with pytest.raises(remote.RemoteJournalPoisonedError):
        await store.async_load()


async def test_save_disconnect_has_no_blind_retry_and_exact_explicit_replay(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    assert await store.async_load() is None
    fake_app.disconnects["/v1/save"] = 1

    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_save(root_for(0, "replay"))
    assert len(fake_app.path_requests("/v1/save")) == 1
    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_load()

    await store.async_replay_save()
    saves = fake_app.path_requests("/v1/save")
    assert len(saves) == 2
    assert saves[0] == saves[1]
    assert fake_app.generation == 0
    await store.async_replay_save()
    assert fake_app.generation == 0
    await store.async_barrier()


async def test_pruned_save_id_reuse_after_4096_newer_generations_conflicts(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    """A deterministic old save ID cannot overwrite state after its receipt prunes."""

    store = await fake_app.open_store(hass)
    assert await store.async_load() is None
    await store.async_save(root_for(0, "receipt-to-prune"))
    old_save = fake_app.path_requests("/v1/save")[0]
    assert old_save.request_id == save_request_id(old_save.body_digest)
    await store.async_barrier()

    fake_app.receipts.clear()
    fake_app.generation = 4096
    fake_app.root = root_for(4096, "newest-retained-generation")
    fake_app.revision = hashlib.sha256(app_encode(fake_app.root)).hexdigest()
    newest_root = fake_app.root
    replay = remote._SignedRequest(
        path=old_save.path,
        request_id=old_save.request_id,
        body=old_save.body,
        body_digest=old_save.body_digest,
    )

    with pytest.raises(remote.RemoteJournalConflictError):
        await store._async_post(
            replay,
            timeout=remote.MUTATION_TIMEOUT_SECONDS,
            attempts=1,
        )

    assert fake_app.generation == 4096
    assert fake_app.root == newest_root


async def test_save_5xx_is_typed_unavailable_but_retains_explicit_replay(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    await store.async_load()
    fake_app.signed_statuses["/v1/save"] = (500, "storage_failure")

    with pytest.raises(remote.RemoteJournalUnavailableError):
        await store.async_save(root_for(0, "five-hundred"))
    assert len(fake_app.path_requests("/v1/save")) == 1
    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_load()
    await store.async_replay_save()
    saves = fake_app.path_requests("/v1/save")
    assert len(saves) == 2 and saves[0] == saves[1]
    await store.async_barrier()


async def test_save_oversized_response_after_commit_is_ambiguous_and_replayable(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    await store.async_load()
    fake_app.response_faults["/v1/save"] = "oversize"

    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_save(root_for(0, "oversized-response"))

    saves = fake_app.path_requests("/v1/save")
    assert len(saves) == 1
    assert fake_app.generation == 0
    assert fake_app.root == root_for(0, "oversized-response")
    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_load()

    await store.async_replay_save()
    replayed = fake_app.path_requests("/v1/save")
    assert len(replayed) == 2
    assert replayed[0] == replayed[1]
    await store.async_barrier()


@pytest.mark.parametrize("after_commit", (False, True))
async def test_save_timeout_before_or_after_commit_replays_same_receipt(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    monkeypatch: pytest.MonkeyPatch,
    after_commit: bool,
) -> None:
    monkeypatch.setattr(remote, "MUTATION_TIMEOUT_SECONDS", 0.03)
    store = await fake_app.open_store(hass)
    assert await store.async_load() is None
    if after_commit:
        fake_app.after_delays["/v1/save"] = 0.09
    else:
        fake_app.before_delays["/v1/save"] = 0.09
        fake_app.drop_save_before_commit = True

    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_save(root_for(0, f"after-{after_commit}"))
    assert len(fake_app.path_requests("/v1/save")) == 1
    if after_commit:
        assert fake_app.generation == 0
    else:
        assert fake_app.generation is None
        await asyncio.sleep(0.1)
        assert fake_app.generation is None
    fake_app.before_delays["/v1/save"] = 0
    fake_app.after_delays["/v1/save"] = 0
    await store.async_replay_save()

    saves = fake_app.path_requests("/v1/save")
    assert len(saves) == 2
    assert saves[0] == saves[1]
    assert fake_app.generation == 0
    await store.async_barrier()


async def test_barrier_timeout_poison_requires_reopen_and_reconcile(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remote, "MUTATION_TIMEOUT_SECONDS", 0.03)
    store = await fake_app.open_store(hass)
    await store.async_load()
    root = root_for(0, "barrier-timeout")
    await store.async_save(root)
    fake_app.after_delays["/v1/barrier"] = 0.09

    with pytest.raises(remote.RemoteJournalTimeoutError):
        await store.async_barrier()
    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_load()
    with pytest.raises(remote.RemoteJournalProtocolError):
        await store.async_replay_save()
    fake_app.after_delays["/v1/barrier"] = 0
    monkeypatch.setattr(remote, "MUTATION_TIMEOUT_SECONDS", 1.0)
    await store.async_close()
    recovered = await fake_app.open_store(hass)
    assert await recovered.async_load() == root


@pytest.mark.parametrize("change", ("restart", "rekey"))
async def test_app_restart_or_rekey_is_rejected(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    change: str,
) -> None:
    store = await fake_app.open_store(hass)
    if change == "restart":
        fake_app.boot_id = "f" * 32
    else:
        fake_app.key_hex = "cd" * 32

    with pytest.raises(remote.RemoteJournalAuthenticationError):
        await store.async_load()
    with pytest.raises(remote.RemoteJournalPoisonedError):
        await store.async_load()


async def test_rekey_during_save_surfaces_generation_auth_without_retry(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    assert await store.async_load() is None
    fake_app.key_hex = "cd" * 32

    with pytest.raises(remote.RemoteJournalAuthenticationError):
        await store.async_save(root_for(0, "rekey"))

    assert fake_app.path_requests("/v1/save") == []
    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_load()


async def test_cancelled_save_drains_before_releasing_state(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    await store.async_load()
    gate = asyncio.Event()
    fake_app.after_gates["/v1/save"] = gate
    save = asyncio.create_task(store.async_save(root_for(0, "cancel")))
    await asyncio.wait_for(fake_app.committed.wait(), timeout=1)
    save.cancel()
    await asyncio.sleep(0)
    assert not save.done()
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await save
    await store.async_barrier()
    assert fake_app.generation == 0


async def test_cancelled_close_drains_without_closing_shared_session(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    gate = asyncio.Event()
    fake_app.after_gates["/v1/load"] = gate
    load = asyncio.create_task(store.async_load())
    await asyncio.wait_for(fake_app.entered["/v1/load"].wait(), timeout=1)
    close = asyncio.create_task(store.async_close())
    await asyncio.sleep(0)
    assert not close.done()
    close.cancel()
    await asyncio.sleep(0)
    assert not close.done()
    gate.set()
    assert await load is None
    with pytest.raises(asyncio.CancelledError):
        await close
    await store.async_close()
    assert fake_app.close_count == 0
    assert fake_app.session is not None and not fake_app.session.closed


async def test_close_is_local_only_after_app_rekey_and_uses_no_network(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    requests_before_close = tuple(fake_app.requests)
    fake_app.boot_id = "f" * 32
    fake_app.key_hex = "cd" * 32

    await store.async_close()

    assert tuple(fake_app.requests) == requests_before_close
    assert fake_app.close_count == 0
    assert fake_app.session is not None and not fake_app.session.closed


@pytest.mark.parametrize(
    "mutation",
    ("absent_type", "generation_type", "revision", "root_generation", "extra"),
)
async def test_load_requires_exact_absence_generation_revision_and_root(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    mutation: str,
) -> None:
    fake_app.root = root_for(0, "strict-load")
    fake_app.generation = 0
    fake_app.revision = hashlib.sha256(app_encode(fake_app.root)).hexdigest()

    def mutate(payload: dict[str, Any]) -> dict[str, Any]:
        changed = dict(payload)
        if mutation == "absent_type":
            changed["absent"] = 0
        elif mutation == "generation_type":
            changed["generation"] = True
        elif mutation == "revision":
            changed["revision"] = "0" * 64
        elif mutation == "root_generation":
            changed["root"] = root_for(1, "strict-load")
        else:
            changed["store_id"] = "unexpected"
        return changed

    store = await fake_app.open_store(hass)
    fake_app.response_mutators["/v1/load"] = mutate
    with pytest.raises(
        (remote.RemoteJournalProtocolError, remote.RemoteJournalCorruptionError)
    ):
        await store.async_load()


@pytest.mark.parametrize("mutation", ("commit_token", "generation", "revision"))
async def test_save_response_exactly_matches_request_and_deterministic_token(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    mutation: str,
) -> None:
    store = await fake_app.open_store(hass)
    await store.async_load()

    def mutate(payload: dict[str, Any]) -> dict[str, Any]:
        changed = dict(payload)
        changed[mutation] = True if mutation == "generation" else "0" * 64
        return changed

    fake_app.response_mutators["/v1/save"] = mutate
    with pytest.raises(remote.RemoteJournalAmbiguousMutationError):
        await store.async_save(root_for(0, f"wrong-{mutation}"))
    await store.async_replay_save()
    await store.async_barrier()


async def test_secret_url_and_journal_never_reach_repr_errors_or_logs(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    endpoint = fake_app.endpoint()
    assert HMAC_KEY not in repr(endpoint)
    store = await fake_app.open_store(hass)
    fake_app.disconnects["/v1/load"] = 2
    caplog.set_level(logging.ERROR)

    try:
        await store.async_load()
    except remote.RemoteJournalUnavailableError as err:
        assert err.__cause__ is None
        assert HMAC_KEY not in str(err)
        assert APP_HOSTNAME not in str(err)
        assert JOURNAL_ID not in str(err)
        logging.getLogger("true_family.remote_test").exception("sanitized failure")
    else:
        raise AssertionError("The fake disconnect did not fail the load.")

    assert HMAC_KEY not in caplog.text
    assert APP_HOSTNAME not in caplog.text
    assert JOURNAL_ID not in caplog.text


async def test_network_wait_keeps_event_loop_heartbeat_running(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    fake_app.before_delays["/v1/load"] = 0.12
    ticks = 0
    stop = asyncio.Event()

    async def heartbeat() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    heartbeat_task = asyncio.create_task(heartbeat())
    try:
        assert await store.async_load() is None
    finally:
        stop.set()
        await heartbeat_task
    assert ticks >= 10


async def test_outbound_root_type_identity_generation_and_size_fail_before_send(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    cases: list[Any] = [
        [],
        {**root_for(0), "journal_id": "other-journal"},
        {**root_for(0), "generation": True},
    ]
    for value in cases:
        store = await fake_app.open_store(hass)
        await store.async_load()
        before = len(fake_app.path_requests("/v1/save"))
        with pytest.raises(
            (remote.RemoteJournalCorruptionError, remote.RemoteJournalProtocolError)
        ):
            await store.async_save(value)  # type: ignore[arg-type]
        assert len(fake_app.path_requests("/v1/save")) == before
        with pytest.raises(remote.RemoteJournalPoisonedError):
            await store.async_save(root_for(0))


async def test_root_over_three_mib_is_rejected_before_save_network(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    assert await store.async_load() is None
    saves_before = tuple(fake_app.path_requests("/v1/save"))

    with pytest.raises(remote.RemoteJournalSizeError):
        await store.async_save({**root_for(0), "large": "x" * MAX_ROOT})

    assert tuple(fake_app.path_requests("/v1/save")) == saves_before


async def test_closed_store_rejects_all_new_work(
    hass: HomeAssistant,
    fake_app: FakeJournalApp,
) -> None:
    store = await fake_app.open_store(hass)
    await store.async_close()
    with pytest.raises(remote.RemoteJournalClosedError):
        await store.async_load()
    with pytest.raises(remote.RemoteJournalClosedError):
        await store.async_save(root_for(0))
    with pytest.raises(remote.RemoteJournalClosedError):
        await store.async_barrier()
    with pytest.raises(remote.RemoteJournalClosedError):
        await store.async_replay_save()


async def test_client_round_trips_against_the_actual_companion_app(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
    tmp_path: Path,
) -> None:
    module_name = "true_family_remote_client_contract_app"
    server_path = (
        Path(__file__).resolve().parents[2]
        / "true_family_journal"
        / "server.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, server_path)
    assert spec is not None and spec.loader is not None
    app_server = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = app_server
    spec.loader.exec_module(app_server)

    state = await app_server.JournalServerState.async_create(
        tmp_path,
        key=bytes.fromhex(HMAC_KEY),
        boot_id=BOOT_ID,
    )
    application = app_server.create_web_application(state)
    runner = web.AppRunner(application, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()
    session = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(
            resolver=LoopbackResolver(),
            use_dns_cache=False,
        )
    )
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    try:
        actual_journal_id = f"{JOURNAL_ID}-\u00e9"
        store = await remote.RemoteReferenceJournalStore.async_open(
            hass,
            journal_id=actual_journal_id,
            endpoint=remote.RemoteJournalEndpoint(
                full_slug=APP_SLUG,
                boot_id=BOOT_ID,
                hmac_key=HMAC_KEY,
            ),
        )
        assert store.capabilities == CAPABILITIES
        assert await store.async_load() is None
        root = {
            **root_for(0, "actual-app"),
            "journal_id": actual_journal_id,
        }
        await store.async_save(root)
        await store.async_barrier()
        assert await store.async_load() == root
        await store.async_close()
        assert not session.closed
    finally:
        await session.close()
        await runner.cleanup()
        sys.modules.pop(module_name, None)
