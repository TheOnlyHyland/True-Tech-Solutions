"""Offline vertical-slice tests for the True Family journal companion App."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import pytest
import pytest_asyncio
import yaml


pytestmark = pytest.mark.enable_socket


@pytest.fixture(autouse=True)
def enable_loopback_test_servers(socket_enabled: None) -> None:
    """Re-enable sockets after the HA harness installs its global guard."""


PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = PROJECT_ROOT / "true_family_journal"
SERVER_PATH = APP_ROOT / "server.py"

MODULE_NAME = "true_family_companion_journal_server"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, SERVER_PATH)
assert SPEC is not None and SPEC.loader is not None
journal_app = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = journal_app
SPEC.loader.exec_module(journal_app)

KEY = bytes.fromhex("11" * 32)
OTHER_KEY = bytes.fromhex("22" * 32)
BOOT_ID = "a" * 32
OTHER_BOOT_ID = "b" * 32
CLIENT_ID = "c" * 32
OTHER_CLIENT_ID = "d" * 32
JOURNAL_ID = "true-family-reference-journal-companion-test"

CHILD_SERVER_IMPORT = r"""
import importlib.util
from pathlib import Path
import sys

server_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("true_family_child_journal", server_path)
assert spec is not None and spec.loader is not None
journal_app = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal_app
spec.loader.exec_module(journal_app)
"""


class LoopbackResolver(aiohttp.abc.AbstractResolver):
    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        assert host == "8c9c720e-true-family-journal"
        assert port == 8765
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


def read_child_pipe(fd: int, *, suffix: bytes, timeout: float = 10.0) -> bytes:
    received = bytearray()
    deadline = time.monotonic() + timeout
    while not received.endswith(suffix):
        remaining = deadline - time.monotonic()
        assert remaining > 0, "The child process did not report readiness."
        ready, _writable, _exceptional = select.select([fd], [], [], remaining)
        assert ready, "The child process readiness pipe timed out."
        chunk = os.read(fd, 256)
        assert chunk, "The child process closed its readiness pipe early."
        received.extend(chunk)
    return bytes(received)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def request_id(index: int) -> str:
    return f"tfj-{index:032x}"


def deterministic_save_id(body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()
    material = f"true-family-journal-save-id-v1\n{digest}".encode("ascii")
    return f"tfj-{hashlib.sha256(material).hexdigest()[:32]}"


def request_signature(
    key: bytes,
    method: str,
    path: str,
    boot_id: str,
    correlation_id: str,
    body: bytes,
) -> str:
    digest = hashlib.sha256(body).hexdigest()
    message = (
        "true-family-journal-request-v1\n"
        f"{method}\n{path}\n{boot_id}\n{correlation_id}\n{digest}"
    ).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def response_signature(
    key: bytes,
    status: int,
    path: str,
    boot_id: str,
    correlation_id: str,
    body: bytes,
) -> str:
    digest = hashlib.sha256(body).hexdigest()
    message = (
        "true-family-journal-response-v1\n"
        f"{status}\n{path}\n{boot_id}\n{correlation_id}\n{digest}"
    ).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def signed_headers(
    path: str,
    correlation_id: str,
    body: bytes,
    *,
    key: bytes = KEY,
    boot_id: str = BOOT_ID,
    signature: str | None = None,
) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-True-Family-Boot-ID": boot_id,
        "X-True-Family-Request-ID": correlation_id,
        "X-True-Family-Signature": (
            request_signature(
                key,
                "POST",
                path,
                boot_id,
                correlation_id,
                body,
            )
            if signature is None
            else signature
        ),
    }


def root_for(journal_id: str, generation: int, marker: str) -> dict[str, Any]:
    body = {
        "content": {
            "active_plans": {},
            "bridge_operations": {},
            "completions": {},
            "marker": marker,
            "originals": {},
            "states": {},
        },
        "generation": generation,
        "journal_id": journal_id,
        "schema": 4,
    }
    return {
        **body,
        "content_digest": hashlib.sha256(canonical(body)).hexdigest(),
    }


@dataclass(slots=True)
class RunningService:
    client: TestClient
    state: Any
    data_dir: Path
    key: bytes
    boot_id: str


@dataclass(frozen=True, slots=True)
class RawHttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(slots=True)
class RunningStrictService:
    listener: Any
    state: Any
    session: aiohttp.ClientSession
    host: str
    port: int
    key: bytes
    boot_id: str

    async def async_close(self) -> None:
        await self.session.close()
        try:
            await self.listener.async_close()
        finally:
            await self.state.async_close()


async def start_service(
    data_dir: Path,
    *,
    key: bytes = KEY,
    boot_id: str = BOOT_ID,
) -> RunningService:
    state = await journal_app.JournalServerState.async_create(
        data_dir,
        key=key,
        boot_id=boot_id,
    )
    client = TestClient(TestServer(journal_app.create_web_application(state)))
    try:
        await client.start_server()
    except BaseException:
        await client.close()
        await state.async_close()
        raise
    return RunningService(
        client=client,
        state=state,
        data_dir=data_dir,
        key=key,
        boot_id=boot_id,
    )


async def start_strict_service(
    data_dir: Path,
    *,
    key: bytes = KEY,
    boot_id: str = BOOT_ID,
    port: int = 0,
    **listener_options: Any,
) -> RunningStrictService:
    state = await journal_app.JournalServerState.async_create(
        data_dir,
        key=key,
        boot_id=boot_id,
    )
    listener = journal_app.StrictHttpServer(state, **listener_options)
    try:
        await listener.async_start("127.0.0.1", port)
    except BaseException:
        await state.async_close()
        raise
    return RunningStrictService(
        listener=listener,
        state=state,
        session=aiohttp.ClientSession(),
        host="127.0.0.1",
        port=listener.port,
        key=key,
        boot_id=boot_id,
    )


@pytest_asyncio.fixture
async def service(tmp_path: Path):
    running = await start_service(tmp_path)
    try:
        yield running
    finally:
        await running.client.close()


@pytest_asyncio.fixture
async def strict_service(tmp_path: Path):
    running = await start_strict_service(tmp_path)
    try:
        yield running
    finally:
        await running.async_close()


async def post_raw(
    service: RunningService,
    path: str,
    body: bytes,
    correlation_id: str,
    *,
    key: bytes | None = None,
    boot_id: str | None = None,
    signature: str | None = None,
):
    selected_key = service.key if key is None else key
    selected_boot = service.boot_id if boot_id is None else boot_id
    return await service.client.post(
        path,
        data=body,
        headers=signed_headers(
            path,
            correlation_id,
            body,
            key=selected_key,
            boot_id=selected_boot,
            signature=signature,
        ),
    )


async def post_json(
    service: RunningService,
    path: str,
    payload: dict[str, Any],
    correlation_id: str,
    **kwargs: Any,
):
    body = canonical(payload)
    if path == "/v1/save":
        correlation_id = deterministic_save_id(body)
    return await post_raw(
        service,
        path,
        body,
        correlation_id,
        **kwargs,
    )


async def strict_post_raw(
    service: RunningStrictService,
    path: str,
    body: bytes,
    correlation_id: str,
    *,
    key: bytes | None = None,
    boot_id: str | None = None,
    signature: str | None = None,
):
    selected_key = service.key if key is None else key
    selected_boot = service.boot_id if boot_id is None else boot_id
    return await service.session.post(
        f"http://{service.host}:{service.port}{path}",
        data=body,
        headers=signed_headers(
            path,
            correlation_id,
            body,
            key=selected_key,
            boot_id=selected_boot,
            signature=signature,
        ),
    )


async def strict_post_json(
    service: RunningStrictService,
    path: str,
    payload: dict[str, Any],
    correlation_id: str,
    **kwargs: Any,
):
    body = canonical(payload)
    if path == "/v1/save":
        correlation_id = deterministic_save_id(body)
    return await strict_post_raw(
        service,
        path,
        body,
        correlation_id,
        **kwargs,
    )


async def read_signed_response(
    response,
    path: str,
    correlation_id: str,
    *,
    key: bytes = KEY,
    boot_id: str = BOOT_ID,
) -> tuple[bytes, dict[str, Any]]:
    body = await response.read()
    assert body == canonical(json.loads(body))
    assert response.headers["X-True-Family-Boot-ID"] == boot_id
    response_request_id = response.headers["X-True-Family-Request-ID"]
    if path != "/v1/save":
        assert response_request_id == correlation_id
    expected = response_signature(
        key,
        response.status,
        path,
        boot_id,
        response_request_id,
        body,
    )
    assert hmac.compare_digest(
        response.headers["X-True-Family-Signature"],
        expected,
    )
    return body, json.loads(body)


async def read_unsigned_response(response, *, boot_id: str = BOOT_ID) -> dict[str, Any]:
    body = await response.read()
    for header in (
        "X-True-Family-Boot-ID",
        "X-True-Family-Request-ID",
        "X-True-Family-Signature",
    ):
        assert header not in response.headers
    assert boot_id.encode("ascii") not in body
    assert body == canonical(json.loads(body))
    return json.loads(body)


async def open_slow_request(
    service: RunningService,
    correlation_id: str,
    *,
    boot_id: str | None = None,
    signature: str = "0" * 64,
    content_length: str | None = "100",
    chunked: bool = False,
    extra_headers: tuple[str, ...] = (),
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    host = service.client.server.host
    port = service.client.server.port
    reader, writer = await asyncio.open_connection(host, port)
    headers = [
        "POST /v1/hello HTTP/1.1",
        f"Host: {host}:{port}",
        "Content-Type: application/json",
        f"X-True-Family-Boot-ID: {service.boot_id if boot_id is None else boot_id}",
        f"X-True-Family-Request-ID: {correlation_id}",
        f"X-True-Family-Signature: {signature}",
        "Connection: close",
    ]
    if chunked:
        headers.append("Transfer-Encoding: chunked")
    elif content_length is not None:
        headers.append(f"Content-Length: {content_length}")
    headers.extend(extra_headers)
    writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    return reader, writer


async def open_strict_raw(
    service: RunningStrictService,
    raw: bytes,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(service.host, service.port)
    writer.write(raw)
    await writer.drain()
    return reader, writer


def strict_post_head(
    service: RunningStrictService,
    path: str,
    correlation_id: str,
    body: bytes,
    *,
    content_length: str | None = None,
    include_content_length: bool = True,
    signature: str | None = None,
    extra_headers: tuple[str, ...] = (),
) -> bytes:
    actual_signature = signature or request_signature(
        service.key,
        "POST",
        path,
        service.boot_id,
        correlation_id,
        body,
    )
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {service.host}:{service.port}",
        "Content-Type: application/json",
        f"X-True-Family-Boot-ID: {service.boot_id}",
        f"X-True-Family-Request-ID: {correlation_id}",
        f"X-True-Family-Signature: {actual_signature}",
    ]
    if include_content_length:
        headers.append(
            f"Content-Length: {len(body) if content_length is None else content_length}"
        )
    headers.extend(extra_headers)
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")


async def read_raw_http_response(
    reader: asyncio.StreamReader,
    *,
    timeout: float = 1.0,
) -> RawHttpResponse:
    header_block = await asyncio.wait_for(
        reader.readuntil(b"\r\n\r\n"),
        timeout=timeout,
    )
    lines = header_block[:-4].decode("ascii").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        assert separator == ":"
        headers[name.lower()] = value.strip()
    content_length = int(headers.get("content-length", "0"))
    body = await asyncio.wait_for(
        reader.readexactly(content_length),
        timeout=timeout,
    )
    return RawHttpResponse(status=status, headers=headers, body=body)


def assert_raw_signed_response(
    response: RawHttpResponse,
    path: str,
    correlation_id: str,
    *,
    key: bytes = KEY,
    boot_id: str = BOOT_ID,
) -> dict[str, Any]:
    assert response.headers["x-true-family-boot-id"] == boot_id
    assert response.headers["x-true-family-request-id"] == correlation_id
    assert hmac.compare_digest(
        response.headers["x-true-family-signature"],
        response_signature(
            key,
            response.status,
            path,
            boot_id,
            correlation_id,
            response.body,
        ),
    )
    assert response.body == canonical(json.loads(response.body))
    return json.loads(response.body)


def assert_raw_unsigned_response(
    response: RawHttpResponse,
    *,
    boot_id: str = BOOT_ID,
) -> dict[str, Any]:
    for header in (
        "x-true-family-boot-id",
        "x-true-family-request-id",
        "x-true-family-signature",
    ):
        assert header not in response.headers
    assert boot_id.encode("ascii") not in response.body
    assert response.body == canonical(json.loads(response.body))
    return json.loads(response.body)


def root_with_exact_size(
    journal_id: str,
    generation: int,
    size: int,
) -> dict[str, Any]:
    root = {
        "generation": generation,
        "journal_id": journal_id,
        "padding": "",
    }
    padding_size = size - len(canonical(root))
    assert padding_size >= 0
    root["padding"] = "x" * padding_size
    assert len(canonical(root)) == size
    return root


async def provision(
    service: RunningService,
    *,
    correlation_index: int = 100,
    client_id: str = CLIENT_ID,
    marker: str = "provisioned",
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = root_for(JOURNAL_ID, 0, marker)
    correlation_id = request_id(correlation_index)
    response = await post_json(
        service,
        "/v1/save",
        {
            "client_id": client_id,
            "expected_revision": None,
            "journal_id": JOURNAL_ID,
            "root": root,
        },
        correlation_id,
    )
    assert response.status == 200
    _raw, saved = await read_signed_response(
        response,
        "/v1/save",
        correlation_id,
        key=service.key,
        boot_id=service.boot_id,
    )
    return root, saved


def test_app_package_is_explicit_and_has_no_elevated_surface() -> None:
    config = yaml.safe_load((APP_ROOT / "config.yaml").read_text(encoding="utf-8"))

    assert config == {
        "name": "True Family Journal",
        "version": "0.2.1",
        "slug": "true_family_journal",
        "description": "Durable journal companion for True Family radiator valve replacement",
        "url": (
            "https://github.com/TheOnlyHyland/True-Tech-Solutions/"
            "tree/main/true_family_journal"
        ),
        "arch": ["aarch64", "amd64"],
        "homeassistant": "2026.7.4",
        "startup": "services",
        "boot": "auto",
        "stage": "experimental",
        "init": False,
        "apparmor": True,
        "host_network": False,
        "ingress": False,
        "hassio_api": False,
        "hassio_role": "default",
        "homeassistant_api": False,
        "docker_api": False,
        "full_access": False,
        "backup": "cold",
        "timeout": 60,
        "watchdog": "http://[HOST]:[PORT:8765]/healthz",
        "discovery": ["true_family"],
        "schema": False,
        "image": "ghcr.io/theonlyhyland/true-family-journal",
    }
    for forbidden in ("ports", "map", "privileged", "devices", "uart", "usb"):
        assert forbidden not in config
    assert config["backup"] != "hot"
    assert journal_app.MAX_ACCEPTED_CONNECTIONS == 16
    assert journal_app.MAX_HEADER_BYTES == 8 * 1024
    assert journal_app.HEADER_READ_TIMEOUT_SECONDS == 2.0
    assert journal_app.BODY_READ_TIMEOUT_SECONDS == 5.0
    assert journal_app.MAX_CONTENT_LENGTH_DIGITS == 10
    assert journal_app.RESPONSE_WRITE_TIMEOUT_SECONDS == 5.0
    assert journal_app.HANDLER_DRAIN_TIMEOUT_SECONDS == 15.0

    dockerfile = (APP_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.startswith("FROM ghcr.io/home-assistant/base:3.24\n")
    assert "ARG BUILD_FROM" not in dockerfile
    assert "io.hass.type=\"app\"" in dockerfile
    assert "py3-aiohttp" in dockerfile
    assert "EXPOSE 8765" in dockerfile
    assert "COPY run.sh server.py /app/" in dockerfile
    assert 'ENTRYPOINT [ "/app/run.sh" ]' in dockerfile
    assert "CMD" not in dockerfile

    run_script = (APP_ROOT / "run.sh").read_text(encoding="utf-8")
    assert "umask 077" in run_script
    assert "python3 -I -B /app/server.py" in run_script
    apparmor = (APP_ROOT / "apparmor.txt").read_text(encoding="utf-8")
    assert "profile true_family_journal" in apparmor
    assert "/data/{,**} rwk," in apparmor
    assert "/homeassistant" not in apparmor

    for required in (
        "config.yaml",
        "Dockerfile",
        "run.sh",
        "server.py",
        "README.md",
        "DOCS.md",
        "CHANGELOG.md",
        "apparmor.txt",
    ):
        assert (APP_ROOT / required).is_file()


async def test_health_and_signed_hello(service: RunningService) -> None:
    health = await service.client.get("/healthz")
    assert health.status == 200
    assert await health.read() == canonical(
        {"protocol": "true-family-journal-v1", "status": "ok"}
    )
    assert "X-True-Family-Signature" not in health.headers

    correlation_id = request_id(1)
    hello = await post_json(
        service,
        "/v1/hello",
        {"client_id": CLIENT_ID, "nonce": "hello-nonce"},
        correlation_id,
    )
    assert hello.status == 200
    _raw, payload = await read_signed_response(
        hello,
        "/v1/hello",
        correlation_id,
    )
    assert payload == {
        "capabilities": [
            "barrier",
            "close",
            "idempotent-save",
            "load",
            "revision-and-generation-cas",
            "durability.sqlite-wal-full-process-crash-cas.v1",
        ],
        "nonce": "hello-nonce",
    }


async def test_wrong_signature_key_boot_and_non_idempotent_replay(
    service: RunningService,
) -> None:
    payload = {"client_id": CLIENT_ID, "nonce": "authentication"}

    bad_signature_id = request_id(2)
    response = await post_json(
        service,
        "/v1/hello",
        payload,
        bad_signature_id,
        signature="0" * 64,
    )
    assert response.status == 401
    assert await read_unsigned_response(response) == {
        "error": "authentication_failed"
    }

    wrong_key_id = request_id(3)
    response = await post_json(
        service,
        "/v1/hello",
        payload,
        wrong_key_id,
        key=OTHER_KEY,
    )
    assert response.status == 401
    assert await read_unsigned_response(response) == {
        "error": "authentication_failed"
    }

    wrong_boot_id = request_id(4)
    response = await post_json(
        service,
        "/v1/hello",
        payload,
        wrong_boot_id,
        boot_id=OTHER_BOOT_ID,
    )
    assert response.status == 401
    assert await read_unsigned_response(response) == {
        "error": "authentication_failed"
    }

    replay_id = request_id(5)
    first = await post_json(service, "/v1/hello", payload, replay_id)
    assert first.status == 200
    await read_signed_response(first, "/v1/hello", replay_id)
    replay = await post_json(service, "/v1/hello", payload, replay_id)
    assert replay.status == 409
    _raw, error = await read_signed_response(replay, "/v1/hello", replay_id)
    assert error == {"error": "request_id_conflict"}


@pytest.mark.parametrize(
    ("case", "expected_status", "expected_error"),
    (
        ("signature", 401, "authentication_failed"),
        ("duplicate", 401, "authentication_failed"),
        ("length", 413, "body_too_large"),
    ),
)
async def test_invalid_headers_and_length_reject_before_body_buffering(
    service: RunningService,
    case: str,
    expected_status: int,
    expected_error: str,
) -> None:
    correlation_id = request_id(6 + len(case))
    reader, writer = await open_slow_request(
        service,
        correlation_id,
        signature="z" * 64 if case == "signature" else "0" * 64,
        content_length=(
            str(journal_app.MAX_BODY_BYTES + 1) if case == "length" else "100"
        ),
        extra_headers=(
            ("X-True-Family-Signature: " + "0" * 64,)
            if case == "duplicate"
            else ()
        ),
    )
    try:
        response = await read_raw_http_response(reader, timeout=0.5)
    finally:
        writer.close()
        await writer.wait_closed()
    assert response.status == expected_status
    assert assert_raw_unsigned_response(response) == {"error": expected_error}


async def test_strict_listener_health_normal_request_and_authenticated_error(
    strict_service: RunningStrictService,
) -> None:
    health = await strict_service.session.get(
        f"http://{strict_service.host}:{strict_service.port}/healthz"
    )
    assert health.status == 200
    assert await health.read() == canonical(
        {"protocol": "true-family-journal-v1", "status": "ok"}
    )
    assert "X-True-Family-Boot-ID" not in health.headers

    hello_id = request_id(15)
    hello = await strict_post_json(
        strict_service,
        "/v1/hello",
        {"client_id": CLIENT_ID, "nonce": "strict-listener"},
        hello_id,
    )
    assert hello.status == 200
    _raw, payload = await read_signed_response(hello, "/v1/hello", hello_id)
    assert payload["nonce"] == "strict-listener"

    unauthenticated = await strict_post_json(
        strict_service,
        "/v1/hello",
        {"client_id": CLIENT_ID, "nonce": "wrong-hmac"},
        request_id(19),
        signature="0" * 64,
    )
    assert unauthenticated.status == 401
    assert await read_unsigned_response(unauthenticated) == {
        "error": "authentication_failed"
    }

    malformed_id = request_id(16)
    malformed_body = b'{"client_id":"broken"}'
    malformed = await strict_post_raw(
        strict_service,
        "/v1/hello",
        malformed_body,
        malformed_id,
    )
    assert malformed.status == 400
    _raw, error = await read_signed_response(
        malformed,
        "/v1/hello",
        malformed_id,
    )
    assert error == {"error": "invalid_envelope"}

    root = root_for(JOURNAL_ID, 0, "strict-deterministic-save")
    save_payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": JOURNAL_ID,
        "root": root,
    }
    save_body = canonical(save_payload)
    save_id = deterministic_save_id(save_body)
    saved = await strict_post_raw(
        strict_service,
        "/v1/save",
        save_body,
        save_id,
    )
    assert saved.status == 200
    await read_signed_response(saved, "/v1/save", save_id)

    load_id = request_id(20)
    loaded = await strict_post_json(
        strict_service,
        "/v1/load",
        {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
        load_id,
    )
    assert loaded.status == 200
    _raw, loaded_payload = await read_signed_response(
        loaded,
        "/v1/load",
        load_id,
    )
    assert loaded_payload["root"] == root


async def test_strict_listener_header_and_body_deadlines_are_pre_auth_bounded(
    tmp_path: Path,
) -> None:
    running = await start_strict_service(
        tmp_path,
        header_timeout=0.05,
        body_timeout=0.05,
    )
    try:
        header_reader, header_writer = await open_strict_raw(
            running,
            b"POST /v1/hello HTTP/1.1\r\nHost: slow",
        )
        header_timeout = await read_raw_http_response(header_reader, timeout=0.5)
        assert header_timeout.status == 408
        assert assert_raw_unsigned_response(header_timeout) == {
            "error": "request_timeout"
        }
        header_writer.close()
        await header_writer.wait_closed()

        body = canonical({"client_id": CLIENT_ID, "nonce": "slow-body"})
        body_reader, body_writer = await open_strict_raw(
            running,
            strict_post_head(
                running,
                "/v1/hello",
                request_id(17),
                body,
            ),
        )
        body_timeout = await read_raw_http_response(body_reader, timeout=0.5)
        assert body_timeout.status == 408
        assert assert_raw_unsigned_response(body_timeout) == {
            "error": "request_timeout"
        }
        body_writer.close()
        await body_writer.wait_closed()
    finally:
        await running.async_close()


async def test_strict_listener_total_connection_cap_is_immediate_and_reusable(
    tmp_path: Path,
) -> None:
    running = await start_strict_service(
        tmp_path,
        max_connections=2,
        header_timeout=0.5,
    )
    held: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    try:
        for _ in range(2):
            held.append(await open_strict_raw(running, b"P"))
        for _ in range(100):
            if running.listener.active_connections == 2:
                break
            await asyncio.sleep(0.001)
        assert running.listener.active_connections == 2

        overflow_reader, overflow_writer = await open_strict_raw(running, b"")
        overflow = await read_raw_http_response(overflow_reader, timeout=0.5)
        assert overflow.status == 503
        assert assert_raw_unsigned_response(overflow) == {"error": "request_busy"}
        overflow_writer.close()
        await overflow_writer.wait_closed()

        for _reader, writer in held:
            writer.close()
            await writer.wait_closed()
        held.clear()
        for _ in range(100):
            if running.listener.active_connections == 0:
                break
            await asyncio.sleep(0.001)
        assert running.listener.active_connections == 0

        healthy = await running.session.get(
            f"http://{running.host}:{running.port}/healthz"
        )
        assert healthy.status == 200
        await healthy.read()
    finally:
        for _reader, writer in held:
            writer.close()
        await running.async_close()


async def test_strict_listener_rejects_malformed_duplicate_and_chunked_headers(
    strict_service: RunningStrictService,
) -> None:
    body = canonical({"client_id": CLIENT_ID, "nonce": "framing"})
    correlation_id = request_id(18)
    valid_head = strict_post_head(
        strict_service,
        "/v1/hello",
        correlation_id,
        body,
    )
    cases = (
        (
            b"POST  /v1/hello HTTP/1.1\r\nHost: test\r\n\r\n",
            400,
            "invalid_http",
        ),
        (
            valid_head.replace(
                b"Content-Type: application/json\r\n",
                b"Content-Type: application/json\r\n folded: value\r\n",
            ),
            400,
            "invalid_headers",
        ),
        (
            valid_head.replace(
                b"\r\n\r\n",
                b"\r\nX-True-Family-Signature: " + b"0" * 64 + b"\r\n\r\n",
            ),
            400,
            "invalid_headers",
        ),
        (
            valid_head.replace(BOOT_ID.encode("ascii"), OTHER_BOOT_ID.encode("ascii")),
            401,
            "authentication_failed",
        ),
        (
            valid_head.replace(
                request_signature(
                    strict_service.key,
                    "POST",
                    "/v1/hello",
                    strict_service.boot_id,
                    correlation_id,
                    body,
                ).encode("ascii"),
                b"z" * 64,
            ),
            401,
            "authentication_failed",
        ),
        (
            strict_post_head(
                strict_service,
                "/v1/hello",
                correlation_id,
                body,
                include_content_length=False,
            ),
            400,
            "invalid_content_length",
        ),
        (
            strict_post_head(
                strict_service,
                "/v1/hello",
                correlation_id,
                body,
                include_content_length=False,
                extra_headers=("Transfer-Encoding: chunked",),
            ),
            400,
            "invalid_transfer_encoding",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nHost: test\r\nX-Fill: "
            + b"x" * journal_app.MAX_HEADER_BYTES,
            431,
            "headers_too_large",
        ),
    )
    for raw, status, code in cases:
        reader, writer = await open_strict_raw(strict_service, raw)
        try:
            response = await read_raw_http_response(reader, timeout=0.5)
        finally:
            writer.close()
            await writer.wait_closed()
        assert response.status == status
        assert assert_raw_unsigned_response(response) == {"error": code}


@pytest.mark.parametrize("digit_count", (4_000, 8_000))
async def test_content_length_digit_bombs_are_bounded_before_conversion(
    strict_service: RunningStrictService,
    caplog: pytest.LogCaptureFixture,
    digit_count: int,
) -> None:
    caplog.set_level(logging.ERROR, logger="true_family_journal")
    raw = (
        b"POST /v1/hello HTTP/1.1\r\nHost: test\r\nContent-Length: "
        + b"9" * digit_count
        + b"\r\n\r\n"
    )
    assert len(raw) <= journal_app.MAX_HEADER_BYTES
    reader, writer = await open_strict_raw(strict_service, raw)
    try:
        response = await read_raw_http_response(reader, timeout=0.5)
    finally:
        writer.close()
        await writer.wait_closed()
    assert response.status == 400
    assert assert_raw_unsigned_response(response) == {
        "error": "invalid_content_length"
    }
    assert not caplog.records


async def test_current_remote_client_round_trips_process_crash_protocol(
    hass: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from custom_components.true_family import reference_journal_remote as remote

    running = await start_strict_service(tmp_path, port=8765)
    client_session = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(
            resolver=LoopbackResolver(),
            use_dns_cache=False,
        )
    )
    monkeypatch.setattr(
        remote,
        "async_get_clientsession",
        lambda _hass: client_session,
    )
    store = None
    try:
        store = await remote.RemoteReferenceJournalStore.async_open(
            hass,
            journal_id=JOURNAL_ID,
            endpoint=remote.RemoteJournalEndpoint(
                full_slug="8c9c720e_true_family_journal",
                boot_id=BOOT_ID,
                hmac_key=KEY.hex(),
            ),
        )
        assert await store.async_load() is None
        root = root_for(JOURNAL_ID, 0, "strict-current-client")
        await store.async_save(root)
        await store.async_replay_save()
        await store.async_barrier()
        assert await store.async_load() == root
    finally:
        if store is not None:
            await store.async_close()
        await client_session.close()
        await running.async_close()


@pytest.mark.parametrize(
    ("body", "expected_error"),
    (
        (
            (
                b'{"client_id":"'
                + CLIENT_ID.encode()
                + b'","client_id":"'
                + CLIENT_ID.encode()
                + b'","nonce":"duplicate"}'
            ),
            "invalid_json",
        ),
        (
            canonical(
                {"client_id": CLIENT_ID, "nonce": "unknown", "unknown": True}
            ),
            "invalid_envelope",
        ),
        (
            b'{"client_id": "' + CLIENT_ID.encode() + b'","nonce":"spaces"}',
            "noncanonical_json",
        ),
        (
            b'{"client_id":"'
            + CLIENT_ID.encode()
            + b'","nonce":NaN}',
            "invalid_json",
        ),
    ),
)
async def test_strict_json_rejects_duplicates_unknown_keys_and_noncanonical_values(
    service: RunningService,
    body: bytes,
    expected_error: str,
) -> None:
    correlation_id = request_id(10 + len(body) % 1000)
    response = await post_raw(service, "/v1/hello", body, correlation_id)
    assert response.status == 400
    _raw, payload = await read_signed_response(
        response,
        "/v1/hello",
        correlation_id,
    )
    assert payload == {"error": expected_error}


async def test_json_depth_and_body_size_are_bounded(service: RunningService) -> None:
    nested: Any = "nonce"
    for _ in range(journal_app.MAX_JSON_DEPTH + 2):
        nested = [nested]
    deep_body = canonical({"client_id": CLIENT_ID, "nonce": nested})
    deep_id = request_id(20)
    response = await post_raw(service, "/v1/hello", deep_body, deep_id)
    assert response.status == 400
    _raw, payload = await read_signed_response(response, "/v1/hello", deep_id)
    assert payload == {"error": "invalid_json"}

    oversized_body = b"x" * (journal_app.MAX_BODY_BYTES + 1)
    oversized_id = request_id(21)
    response = await post_raw(
        service,
        "/v1/hello",
        oversized_body,
        oversized_id,
    )
    assert response.status == 413
    assert await read_unsigned_response(response) == {"error": "body_too_large"}


async def test_root_limit_exactly_preserves_load_response_wire_bound(
    service: RunningService,
) -> None:
    boundary_root = root_with_exact_size(
        JOURNAL_ID,
        0,
        journal_app.MAX_ROOT_BYTES,
    )
    boundary_payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": JOURNAL_ID,
        "root": boundary_root,
    }
    boundary_request = canonical(boundary_payload)
    assert len(boundary_request) <= journal_app.MAX_BODY_BYTES
    save_id = deterministic_save_id(boundary_request)
    response = await post_raw(
        service,
        "/v1/save",
        boundary_request,
        save_id,
    )
    assert response.status == 200
    _save_raw, saved = await read_signed_response(response, "/v1/save", save_id)

    load_id = request_id(23)
    response = await post_json(
        service,
        "/v1/load",
        {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
        load_id,
    )
    assert response.status == 200
    load_raw, loaded = await read_signed_response(response, "/v1/load", load_id)
    assert loaded["root"] == boundary_root
    assert loaded["revision"] == saved["revision"]
    assert len(load_raw) == (
        journal_app.MAX_ROOT_BYTES
        + len(
            canonical(
                {
                    "absent": False,
                    "generation": 0,
                    "revision": saved["revision"],
                    "root": {},
                }
            )
        )
        - 2
    )
    assert len(load_raw) <= journal_app.MAX_BODY_BYTES
    assert (
        journal_app.MAX_ROOT_BYTES + journal_app.MAX_LOAD_RESPONSE_OVERHEAD
        <= journal_app.MAX_BODY_BYTES
    )

    oversized_journal_id = f"{JOURNAL_ID}-oversized"
    oversized_root = root_with_exact_size(
        oversized_journal_id,
        0,
        journal_app.MAX_ROOT_BYTES + 1,
    )
    oversized_payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": oversized_journal_id,
        "root": oversized_root,
    }
    oversized_request = canonical(oversized_payload)
    assert len(oversized_request) <= journal_app.MAX_BODY_BYTES
    oversized_id = deterministic_save_id(oversized_request)
    response = await post_raw(
        service,
        "/v1/save",
        oversized_request,
        oversized_id,
    )
    assert response.status == 413
    _raw, error = await read_signed_response(
        response,
        "/v1/save",
        oversized_id,
    )
    assert error == {"error": "root_too_large"}
    assert await service.state.store.async_load(oversized_journal_id) is None


async def test_absent_provision_save_load_barrier_and_close(
    service: RunningService,
) -> None:
    load_id = request_id(30)
    response = await post_json(
        service,
        "/v1/load",
        {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
        load_id,
    )
    assert response.status == 200
    _raw, absent = await read_signed_response(response, "/v1/load", load_id)
    assert absent == {
        "absent": True,
        "generation": None,
        "revision": None,
        "root": None,
    }

    root, saved = await provision(service, correlation_index=31)
    assert saved["generation"] == 0
    assert re.fullmatch(r"[0-9a-f]{64}", saved["revision"])
    assert re.fullmatch(r"[0-9a-f]{64}", saved["commit_token"])

    load_id = request_id(32)
    response = await post_json(
        service,
        "/v1/load",
        {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
        load_id,
    )
    assert response.status == 200
    _raw, present = await read_signed_response(response, "/v1/load", load_id)
    assert present == {
        "absent": False,
        "generation": 0,
        "revision": saved["revision"],
        "root": root,
    }

    barrier_id = request_id(33)
    response = await post_json(
        service,
        "/v1/barrier",
        {
            "client_id": CLIENT_ID,
            "commit_token": saved["commit_token"],
            "journal_id": JOURNAL_ID,
        },
        barrier_id,
    )
    assert response.status == 200
    _raw, barrier = await read_signed_response(
        response,
        "/v1/barrier",
        barrier_id,
    )
    assert barrier == {"commit_token": saved["commit_token"]}

    unknown_barrier_id = request_id(34)
    response = await post_json(
        service,
        "/v1/barrier",
        {
            "client_id": CLIENT_ID,
            "commit_token": "f" * 64,
            "journal_id": JOURNAL_ID,
        },
        unknown_barrier_id,
    )
    assert response.status == 409
    _raw, error = await read_signed_response(
        response,
        "/v1/barrier",
        unknown_barrier_id,
    )
    assert error == {"error": "unknown_commit_token"}

    close_id = request_id(35)
    response = await post_json(
        service,
        "/v1/close",
        {"client_id": CLIENT_ID},
        close_id,
    )
    assert response.status == 200
    _raw, closed = await read_signed_response(response, "/v1/close", close_id)
    assert closed == {"closed": True}


async def test_stale_generation_and_revision_never_overwrite(
    service: RunningService,
) -> None:
    _root, saved = await provision(service, correlation_index=40)

    stale_generation_id = request_id(41)
    response = await post_json(
        service,
        "/v1/save",
        {
            "client_id": CLIENT_ID,
            "expected_revision": saved["revision"],
            "journal_id": JOURNAL_ID,
            "root": root_for(JOURNAL_ID, 0, "stale-generation"),
        },
        stale_generation_id,
    )
    assert response.status == 409
    _raw, error = await read_signed_response(
        response,
        "/v1/save",
        stale_generation_id,
    )
    assert error == {"error": "stale_generation"}

    stale_revision_id = request_id(42)
    response = await post_json(
        service,
        "/v1/save",
        {
            "client_id": CLIENT_ID,
            "expected_revision": "f" * 64,
            "journal_id": JOURNAL_ID,
            "root": root_for(JOURNAL_ID, 1, "stale-revision"),
        },
        stale_revision_id,
    )
    assert response.status == 409
    _raw, error = await read_signed_response(
        response,
        "/v1/save",
        stale_revision_id,
    )
    assert error == {"error": "stale_revision"}

    future_generation_id = request_id(43)
    response = await post_json(
        service,
        "/v1/save",
        {
            "client_id": CLIENT_ID,
            "expected_revision": saved["revision"],
            "journal_id": JOURNAL_ID,
            "root": root_for(JOURNAL_ID, 2, "future-generation"),
        },
        future_generation_id,
    )
    assert response.status == 409
    _raw, error = await read_signed_response(
        response,
        "/v1/save",
        future_generation_id,
    )
    assert error == {"error": "stale_generation"}

    load_id = request_id(44)
    response = await post_json(
        service,
        "/v1/load",
        {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
        load_id,
    )
    _raw, loaded = await read_signed_response(response, "/v1/load", load_id)
    assert loaded["generation"] == 0
    assert loaded["revision"] == saved["revision"]


async def test_save_request_receipt_replays_and_body_bound_id_rejects_new_digest(
    service: RunningService,
) -> None:
    root = root_for(JOURNAL_ID, 0, "idempotency")
    payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": JOURNAL_ID,
        "root": root,
    }
    correlation_id = deterministic_save_id(canonical(payload))
    first = await post_json(service, "/v1/save", payload, correlation_id)
    assert first.status == 200
    first_raw, first_body = await read_signed_response(
        first,
        "/v1/save",
        correlation_id,
    )

    replay = await post_json(service, "/v1/save", payload, correlation_id)
    assert replay.status == 200
    replay_raw, replay_body = await read_signed_response(
        replay,
        "/v1/save",
        correlation_id,
    )
    assert replay_raw == first_raw
    assert replay_body == first_body

    conflict_payload = {
        **payload,
        "root": root_for(JOURNAL_ID, 0, "different-digest"),
    }
    conflict_body = canonical(conflict_payload)
    conflict = await post_raw(
        service,
        "/v1/save",
        conflict_body,
        correlation_id,
    )
    assert conflict.status == 400
    _raw, error = await read_signed_response(
        conflict,
        "/v1/save",
        correlation_id,
    )
    assert error == {"error": "invalid_save_request_id"}

    next_response = await post_json(
        service,
        "/v1/save",
        {
            "client_id": CLIENT_ID,
            "expected_revision": first_body["revision"],
            "journal_id": JOURNAL_ID,
            "root": root_for(JOURNAL_ID, 1, "later-generation"),
        },
        request_id(51),
    )
    assert next_response.status == 200
    await next_response.read()

    historical_replay = await post_json(
        service,
        "/v1/save",
        payload,
        correlation_id,
    )
    assert historical_replay.status == 200
    historical_raw, _historical_body = await read_signed_response(
        historical_replay,
        "/v1/save",
        correlation_id,
    )
    assert historical_raw == first_raw


async def test_two_clients_racing_one_generation_have_one_winner(
    service: RunningService,
) -> None:
    _root, saved = await provision(service, correlation_index=60)
    first_payload = {
        "client_id": CLIENT_ID,
        "expected_revision": saved["revision"],
        "journal_id": JOURNAL_ID,
        "root": root_for(JOURNAL_ID, 1, "client-one"),
    }
    second_payload = {
        "client_id": OTHER_CLIENT_ID,
        "expected_revision": saved["revision"],
        "journal_id": JOURNAL_ID,
        "root": root_for(JOURNAL_ID, 1, "client-two"),
    }

    first, second = await asyncio.gather(
        post_json(service, "/v1/save", first_payload, request_id(61)),
        post_json(service, "/v1/save", second_payload, request_id(62)),
    )
    assert sorted((first.status, second.status)) == [200, 409]
    await first.read()
    await second.read()

    load_id = request_id(63)
    loaded_response = await post_json(
        service,
        "/v1/load",
        {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
        load_id,
    )
    _raw, loaded = await read_signed_response(
        loaded_response,
        "/v1/load",
        load_id,
    )
    assert loaded["generation"] == 1
    assert loaded["root"]["content"]["marker"] in {"client-one", "client-two"}


async def test_sqlite_process_restart_preserves_exact_root(tmp_path: Path) -> None:
    first = await start_service(tmp_path)
    root, saved = await provision(first, correlation_index=70)
    await first.client.close()

    second_key = bytes.fromhex("33" * 32)
    second_boot = "e" * 32
    second = await start_service(tmp_path, key=second_key, boot_id=second_boot)
    try:
        load_id = request_id(71)
        response = await post_json(
            second,
            "/v1/load",
            {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
            load_id,
        )
        assert response.status == 200
        _raw, loaded = await read_signed_response(
            response,
            "/v1/load",
            load_id,
            key=second_key,
            boot_id=second_boot,
        )
        assert loaded == {
            "absent": False,
            "generation": 0,
            "revision": saved["revision"],
            "root": root,
        }

        old_boot_id = request_id(72)
        old_boot_response = await post_json(
            second,
            "/v1/load",
            {"client_id": CLIENT_ID, "journal_id": JOURNAL_ID},
            old_boot_id,
            key=KEY,
            boot_id=BOOT_ID,
        )
        assert old_boot_response.status == 401
        assert await read_unsigned_response(
            old_boot_response,
            boot_id=second_boot,
        ) == {"error": "authentication_failed"}
    finally:
        await second.client.close()


async def test_response_loss_recovers_from_durable_idempotency_receipt(
    service: RunningService,
) -> None:
    root = root_for(JOURNAL_ID, 0, "response-loss")
    payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": JOURNAL_ID,
        "root": root,
    }
    body = canonical(payload)
    correlation_id = deterministic_save_id(body)
    committed = await service.state.store.async_save(
        journal_id=JOURNAL_ID,
        expected_revision=None,
        root=root,
        request_id=correlation_id,
        request_digest=hashlib.sha256(body).hexdigest(),
    )
    assert committed.replayed is False

    retry = await post_raw(
        service,
        "/v1/save",
        body,
        correlation_id,
    )
    assert retry.status == 200
    retry_raw, _retry_body = await read_signed_response(
        retry,
        "/v1/save",
        correlation_id,
    )
    assert retry_raw == committed.response


async def test_corruption_and_schema_mismatch_fail_startup(tmp_path: Path) -> None:
    corrupt_dir = tmp_path / "corrupt"
    corrupt_dir.mkdir()
    (corrupt_dir / journal_app.DATABASE_NAME).write_bytes(b"not-a-sqlite-database")
    with pytest.raises(journal_app.JournalStoreCorruption):
        await journal_app.SQLiteJournalStore.async_open(corrupt_dir)

    mismatch_dir = tmp_path / "mismatch"
    mismatch_dir.mkdir()
    connection = sqlite3.connect(mismatch_dir / journal_app.DATABASE_NAME)
    connection.execute("PRAGMA user_version=999")
    connection.commit()
    connection.close()
    with pytest.raises(journal_app.JournalStoreSchemaError):
        await journal_app.SQLiteJournalStore.async_open(mismatch_dir)

    old_schema_dir = tmp_path / "old-schema"
    old_schema_dir.mkdir()
    connection = sqlite3.connect(old_schema_dir / journal_app.DATABASE_NAME)
    connection.execute("PRAGMA user_version=2")
    connection.commit()
    connection.close()
    with pytest.raises(journal_app.JournalStoreSchemaError):
        await journal_app.SQLiteJournalStore.async_open(old_schema_dir)

    malformed_dir = tmp_path / "malformed"
    malformed_dir.mkdir()
    connection = sqlite3.connect(malformed_dir / journal_app.DATABASE_NAME)
    connection.execute("CREATE TABLE unexpected (value TEXT)")
    connection.execute("PRAGMA user_version=1")
    connection.commit()
    connection.close()
    with pytest.raises(journal_app.JournalStoreSchemaError):
        await journal_app.SQLiteJournalStore.async_open(malformed_dir)


async def test_schema_v3_and_durability_pragmas_are_exact(tmp_path: Path) -> None:
    store = await journal_app.SQLiteJournalStore.async_open(tmp_path)

    def inspect() -> tuple[dict[str, Any], int, int]:
        connection = store._require_connection()
        pragmas = {
            name: connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in (
                "busy_timeout",
                "foreign_keys",
                "journal_mode",
                "synchronous",
                "user_version",
            )
        }
        objects = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
        foreign_keys = len(
            connection.execute(
                "PRAGMA foreign_key_list(operation_receipts)"
            ).fetchall()
        )
        return pragmas, objects, foreign_keys

    try:
        pragmas, objects, foreign_keys = await store._submit(inspect)
        assert pragmas == {
            "busy_timeout": 5_000,
            "foreign_keys": 1,
            "journal_mode": "wal",
            "synchronous": 2,
            "user_version": 3,
        }
        assert objects == 5
        assert foreign_keys == 1
    finally:
        await store.async_close()


@pytest.mark.parametrize(
    "statement",
    (
        "CREATE TABLE unexpected_table (value TEXT)",
        "CREATE INDEX unexpected_index ON journals(revision)",
        "CREATE VIEW unexpected_view AS SELECT journal_id FROM journals",
        (
            "CREATE TRIGGER unexpected_trigger AFTER INSERT ON journals "
            "BEGIN SELECT 1; END"
        ),
    ),
)
async def test_schema_rejects_extra_table_index_view_or_trigger(
    tmp_path: Path,
    statement: str,
) -> None:
    store = await journal_app.SQLiteJournalStore.async_open(tmp_path)
    await store.async_close()
    connection = sqlite3.connect(tmp_path / journal_app.DATABASE_NAME)
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises(journal_app.JournalStoreSchemaError):
        await journal_app.SQLiteJournalStore.async_open(tmp_path)


@pytest.mark.parametrize("case", ("ddl", "foreign_key"))
async def test_schema_rejects_altered_ddl_or_foreign_key_actions(
    tmp_path: Path,
    case: str,
) -> None:
    journal_sql = journal_app.JOURNAL_TABLE_SQL
    receipt_sql = journal_app.RECEIPT_TABLE_SQL
    if case == "ddl":
        journal_sql = journal_sql.replace("generation >= 0", "generation > -1", 1)
    else:
        receipt_sql = receipt_sql.replace(
            "ON UPDATE RESTRICT ON DELETE RESTRICT",
            "ON UPDATE NO ACTION ON DELETE NO ACTION",
        )
    connection = sqlite3.connect(tmp_path / journal_app.DATABASE_NAME)
    connection.execute(journal_sql)
    connection.execute(receipt_sql)
    connection.execute(journal_app.JOURNAL_TOKEN_INDEX_SQL)
    connection.execute(journal_app.RECEIPT_TOKEN_INDEX_SQL)
    connection.execute(journal_app.RECEIPT_VERSION_INDEX_SQL)
    connection.execute(f"PRAGMA user_version={journal_app.DATABASE_USER_VERSION}")
    connection.commit()
    connection.close()
    with pytest.raises(journal_app.JournalStoreSchemaError):
        await journal_app.SQLiteJournalStore.async_open(tmp_path)


async def persist_two_generations(data_dir: Path) -> None:
    running = await start_service(data_dir)
    try:
        _root, first = await provision(running, correlation_index=120)
        response = await post_json(
            running,
            "/v1/save",
            {
                "client_id": CLIENT_ID,
                "expected_revision": first["revision"],
                "journal_id": JOURNAL_ID,
                "root": root_for(JOURNAL_ID, 1, "generation-one"),
            },
            request_id(121),
        )
        assert response.status == 200
        await response.read()
    finally:
        await running.client.close()


@pytest.mark.parametrize(
    "tamper",
    ("token", "response", "generation"),
)
async def test_receipt_token_response_and_generation_tampering_fail_startup(
    tmp_path: Path,
    tamper: str,
) -> None:
    await persist_two_generations(tmp_path)
    connection = sqlite3.connect(tmp_path / journal_app.DATABASE_NAME)
    row = connection.execute(
        "SELECT commit_token, generation, revision FROM operation_receipts "
        "WHERE journal_id = ? AND generation = 0",
        (JOURNAL_ID,),
    ).fetchone()
    assert row is not None
    token, generation, revision = row
    if tamper == "token":
        replacement = "e" * 64
        assert replacement != token
        connection.execute(
            "UPDATE operation_receipts SET commit_token = ? "
            "WHERE journal_id = ? AND generation = 0",
            (replacement, JOURNAL_ID),
        )
    elif tamper == "response":
        connection.execute(
            "UPDATE operation_receipts SET canonical_response = ? "
            "WHERE journal_id = ? AND generation = 0",
            (
                canonical(
                    {
                        "commit_token": token,
                        "generation": generation + 1,
                        "revision": revision,
                    }
                ),
                JOURNAL_ID,
            ),
        )
    else:
        connection.execute(
            "UPDATE operation_receipts SET generation = 7 "
            "WHERE journal_id = ? AND generation = 0",
            (JOURNAL_ID,),
        )
    connection.commit()
    connection.close()
    with pytest.raises(journal_app.JournalStoreCorruption):
        await journal_app.SQLiteJournalStore.async_open(tmp_path)


@pytest.mark.no_fail_on_log_exception
async def test_receipt_is_revalidated_before_same_request_replay(
    service: RunningService,
) -> None:
    root = root_for(JOURNAL_ID, 0, "runtime-receipt-tamper")
    payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": JOURNAL_ID,
        "root": root,
    }
    correlation_id = deterministic_save_id(canonical(payload))
    first = await post_json(service, "/v1/save", payload, correlation_id)
    assert first.status == 200
    await first.read()

    def tamper() -> None:
        connection = service.state.store._require_connection()
        row = connection.execute(
            "SELECT generation, revision FROM operation_receipts "
            "WHERE request_id = ?",
            (correlation_id,),
        ).fetchone()
        assert row is not None
        fake_token = "e" * 64
        connection.execute(
            "UPDATE operation_receipts SET commit_token = ?, canonical_response = ? "
            "WHERE request_id = ?",
            (
                fake_token,
                canonical(
                    {
                        "commit_token": fake_token,
                        "generation": row[0],
                        "revision": row[1],
                    }
                ),
                correlation_id,
            ),
        )

    await service.state.store._submit(tamper)
    replay = await post_json(service, "/v1/save", payload, correlation_id)
    assert replay.status == 500
    _raw, error = await read_signed_response(
        replay,
        "/v1/save",
        correlation_id,
    )
    assert error == {"error": "storage_failure"}


async def test_ten_thousand_generations_keep_one_bounded_receipt_suffix(
    tmp_path: Path,
) -> None:
    store = await journal_app.SQLiteJournalStore.async_open(tmp_path)

    def write_range(
        start: int,
        stop: int,
        expected_revision: str | None,
    ) -> tuple[str, dict[int, tuple[str, str, str, dict[str, Any]]]]:
        selected: dict[int, tuple[str, str, str, dict[str, Any]]] = {}
        current_revision = expected_revision
        for generation in range(start, stop):
            root = {
                "generation": generation,
                "journal_id": JOURNAL_ID,
                "marker": generation,
            }
            request_body = canonical(
                {
                    "client_id": CLIENT_ID,
                    "expected_revision": current_revision,
                    "journal_id": JOURNAL_ID,
                    "root": root,
                }
            )
            identifier = deterministic_save_id(request_body)
            digest = hashlib.sha256(request_body).hexdigest()
            outcome = store._save_sync(
                JOURNAL_ID,
                current_revision,
                canonical(root),
                generation,
                identifier,
                digest,
            )
            response = json.loads(outcome.response)
            current_revision = response["revision"]
            if generation in {0, stop - 1}:
                selected[generation] = (
                    identifier,
                    digest,
                    response["commit_token"],
                    root,
                )
        assert current_revision is not None
        return current_revision, selected

    def checkpoint_stats() -> tuple[int, int, int, int]:
        connection = store._require_connection()
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (
            0,
            0,
            0,
        )
        count, first_generation, last_generation = connection.execute(
            "SELECT count(*), min(generation), max(generation) "
            "FROM operation_receipts WHERE journal_id = ?",
            (JOURNAL_ID,),
        ).fetchone()
        return count, first_generation, last_generation, connection.execute(
            "PRAGMA page_size"
        ).fetchone()[0]

    try:
        revision, first_records = await store._submit(write_range, 0, 5_000, None)
        first_stats = await store._submit(checkpoint_stats)
        first_size = store.database_path.stat().st_size
        assert first_stats[:3] == (4_096, 904, 4_999)

        revision, second_records = await store._submit(
            write_range,
            5_000,
            10_000,
            revision,
        )
        second_stats = await store._submit(checkpoint_stats)
        second_size = store.database_path.stat().st_size
        assert second_stats[:3] == (4_096, 5_904, 9_999)
        assert second_size <= first_size + (second_stats[3] * 64)
        assert second_size < 16 * 1024 * 1024

        old_id, old_digest, old_token, old_root = first_records[0]
        changed_body = canonical(
            {
                "client_id": CLIENT_ID,
                "expected_revision": None,
                "journal_id": JOURNAL_ID,
                "root": {**old_root, "marker": "changed-after-prune"},
            }
        )
        assert deterministic_save_id(changed_body) != old_id
        protocol_state = journal_app.JournalServerState(
            store,
            key=KEY,
            boot_id=BOOT_ID,
        )
        changed_response = await journal_app._process_signed_request(
            protocol_state,
            method="POST",
            path="/v1/save",
            boot_id=BOOT_ID,
            request_id=old_id,
            signature=request_signature(
                KEY,
                "POST",
                "/v1/save",
                BOOT_ID,
                old_id,
                changed_body,
            ),
            body=changed_body,
        )
        assert changed_response.status == 400
        assert changed_response.request_id == old_id
        assert json.loads(changed_response.body) == {
            "error": "invalid_save_request_id"
        }

        with pytest.raises(journal_app.JournalStoreConflict) as pruned_replay:
            await store.async_save(
                journal_id=JOURNAL_ID,
                expected_revision=None,
                root=old_root,
                request_id=old_id,
                request_digest=old_digest,
            )
        assert pruned_replay.value.code == "stale_generation"
        with pytest.raises(journal_app.JournalStoreConflict) as pruned_barrier:
            await store.async_barrier(JOURNAL_ID, old_token)
        assert pruned_barrier.value.code == "unknown_commit_token"

        latest_id, latest_digest, latest_token, latest_root = second_records[9_999]
        replay = await store.async_save(
            journal_id=JOURNAL_ID,
            expected_revision=revision,
            root=latest_root,
            request_id=latest_id,
            request_digest=latest_digest,
        )
        assert replay.replayed is True
        await store.async_barrier(JOURNAL_ID, latest_token)
    finally:
        await store.async_close()

    reopened = await journal_app.SQLiteJournalStore.async_open(tmp_path)
    try:
        loaded = await reopened.async_load(JOURNAL_ID)
        assert loaded is not None
        assert loaded.generation == 9_999
    finally:
        await reopened.async_close()


def test_sigkill_after_commit_reopens_wal_and_replays_exact_receipt(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "commit-crash"
    data_dir.mkdir()
    root = root_for(JOURNAL_ID, 0, "sigkill-after-commit")
    payload = {
        "client_id": CLIENT_ID,
        "expected_revision": None,
        "journal_id": JOURNAL_ID,
        "root": root,
    }
    body = canonical(payload)
    identifier = request_id(30_000)
    digest = hashlib.sha256(body).hexdigest()
    token = journal_app._commit_token(identifier, digest)
    expected_response = canonical(
        {
            "commit_token": token,
            "generation": 0,
            "revision": hashlib.sha256(canonical(root)).hexdigest(),
        }
    )
    read_fd, write_fd = os.pipe()
    script = CHILD_SERVER_IMPORT + r"""
import asyncio
import json
import os
import signal

async def run():
    store = await journal_app.SQLiteJournalStore.async_open(Path(sys.argv[2]))
    root = json.loads(sys.argv[3])
    outcome = await store.async_save(
        journal_id=root["journal_id"],
        expected_revision=None,
        root=root,
        request_id=sys.argv[4],
        request_digest=sys.argv[5],
    )
    assert outcome.response.hex() == sys.argv[6]
    os.write(int(sys.argv[7]), b"C")
    signal.pause()

asyncio.run(run())
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(SERVER_PATH),
            str(data_dir),
            json.dumps(root, separators=(",", ":"), sort_keys=True),
            identifier,
            digest,
            expected_response.hex(),
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    try:
        assert read_child_pipe(read_fd, suffix=b"C") == b"C"
        wal_path = Path(f"{data_dir / journal_app.DATABASE_NAME}-wal")
        assert wal_path.exists()
        assert wal_path.stat().st_size > 0
        process.send_signal(signal.SIGKILL)
        assert process.wait(timeout=10) == -signal.SIGKILL
    finally:
        os.close(read_fd)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    reopen_script = CHILD_SERVER_IMPORT + r"""
import asyncio
import json

async def run():
    store = await journal_app.SQLiteJournalStore.async_open(Path(sys.argv[2]))
    root = json.loads(sys.argv[3])
    loaded = await store.async_load(root["journal_id"])
    assert loaded is not None and loaded.root == root and loaded.generation == 0
    outcome = await store.async_save(
        journal_id=root["journal_id"],
        expected_revision=None,
        root=root,
        request_id=sys.argv[4],
        request_digest=sys.argv[5],
    )
    assert outcome.replayed is True
    assert outcome.response.hex() == sys.argv[6]
    await store.async_barrier(root["journal_id"], sys.argv[7])
    await store.async_close()
    print(json.dumps({"generation": loaded.generation, "root": loaded.root}, sort_keys=True))

asyncio.run(run())
"""
    reopened = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            reopen_script,
            str(SERVER_PATH),
            str(data_dir),
            json.dumps(root, separators=(",", ":"), sort_keys=True),
            identifier,
            digest,
            expected_response.hex(),
            token,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert json.loads(reopened.stdout) == {"generation": 0, "root": root}


def test_sigkill_during_accepted_partial_request_reopens_cleanly(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "accepted-crash"
    data_dir.mkdir()
    read_fd, write_fd = os.pipe()
    script = CHILD_SERVER_IMPORT + r"""
import asyncio
import os

async def run():
    event_fd = int(sys.argv[3])
    state = await journal_app.JournalServerState.async_create(
        Path(sys.argv[2]),
        key=bytes.fromhex("11" * 32),
        boot_id="a" * 32,
    )
    listener = journal_app.StrictHttpServer(
        state,
        connection_started=lambda: os.write(event_fd, b"A"),
    )
    await listener.async_start("127.0.0.1", 0)
    os.write(event_fd, f"P{listener.port}\n".encode("ascii"))
    await asyncio.Event().wait()

asyncio.run(run())
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(SERVER_PATH),
            str(data_dir),
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    client_socket: socket.socket | None = None
    try:
        port_report = read_child_pipe(read_fd, suffix=b"\n")
        assert port_report.startswith(b"P")
        port = int(port_report[1:-1])
        client_socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        client_socket.sendall(b"POST /v1/hello HTTP/1.1\r\nHost: partial")
        assert read_child_pipe(read_fd, suffix=b"A") == b"A"
        process.send_signal(signal.SIGKILL)
        assert process.wait(timeout=10) == -signal.SIGKILL
    finally:
        if client_socket is not None:
            client_socket.close()
        os.close(read_fd)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    inspect_script = CHILD_SERVER_IMPORT + r"""
import asyncio

async def run():
    store = await journal_app.SQLiteJournalStore.async_open(Path(sys.argv[2]))
    assert await store.async_load("true-family-reference-journal-companion-test") is None
    await store.async_close()

asyncio.run(run())
"""
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            inspect_script,
            str(SERVER_PATH),
            str(data_dir),
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )


def test_nonreading_max_load_cap_and_sigterm_cold_checkpoint(tmp_path: Path) -> None:
    data_dir = tmp_path / "cold-stop-process"
    data_dir.mkdir()
    read_fd, write_fd = os.pipe()
    script = CHILD_SERVER_IMPORT + r"""
import asyncio
import hashlib
import os

async def run():
    event_fd = int(sys.argv[3])
    state = await journal_app.JournalServerState.async_create(
        Path(sys.argv[2]),
        key=bytes.fromhex("11" * 32),
        boot_id="a" * 32,
    )
    root = {
        "generation": 0,
        "journal_id": "true-family-reference-journal-companion-test",
        "padding": "",
    }
    root["padding"] = "x" * (
        journal_app.MAX_ROOT_BYTES - len(journal_app.canonical_json(root))
    )
    assert len(journal_app.canonical_json(root)) == journal_app.MAX_ROOT_BYTES
    await state.store.async_save(
        journal_id=root["journal_id"],
        expected_revision=None,
        root=root,
        request_id="tfj-00000000000000000000000000007918",
        request_digest=hashlib.sha256(journal_app.canonical_json(root)).hexdigest(),
    )
    listener = journal_app.StrictHttpServer(
        state,
        response_started=lambda response: (
            os.write(event_fd, b"W")
            if response.status == 200 and len(response.body) > journal_app.MAX_ROOT_BYTES
            else None
        ),
    )

    class ReadyDiscovery:
        async def async_replace(self, _config):
            os.write(event_fd, f"P{listener.port}\n".encode("ascii"))

    await journal_app.async_run_service(
        state,
        listener,
        ReadyDiscovery(),
        internal_host="8c9c720e-true-family-journal",
        bind_host="127.0.0.1",
        port=0,
    )
    os.write(event_fd, b"D")

asyncio.run(run())
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(SERVER_PATH),
            str(data_dir),
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    clients: list[socket.socket] = []
    overflow: socket.socket | None = None
    try:
        port_report = read_child_pipe(read_fd, suffix=b"\n")
        assert port_report.startswith(b"P")
        port = int(port_report[1:-1])
        load_body = canonical({"client_id": CLIENT_ID, "journal_id": JOURNAL_ID})
        for index in range(journal_app.MAX_ACCEPTED_CONNECTIONS):
            identifier = request_id(40_000 + index)
            signature = request_signature(
                KEY,
                "POST",
                "/v1/load",
                BOOT_ID,
                identifier,
                load_body,
            )
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1_024)
            client.settimeout(5)
            client.connect(("127.0.0.1", port))
            client.sendall(
                (
                    "POST /v1/load HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(load_body)}\r\n"
                    f"X-True-Family-Boot-ID: {BOOT_ID}\r\n"
                    f"X-True-Family-Request-ID: {identifier}\r\n"
                    f"X-True-Family-Signature: {signature}\r\n\r\n"
                ).encode("ascii")
                + load_body
            )
            clients.append(client)
        assert read_child_pipe(
            read_fd,
            suffix=b"W" * journal_app.MAX_ACCEPTED_CONNECTIONS,
        ) == b"W" * journal_app.MAX_ACCEPTED_CONNECTIONS

        overflow = socket.create_connection(("127.0.0.1", port), timeout=5)
        overflow.settimeout(5)
        overflow_response = bytearray()
        while b"\r\n\r\n" not in overflow_response or not overflow_response.endswith(
            b"}"
        ):
            chunk = overflow.recv(4_096)
            assert chunk
            overflow_response.extend(chunk)
        assert overflow_response.startswith(b"HTTP/1.1 503 Service Unavailable\r\n")
        assert BOOT_ID.encode("ascii") not in overflow_response

        shutdown_started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        assert read_child_pipe(read_fd, suffix=b"D", timeout=20) == b"D"
        assert process.wait(timeout=20) == 0
        assert time.monotonic() - shutdown_started < 8
    finally:
        for client in clients:
            client.close()
        if overflow is not None:
            overflow.close()
        os.close(read_fd)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    database_path = data_dir / journal_app.DATABASE_NAME
    wal_path = Path(f"{database_path}-wal")
    assert not wal_path.exists() or wal_path.stat().st_size == 0
    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute(
            "SELECT length(canonical_root), generation FROM journals "
            "WHERE journal_id = ?",
            (JOURNAL_ID,),
        ).fetchone() == (journal_app.MAX_ROOT_BYTES, 0)
    finally:
        connection.close()


def test_sigterm_during_hung_discovery_cancels_and_checkpoints(tmp_path: Path) -> None:
    data_dir = tmp_path / "hung-discovery-stop"
    data_dir.mkdir()
    read_fd, write_fd = os.pipe()
    script = CHILD_SERVER_IMPORT + r"""
import asyncio
import hashlib
import os

async def run():
    event_fd = int(sys.argv[3])
    state = await journal_app.JournalServerState.async_create(
        Path(sys.argv[2]),
        key=bytes.fromhex("11" * 32),
        boot_id="a" * 32,
    )
    root = {
        "generation": 0,
        "journal_id": "true-family-reference-journal-companion-test",
        "marker": "hung-discovery",
    }
    await state.store.async_save(
        journal_id=root["journal_id"],
        expected_revision=None,
        root=root,
        request_id="tfj-00000000000000000000000000007a18",
        request_digest=hashlib.sha256(journal_app.canonical_json(root)).hexdigest(),
    )
    listener = journal_app.StrictHttpServer(state)

    class HangingDiscovery:
        async def async_replace(self, _config):
            os.write(event_fd, b"H")
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                os.write(event_fd, b"C")
                raise

    await journal_app.async_run_service(
        state,
        listener,
        HangingDiscovery(),
        internal_host="8c9c720e-true-family-journal",
        bind_host="127.0.0.1",
        port=0,
    )
    os.write(event_fd, b"D")

asyncio.run(run())
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(SERVER_PATH),
            str(data_dir),
            str(write_fd),
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    try:
        assert read_child_pipe(read_fd, suffix=b"H") == b"H"
        process.send_signal(signal.SIGTERM)
        assert read_child_pipe(read_fd, suffix=b"D", timeout=20) == b"CD"
        assert process.wait(timeout=20) == 0
    finally:
        os.close(read_fd)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    database_path = data_dir / journal_app.DATABASE_NAME
    wal_path = Path(f"{database_path}-wal")
    assert not wal_path.exists() or wal_path.stat().st_size == 0
    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute(
            "SELECT generation FROM journals WHERE journal_id = ?",
            (JOURNAL_ID,),
        ).fetchone() == (0,)
    finally:
        connection.close()


async def wait_for_thread_event(event: threading.Event) -> None:
    for _ in range(2_000):
        if event.is_set():
            return
        await asyncio.sleep(0.001)
    raise AssertionError("The SQLite worker did not reach the test gate.")


async def test_cancelled_save_drains_worker_while_event_loop_keeps_heartbeat(
    tmp_path: Path,
) -> None:
    store = await journal_app.SQLiteJournalStore.async_open(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_save = store._save_sync

    def blocked_save(*args: Any):
        entered.set()
        if not release.wait(timeout=5):
            raise TimeoutError("The SQLite worker test gate timed out.")
        return original_save(*args)

    store._save_sync = blocked_save
    root = root_for(JOURNAL_ID, 0, "cancelled-save")
    body = canonical(
        {
            "client_id": CLIENT_ID,
            "expected_revision": None,
            "journal_id": JOURNAL_ID,
            "root": root,
        }
    )
    beats = 0
    heartbeat_running = True

    async def heartbeat() -> None:
        nonlocal beats
        while heartbeat_running:
            beats += 1
            await asyncio.sleep(0)

    heartbeat_task = asyncio.create_task(heartbeat())
    saving = asyncio.create_task(
        store.async_save(
            journal_id=JOURNAL_ID,
            expected_revision=None,
            root=root,
            request_id=request_id(90),
            request_digest=hashlib.sha256(body).hexdigest(),
        )
    )
    try:
        await wait_for_thread_event(entered)
        saving.cancel()
        await asyncio.sleep(0)
        saving.cancel()
        await asyncio.sleep(0.03)
        assert beats > 10
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await saving
        loaded = await store.async_load(JOURNAL_ID)
        assert loaded is not None
        assert loaded.root == root
    finally:
        release.set()
        heartbeat_running = False
        await heartbeat_task
        await store.async_close()


async def test_cancelled_close_drains_and_is_idempotent(tmp_path: Path) -> None:
    store = await journal_app.SQLiteJournalStore.async_open(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_close = store._close_sync

    def blocked_close() -> None:
        entered.set()
        if not release.wait(timeout=5):
            raise TimeoutError("The SQLite close test gate timed out.")
        original_close()

    store._close_sync = blocked_close
    closing = asyncio.create_task(store.async_close())
    await wait_for_thread_event(entered)
    closing.cancel()
    await asyncio.sleep(0)
    closing.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert store._closed is True
    await store.async_close()


async def test_cold_stop_waits_for_checkpoint_and_closed_database(
    tmp_path: Path,
) -> None:
    running = await start_service(tmp_path)
    root, _saved = await provision(running, correlation_index=130)
    entered = threading.Event()
    release = threading.Event()
    original_close = running.state.store._close_sync

    def gated_close() -> None:
        entered.set()
        if not release.wait(timeout=5):
            raise TimeoutError("The cold-stop checkpoint gate timed out.")
        original_close()

    running.state.store._close_sync = gated_close
    stopping = asyncio.create_task(running.client.close())
    await wait_for_thread_event(entered)
    await asyncio.sleep(0)
    assert stopping.done() is False
    assert running.state.store._closed is False
    release.set()
    await stopping

    database_path = tmp_path / journal_app.DATABASE_NAME
    wal_path = Path(f"{database_path}-wal")
    assert running.state.store._closed is True
    assert running.state.store._connection is None
    assert not wal_path.exists() or wal_path.stat().st_size == 0
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            "SELECT canonical_root FROM journals WHERE journal_id = ?",
            (JOURNAL_ID,),
        ).fetchone()
        assert row == (canonical(root),)
    finally:
        connection.close()


async def test_discovery_replaces_stale_uuid_and_never_logs_key_or_payload(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    marker = tmp_path / journal_app.DISCOVERY_UUID_NAME
    marker.write_text("stale-discovery-uuid\n", encoding="ascii")
    events: list[tuple[str, Any]] = []

    async def delete_discovery(request: web.Request) -> web.Response:
        events.append(
            (
                "delete",
                (
                    request.match_info["uuid"],
                    request.headers.get("Authorization"),
                ),
            )
        )
        return web.json_response({"result": "ok"})

    async def post_discovery(request: web.Request) -> web.Response:
        events.append(
            (
                "post",
                (await request.json(), request.headers.get("Authorization")),
            )
        )
        return web.json_response(
            {"data": {"uuid": "replacement-discovery-uuid"}, "result": "ok"}
        )

    supervisor_app = web.Application()
    supervisor_app.router.add_delete(
        "/discovery/{uuid}",
        delete_discovery,
    )
    supervisor_app.router.add_post("/discovery", post_discovery)
    supervisor = TestServer(supervisor_app)
    await supervisor.start_server()

    state = await journal_app.JournalServerState.async_create(tmp_path)
    with pytest.raises(journal_app.SupervisorDiscoveryError):
        state.discovery_config("local-true-family-journal")
    config = state.discovery_config("8c9c720e-true-family-journal")
    key_hex = state.key_hex
    caplog.set_level(logging.INFO, logger="true_family_journal")
    try:
        client = journal_app.SupervisorDiscovery(
            tmp_path,
            token="supervisor-test-token",
            base_url=str(supervisor.make_url("/")).rstrip("/"),
        )
        discovered = await client.async_replace(config)
    finally:
        await state.async_close()
        await supervisor.close()

    assert discovered == "replacement-discovery-uuid"
    assert [event[0] for event in events] == ["delete", "post"]
    assert events[0][1] == (
        "stale-discovery-uuid",
        "Bearer supervisor-test-token",
    )
    posted, authorization = events[1][1]
    assert authorization == "Bearer supervisor-test-token"
    assert posted == {"config": config, "service": "true_family"}
    assert marker.read_text(encoding="ascii") == "replacement-discovery-uuid\n"
    assert re.fullmatch(r"[0-9a-f]{64}", key_hex)
    assert re.fullmatch(r"[0-9a-f]{32}", config["boot_id"])
    rendered_logs = "\n".join(record.getMessage() for record in caplog.records)
    assert key_hex not in rendered_logs
    assert json.dumps(config, sort_keys=True) not in rendered_logs


async def test_discovery_failure_redacts_supervisor_response(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_key = "9" * 64

    async def reject_discovery(_request: web.Request) -> web.Response:
        return web.Response(status=500, text=f"rejected config key={secret_key}")

    supervisor_app = web.Application()
    supervisor_app.router.add_post("/discovery", reject_discovery)
    supervisor = TestServer(supervisor_app)
    await supervisor.start_server()
    caplog.set_level(logging.INFO, logger="true_family_journal")
    client = journal_app.SupervisorDiscovery(
        tmp_path,
        token="supervisor-test-token",
        base_url=str(supervisor.make_url("/")).rstrip("/"),
    )
    try:
        with pytest.raises(journal_app.SupervisorDiscoveryError) as raised:
            await client.async_replace(
                {
                    "boot_id": BOOT_ID,
                    "host": "true-family-journal",
                    "key": secret_key,
                    "port": 8765,
                    "protocol": "true-family-journal-v1",
                }
            )
    finally:
        await supervisor.close()

    assert secret_key not in str(raised.value)
    assert secret_key not in "\n".join(
        record.getMessage() for record in caplog.records
    )


async def test_process_state_rotates_key_and_boot_without_persisting_them(
    tmp_path: Path,
) -> None:
    first = await journal_app.JournalServerState.async_create(tmp_path)
    first_key = first.key_hex
    first_boot = first.boot_id
    await first.async_close()

    second = await journal_app.JournalServerState.async_create(tmp_path)
    try:
        assert second.key_hex != first_key
        assert second.boot_id != first_boot
        assert re.fullmatch(r"[0-9a-f]{64}", second.key_hex)
        assert re.fullmatch(r"[0-9a-f]{32}", second.boot_id)
        database_bytes = (tmp_path / journal_app.DATABASE_NAME).read_bytes()
        assert first_key.encode("ascii") not in database_bytes
        assert second.key_hex.encode("ascii") not in database_bytes
    finally:
        await second.async_close()
