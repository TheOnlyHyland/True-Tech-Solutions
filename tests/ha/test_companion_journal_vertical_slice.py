"""Production vertical slice from Supervisor discovery through companion SQLite."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
import importlib.util
import logging
from pathlib import Path
import shutil
import socket
import sys
import threading
from typing import Any
from unittest.mock import patch

import aiohttp
from aiohttp import web
from homeassistant.config_entries import ConfigEntryState, SOURCE_HASSIO, SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.service_info.hassio import HassioServiceInfo
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import true_family as true_family_integration
from custom_components.true_family import reference_journal_discovery as discovery
from custom_components.true_family import reference_journal_remote as remote
from custom_components.true_family import reference_migration as migration
from custom_components.true_family import reference_migration_ha as journal_ha
from custom_components.true_family.const import (
    CONF_BASE_TOPIC,
    CONF_REFERENCE_JOURNAL_ID,
    CONF_ROOMS,
    DEFAULT_BASE_TOPIC,
    DOMAIN,
)
from custom_components.true_family.models import default_rooms, rooms_as_dict


pytestmark = pytest.mark.enable_socket

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = PROJECT_ROOT / "true_family_journal" / "server.py"
MODULE_NAME = "true_family_companion_vertical_slice_server"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, SERVER_PATH)
assert SPEC is not None and SPEC.loader is not None
journal_app = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = journal_app
SPEC.loader.exec_module(journal_app)

APP_SLUG = "8c9c720e_true_family_journal"
APP_HOST = "8c9c720e-true-family-journal"
APP_NAME = "True Family Journal"
PORT = 8765
PLAN_ONE = f"tf-reference-{'1' * 24}"
PLAN_TWO = f"tf-reference-{'2' * 24}"


@pytest.fixture(autouse=True)
def enable_loopback_test_server(socket_enabled: None) -> None:
    """Re-enable loopback after the Home Assistant harness socket guard."""


class SlugLoopbackResolver(aiohttp.abc.AbstractResolver):
    """Resolve only the validated slug-derived App hostname to loopback."""

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        assert host == APP_HOST
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


@dataclass(slots=True)
class RunningJournalApp:
    """One actual companion App process-state hosted by the test loop."""

    state: Any
    runner: web.AppRunner

    async def async_stop(self) -> None:
        await self.runner.cleanup()


async def start_journal_app(data_dir: Path) -> RunningJournalApp:
    """Start the real server on its fixed internal port with real SQLite data."""

    state = await journal_app.JournalServerState.async_create(data_dir)
    runner = web.AppRunner(
        journal_app.create_web_application(state),
        access_log=None,
    )
    await runner.setup()
    try:
        await web.TCPSite(runner, "127.0.0.1", PORT).start()
    except BaseException:
        await runner.cleanup()
        raise
    return RunningJournalApp(state=state, runner=runner)


def new_shared_session() -> aiohttp.ClientSession:
    """Create HA's test shared session with only private-host DNS redirected."""

    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(
            resolver=SlugLoopbackResolver(),
            use_dns_cache=False,
        )
    )


def service_info(state: Any, *, config_updates: dict[str, Any] | None = None):
    """Build the actual App's Supervisor discovery payload for one boot."""

    config = state.discovery_config(APP_HOST)
    if config_updates:
        config.update(config_updates)
    return HassioServiceInfo(
        config=config,
        name=APP_NAME,
        slug=APP_SLUG,
        uuid=f"journal-{state.boot_id}",
    )


async def discover(hass: HomeAssistant, state: Any) -> None:
    """Run the integration's real Hassio config-flow step."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_HASSIO},
        data=service_info(state),
    )
    assert result["type"] == "abort"
    assert result["reason"] == "journal_app_discovered"


def next_root(
    current: dict[str, Any],
    plan_id: str,
) -> dict[str, Any]:
    """Build one distinct, fully valid next-generation schema-v4 root."""

    content = deepcopy(current["content"])
    content["states"][plan_id] = {
        "state": migration.MigrationState.PLANNED.value,
        "reason": None,
    }
    return journal_ha._build_root(
        current["journal_id"],
        current["generation"] + 1,
        content,
    )


async def test_production_client_auto_reloads_after_rekey_during_active_work(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    mqtt_mock,
    tmp_path: Path,
    production_reference_journal_backend: None,
) -> None:
    """Defer one rekey during work, then reload automatically and enforce CAS."""

    running = await start_journal_app(tmp_path)
    first_boot = running.state.boot_id
    first_key = running.state.key_hex
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    entry = None
    active_work: asyncio.Task[None] | None = None
    work_release = threading.Event()
    try:
        await discover(hass, running.state)
        endpoint = discovery.get_reference_journal_endpoint(hass)
        assert endpoint is not None
        assert endpoint.hostname == APP_HOST
        assert first_key not in repr(endpoint)

        user_flow = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
        )
        created = await hass.config_entries.flow.async_configure(
            user_flow["flow_id"],
            {CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC},
        )
        assert created["type"] == "create_entry"
        entry = created["result"]
        journal_id = entry.data[CONF_REFERENCE_JOURNAL_ID]
        assert first_key not in repr(entry.data)
        assert set(entry.data) == {
            CONF_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID,
            CONF_ROOMS,
        }
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        initial_adapter = entry.runtime_data.reference_journal
        assert initial_adapter._root == journal_ha.empty_reference_journal_data(
            journal_id
        )
        initial_proof = initial_adapter._durability_barrier.durability_proof
        assert initial_proof is not None
        assert initial_proof.guarantee == "sqlite-wal-full-process-crash-cas/v1"
        assert initial_adapter.durability_scope is (
            journal_ha.ReferenceJournalDurabilityScope.PROCESS_CRASH_ONLY
        )
        assert not initial_adapter.host_mutation_authorized
        assert await hass.config_entries.async_unload(entry.entry_id)

        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=journal_id,
        )
        initial_record = await running.state.store.async_load(journal_id)
        assert initial_record is not None
        assert initial_record.generation == 0
        assert initial_record.root == journal_ha.empty_reference_journal_data(
            journal_id
        )

        adapter = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
        )
        assert adapter._store is adapter._durability_barrier
        durability_proof = adapter._durability_barrier.durability_proof
        assert durability_proof is not None
        assert durability_proof.guarantee == (
            "sqlite-wal-full-process-crash-cas/v1"
        )
        await adapter.async_run(
            adapter.set_state,
            PLAN_ONE,
            migration.MigrationState.PLANNED,
        )
        assert adapter._root["generation"] == 1
        await adapter.async_close()

        mutated_record = await running.state.store.async_load(journal_id)
        assert mutated_record is not None
        assert mutated_record.generation == 1
        assert mutated_record.root["content"]["states"][PLAN_ONE] == {
            "reason": None,
            "state": migration.MigrationState.PLANNED.value,
        }

        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert first_key not in repr(entry.runtime_data)
        runtime_before_rekey = entry.runtime_data
        work_entered = threading.Event()

        def hold_active_work() -> None:
            work_entered.set()
            if not work_release.wait(timeout=5):
                raise TimeoutError("active journal work was not released")

        active_work = asyncio.create_task(
            runtime_before_rekey.reference_journal.async_run(hold_active_work)
        )
        assert await hass.async_add_executor_job(work_entered.wait, 5)

        await running.async_stop()
        running = await start_journal_app(tmp_path)
        assert running.state.boot_id != first_boot
        assert running.state.key_hex != first_key

        schedule_reload = hass.config_entries.async_schedule_reload
        with patch.object(
            hass.config_entries,
            "async_schedule_reload",
            wraps=schedule_reload,
        ) as schedule:
            await discover(hass, running.state)
            schedule.assert_not_called()
            assert discovery.reference_journal_reload_is_pending(
                hass,
                entry.entry_id,
            )

            work_release.set()
            await active_work
            await hass.async_block_till_done()

        schedule.assert_called_once_with(entry.entry_id)
        assert not discovery.reference_journal_reload_is_pending(
            hass,
            entry.entry_id,
        )
        assert len(hass.config_entries.async_entries(DOMAIN)) == 1
        assert entry.state is ConfigEntryState.LOADED
        assert entry.runtime_data is not runtime_before_rekey
        assert entry.runtime_data.reference_journal._root["generation"] == 1
        assert (
            entry.runtime_data.reference_journal._store.endpoint
            == discovery.get_reference_journal_endpoint(hass)
        )
        assert (
            entry.runtime_data.reference_journal._store.endpoint.boot_id
            == running.state.boot_id
        )
        assert first_key not in repr(entry.data)
        assert await hass.config_entries.async_unload(entry.entry_id)

        first = await journal_ha._new_store(hass, journal_id)
        second = await journal_ha._new_store(hass, journal_id)
        try:
            first_root = await first.async_load()
            second_root = await second.async_load()
            assert first_root is not None
            assert second_root is not None
            assert first_root == second_root == mutated_record.root
            await first.async_save(next_root(first_root, PLAN_TWO))
            await first.async_barrier()
            with pytest.raises(remote.RemoteJournalConflictError) as conflict:
                await second.async_save(next_root(second_root, "tf-reference-" + "3" * 24))
            normalized = journal_ha._normalized_backend_error(conflict.value)
            assert isinstance(normalized, journal_ha.ReferenceJournalConflictError)
        finally:
            await first.async_close()
            await second.async_close()

        reopened = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
        )
        assert reopened._root["generation"] == 2
        assert PLAN_TWO in reopened._root["content"]["states"]
        await reopened.async_close()
    finally:
        work_release.set()
        if active_work is not None and not active_work.done():
            try:
                await active_work
            except BaseException:
                pass
        if entry is not None and entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
        await running.async_stop()
        await session.close()


async def test_process_crash_remote_persists_schema_four_but_blocks_host_mutation(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    production_reference_journal_backend: None,
) -> None:
    """Keep remote journal storage usable without granting mutation authority."""

    running = await start_journal_app(tmp_path)
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    journal = None
    try:
        await discover(hass, running.state)
        journal_id = "process-crash-scope-journal"
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=journal_id,
        )
        journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
        )
        assert journal.durability_scope is (
            journal_ha.ReferenceJournalDurabilityScope.PROCESS_CRASH_ONLY
        )
        assert not journal.host_mutation_authorized

        await journal.async_run(
            journal.set_state,
            PLAN_ONE,
            migration.MigrationState.PLANNED,
        )
        await journal.async_close()
        journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
        )
        assert await journal.async_run(journal.state, PLAN_ONE) == (
            migration.MigrationState.PLANNED,
            None,
        )
        before = await running.state.store.async_load(journal_id)
        assert before is not None and before.generation == 1

        invalid: Any = object()
        blocked_operations = (
            lambda: journal.append_attempt(invalid),
            lambda: journal.record_original(PLAN_ONE, invalid, "0" * 64),
            lambda: journal.arm_operation("unrecorded-operation", invalid),
            lambda: journal.set_attempt_state(
                PLAN_ONE,
                1,
                journal_ha.BridgeAttemptState.COMMITTED,
            ),
            lambda: journal.set_state(
                PLAN_ONE,
                migration.MigrationState.APPLYING,
            ),
            lambda: journal.record_completion(invalid),
        )
        for operation in blocked_operations:
            with pytest.raises(
                journal_ha.ReferenceJournalDurabilityError,
                match="does not authorize host mutation",
            ):
                await journal.async_run(operation)

        after = await running.state.store.async_load(journal_id)
        assert after == before
        await journal.async_run(
            journal.set_state,
            PLAN_TWO,
            migration.MigrationState.PLANNED,
        )
        final = await running.state.store.async_load(journal_id)
        assert final is not None and final.generation == 2
    finally:
        if journal is not None:
            await journal.async_close()
        await running.async_stop()
        await session.close()


async def test_app_unavailable_is_retryable_for_user_flow_and_entry_setup(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    production_reference_journal_backend: None,
) -> None:
    """Map a discovered but stopped App to form retry and ConfigEntryNotReady."""

    running = await start_journal_app(tmp_path)
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    await discover(hass, running.state)
    endpoint = discovery.get_reference_journal_endpoint(hass)
    assert endpoint is not None
    secret = running.state.key_hex
    await running.async_stop()
    try:
        user_flow = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
        )
        retry = await hass.config_entries.flow.async_configure(
            user_flow["flow_id"],
            {CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC},
        )
        assert retry["type"] == "form"
        assert retry["errors"] == {"base": "journal_durability_unavailable"}
        assert hass.config_entries.async_entries(DOMAIN) == []

        with pytest.raises(journal_ha.ReferenceJournalIOError) as unavailable:
            await journal_ha.async_provision_reference_journal(
                hass,
                journal_id="unavailable-companion-journal",
            )
        assert secret not in str(unavailable.value)
        assert APP_HOST not in str(unavailable.value)

        entry = MockConfigEntry(
            domain=DOMAIN,
            data={
                CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
                CONF_REFERENCE_JOURNAL_ID: "unavailable-companion-journal",
                CONF_ROOMS: rooms_as_dict(default_rooms()),
            },
        )
        with pytest.raises(ConfigEntryNotReady) as not_ready:
            await true_family_integration.async_setup_entry(hass, entry)
        assert str(not_ready.value) == (
            "Reference journal storage is temporarily unavailable."
        )
        assert secret not in repr(not_ready.value)
    finally:
        await session.close()


async def test_fresh_discovery_wakes_setup_retry_after_app_generation_change(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    mqtt_mock,
    tmp_path: Path,
    production_reference_journal_backend: None,
) -> None:
    """Cancel setup backoff and load immediately with the fresh in-memory key."""

    running = await start_journal_app(tmp_path)
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    entry = None
    try:
        await discover(hass, running.state)
        journal_id = "setup-retry-generation-journal"
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=journal_id,
        )
        old_boot_id = running.state.boot_id
        old_key = running.state.key_hex
        entry = MockConfigEntry(
            domain=DOMAIN,
            data={
                CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
                CONF_REFERENCE_JOURNAL_ID: journal_id,
                CONF_ROOMS: rooms_as_dict(default_rooms()),
            },
        )
        entry.add_to_hass(hass)

        await running.async_stop()
        running = await start_journal_app(tmp_path)
        assert running.state.boot_id != old_boot_id
        assert running.state.key_hex != old_key

        assert not await hass.config_entries.async_setup(entry.entry_id)
        assert entry.state is ConfigEntryState.SETUP_RETRY
        assert old_key not in repr(entry.data)

        await discover(hass, running.state)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert (
            entry.runtime_data.reference_journal._store.endpoint.boot_id
            == running.state.boot_id
        )
        assert running.state.key_hex not in repr(entry.data)
    finally:
        if entry is not None and entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
        await running.async_stop()
        await session.close()


async def test_discovery_kicks_existing_not_loaded_entry(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    mqtt_mock,
    tmp_path: Path,
    production_reference_journal_backend: None,
) -> None:
    """Use Home Assistant's supported reload path to load an existing entry."""

    running = await start_journal_app(tmp_path)
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    entry = None
    try:
        await discover(hass, running.state)
        journal_id = "not-loaded-discovery-journal"
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=journal_id,
        )
        entry = MockConfigEntry(
            domain=DOMAIN,
            data={
                CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
                CONF_REFERENCE_JOURNAL_ID: journal_id,
                CONF_ROOMS: rooms_as_dict(default_rooms()),
            },
        )
        entry.add_to_hass(hass)
        assert entry.state is ConfigEntryState.NOT_LOADED

        await discover(hass, running.state)
        await hass.async_block_till_done()

        assert entry.state is ConfigEntryState.LOADED
        assert running.state.key_hex not in repr(entry.data)
    finally:
        if entry is not None and entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
        await running.async_stop()
        await session.close()


async def test_restored_app_wakes_setup_error_and_preserves_exact_journal(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    mqtt_mock,
    tmp_path: Path,
    production_reference_journal_backend: None,
) -> None:
    """Recover a failed entry only after its exact App data is restored."""

    data_dir = tmp_path / "app-data"
    backup_dir = tmp_path / "cold-backup"
    data_dir.mkdir()
    backup_dir.mkdir()
    database_name = journal_app.DATABASE_NAME
    running: RunningJournalApp | None = await start_journal_app(data_dir)
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    entry = None
    try:
        await discover(hass, running.state)
        journal_id = "restored-setup-error-journal"
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=journal_id,
        )
        adapter = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
        )
        await adapter.async_run(
            adapter.set_state,
            PLAN_ONE,
            migration.MigrationState.PLANNED,
        )
        await adapter.async_close()
        expected = await running.state.store.async_load(journal_id)
        assert expected is not None
        assert expected.generation == 1
        entry = MockConfigEntry(
            domain=DOMAIN,
            data={
                CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
                CONF_REFERENCE_JOURNAL_ID: journal_id,
                CONF_ROOMS: rooms_as_dict(default_rooms()),
            },
        )
        entry.add_to_hass(hass)
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert await hass.config_entries.async_unload(entry.entry_id)

        await running.async_stop()
        running = None
        shutil.copy2(data_dir / database_name, backup_dir / database_name)
        for path in data_dir.iterdir():
            path.unlink()

        running = await start_journal_app(data_dir)
        await discover(hass, running.state)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.SETUP_ERROR
        assert await running.state.store.async_load(journal_id) is None

        await running.async_stop()
        running = None
        for path in data_dir.iterdir():
            path.unlink()
        shutil.copy2(backup_dir / database_name, data_dir / database_name)

        running = await start_journal_app(data_dir)
        await discover(hass, running.state)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert await running.state.store.async_load(journal_id) == expected
        assert entry.runtime_data.reference_journal._root == expected.root
        assert running.state.key_hex not in repr(entry.data)
    finally:
        if entry is not None and entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
        if running is not None:
            await running.async_stop()
        await session.close()


@pytest.mark.parametrize("credential", ("key", "boot_id"))
async def test_signed_wrong_key_or_boot_is_retryable_and_secret_free(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    mqtt_mock,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    production_reference_journal_backend: None,
    credential: str,
) -> None:
    """Treat stale generation authentication as unavailable, then recover."""

    running = await start_journal_app(tmp_path)
    session = new_shared_session()
    monkeypatch.setattr(remote, "async_get_clientsession", lambda _hass: session)
    actual_key = running.state.key_hex
    supplied_key = "f" * 64
    updates = (
        {"key": supplied_key}
        if credential == "key"
        else {"boot_id": "e" * 32}
    )
    caplog.set_level(logging.DEBUG)
    entry = None
    try:
        discovered = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_HASSIO},
            data=service_info(running.state, config_updates=updates),
        )
        assert discovered["type"] == "abort"
        assert discovered["reason"] == "journal_app_discovered"
        endpoint = discovery.get_reference_journal_endpoint(hass)
        assert endpoint is not None
        assert actual_key not in repr(endpoint)
        assert supplied_key not in repr(endpoint)

        user_flow = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
        )
        retry = await hass.config_entries.flow.async_configure(
            user_flow["flow_id"],
            {CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC},
        )
        assert retry["type"] == "form"
        assert retry["errors"] == {"base": "journal_durability_unavailable"}
        assert hass.config_entries.async_entries(DOMAIN) == []

        with pytest.raises(journal_ha.ReferenceJournalIOError) as unavailable:
            await journal_ha.async_provision_reference_journal(
                hass,
                journal_id="wrong-signed-credential-journal",
            )
        assert actual_key not in repr(unavailable.value)
        assert supplied_key not in repr(unavailable.value)
        assert APP_HOST not in str(unavailable.value)

        await discover(hass, running.state)
        created = await hass.config_entries.flow.async_configure(
            retry["flow_id"],
            {CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC},
        )
        assert created["type"] == "create_entry"
        entry = created["result"]
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert set(entry.data) == {
            CONF_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID,
            CONF_ROOMS,
        }
        rendered = caplog.text
        for secret in (actual_key, supplied_key):
            assert secret not in repr(entry.data)
            assert secret not in rendered
    finally:
        if entry is not None and entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
        await running.async_stop()
        await session.close()
