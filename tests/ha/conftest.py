"""Fixtures for the disposable Home Assistant harness."""

from __future__ import annotations

from copy import deepcopy
import os
import secrets
from typing import Any

import pytest
import pytest_asyncio

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.true_family.const import (
    CONF_BASE_TOPIC,
    CONF_REFERENCE_JOURNAL_ID,
    CONF_ROOMS,
    DEFAULT_BASE_TOPIC,
    DOMAIN,
)
from custom_components.true_family.models import default_rooms, rooms_as_dict
from custom_components.true_family import reference_journal_file
from custom_components.true_family.reference_migration_ha import (
    REFERENCE_JOURNAL_FILESYSTEM_POLICY_DATA,
    async_provision_reference_journal,
)


_HARNESS_BACKEND_SEAL = object()


class HarnessOwnedJournalStore:
    """Sealed in-memory owned store for tests outside the production slice."""

    def __init__(
        self,
        journals: dict[str, dict[str, Any]],
        journal_id: str,
        *,
        _seal: object,
    ) -> None:
        if _seal is not _HARNESS_BACKEND_SEAL:
            raise TypeError("The harness journal store is test-only.")
        self._journals = journals
        self._journal_id = journal_id
        self._closed = False

    @property
    def durability_proof(self):
        from custom_components.true_family import reference_migration_ha

        return reference_migration_ha.ReferenceJournalTestDurabilityProof.create(
            "true-family-ha-test-harness"
        )

    async def async_load(self) -> dict[str, Any] | None:
        return deepcopy(self._journals.get(self._journal_id))

    async def async_save(self, data: dict[str, Any]) -> None:
        self._journals[self._journal_id] = deepcopy(data)

    async def async_barrier(self) -> None:
        return None

    async def async_close(self) -> None:
        self._closed = True


@pytest.fixture
def production_reference_journal_backend() -> None:
    """Opt one test out of the sealed in-memory journal factory."""


@pytest.fixture(autouse=True)
def inject_harness_durability_dependencies(
    hass: HomeAssistant,
    monkeypatch,
    request: pytest.FixtureRequest,
) -> None:
    """Trust the disposable mount and isolate ordinary tests from the App."""

    from custom_components.true_family import reference_migration_ha

    if "production_reference_journal_backend" in request.fixturenames:
        return

    descriptor = os.open(
        hass.config.config_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        filesystem = reference_journal_file._filesystem_identity_for_fd(descriptor)
    finally:
        os.close(descriptor)
    test_policy = reference_journal_file.DurableFilesystemPolicy.for_test_filesystems(
        frozenset({filesystem.filesystem_type})
    )
    monkeypatch.setitem(
        hass.data,
        REFERENCE_JOURNAL_FILESYSTEM_POLICY_DATA,
        test_policy,
    )

    journals: dict[str, dict[str, Any]] = {}

    async def new_store(
        _hass: HomeAssistant,
        journal_id: str,
    ) -> HarnessOwnedJournalStore:
        return HarnessOwnedJournalStore(
            journals,
            journal_id,
            _seal=_HARNESS_BACKEND_SEAL,
        )

    monkeypatch.setattr(reference_migration_ha, "_new_store", new_store)

@pytest.fixture(autouse=True)
def enable_true_family_custom_integration(enable_custom_integrations) -> None:
    """Allow loading the project custom integration."""


@pytest_asyncio.fixture(autouse=True)
async def unload_harness_entries(hass: HomeAssistant):
    """Unload test integrations before the plugin checks for leaked timers."""

    yield
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
        elif entry.state is ConfigEntryState.FAILED_UNLOAD:
            runtime = entry.runtime_data
            if (
                getattr(runtime, "_shutdown_complete", False)
                and runtime.reference_journal is not None
            ):
                await runtime.reference_journal.async_close()

    # The official MQTT fixture's fake disconnect does not emit socket-close,
    # so cancel the mock-only paho misc timer before unloading MQTT.
    mqtt_data = hass.data.get("mqtt")
    mqtt_client = mqtt_data.client if mqtt_data else None
    misc_timer = getattr(mqtt_client, "_misc_timer", None)
    if misc_timer:
        misc_timer.cancel()
        setattr(mqtt_client, "_misc_timer", None)

    for entry in hass.config_entries.async_entries("mqtt"):
        if entry.state is ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()


@pytest_asyncio.fixture
async def true_family_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Create an unbound True Family config entry."""

    journal_id = secrets.token_hex(16)
    await async_provision_reference_journal(hass, journal_id=journal_id)
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="True Family",
        unique_id=DOMAIN,
        version=1,
        data={
            CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID: journal_id,
            CONF_ROOMS: rooms_as_dict(default_rooms()),
        },
    )
    entry.add_to_hass(hass)
    return entry
