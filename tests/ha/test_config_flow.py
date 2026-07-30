"""Test the real Home Assistant config flow."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState, SOURCE_HASSIO, SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.helpers.service_info.hassio import HassioServiceInfo
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import true_family as true_family_integration
from custom_components.true_family.config_flow import valid_base_topic
from custom_components.true_family.const import (
    CONF_BASE_TOPIC,
    CONF_REFERENCE_JOURNAL_ID,
    CONF_ROOMS,
    DEFAULT_BASE_TOPIC,
    DOMAIN,
)
from custom_components.true_family.models import default_rooms, rooms_as_dict
from custom_components.true_family import reference_migration_ha as journal_ha
from custom_components.true_family import reference_journal_discovery as discovery
from custom_components.true_family.reference_migration_ha import (
    async_load_reference_journal,
    async_provision_reference_journal,
)


APP_SLUG = "8c9c720e_true_family_journal"
APP_HOST = "8c9c720e-true-family-journal"
BOOT_ID = "a" * 32
HMAC_KEY = "b" * 64


def hassio_discovery_info(
    *,
    config_updates: dict | None = None,
    slug: str = APP_SLUG,
    include_core_addon_name: bool = False,
) -> HassioServiceInfo:
    """Build one realistic Supervisor discovery envelope."""

    config = {
        "boot_id": BOOT_ID,
        "host": APP_HOST,
        "key": HMAC_KEY,
        "port": 8765,
        "protocol": "true-family-journal-v1",
    }
    if config_updates:
        config.update(config_updates)
    if include_core_addon_name:
        config["addon"] = "True Family Journal"
    return HassioServiceInfo(
        config=config,
        name="True Family Journal",
        slug=slug,
        uuid="journal-discovery-uuid",
    )


async def test_config_flow_creates_seven_unbound_rooms(hass: HomeAssistant) -> None:
    """Create the singleton entry through Home Assistant's flow manager."""

    discovered = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_HASSIO},
        data=hassio_discovery_info(include_core_addon_name=True),
    )
    assert discovered["type"] == "abort"
    assert discovered["reason"] == "journal_app_discovered"

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
    )
    assert result["type"] == "form"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_BASE_TOPIC: "zigbee2mqtt/"},
    )
    assert result["type"] == "create_entry"
    assert result["data"][CONF_BASE_TOPIC] == "zigbee2mqtt"
    assert len(result["data"][CONF_REFERENCE_JOURNAL_ID]) == 32
    assert len(result["data"][CONF_ROOMS]) == 7
    assert all(
        room["binding"] is None for room in result["data"][CONF_ROOMS].values()
    )
    assert HMAC_KEY not in repr(result["data"])
    journal = await async_load_reference_journal(
        hass,
        journal_id=result["data"][CONF_REFERENCE_JOURNAL_ID],
    )
    assert journal is not None
    await journal.async_close()

    duplicate = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
    )
    assert duplicate["type"] == "abort"
    assert duplicate["reason"] == "already_configured"


async def test_config_flow_without_discovered_app_is_retryable_before_mutation(
    hass: HomeAssistant,
    production_reference_journal_backend: None,
) -> None:
    """Keep the user form retryable when the companion App is absent."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_BASE_TOPIC: "zigbee2mqtt"},
    )

    assert result["type"] == "form"
    assert result["errors"] == {"base": "journal_durability_unavailable"}
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_hassio_discovery_caches_only_redacted_endpoint_and_never_adds_entry(
    hass: HomeAssistant,
) -> None:
    """Accept strict discovery while keeping the per-boot key out of entries."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_HASSIO},
        data=hassio_discovery_info(),
    )

    assert result["type"] == "abort"
    assert result["reason"] == "journal_app_discovered"
    assert hass.config_entries.async_entries(DOMAIN) == []
    endpoint = discovery.get_reference_journal_endpoint(hass)
    assert endpoint is not None
    assert endpoint.full_slug == APP_SLUG
    assert endpoint.hostname == APP_HOST
    assert endpoint.boot_id == BOOT_ID
    assert HMAC_KEY not in repr(endpoint)


@pytest.mark.parametrize(
    "discovery_info",
    (
        hassio_discovery_info(config_updates={"host": "attacker.invalid"}),
        hassio_discovery_info(config_updates={"port": 8766}),
        hassio_discovery_info(config_updates={"protocol": "other-protocol"}),
        hassio_discovery_info(config_updates={"boot_id": "A" * 32}),
        hassio_discovery_info(config_updates={"key": "g" * 64}),
        hassio_discovery_info(config_updates={"unexpected": True}),
        hassio_discovery_info(slug="true_family_journal"),
        hassio_discovery_info(slug="attacker_true_family_journal"),
        hassio_discovery_info(slug="repository_true_family_journal"),
        hassio_discovery_info(slug="local_attacker_journal"),
        hassio_discovery_info(slug="local_true_family_journal"),
        hassio_discovery_info(slug="8c22f541_true_family_journal"),
        hassio_discovery_info(slug="8c9c720e_true_family_journal_suffix"),
    ),
)
async def test_hassio_discovery_rejects_noncanonical_or_untrusted_data(
    hass: HomeAssistant,
    discovery_info: HassioServiceInfo,
) -> None:
    """Reject arbitrary hosts, partial slugs, wrong protocol, and extra data."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_HASSIO},
        data=discovery_info,
    )

    assert result["type"] == "abort"
    assert result["reason"] == "journal_app_discovery_invalid"
    assert discovery.get_reference_journal_endpoint(hass) is None
    assert hass.config_entries.async_entries(DOMAIN) == []


@pytest.mark.parametrize(
    "state",
    (ConfigEntryState.NOT_LOADED, ConfigEntryState.SETUP_RETRY),
)
async def test_discovery_explicitly_wakes_retryable_existing_entry(
    hass: HomeAssistant,
    state: ConfigEntryState,
) -> None:
    """Kick setup immediately without persisting the discovered HMAC key."""

    entry = MockConfigEntry(
        domain=DOMAIN,
        state=state,
        data={"sentinel": "unchanged"},
    )
    entry.add_to_hass(hass)
    original_data = dict(entry.data)

    with patch.object(hass.config_entries, "async_schedule_reload") as schedule:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_HASSIO},
            data=hassio_discovery_info(),
        )

    assert result["type"] == "abort"
    assert result["reason"] == "journal_app_discovered"
    schedule.assert_called_once_with(entry.entry_id)
    assert dict(entry.data) == original_data
    assert HMAC_KEY not in repr(entry.data)


async def test_rekey_during_setup_schedules_one_reload_after_runtime_registration(
    hass: HomeAssistant,
) -> None:
    """Defer a setup race until the old journal owner is fully registered."""

    discovery.cache_reference_journal_endpoint(
        hass,
        discovery.endpoint_from_hassio_service_info(hassio_discovery_info()),
    )
    entry = MockConfigEntry(
        domain=DOMAIN,
        state=ConfigEntryState.SETUP_IN_PROGRESS,
        data={
            CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID: "setup-in-progress-rekey-journal",
            CONF_ROOMS: rooms_as_dict(default_rooms()),
        },
    )
    entry.add_to_hass(hass)
    journal = AsyncMock()
    journal.migration_operation_in_progress = False
    load_entered = asyncio.Event()
    release_load = asyncio.Event()

    async def load_journal(*_args, **_kwargs):
        load_entered.set()
        await release_load.wait()
        return journal

    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            AsyncMock(side_effect=load_journal),
        ),
        patch.object(
            true_family_integration.TrueFamilyRuntime,
            "async_setup",
            AsyncMock(),
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            AsyncMock(),
        ),
        patch.object(hass.config_entries, "async_schedule_reload") as schedule,
    ):
        setup = asyncio.create_task(
            true_family_integration.async_setup_entry(hass, entry)
        )
        await load_entered.wait()
        rekey = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_HASSIO},
            data=hassio_discovery_info(
                config_updates={"boot_id": "c" * 32, "key": "d" * 64}
            ),
        )
        assert rekey["reason"] == "journal_app_discovered"
        assert discovery.reference_journal_reload_is_pending(hass, entry.entry_id)
        schedule.assert_not_called()

        release_load.set()
        assert await setup

    schedule.assert_called_once_with(entry.entry_id)
    assert not discovery.reference_journal_reload_is_pending(hass, entry.entry_id)
    assert entry.runtime_data.reference_journal is journal
    assert hass.data[DOMAIN][entry.entry_id] is entry.runtime_data
    hass.data[DOMAIN].pop(entry.entry_id)
    await journal.async_close()
    entry.mock_state(hass, ConfigEntryState.NOT_LOADED)


async def test_discovery_defers_loaded_reload_until_journal_completion(
    hass: HomeAssistant,
) -> None:
    """Consume one entry-bound reload when its exact journal becomes idle."""

    journal = SimpleNamespace(migration_operation_in_progress=True)
    runtime = SimpleNamespace(reference_journal=journal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        state=ConfigEntryState.LOADED,
        data={"sentinel": "unchanged"},
    )
    entry.runtime_data = runtime
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime

    with patch.object(hass.config_entries, "async_schedule_reload") as schedule:
        first = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_HASSIO},
            data=hassio_discovery_info(),
        )
        assert first["reason"] == "journal_app_discovered"
        schedule.assert_not_called()
        assert discovery.reference_journal_reload_is_pending(hass, entry.entry_id)

        journal.migration_operation_in_progress = False
        assert discovery.async_schedule_pending_reference_journal_reload(
            hass,
            journal,
        )
        assert not discovery.async_schedule_pending_reference_journal_reload(
            hass,
            journal,
        )

    schedule.assert_called_once_with(entry.entry_id)
    assert not discovery.reference_journal_reload_is_pending(hass, entry.entry_id)
    assert dict(entry.data) == {"sentinel": "unchanged"}
    assert HMAC_KEY not in repr(entry.data)
    hass.data[DOMAIN].pop(entry.entry_id)
    entry.mock_state(hass, ConfigEntryState.NOT_LOADED)


async def test_pending_reload_is_consumed_without_scheduling_failed_entry(
    hass: HomeAssistant,
) -> None:
    """Drop stale deferred work when its exact config entry is no longer loaded."""

    journal = SimpleNamespace(migration_operation_in_progress=False)
    runtime = SimpleNamespace(reference_journal=journal)
    entry = MockConfigEntry(
        domain=DOMAIN,
        state=ConfigEntryState.SETUP_ERROR,
        data={"sentinel": "unchanged"},
    )
    entry.runtime_data = runtime
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime
    discovery.mark_reference_journal_reload_pending(
        hass,
        entry.entry_id,
        journal,
    )

    with patch.object(hass.config_entries, "async_schedule_reload") as schedule:
        assert not discovery.async_schedule_pending_reference_journal_reload(
            hass,
            journal,
        )

    schedule.assert_not_called()
    assert not discovery.reference_journal_reload_is_pending(hass, entry.entry_id)
    hass.data[DOMAIN].pop(entry.entry_id)


def test_base_topic_rejects_wildcards() -> None:
    """Reject wildcard or empty MQTT roots before config entry creation."""

    for value in (None, "", "/", "zigbee2mqtt/#", "zigbee2mqtt/+", "zigbee2mqtt/\x00"):
        try:
            valid_base_topic(value)
        except Exception:
            continue
        raise AssertionError(f"Invalid base topic was accepted: {value!r}")


async def test_orphaned_random_journal_does_not_block_new_config_flow(
    hass: HomeAssistant,
) -> None:
    """Use a journal-specific Store key so an interrupted flow is recoverable."""

    await async_provision_reference_journal(
        hass,
        journal_id="orphaned-config-flow-journal",
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_BASE_TOPIC: "zigbee2mqtt"},
    )

    assert result["type"] == "create_entry"
    assert result["data"][CONF_REFERENCE_JOURNAL_ID] != (
        "orphaned-config-flow-journal"
    )


async def test_config_flow_retry_reuses_one_journal_id(
    hass: HomeAssistant,
) -> None:
    """Keep one opaque journal identity across a transient provisioning retry."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
    )
    provision = AsyncMock(
        side_effect=[
            journal_ha.ReferenceJournalBusyError("injected busy backend"),
            None,
        ]
    )
    with patch(
        "custom_components.true_family.config_flow.async_provision_reference_journal",
        provision,
    ):
        retry = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_BASE_TOPIC: "zigbee2mqtt"},
        )
        assert retry["type"] == "form"
        assert retry["errors"] == {"base": "journal_durability_unavailable"}

        created = await hass.config_entries.flow.async_configure(
            retry["flow_id"],
            {CONF_BASE_TOPIC: "zigbee2mqtt"},
        )

    assert created["type"] == "create_entry"
    journal_ids = [call.kwargs["journal_id"] for call in provision.await_args_list]
    assert len(journal_ids) == 2
    assert journal_ids[0] == journal_ids[1]
    assert created["data"][CONF_REFERENCE_JOURNAL_ID] == journal_ids[0]


@pytest.mark.parametrize(
    ("failure", "error_key"),
    (
        (
            journal_ha.ReferenceJournalBusyError("injected busy backend"),
            "journal_durability_unavailable",
        ),
        (
            journal_ha.ReferenceJournalUnsupportedFilesystemError(
                "injected unsupported backend"
            ),
            "journal_durability_unavailable",
        ),
        (
            journal_ha.ReferenceJournalIOError("injected I/O failure"),
            "journal_durability_unavailable",
        ),
        (
            journal_ha.ReferenceJournalCorruptionError("injected corrupt bytes"),
            "journal_corrupt_or_unsafe",
        ),
        (
            journal_ha.ReferenceJournalCodecError("injected signed protocol shape"),
            "journal_corrupt_or_unsafe",
        ),
        (
            journal_ha.ReferenceJournalSecurityError("injected unsafe bytes"),
            "journal_corrupt_or_unsafe",
        ),
    ),
)
async def test_config_flow_reports_typed_journal_failures(
    hass: HomeAssistant,
    failure: Exception,
    error_key: str,
) -> None:
    """Separate durability availability from corruption or security failures."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
    )
    with patch(
        "custom_components.true_family.config_flow.async_provision_reference_journal",
        AsyncMock(side_effect=failure),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_BASE_TOPIC: "zigbee2mqtt"},
        )

    assert result["type"] == "form"
    assert result["errors"] == {"base": error_key}
