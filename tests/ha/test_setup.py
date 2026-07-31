"""Test config-entry setup, logical entities, and unload."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, ATTR_TEMPERATURE
from homeassistant.core import Context
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import storage
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import true_family as true_family_integration
from custom_components.true_family import reference_providers_ha as providers
from custom_components.true_family.const import CONF_BASE_TOPIC, CONF_ROOMS, DOMAIN
from custom_components.true_family.models import default_rooms, rooms_as_dict
from custom_components.true_family.mqtt import JoinRequestError
from custom_components.true_family.replacement import ReplacementError

from helpers import (
    async_ack_join_request,
    async_start_pairing_with_ack,
    async_wait_for_publish,
    create_physical_climate,
)


def test_yaml_configuration_is_explicitly_config_entry_only() -> None:
    """Expose the standard schema required for config-entry-only setup."""

    assert true_family_integration.CONFIG_SCHEMA({}) == {}


def test_harness_imports_true_family_from_canonical_project_source() -> None:
    """Never let the disposable harness resolve the installed live integration."""

    project_source = Path(__file__).resolve().parents[2]
    canonical_source = Path(
        "/homeassistant/projects/true-family-trv-replacement"
    ).resolve()
    integration_file = Path(true_family_integration.__file__).resolve()
    expected_file = (
        project_source / "custom_components" / "true_family" / "__init__.py"
    )

    assert integration_file == expected_file
    if canonical_source.is_dir():
        assert project_source == canonical_source
        assert integration_file.is_relative_to(
            canonical_source / "custom_components" / "true_family"
        )


async def test_config_entry_reference_snapshot_reader_has_no_mutation_surface(
    hass: HomeAssistant,
) -> None:
    """Prove the snapshot read cannot mutate or schedule Home Assistant work."""

    generic = MockConfigEntry(
        domain="generic_thermostat",
        version=1,
        minor_version=3,
        data={},
        options={
            "name": "Read-only generic thermostat",
            "heater": "switch.read_only_heater",
            "target_sensor": "sensor.read_only_temperature",
            "ac_mode": False,
            "cold_tolerance": 0.3,
            "hot_tolerance": 0.3,
        },
    )
    template = MockConfigEntry(
        domain="template",
        version=1,
        minor_version=2,
        data={},
        options={
            "name": "Read-only template",
            "template_type": "sensor",
            "state": "{{ states('climate.read_only_source') }}",
            "advanced_options": {
                "availability": "{{ has_value('sensor.read_only_temperature') }}"
            },
        },
    )
    generic.add_to_hass(hass)
    template.add_to_hass(hass)
    policy = tuple(
        sorted(
            (
                providers.ConfigEntryReferenceObjectPolicy(
                    generic.entry_id,
                    "generic_thermostat",
                ),
                providers.ConfigEntryReferenceObjectPolicy(
                    template.entry_id,
                    "template",
                ),
            ),
            key=lambda item: item.entry_id,
        )
    )
    service_call = AsyncMock()
    store_save = AsyncMock()

    with (
        patch.object(hass.config_entries, "async_update_entry") as update_entry,
        patch.object(hass.config_entries, "async_schedule_reload") as schedule_reload,
        patch.object(type(hass.services), "async_call", service_call),
        patch.object(storage.Store, "async_save", store_save),
        patch.object(storage.Store, "async_delay_save") as store_save_delay,
        patch.object(type(hass.bus), "async_fire") as fire_event,
    ):
        snapshots = await providers.async_read_config_entry_reference_snapshot(
            hass,
            policy,
        )

    assert tuple(snapshot.object_id for snapshot in snapshots) == tuple(
        item.entry_id for item in policy
    )
    assert all(snapshot.writable is False for snapshot in snapshots)
    update_entry.assert_not_called()
    schedule_reload.assert_not_called()
    service_call.assert_not_awaited()
    store_save.assert_not_awaited()
    store_save_delay.assert_not_called()
    fire_event.assert_not_called()


async def test_setup_creates_seven_unavailable_logical_valves_and_unloads(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Load the actual custom component without publishing MQTT."""

    publish_count = mqtt_client_mock.publish.call_count
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()

    entries = er.async_entries_for_config_entry(
        er.async_get(hass),
        true_family_entry.entry_id,
    )
    logical_entries = [
        entry
        for entry in entries
        if entry.domain == "climate" and entry.platform == DOMAIN
    ]
    assert len(logical_entries) == 7
    assert len({entry.unique_id for entry in logical_entries}) == 7
    assert all(
        hass.states.get(entry.entity_id).state == "unavailable"
        for entry in logical_entries
    )
    assert mqtt_client_mock.publish.call_count == publish_count

    assert await hass.config_entries.async_unload(true_family_entry.entry_id)
    await hass.async_block_till_done()
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})


async def test_unload_during_active_join_confirms_closure(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Close an acknowledged join window before config-entry unload completes."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    await async_start_pairing_with_ack(hass, runtime, mqtt_client_mock)

    unload_task = asyncio.create_task(
        hass.config_entries.async_unload(true_family_entry.entry_id)
    )
    _topic, close_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    assert close_request["time"] == 0
    async_ack_join_request(hass, close_request)
    assert await unload_task
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})


async def test_mqtt_not_ready_places_entry_in_setup_retry(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Fail setup cleanly when Home Assistant's MQTT client is not ready."""

    with patch(
        "homeassistant.components.mqtt.async_wait_for_mqtt_client",
        AsyncMock(return_value=False),
    ):
        assert not await hass.config_entries.async_setup(true_family_entry.entry_id)
    assert true_family_entry.state is ConfigEntryState.SETUP_RETRY
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})


async def test_logical_climate_forwards_target_with_service_context(
    hass: HomeAssistant,
    hass_admin_user,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Forward a logical climate service call with the initiating user context."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    binding = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000007",
        object_id="context_guest_trv",
    )
    rooms = default_rooms()
    rooms["guest_room"].binding = binding
    hass.config_entries.async_update_entry(
        true_family_entry,
        data={
            **dict(true_family_entry.data),
            CONF_BASE_TOPIC: "zigbee2mqtt",
            CONF_ROOMS: rooms_as_dict(rooms),
        },
    )
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime = true_family_entry.runtime_data
    guest_logical = er.async_get(hass).async_get_entity_id(
        "climate",
        DOMAIN,
        "logical_valve_guest_room",
    )
    assert guest_logical is not None
    context = Context(user_id=hass_admin_user.id)

    with patch.object(
        runtime,
        "async_set_temperature",
        AsyncMock(),
    ) as forward:
        await hass.services.async_call(
            "climate",
            "set_temperature",
            {
                ATTR_ENTITY_ID: guest_logical,
                ATTR_TEMPERATURE: 18,
            },
            blocking=True,
            context=context,
        )
    forward.assert_awaited_once()
    assert forward.await_args is not None
    room_id, temperature, forwarded_context = forward.await_args.args
    assert room_id == "guest_room"
    assert temperature == 18
    assert forwarded_context.user_id == hass_admin_user.id

    physical_call = AsyncMock()
    with patch.object(runtime, "_async_call_physical", physical_call):
        await runtime.async_set_temperature("guest_room", 19, context)
        with pytest.raises(ReplacementError):
            await runtime.async_set_temperature("guest_room", 100, context)
        with pytest.raises(ReplacementError):
            await runtime.async_set_temperature("guest_room", float("inf"), context)
        with pytest.raises(ReplacementError):
            await runtime._async_test_binding(binding, 100, context)
    physical_call.assert_awaited_once()
    assert runtime._intended_targets["guest_room"] == 19

    await hass.services.async_call(
        "climate",
        "set_hvac_mode",
        {
            ATTR_ENTITY_ID: guest_logical,
            "hvac_mode": "heat",
        },
        blocking=True,
        context=context,
    )


async def test_failed_unload_stays_closed_until_runtime_cleanup(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Expose HA's failed-unload state while preserving a later safe cleanup."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session = await async_start_pairing_with_ack(hass, runtime, mqtt_client_mock)
    runtime._mqtt.async_close_join = AsyncMock(
        side_effect=JoinRequestError("close not acknowledged")
    )

    assert not await hass.config_entries.async_unload(true_family_entry.entry_id)
    assert true_family_entry.state is ConfigEntryState.FAILED_UNLOAD
    assert runtime.sessions[session["session_id"]].join_closed is False
    assert runtime._shutdown_complete is False

    runtime._mqtt.async_close_join = AsyncMock(return_value=datetime.now(UTC))
    await runtime.async_shutdown()
    assert runtime.sessions[session["session_id"]].join_closed is True
    assert runtime._shutdown_complete is True


async def test_shutdown_drains_waiting_room_commands_without_forwarding(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject a room command that was queued when unload began."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    binding = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000008",
        object_id="shutdown_guest_trv",
    )
    rooms = default_rooms()
    rooms["guest_room"].binding = binding
    hass.config_entries.async_update_entry(
        true_family_entry,
        data={
            **dict(true_family_entry.data),
            CONF_BASE_TOPIC: "zigbee2mqtt",
            CONF_ROOMS: rooms_as_dict(rooms),
        },
    )
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime = true_family_entry.runtime_data
    physical_call = AsyncMock()
    room_lock = runtime._room_locks["guest_room"]
    await room_lock.acquire()
    with patch.object(runtime, "_async_call_physical", physical_call):
        command_task = asyncio.create_task(
            runtime.async_set_temperature("guest_room", 18, Context())
        )
        await asyncio.sleep(0)
        shutdown_task = asyncio.create_task(runtime.async_shutdown())
        await asyncio.sleep(0)
        room_lock.release()
        with pytest.raises(ReplacementError):
            await command_task
        await shutdown_task
    physical_call.assert_not_awaited()
