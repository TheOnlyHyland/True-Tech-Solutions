"""Test config-entry setup, logical entities, and unload."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, ATTR_TEMPERATURE
from homeassistant.core import Context
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
import pytest

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
