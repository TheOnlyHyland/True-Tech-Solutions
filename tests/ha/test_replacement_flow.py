"""Test one fully mocked replacement through real HA registries and state."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
from unittest.mock import AsyncMock, patch

from homeassistant.core import Context, HomeAssistant
from homeassistant.helpers import entity_registry as er
import pytest

from custom_components.true_family.const import CONF_BASE_TOPIC, CONF_ROOMS
from custom_components.true_family.models import default_rooms, rooms_as_dict
from custom_components.true_family.mqtt import BridgeEvent, JoinRequestError
from custom_components.true_family.replacement import (
    ReplacementError,
    TrueFamilyRuntime,
)

from helpers import (
    BRIDGE_EVENT_TOPIC,
    async_ack_join_request,
    async_fire_bridge_event,
    async_prepare_new_candidate,
    async_wait_for_session_phase,
    async_wait_for_publish,
    async_start_pairing_with_ack,
    create_physical_climate,
    freshen_target_state,
)

IEEE = "0x00124b0000000001"


async def test_replacement_tests_before_persist_and_survives_reload(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Verify pairing, candidate discovery, fresh read-back, and reload."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    candidate = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address=IEEE,
        object_id="synthetic_guest_trv",
    )
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()

    start_task = asyncio.create_task(
        runtime.async_start_pairing("guest_room", "replace")
    )
    _topic, open_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock, 1
    )
    async_ack_join_request(hass, open_request)
    session = await start_task

    async_fire_bridge_event(
        hass,
        {
            "type": "device_joined",
            "data": {"ieee_address": IEEE, "friendly_name": "synthetic_guest_trv"},
        },
    )
    await async_wait_for_session_phase(
        runtime,
        session["session_id"],
        "interviewing",
    )

    async_fire_bridge_event(
        hass,
        {
            "type": "device_interview",
            "data": {
                "ieee_address": IEEE,
                "friendly_name": "synthetic_guest_trv",
                "status": "successful",
                "supported": True,
                "definition": {"model": "BRT-100-TRV", "vendor": "Moes"},
            },
        },
    )
    _topic, close_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock, 2
    )
    async_ack_join_request(hass, close_request)
    await async_wait_for_session_phase(
        runtime,
        session["session_id"],
        "ready_to_commit",
    )
    assert true_family_entry.data[CONF_ROOMS]["guest_room"]["binding"] is None

    async def report_target(entity_id: str, temperature: float, _context) -> None:
        freshen_target_state(hass, entity_id, temperature)
        await asyncio.sleep(0)

    with patch.object(runtime, "_async_call_physical", side_effect=report_target):
        completed = await runtime.async_commit(session["session_id"], Context())
    await hass.async_block_till_done()
    assert completed["phase"] == "complete"
    stored = true_family_entry.data[CONF_ROOMS]["guest_room"]["binding"]
    assert stored["registry_entry_id"] == candidate.registry_entry_id

    guest_logical = er.async_get(hass).async_get_entity_id(
        "climate",
        "true_family",
        "logical_valve_guest_room",
    )
    assert guest_logical is not None
    logical_state = hass.states.get(guest_logical)
    assert logical_state is not None
    assert "physical_entity_id" not in logical_state.attributes
    assert logical_state.attributes["temperature"] == 12

    assert await hass.config_entries.async_reload(true_family_entry.entry_id)
    await hass.async_block_till_done()
    reloaded: TrueFamilyRuntime = true_family_entry.runtime_data
    assert reloaded.rooms["guest_room"].binding is not None
    assert (
        reloaded.rooms["guest_room"].binding.registry_entry_id
        == candidate.registry_entry_id
    )


async def test_wrong_model_fails_closed_without_binding(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Reject a newly joined non-TRV and close joining."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session = await async_start_pairing_with_ack(hass, runtime, mqtt_client_mock)

    async_fire_bridge_event(
        hass,
        {
            "type": "device_joined",
            "data": {"ieee_address": IEEE, "friendly_name": "wrong_device"},
        },
    )
    await async_wait_for_session_phase(runtime, session["session_id"], "interviewing")
    async_fire_bridge_event(
        hass,
        {
            "type": "device_interview",
            "data": {
                "ieee_address": IEEE,
                "friendly_name": "wrong_device",
                "status": "successful",
                "supported": True,
                "definition": {"model": "UNAPPROVED-SWITCH", "vendor": "Moes"},
            },
        },
    )
    _topic, close_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    async_ack_join_request(hass, close_request)
    await async_wait_for_session_phase(runtime, session["session_id"], "failed")
    failed = runtime.sessions[session["session_id"]]
    assert failed.requires_remediation is True
    assert runtime.rooms["guest_room"].binding is None


async def test_unconfirmed_close_lease_blocks_another_pairing(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Keep the global lease until closure is positively confirmed."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    now = datetime.now(UTC)
    runtime._mqtt.async_open_join = AsyncMock(return_value=now)
    runtime._mqtt.async_close_join = AsyncMock(
        side_effect=JoinRequestError("close not acknowledged")
    )
    session_data = await runtime.async_start_pairing("guest_room", "replace")
    session = runtime.sessions[session_data["session_id"]]

    await runtime._async_fail(session, "Synthetic close failure.")
    assert runtime._join_owner_session_id == session.session_id
    with pytest.raises(ReplacementError):
        await runtime.async_start_pairing("kitchen", "replace")

    runtime._mqtt.async_close_join = AsyncMock(return_value=datetime.now(UTC))
    await runtime._async_close_join_confirmed(session)
    assert runtime._join_owner_session_id is None


async def test_restart_safe_rollback_swaps_verified_previous_binding(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Restore the persisted previous valve by room revision after restart."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    current = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000002",
        object_id="current_guest_trv",
    )
    previous = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000003",
        object_id="previous_guest_trv",
    )
    rooms = default_rooms()
    rooms["guest_room"].binding = current
    rooms["guest_room"].previous_binding = previous
    rooms["guest_room"].revision = 7
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
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data

    async def report_target(entity_id: str, temperature: float, _context) -> None:
        freshen_target_state(hass, entity_id, temperature)
        await asyncio.sleep(0)

    with patch.object(runtime, "_async_call_physical", side_effect=report_target):
        result = await runtime.async_rollback_room("guest_room", 7, Context())
    assert result["revision"] == 8
    assert runtime.rooms["guest_room"].binding == previous
    assert runtime.rooms["guest_room"].previous_binding == current

    assert await hass.config_entries.async_reload(true_family_entry.entry_id)
    await hass.async_block_till_done()
    reloaded: TrueFamilyRuntime = true_family_entry.runtime_data
    assert reloaded.rooms["guest_room"].binding == previous
    assert reloaded.rooms["guest_room"].revision == 8


async def test_physical_entity_rename_resubscribes_logical_valve(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Resolve the source registry UUID again after an entity-ID rename."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    binding = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000004",
        object_id="rename_guest_trv",
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
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    old_entity_id = binding.climate_entity_id
    new_entity_id = "climate.renamed_synthetic_guest_trv"

    er.async_get(hass).async_update_entity(
        old_entity_id,
        new_entity_id=new_entity_id,
    )
    hass.states.async_remove(old_entity_id)
    hass.states.async_set(
        new_entity_id,
        "heat",
        {
            "hvac_modes": ["heat"],
            "min_temp": 0,
            "max_temp": 35,
            "target_temp_step": 1,
            "current_temperature": 20,
            "temperature": 14,
            "hvac_action": "idle",
            "supported_features": 1,
        },
    )
    await hass.async_block_till_done()
    assert runtime.source_entity_id("guest_room") == new_entity_id
    guest_logical = er.async_get(hass).async_get_entity_id(
        "climate",
        "true_family",
        "logical_valve_guest_room",
    )
    logical_state = hass.states.get(guest_logical)
    assert logical_state is not None
    assert "physical_entity_id" not in logical_state.attributes
    assert logical_state.attributes["temperature"] == 14


async def test_second_joined_device_fails_the_active_session(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Treat every additional join in the same window as remediation-required."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session = await async_start_pairing_with_ack(hass, runtime, mqtt_client_mock)
    async_fire_bridge_event(
        hass,
        {
            "type": "device_joined",
            "data": {"ieee_address": IEEE, "friendly_name": "first_candidate"},
        },
    )
    await async_wait_for_session_phase(runtime, session["session_id"], "interviewing")

    async_fire_bridge_event(
        hass,
        {
            "type": "device_joined",
            "data": {
                "ieee_address": "0x00124b0000000005",
                "friendly_name": "second_candidate",
            },
        },
    )
    _topic, close_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    async_ack_join_request(hass, close_request)
    await async_wait_for_session_phase(runtime, session["session_id"], "failed")
    failed = runtime.sessions[session["session_id"]]
    assert failed.requires_remediation is True
    assert len(failed.joined_ieee_addresses) == 2


async def test_failed_restore_never_persists_candidate_binding(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Keep the old room binding untouched when target restoration is stale."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    candidate = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000006",
        object_id="failed_restore_trv",
    )
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session = await async_prepare_new_candidate(
        hass,
        runtime,
        mqtt_client_mock,
        ieee_address=candidate.ieee_address,
    )
    call_count = 0

    async def fail_restore(entity_id: str, temperature: float, _context) -> None:
        nonlocal call_count
        call_count += 1
        if call_count in {1, 3}:
            freshen_target_state(hass, entity_id, temperature)
        await asyncio.sleep(0)

    with (
        patch.object(runtime, "_async_call_physical", side_effect=fail_restore),
        patch("custom_components.true_family.replacement.READBACK_SECONDS", 1),
        pytest.raises(ReplacementError),
    ):
        await runtime.async_commit(session["session_id"], Context())
    assert runtime.rooms["guest_room"].binding is None
    assert true_family_entry.data[CONF_ROOMS]["guest_room"]["binding"] is None
    assert runtime.sessions[session["session_id"]].phase == "failed"


async def test_second_join_during_candidate_test_cannot_be_committed(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Keep a queued second join from being overwritten by commit completion."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    candidate = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0x00124b0000000009",
        object_id="racing_guest_trv",
    )
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session = await async_prepare_new_candidate(
        hass,
        runtime,
        mqtt_client_mock,
        ieee_address=candidate.ieee_address,
    )
    test_started = asyncio.Event()
    release_test = asyncio.Event()

    async def pause_candidate_test(*_args) -> float:
        test_started.set()
        await release_test.wait()
        return 13

    with patch.object(runtime, "_async_test_binding", side_effect=pause_candidate_test):
        commit_task = asyncio.create_task(
            runtime.async_commit(session["session_id"], Context())
        )
        await test_started.wait()
        tracked = runtime.sessions[session["session_id"]]
        assert tracked.join_closed_at is not None
        await runtime.async_handle_bridge_event(
            BridgeEvent(
                event_type="device_joined",
                ieee_address="0x00124b0000000010",
                friendly_name="late_second_candidate",
                received_at=tracked.join_closed_at - timedelta(microseconds=1),
            )
        )
        await async_wait_for_session_phase(
            runtime,
            session["session_id"],
            "failed",
        )
        release_test.set()
        with pytest.raises(ReplacementError):
            await commit_task
    assert runtime.rooms["guest_room"].binding is None
    assert runtime.sessions[session["session_id"]].phase == "failed"


async def test_failed_session_cannot_be_relabelled_cancelled(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Preserve remediation-required terminal failures across cancel races."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    runtime._mqtt.async_open_join = AsyncMock(return_value=datetime.now(UTC))
    runtime._mqtt.async_close_join = AsyncMock(return_value=datetime.now(UTC))
    session_data = await runtime.async_start_pairing("guest_room", "replace")
    session = runtime.sessions[session_data["session_id"]]
    await runtime._async_fail(session, "Synthetic terminal failure.")

    with pytest.raises(ReplacementError):
        await runtime.async_cancel(session.session_id)
    assert session.phase == "failed"
    assert session.failure_reason == "Synthetic terminal failure."
