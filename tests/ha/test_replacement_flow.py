"""Test one fully mocked replacement through real HA registries and state."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
from unittest.mock import AsyncMock, patch

from homeassistant.core import Context, HomeAssistant
from homeassistant.helpers import entity_registry as er
import pytest

from custom_components.true_family.const import (
    CONF_BASE_TOPIC,
    CONF_ROOMS,
    PERMIT_JOIN_BASELINE_MAX_AGE_SECONDS,
)
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
    async_fire_bridge_info,
    async_fire_bridge_state,
    async_prepare_new_candidate,
    async_wait_for_session_phase,
    async_wait_for_publish,
    async_start_pairing_with_ack,
    bridge_harness_for,
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


async def test_unexpected_external_open_fails_synchronously_then_closes_on_api(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Do not adopt an external open or create a callback closure task."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session_data = await async_start_pairing_with_ack(
        hass,
        runtime,
        mqtt_client_mock,
    )
    session = runtime.sessions[session_data["session_id"]]
    tasks_before = set(runtime._tasks)
    publish_count = mqtt_client_mock.publish.call_count

    async_fire_bridge_info(
        hass,
        {
            "permit_join": True,
            "permit_join_end": int(
                (datetime.now(UTC) + timedelta(seconds=120)).timestamp() * 1000
            ),
        },
    )
    assert session.phase == "failed"
    assert session.requires_remediation is True
    assert runtime._bridge_requires_closure is True
    assert set(runtime._tasks) == tasks_before
    assert mqtt_client_mock.publish.call_count == publish_count

    with pytest.raises(ReplacementError):
        await runtime.async_cancel(session.session_id)
    _topic, close_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        publish_count + 1,
    )
    assert close_request["time"] == 0
    assert qos == 1
    assert retain is False
    assert session.join_closed is True
    assert runtime._join_owner_session_id is None


async def test_repeated_online_during_open_fails_then_reconciles(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Treat an online-only Zigbee2MQTT restart during pairing as unsafe."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()
    session_data = await async_start_pairing_with_ack(
        hass,
        runtime,
        mqtt_client_mock,
    )
    session = runtime.sessions[session_data["session_id"]]
    publish_count = mqtt_client_mock.publish.call_count

    async_fire_bridge_state(hass, {"state": "online"})
    assert session.phase == "failed"
    assert session.requires_remediation is True
    assert mqtt_client_mock.publish.call_count == publish_count

    with pytest.raises(ReplacementError):
        await runtime.async_cancel(session.session_id)
    _topic, close_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        publish_count + 1,
    )
    assert close_request["time"] == 0
    assert qos == 1
    assert retain is False
    assert session.join_closed is True


async def test_repeated_online_while_idle_requires_zero_only_reconciliation(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Invalidate idle proof on an online-only restart without opening join."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()

    async_fire_bridge_state(hass, {"state": "online"})
    assert runtime._bridge_requires_closure is True
    assert runtime._mqtt.current_closed_baseline() is None
    assert mqtt_client_mock.publish.call_count == 0

    harness = bridge_harness_for(hass)
    harness.auto_close = False
    reconcile_task = asyncio.create_task(runtime._async_reconcile_if_required())
    _topic, request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        1,
    )
    assert request["time"] == 0
    assert qos == 1
    assert retain is False
    assert mqtt_client_mock.publish.call_count == 1
    async_ack_join_request(hass, request)
    await reconcile_task
    harness.auto_close = True
    assert runtime._bridge_requires_closure is False


@pytest.mark.parametrize(
    "ordering",
    ("info_before_ack", "ack_before_info"),
)
async def test_open_info_and_ack_both_required_before_pairing_success(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    ordering: str,
) -> None:
    """Accept either upstream ordering without committing provisional info."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()

    start_task = asyncio.create_task(
        runtime.async_start_pairing("guest_room", "replace")
    )
    _topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert request["time"] == 60
    assert qos == 1
    assert retain is False
    session = runtime.active_session
    assert session is not None
    expected = runtime._mqtt._open_expected_end
    assert expected is not None
    expected_end = int(expected.timestamp() * 1000)
    info = {
        "permit_join": True,
        "permit_join_end": expected_end,
    }

    if ordering == "info_before_ack":
        async_fire_bridge_info(hass, info)
    else:
        async_ack_join_request(hass, request, bridge_info=None)
    await asyncio.sleep(0)
    assert start_task.done() is False
    assert session.phase == "awaiting_pairing"

    if ordering == "info_before_ack":
        async_ack_join_request(hass, request, bridge_info=None)
    else:
        async_fire_bridge_info(hass, info)
    started = await start_task
    assert started["phase"] == "awaiting_pairing"

    cancel_task = asyncio.create_task(runtime.async_cancel(session.session_id))
    await async_wait_for_publish(mqtt_client_mock, 2)
    cancelled = await cancel_task
    assert cancelled["phase"] == "cancelled"


@pytest.mark.parametrize(
    "scenario",
    ("invalid_buffered_end", "multiple_provisional", "wrong_ack", "error_ack"),
)
async def test_invalid_provisional_open_never_becomes_attributed(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    scenario: str,
) -> None:
    """Fail buffered ambiguity synchronously and retain terminal failure."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()

    start_task = asyncio.create_task(
        runtime.async_start_pairing("guest_room", "replace")
    )
    _topic, request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock,
        1,
    )
    session = runtime.active_session
    assert session is not None
    expected = runtime._mqtt._open_expected_end
    assert expected is not None
    expected_end = int(expected.timestamp() * 1000)
    info = {
        "permit_join": True,
        "permit_join_end": (
            expected_end - 6_000
            if scenario == "invalid_buffered_end"
            else expected_end
        ),
    }
    async_fire_bridge_info(hass, info)
    assert start_task.done() is False
    assert session.phase == "awaiting_pairing"

    if scenario == "multiple_provisional":
        async_fire_bridge_info(
            hass,
            {
                "permit_join": True,
                "permit_join_end": expected_end - 1_000,
            },
        )
        assert session.phase == "failed"
        async_ack_join_request(hass, request, bridge_info=None)
    elif scenario == "wrong_ack":
        async_ack_join_request(
            hass,
            request,
            transaction="wrong-transaction",
            bridge_info=None,
        )
        assert session.phase == "failed"
    elif scenario == "error_ack":
        async_ack_join_request(
            hass,
            request,
            status="error",
            bridge_info=None,
        )
        assert session.phase == "failed"
    else:
        async_ack_join_request(hass, request, bridge_info=None)
        assert session.phase == "failed"

    with pytest.raises(ReplacementError):
        await start_task
    _topic, close_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    assert close_request["time"] == 0
    assert qos == 1
    assert retain is False
    assert session.phase == "failed"
    assert session.requires_remediation is True
    assert session.join_closed is True


@pytest.mark.parametrize(
    "scenario",
    ("after_attribution_deadline", "mismatched_end"),
)
async def test_post_ack_external_open_never_becomes_attributed(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    scenario: str,
) -> None:
    """Require deadlines and exact end under the broker single-writer contract."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()

    start_task = asyncio.create_task(
        runtime.async_start_pairing("guest_room", "replace")
    )
    _topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert request["time"] == 60
    assert qos == 1
    assert retain is False
    session = runtime.active_session
    assert session is not None
    expected = runtime._mqtt._open_expected_end
    assert expected is not None
    matching_end = int(expected.timestamp() * 1000)
    info = {
        "permit_join": True,
        "permit_join_end": (
            matching_end - 6_000 if scenario == "mismatched_end" else matching_end
        ),
    }

    async_ack_join_request(hass, request, bridge_info=None)
    if scenario == "after_attribution_deadline":
        runtime._mqtt._open_attribution_deadline = hass.loop.time() - 1
    async_fire_bridge_info(hass, info)

    with pytest.raises(ReplacementError):
        await start_task
    _topic, close_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    assert close_request["time"] == 0
    assert qos == 1
    assert retain is False
    assert session.phase == "failed"
    assert session.requires_remediation is True
    assert session.join_closed is True


async def test_stale_closed_baseline_is_refreshed_before_positive_open(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Put a fresh zero-duration proof ahead of any positive pairing request."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    assert runtime._mqtt._permit_observed_monotonic is not None
    runtime._mqtt._permit_observed_monotonic = (
        hass.loop.time() - PERMIT_JOIN_BASELINE_MAX_AGE_SECONDS - 1
    )
    mqtt_client_mock.publish.reset_mock()

    start_task = asyncio.create_task(
        runtime.async_start_pairing("guest_room", "replace")
    )
    _topic, baseline_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        1,
    )
    assert baseline_request["time"] == 0
    assert qos == 1
    assert retain is False
    _topic, open_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    assert open_request["time"] == 60
    assert qos == 1
    assert retain is False
    async_ack_join_request(hass, open_request)
    session_data = await start_task
    cancelled = await runtime.async_cancel(session_data["session_id"])
    assert cancelled["phase"] == "cancelled"


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
