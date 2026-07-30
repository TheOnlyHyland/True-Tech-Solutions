"""Helpers for synthetic MQTT and registry objects in the HA harness."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
from typing import Any
from unittest.mock import MagicMock

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import async_fire_mqtt_message

from custom_components.true_family.models import RoomBinding

BASE_TOPIC = "zigbee2mqtt"
PERMIT_REQUEST_TOPIC = f"{BASE_TOPIC}/bridge/request/permit_join"
PERMIT_RESPONSE_TOPIC = f"{BASE_TOPIC}/bridge/response/permit_join"
BRIDGE_EVENT_TOPIC = f"{BASE_TOPIC}/bridge/event"


async def async_wait_for_publish(
    mqtt_client_mock: MagicMock,
    call_number: int,
) -> tuple[str, dict[str, Any], int, bool]:
    """Wait for one underlying Paho publish call and normalize its arguments."""

    for _ in range(100):
        if mqtt_client_mock.publish.call_count >= call_number:
            call = mqtt_client_mock.publish.call_args_list[call_number - 1]
            topic = call.args[0]
            payload = call.args[1]
            qos = call.args[2] if len(call.args) > 2 else call.kwargs.get("qos", 0)
            retain = (
                call.args[3]
                if len(call.args) > 3
                else call.kwargs.get("retain", False)
            )
            if isinstance(payload, bytes):
                payload = payload.decode()
            return topic, json.loads(payload), qos, retain
        await asyncio.sleep(0)
    raise AssertionError(f"MQTT publish call {call_number} was not observed.")


def async_ack_join_request(
    hass: HomeAssistant,
    request: dict[str, Any],
    *,
    status: str = "ok",
) -> None:
    """Fire a correlated synthetic Zigbee2MQTT permit-join response."""

    async_fire_mqtt_message(
        hass,
        PERMIT_RESPONSE_TOPIC,
        json.dumps(
            {
                "status": status,
                "data": {"time": request["time"]},
                "transaction": request["transaction"],
            }
        ),
    )


def async_fire_bridge_event(hass: HomeAssistant, payload: dict[str, Any]) -> None:
    """Fire a synthetic Zigbee2MQTT bridge event."""

    async_fire_mqtt_message(hass, BRIDGE_EVENT_TOPIC, json.dumps(payload))


def create_physical_climate(
    hass: HomeAssistant,
    *,
    mqtt_entry,
    ieee_address: str,
    object_id: str,
    temperature: float = 12,
) -> RoomBinding:
    """Create synthetic MQTT device/entity registry records and climate state."""

    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=mqtt_entry.entry_id,
        identifiers={("mqtt", f"zigbee2mqtt_{ieee_address}")},
        manufacturer="Moes",
        model="Thermostatic radiator valve",
        model_id="BRT-100-TRV",
        name=object_id,
    )
    entity = er.async_get(hass).async_get_or_create(
        "climate",
        "mqtt",
        f"{ieee_address}_climate_zigbee2mqtt",
        config_entry=mqtt_entry,
        device_id=device.id,
        suggested_object_id=object_id,
        supported_features=1,
    )
    hass.states.async_set(
        entity.entity_id,
        "heat",
        {
            "hvac_modes": ["heat"],
            "min_temp": 0,
            "max_temp": 35,
            "target_temp_step": 1,
            "current_temperature": 20,
            "temperature": temperature,
            "hvac_action": "idle",
            "supported_features": 1,
        },
    )
    return RoomBinding(
        registry_entry_id=entity.id,
        climate_entity_id=entity.entity_id,
        mqtt_unique_id=f"{ieee_address}_climate_zigbee2mqtt",
        device_identifier=f"zigbee2mqtt_{ieee_address}",
        ieee_address=ieee_address,
        model="BRT-100-TRV",
        manufacturer="Moes",
        z2m_friendly_name=object_id,
    )


def freshen_target_state(
    hass: HomeAssistant,
    entity_id: str,
    temperature: float,
) -> None:
    """Report a changed synthetic physical target after a command."""

    state = hass.states.get(entity_id)
    assert state is not None
    attributes = dict(state.attributes)
    attributes["temperature"] = temperature
    hass.states.async_set(entity_id, state.state, attributes)


def now_utc() -> datetime:
    """Return a real timezone-aware timestamp for bridge events."""

    return datetime.now(UTC)


async def async_wait_for_session_phase(runtime, session_id: str, phase: str) -> None:
    """Yield until a tracked replacement session reaches one phase."""

    for _ in range(100):
        if runtime.sessions[session_id].phase == phase:
            return
        await asyncio.sleep(0)
    session = runtime.sessions[session_id]
    raise AssertionError(
        f"Session did not reach {phase}: {session.phase}, {session.failure_reason}"
    )


async def async_start_pairing_with_ack(
    hass: HomeAssistant,
    runtime,
    mqtt_client_mock: MagicMock,
    *,
    room_id: str = "guest_room",
    operation: str = "replace",
) -> dict[str, Any]:
    """Start pairing and acknowledge its next MQTT request."""

    call_number = mqtt_client_mock.publish.call_count + 1
    task = asyncio.create_task(runtime.async_start_pairing(room_id, operation))
    topic, request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        call_number,
    )
    assert topic == PERMIT_REQUEST_TOPIC
    assert request["time"] == 60
    assert qos == 1
    assert retain is False
    async_ack_join_request(hass, request)
    return await task


async def async_prepare_new_candidate(
    hass: HomeAssistant,
    runtime,
    mqtt_client_mock: MagicMock,
    *,
    ieee_address: str,
    model: str = "BRT-100-TRV",
    manufacturer: str = "Moes",
) -> dict[str, Any]:
    """Pair and interview one candidate through real MQTT subscriptions."""

    device = dr.async_get(hass).async_get_device(
        identifiers={("mqtt", f"zigbee2mqtt_{ieee_address}")}
    )
    assert device is not None
    friendly_name = device.name
    assert friendly_name is not None
    session = await async_start_pairing_with_ack(
        hass,
        runtime,
        mqtt_client_mock,
    )
    async_fire_bridge_event(
        hass,
        {
            "type": "device_joined",
            "data": {
                "ieee_address": ieee_address,
                "friendly_name": friendly_name,
            },
        },
    )
    await async_wait_for_session_phase(runtime, session["session_id"], "interviewing")

    close_call = mqtt_client_mock.publish.call_count + 1
    async_fire_bridge_event(
        hass,
        {
            "type": "device_interview",
            "data": {
                "ieee_address": ieee_address,
                "friendly_name": friendly_name,
                "status": "successful",
                "supported": True,
                "definition": {"model": model, "vendor": manufacturer},
            },
        },
    )
    _topic, close_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock,
        close_call,
    )
    async_ack_join_request(hass, close_request)
    await async_wait_for_session_phase(
        runtime,
        session["session_id"],
        "ready_to_commit",
    )
    return session
