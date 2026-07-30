"""Test acknowledged permit-join requests through HA's mocked MQTT client."""

from __future__ import annotations

import asyncio

from homeassistant.core import HomeAssistant

from custom_components.true_family.replacement import TrueFamilyRuntime

from helpers import (
    PERMIT_REQUEST_TOPIC,
    async_ack_join_request,
    async_wait_for_publish,
)


async def test_pairing_open_and_cancel_require_correlated_acknowledgements(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Verify exact open/close payloads, QoS, retain, and transactions."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    mqtt_client_mock.publish.reset_mock()

    start_task = asyncio.create_task(
        runtime.async_start_pairing("guest_room", "replace")
    )
    topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert topic == PERMIT_REQUEST_TOPIC
    assert request["time"] == 60
    assert qos == 1
    assert retain is False
    async_ack_join_request(hass, request)
    session = await start_task

    cancel_task = asyncio.create_task(runtime.async_cancel(session["session_id"]))
    topic, close_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock, 2
    )
    assert topic == PERMIT_REQUEST_TOPIC
    assert close_request == {
        "time": 0,
        "transaction": request["transaction"],
    }
    assert qos == 1
    assert retain is False
    async_ack_join_request(hass, close_request)
    cancelled = await cancel_task
    assert cancelled["phase"] == "cancelled"
