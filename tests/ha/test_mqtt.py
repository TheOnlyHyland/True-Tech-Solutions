"""Test acknowledged permit-join requests through HA's mocked MQTT client."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from homeassistant.components import mqtt as mqtt_component
from homeassistant.core import HomeAssistant
import pytest

from custom_components.true_family.replacement import ReplacementError, TrueFamilyRuntime

from helpers import (
    PERMIT_REQUEST_TOPIC,
    async_ack_join_request,
    async_fire_bridge_info,
    async_fire_bridge_state,
    async_wait_for_publish,
    install_bridge_harness,
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
    assert close_request["time"] == 0
    assert close_request["transaction"].startswith("close-")
    assert close_request["transaction"] != request["transaction"]
    assert qos == 1
    assert retain is False
    async_ack_join_request(hass, close_request)
    cancelled = await cancel_task
    assert cancelled["phase"] == "cancelled"


def test_bridge_harness_patch_is_scoped_and_restored(monkeypatch) -> None:
    """Restore the surrounding MQTT functions when a fixture scope exits."""

    outer_subscribe = mqtt_component.async_subscribe
    outer_publish = mqtt_component.async_publish
    with monkeypatch.context() as scoped:
        original_subscribe, original_publish = install_bridge_harness(scoped)
        assert original_subscribe is outer_subscribe
        assert original_publish is outer_publish
        assert mqtt_component.async_subscribe is not outer_subscribe
        assert mqtt_component.async_publish is not outer_publish
    assert mqtt_component.async_subscribe is outer_subscribe
    assert mqtt_component.async_publish is outer_publish


@pytest.mark.parametrize(
    ("failed_role", "safety_coverage_remains"),
    (("event", True), ("state", False)),
)
async def test_runtime_shutdown_retry_never_reuses_stale_closure_proof(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    failed_role: str,
    safety_coverage_remains: bool,
) -> None:
    """Require a fresh barrier or fail closed after partial unsubscribe."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    subscription = next(
        item for item in runtime._mqtt._subscriptions if item.role == failed_role
    )
    original_unsubscribe = subscription.unsubscribe
    attempts = 0

    def unsubscribe_once() -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("private-unsubscribe-canary")
        original_unsubscribe()

    subscription.unsubscribe = unsubscribe_once
    mqtt_client_mock.publish.reset_mock()

    with pytest.raises(ReplacementError) as error:
        await runtime.async_shutdown()
    assert "private-unsubscribe-canary" not in str(error.value)
    assert runtime._shutdown_complete is False
    _topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert request["time"] == 0
    assert qos == 1
    assert retain is False

    async_fire_bridge_state(hass, {"state": "online"})
    if safety_coverage_remains:
        async_fire_bridge_info(
            hass,
            {
                "permit_join": True,
                "permit_join_end": int(datetime.now(UTC).timestamp() * 1000)
                + 60_000,
            },
        )
        await runtime.async_shutdown()
        _topic, retry_request, qos, retain = await async_wait_for_publish(
            mqtt_client_mock,
            2,
        )
        assert retry_request["time"] == 0
        assert qos == 1
        assert retain is False
        assert attempts == 2
        assert runtime._shutdown_complete is True
        assert runtime._mqtt._subscriptions == []
    else:
        with pytest.raises(ReplacementError):
            await runtime.async_shutdown()
        assert mqtt_client_mock.publish.call_count == 1
        assert runtime._shutdown_complete is False
        assert runtime.cleanup_pending is True
        assert runtime._mqtt.has_shutdown_safety_coverage is False
        # The disposable harness now represents process teardown, not a
        # successful runtime shutdown claim.
        await runtime._mqtt.async_shutdown()
        with patch.object(runtime, "async_shutdown", AsyncMock()):
            assert await hass.config_entries.async_unload(
                true_family_entry.entry_id
            )
        assert runtime._shutdown_complete is False
        return
    assert await hass.config_entries.async_unload(true_family_entry.entry_id)


async def test_shutdown_cancellation_after_closure_requires_fresh_retry_barrier(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    monkeypatch,
) -> None:
    """Never carry closure proof across cancellation before unsubscribe."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    original_shutdown = runtime._mqtt.async_shutdown

    async def cancel_after_closure() -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(runtime._mqtt, "async_shutdown", cancel_after_closure)
    mqtt_client_mock.publish.reset_mock()
    with pytest.raises(asyncio.CancelledError):
        await runtime.async_shutdown()
    _topic, first_request, _qos, _retain = await async_wait_for_publish(
        mqtt_client_mock,
        1,
    )
    assert first_request["time"] == 0
    assert runtime._shutdown_complete is False

    monkeypatch.setattr(runtime._mqtt, "async_shutdown", original_shutdown)
    await runtime.async_shutdown()
    _topic, retry_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        2,
    )
    assert retry_request["time"] == 0
    assert qos == 1
    assert retain is False
    assert runtime._shutdown_complete is True
    assert await hass.config_entries.async_unload(true_family_entry.entry_id)
