"""Test config-entry setup, logical entities, and unload."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from homeassistant.components import mqtt as mqtt_component
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, ATTR_TEMPERATURE
from homeassistant.core import Context
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import storage
from homeassistant.exceptions import ConfigEntryNotReady
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import true_family as true_family_integration
from custom_components.true_family import mqtt as mqtt_adapter
from custom_components.true_family import reference_providers_ha as providers
from custom_components.true_family.const import CONF_BASE_TOPIC, CONF_ROOMS, DOMAIN
from custom_components.true_family.models import default_rooms, rooms_as_dict
from custom_components.true_family.mqtt import JoinRequestError
from custom_components.true_family.replacement import ReplacementError
from custom_components.true_family.replacement import TrueFamilyRuntime

from helpers import (
    BRIDGE_INFO_TOPIC,
    MISSING,
    PERMIT_REQUEST_TOPIC,
    PERMIT_RESPONSE_TOPIC,
    async_ack_join_request,
    async_fire_bridge_info,
    async_start_pairing_with_ack,
    async_wait_for_publish,
    bridge_harness_for,
    create_physical_climate,
)


def install_incomplete_startup_failure(
    monkeypatch,
    *,
    unsubscribe_failures: int,
) -> dict[str, int]:
    """Fail one response subscription and bounded info unsubscriptions."""

    original_subscribe = mqtt_component.async_subscribe
    state = {
        "install_failures": 1,
        "unsubscribe_failures": unsubscribe_failures,
        "unsubscribe_attempts": 0,
    }

    async def failing_subscribe(
        hass,
        topic,
        message_callback,
        *args,
        **kwargs,
    ):
        if topic == PERMIT_RESPONSE_TOPIC and state["install_failures"]:
            state["install_failures"] -= 1
            raise RuntimeError("private-subscription-install-canary")
        unsubscribe = await original_subscribe(
            hass,
            topic,
            message_callback,
            *args,
            **kwargs,
        )
        if topic != BRIDGE_INFO_TOPIC:
            return unsubscribe

        def unreliable_unsubscribe() -> None:
            state["unsubscribe_attempts"] += 1
            if state["unsubscribe_failures"]:
                state["unsubscribe_failures"] -= 1
                raise RuntimeError("private-subscription-cleanup-canary")
            unsubscribe()

        return unreliable_unsubscribe

    monkeypatch.setattr(mqtt_component, "async_subscribe", failing_subscribe)
    return state


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
    """Reconcile closed before exposing the seven logical valves."""

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
    assert mqtt_client_mock.publish.call_count == publish_count + 1
    topic, startup_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        publish_count + 1,
    )
    assert topic == PERMIT_REQUEST_TOPIC
    assert startup_request["time"] == 0
    assert qos == 1
    assert retain is False

    assert await hass.config_entries.async_unload(true_family_entry.entry_id)
    await hass.async_block_till_done()
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
    _topic, shutdown_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        publish_count + 2,
    )
    assert shutdown_request["time"] == 0
    assert qos == 1
    assert retain is False


async def test_startup_retained_open_is_closed_before_runtime_exposure(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Replace a retained open snapshot with ACKed, newer closed bridge info."""

    harness = bridge_harness_for(hass)
    harness.retained_info = {
        "permit_join": True,
        "permit_join_end": int(
            (datetime.now(UTC) + timedelta(seconds=60)).timestamp() * 1000
        ),
        "config": {"private": "startup-private-payload-canary"},
    }

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    assert runtime._mqtt.current_closed_baseline() is not None
    assert hass.data[DOMAIN][true_family_entry.entry_id] is runtime

    _topic, request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        1,
    )
    assert request["time"] == 0
    assert qos == 1
    assert retain is False


async def test_runtime_is_not_exposed_until_startup_close_proof_arrives(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Keep WebSocket lookup and platforms unavailable while closure is pending."""

    harness = bridge_harness_for(hass)
    harness.auto_close = False
    setup_task = asyncio.create_task(
        hass.config_entries.async_setup(true_family_entry.entry_id)
    )
    _topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert request["time"] == 0
    assert qos == 1
    assert retain is False
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
    assert not er.async_entries_for_config_entry(
        er.async_get(hass),
        true_family_entry.entry_id,
    )

    async_ack_join_request(hass, request)
    harness.auto_close = True
    assert await setup_task
    assert true_family_entry.entry_id in hass.data[DOMAIN]


@pytest.mark.parametrize(
    "scenario",
    (
        "missing_info",
        "malformed_info",
        "offline",
        "unknown_state",
        "wrong_transaction",
        "wrong_time",
        "error_ack",
        "bridge_remains_open",
        "retained_replay",
    ),
)
async def test_startup_reconciliation_failures_leave_no_runtime_or_subscriptions(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    scenario: str,
) -> None:
    """Fail setup closed for every missing, malformed, offline, or bad-ACK path."""

    harness = bridge_harness_for(hass)
    harness.auto_close = False
    if scenario == "missing_info":
        harness.retained_info = MISSING
        harness.close_info = MISSING
    elif scenario == "malformed_info":
        harness.retained_info = MISSING
        harness.close_info = {"permit_join": "private-info-canary"}
    elif scenario == "offline":
        harness.retained_state = {"state": "offline"}
    elif scenario == "unknown_state":
        harness.retained_state = {"state": "private-state-canary"}

    mqtt_client_mock.unsubscribe.reset_mock()
    with (
        patch.object(mqtt_adapter, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RECONCILE_SECONDS", 0.03),
    ):
        if scenario in {"offline", "unknown_state"}:
            assert not await hass.config_entries.async_setup(true_family_entry.entry_id)
        else:
            setup_task = asyncio.create_task(
                hass.config_entries.async_setup(true_family_entry.entry_id)
            )
            _topic, request, _qos, _retain = await async_wait_for_publish(
                mqtt_client_mock,
                1,
            )
            if scenario == "missing_info":
                async_ack_join_request(hass, request, bridge_info=None)
            elif scenario == "malformed_info":
                async_ack_join_request(
                    hass,
                    request,
                    bridge_info={"permit_join": "private-info-canary"},
                )
            elif scenario == "wrong_transaction":
                async_ack_join_request(
                    hass,
                    request,
                    transaction="wrong-transaction",
                    bridge_info={"permit_join": False},
                )
            elif scenario == "wrong_time":
                async_ack_join_request(
                    hass,
                    request,
                    acknowledged_time=60,
                    bridge_info={"permit_join": False},
                )
            elif scenario == "error_ack":
                async_ack_join_request(
                    hass,
                    request,
                    status="error",
                    bridge_info={"permit_join": False},
                )
            elif scenario == "bridge_remains_open":
                async_ack_join_request(
                    hass,
                    request,
                    bridge_info={
                        "permit_join": True,
                        "permit_join_end": int(
                            (
                                datetime.now(UTC) + timedelta(seconds=60)
                            ).timestamp()
                            * 1000
                        ),
                    },
                )
            else:
                async_ack_join_request(hass, request, bridge_info=None)
                async_fire_bridge_info(
                    hass,
                    {"permit_join": False},
                    retain=True,
                )
            assert not await setup_task

    assert true_family_entry.state is ConfigEntryState.SETUP_RETRY
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
    published = [
        call
        for call in mqtt_client_mock.publish.call_args_list
        if call.args[0] == PERMIT_REQUEST_TOPIC
    ]
    if scenario in {"offline", "unknown_state"}:
        assert published == []
    else:
        assert len(published) == 1
        payload = published[0].args[1]
        if isinstance(payload, bytes):
            payload = payload.decode()
        request = json.loads(payload)
        assert request["time"] == 0
        assert published[0].args[2] == 1
        assert published[0].args[3] is False


async def test_shutdown_without_session_reconciles_before_unsubscribe(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Always issue a zero-duration global barrier before removing listeners."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    assert runtime.sessions == {}
    harness = bridge_harness_for(hass)
    harness.auto_close = False
    mqtt_client_mock.reset_mock()

    unload_task = asyncio.create_task(
        hass.config_entries.async_unload(true_family_entry.entry_id)
    )
    _topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert request["time"] == 0
    assert qos == 1
    assert retain is False
    assert len(runtime._mqtt._subscriptions) == 4
    async_ack_join_request(hass, request)
    harness.auto_close = True
    assert await unload_task
    assert runtime._mqtt._subscriptions == []


async def test_failed_unload_then_fresh_runtime_still_closes_without_old_session(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Make restart safety independent of an in-memory replacement session."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    old_runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    assert old_runtime.sessions == {}
    harness = bridge_harness_for(hass)
    harness.auto_close = False
    with (
        patch.object(mqtt_adapter, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RECONCILE_SECONDS", 0.03),
    ):
        assert not await hass.config_entries.async_unload(true_family_entry.entry_id)
    assert true_family_entry.state is ConfigEntryState.FAILED_UNLOAD
    assert old_runtime._shutdown_complete is False
    assert old_runtime._mqtt._subscriptions

    harness.auto_close = True
    mqtt_client_mock.publish.reset_mock()
    fresh_runtime = TrueFamilyRuntime(hass, true_family_entry, default_rooms())
    await fresh_runtime.async_setup()
    assert fresh_runtime.sessions == {}
    _topic, startup_request, qos, retain = await async_wait_for_publish(
        mqtt_client_mock,
        1,
    )
    assert startup_request["time"] == 0
    assert qos == 1
    assert retain is False
    await fresh_runtime.async_shutdown()
    await old_runtime.async_shutdown()
    assert fresh_runtime._shutdown_complete is True
    assert old_runtime._shutdown_complete is True


async def test_incomplete_startup_runtime_is_cleaned_before_fresh_setup(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    monkeypatch,
) -> None:
    """Retry only subscription cleanup for a retained pre-exposure runtime."""

    failure = install_incomplete_startup_failure(
        monkeypatch,
        unsubscribe_failures=2,
    )
    old_journal = AsyncMock()
    new_journal = AsyncMock()
    load_journal = AsyncMock(side_effect=(old_journal, new_journal))
    mqtt_client_mock.publish.reset_mock()

    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            load_journal,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            AsyncMock(),
        ),
    ):
        with pytest.raises(ConfigEntryNotReady) as error:
            await true_family_integration.async_setup_entry(
                hass,
                true_family_entry,
            )
        assert "private-subscription" not in str(error.value)
        orphan = true_family_entry.runtime_data
        assert isinstance(orphan, TrueFamilyRuntime)
        assert orphan._startup_complete is False
        assert orphan._shutdown_complete is False
        assert orphan.cleanup_pending is True
        assert [item.role for item in orphan._mqtt._subscriptions] == [
            "state",
            "info",
        ]
        assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
        assert failure["unsubscribe_attempts"] == 2
        assert load_journal.await_count == 1
        old_journal.async_close.assert_not_awaited()
        with pytest.raises(ReplacementError, match="startup is incomplete"):
            await orphan.async_start_pairing("guest_room", "replace")
        assert not any(
            call.args[0] == PERMIT_REQUEST_TOPIC
            for call in mqtt_client_mock.publish.call_args_list
        )

        assert await true_family_integration.async_setup_entry(
            hass,
            true_family_entry,
        )

    replacement = true_family_entry.runtime_data
    assert replacement is not orphan
    assert replacement._startup_complete is True
    assert orphan._shutdown_complete is True
    assert orphan._mqtt.has_subscriptions is False
    assert failure["unsubscribe_attempts"] == 3
    assert load_journal.await_count == 2
    old_journal.async_close.assert_awaited_once()
    new_journal.async_close.assert_not_awaited()
    assert hass.data[DOMAIN][true_family_entry.entry_id] is replacement
    permit_requests = [
        json.loads(
            call.args[1].decode()
            if isinstance(call.args[1], bytes)
            else call.args[1]
        )
        for call in mqtt_client_mock.publish.call_args_list
        if call.args[0] == PERMIT_REQUEST_TOPIC
    ]
    assert [request["time"] for request in permit_requests] == [0]

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        AsyncMock(return_value=True),
    ):
        assert await true_family_integration.async_unload_entry(
            hass,
            true_family_entry,
        )
    old_journal.async_close.assert_awaited_once()
    new_journal.async_close.assert_awaited_once()


async def test_repeated_incomplete_startup_cleanup_failure_never_overwrites_runtime(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
    monkeypatch,
) -> None:
    """Keep the original runtime and journal until direct cleanup succeeds."""

    failure = install_incomplete_startup_failure(
        monkeypatch,
        unsubscribe_failures=3,
    )
    old_journal = AsyncMock()
    new_journal = AsyncMock()
    load_journal = AsyncMock(side_effect=(old_journal, new_journal))
    mqtt_client_mock.publish.reset_mock()

    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            load_journal,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            AsyncMock(),
        ),
    ):
        with pytest.raises(ConfigEntryNotReady):
            await true_family_integration.async_setup_entry(
                hass,
                true_family_entry,
            )
        orphan = true_family_entry.runtime_data
        assert orphan._startup_complete is False
        assert failure["unsubscribe_attempts"] == 2

        with pytest.raises(ConfigEntryNotReady) as error:
            await true_family_integration.async_setup_entry(
                hass,
                true_family_entry,
            )
        assert "private-subscription" not in str(error.value)
        assert true_family_entry.runtime_data is orphan
        assert orphan._shutdown_complete is False
        assert orphan.cleanup_pending is True
        assert failure["unsubscribe_attempts"] == 3
        assert load_journal.await_count == 1
        old_journal.async_close.assert_not_awaited()
        assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
        assert not any(
            call.args[0] == PERMIT_REQUEST_TOPIC
            for call in mqtt_client_mock.publish.call_args_list
        )

        failure["unsubscribe_failures"] = 0
        assert await true_family_integration.async_setup_entry(
            hass,
            true_family_entry,
        )

    replacement = true_family_entry.runtime_data
    assert replacement is not orphan
    assert orphan._shutdown_complete is True
    assert failure["unsubscribe_attempts"] == 4
    old_journal.async_close.assert_awaited_once()
    assert all(
        request["time"] == 0
        for request in (
            json.loads(
                call.args[1].decode()
                if isinstance(call.args[1], bytes)
                else call.args[1]
            )
            for call in mqtt_client_mock.publish.call_args_list
            if call.args[0] == PERMIT_REQUEST_TOPIC
        )
    )

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        AsyncMock(return_value=True),
    ):
        assert await true_family_integration.async_unload_entry(
            hass,
            true_family_entry,
        )
    old_journal.async_close.assert_awaited_once()
    new_journal.async_close.assert_awaited_once()


async def test_platform_failure_orphan_is_cleaned_before_runtime_replacement(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Retain one hidden failed runtime until closure, unsubscribe, and journal close."""

    harness = bridge_harness_for(hass)
    old_journal = AsyncMock()
    new_journal = AsyncMock()
    load_journal = AsyncMock(side_effect=(old_journal, new_journal))

    async def fail_platform_setup(*_args) -> None:
        harness.auto_close = False
        raise RuntimeError("private-platform-setup-canary")

    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            load_journal,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            side_effect=fail_platform_setup,
        ),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RECONCILE_SECONDS", 0.03),
        pytest.raises(ConfigEntryNotReady),
    ):
        await true_family_integration.async_setup_entry(hass, true_family_entry)

    orphan = true_family_entry.runtime_data
    assert isinstance(orphan, TrueFamilyRuntime)
    assert orphan._shutdown_complete is False
    assert orphan._mqtt.has_subscriptions
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
    old_journal.async_close.assert_not_awaited()
    assert load_journal.await_count == 1

    with (
        patch.object(mqtt_adapter, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RECONCILE_SECONDS", 0.03),
        pytest.raises(ConfigEntryNotReady),
    ):
        await true_family_integration.async_setup_entry(hass, true_family_entry)
    assert true_family_entry.runtime_data is orphan
    assert load_journal.await_count == 1
    old_journal.async_close.assert_not_awaited()

    harness.auto_close = True
    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            load_journal,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            AsyncMock(),
        ),
    ):
        assert await true_family_integration.async_setup_entry(
            hass,
            true_family_entry,
        )
    replacement = true_family_entry.runtime_data
    assert replacement is not orphan
    assert orphan._shutdown_complete is True
    assert orphan._mqtt.has_subscriptions is False
    old_journal.async_close.assert_awaited_once()
    new_journal.async_close.assert_not_awaited()
    assert hass.data[DOMAIN][true_family_entry.entry_id] is replacement

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        AsyncMock(return_value=True),
    ):
        assert await true_family_integration.async_unload_entry(
            hass,
            true_family_entry,
        )
    old_journal.async_close.assert_awaited_once()
    new_journal.async_close.assert_awaited_once()


async def test_platform_cancellation_retains_runtime_until_retry_cleanup(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Propagate cancellation while preserving the exact cleanup owner."""

    harness = bridge_harness_for(hass)
    old_journal = AsyncMock()
    new_journal = AsyncMock()
    load_journal = AsyncMock(side_effect=(old_journal, new_journal))

    async def cancel_platform_setup(*_args) -> None:
        harness.auto_close = False
        raise asyncio.CancelledError

    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            load_journal,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            side_effect=cancel_platform_setup,
        ),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
        patch.object(mqtt_adapter, "PERMIT_JOIN_RECONCILE_SECONDS", 0.03),
        pytest.raises(asyncio.CancelledError),
    ):
        await true_family_integration.async_setup_entry(hass, true_family_entry)

    orphan = true_family_entry.runtime_data
    assert isinstance(orphan, TrueFamilyRuntime)
    assert orphan.cleanup_pending is True
    assert true_family_entry.entry_id not in hass.data.get(DOMAIN, {})
    old_journal.async_close.assert_not_awaited()

    harness.auto_close = True
    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            load_journal,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            AsyncMock(),
        ),
    ):
        assert await true_family_integration.async_setup_entry(
            hass,
            true_family_entry,
        )
    replacement = true_family_entry.runtime_data
    assert replacement is not orphan
    assert orphan._shutdown_complete is True
    old_journal.async_close.assert_awaited_once()

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        AsyncMock(return_value=True),
    ):
        assert await true_family_integration.async_unload_entry(
            hass,
            true_family_entry,
        )
    old_journal.async_close.assert_awaited_once()
    new_journal.async_close.assert_awaited_once()


async def test_cancellation_during_shutdown_closure_keeps_subscriptions_for_retry(
    hass: HomeAssistant,
    mqtt_mock,
    mqtt_client_mock,
    true_family_entry,
) -> None:
    """Propagate cancellation without claiming closure or unsubscribing."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    runtime: TrueFamilyRuntime = true_family_entry.runtime_data
    harness = bridge_harness_for(hass)
    harness.auto_close = False
    mqtt_client_mock.publish.reset_mock()

    shutdown_task = asyncio.create_task(runtime.async_shutdown())
    _topic, request, qos, retain = await async_wait_for_publish(mqtt_client_mock, 1)
    assert request["time"] == 0
    assert qos == 1
    assert retain is False
    shutdown_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await shutdown_task
    assert runtime._shutdown_complete is False
    assert len(runtime._mqtt._subscriptions) == 4

    harness.auto_close = True
    await runtime.async_shutdown()
    assert runtime._shutdown_complete is True
    recovery_requests = []
    for call in mqtt_client_mock.publish.call_args_list:
        if call.args[0] != PERMIT_REQUEST_TOPIC:
            continue
        payload = call.args[1]
        if isinstance(payload, bytes):
            payload = payload.decode()
        recovery_requests.append(json.loads(payload))
    assert recovery_requests
    assert all(request["time"] == 0 for request in recovery_requests)
    assert await hass.config_entries.async_unload(true_family_entry.entry_id)


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
