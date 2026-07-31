"""Protocol tests for the integration's lazy Home Assistant MQTT adapter."""

from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
import importlib
import json
from pathlib import Path
import sys
import types
from typing import Any, Callable
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"


def load_mqtt():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(PACKAGE_ROOT)]
    sys.modules[PACKAGE_NAME] = package
    return importlib.import_module(f"{PACKAGE_NAME}.mqtt")


mqtt = load_mqtt()
DEFAULT_RETAINED = object()


class FakeBroker:
    """Small callback-only broker surface for the lazy adapter."""

    def __init__(
        self,
        *,
        retained_state: Any = DEFAULT_RETAINED,
        retained_info: Any = DEFAULT_RETAINED,
        publish_handler: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.retained_state = (
            {"state": "online"}
            if retained_state is DEFAULT_RETAINED
            else retained_state
        )
        self.retained_info = (
            {"permit_join": False}
            if retained_info is DEFAULT_RETAINED
            else retained_info
        )
        self.publish_handler = publish_handler or self.acknowledge_and_report
        self.callbacks: dict[str, Callable[[Any], None]] = {}
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []
        self.unsubscribe_attempts: list[str] = []
        self.unsubscribe_failures: dict[str, int] = {}
        self.subscribe_failure_topic: str | None = None
        self.published: list[tuple[str, dict[str, Any], int, bool]] = []

    async def async_wait_for_mqtt_client(self, _hass) -> bool:
        return True

    async def async_subscribe(self, _hass, topic, callback):
        if topic == self.subscribe_failure_topic:
            raise RuntimeError("private-subscribe-error-canary")
        self.subscribed.append(topic)
        self.callbacks[topic] = callback
        retained = None
        if topic.endswith("/bridge/state"):
            retained = self.retained_state
        elif topic.endswith("/bridge/info"):
            retained = self.retained_info
        if retained is not None:
            callback(
                types.SimpleNamespace(payload=self.encode(retained), retain=True)
            )

        def unsubscribe() -> None:
            self.unsubscribe_attempts.append(topic)
            remaining_failures = self.unsubscribe_failures.get(topic, 0)
            if remaining_failures:
                self.unsubscribe_failures[topic] = remaining_failures - 1
                raise RuntimeError("private-unsubscribe-error-canary")
            self.unsubscribed.append(topic)
            self.callbacks.pop(topic, None)

        return unsubscribe

    async def async_publish(self, _hass, topic, payload, qos, retain):
        request = json.loads(payload)
        self.published.append((topic, request, qos, retain))
        self.publish_handler(request)

    def acknowledge_and_report(self, request: dict[str, Any]) -> None:
        self.fire(
            "bridge/response/permit_join",
            {
                "status": "ok",
                "data": {"time": request["time"]},
                "transaction": request["transaction"],
            },
        )
        info: dict[str, Any] = {"permit_join": request["time"] > 0}
        if request["time"] > 0:
            info["permit_join_end"] = (
                int(datetime.now(UTC).timestamp() * 1000) + request["time"] * 1000
            )
        self.fire("bridge/info", info)

    def fire(
        self,
        suffix: str,
        payload: Any,
        *,
        retain: bool = False,
        include_retain: bool = True,
    ) -> None:
        message = types.SimpleNamespace(payload=self.encode(payload))
        if include_retain:
            message.retain = retain
        self.callbacks[f"zigbee2mqtt/{suffix}"](message)

    @staticmethod
    def encode(payload: Any) -> str | bytes:
        if isinstance(payload, (str, bytes)):
            return payload
        return json.dumps(payload)


class FakeHass:
    loop: Any = None


def fake_home_assistant(broker: FakeBroker):
    mqtt_module = types.ModuleType("homeassistant.components.mqtt")
    setattr(mqtt_module, "async_subscribe", broker.async_subscribe)
    setattr(mqtt_module, "async_publish", broker.async_publish)
    setattr(
        mqtt_module,
        "async_wait_for_mqtt_client",
        broker.async_wait_for_mqtt_client,
    )
    components_module = types.ModuleType("homeassistant.components")
    setattr(components_module, "mqtt", mqtt_module)
    core_module = types.ModuleType("homeassistant.core")
    setattr(core_module, "callback", lambda func: func)
    homeassistant_module = types.ModuleType("homeassistant")
    setattr(homeassistant_module, "components", components_module)
    return patch.dict(
        sys.modules,
        {
            "homeassistant": homeassistant_module,
            "homeassistant.components": components_module,
            "homeassistant.components.mqtt": mqtt_module,
            "homeassistant.core": core_module,
        },
    )


async def new_client(broker: FakeBroker, state_handler=None):
    client = create_client(broker, state_handler)
    await client.async_setup()
    return client


def create_client(broker: FakeBroker, state_handler=None):
    hass = FakeHass()
    hass.loop = asyncio.get_running_loop()

    async def ignore_event(_event) -> None:
        return None

    return mqtt.Zigbee2MqttClient(
        hass,
        "zigbee2mqtt",
        ignore_event,
        lambda _coroutine, _name: None,
        state_handler,
    )


class MqttProtocolTests(unittest.TestCase):
    def test_successful_interview_is_normalized(self) -> None:
        event = mqtt.parse_bridge_event(
            {
                "type": "device_interview",
                "data": {
                    "ieee_address": "0xa4c138669e76493f",
                    "friendly_name": "candidate",
                    "status": "successful",
                    "supported": True,
                    "definition": {"model": "BRT-100-TRV", "vendor": "Moes"},
                },
            }
        )
        self.assertEqual(event.model, "BRT-100-TRV")
        self.assertEqual(event.manufacturer, "Moes")
        self.assertTrue(event.supported)

    def test_bridge_info_and_state_parsers_are_strict_and_payload_hidden(self) -> None:
        observed = datetime(2026, 7, 31, 10, 0, tzinfo=UTC)
        private_canary = "private-bridge-config-canary"
        current_milliseconds = int(
            (observed + timedelta(seconds=60)).timestamp() * 1000
        )
        parsed = mqtt.parse_bridge_info(
            {
                "permit_join": True,
                "permit_join_end": current_milliseconds,
                "config": {"private": private_canary},
            },
            observed_at=observed,
        )
        self.assertTrue(parsed.permit_join)
        self.assertEqual(
            parsed.permit_join_end,
            observed + timedelta(seconds=60),
        )
        self.assertFalse(parsed.online)
        self.assertEqual(parsed.generation, 0)
        legacy = mqtt.parse_bridge_info(
            {
                "permit_join": True,
                "permit_join_end": int(
                    (observed + timedelta(seconds=45)).timestamp()
                ),
            },
            observed_at=observed,
        )
        self.assertEqual(
            legacy.permit_join_end,
            observed + timedelta(seconds=45),
        )
        disabled = mqtt.parse_bridge_info(
            {"permit_join": False},
            observed_at=observed,
        )
        self.assertFalse(disabled.permit_join)
        self.assertIsNone(disabled.permit_join_end)
        self.assertTrue(mqtt.parse_bridge_state({"state": "online"}))
        self.assertFalse(mqtt.parse_bridge_state(b'{"state":"offline"}'))

        invalid_info = (
            {},
            {"permit_join": 0},
            {"permit_join": False, "permit_join_end": 1},
            {"permit_join": True, "permit_join_end": 1.0},
            {"permit_join": True, "permit_join_end": True},
            {"permit_join": True, "permit_join_end": 500_000_000_000},
            {"permit_join": True, "permit_join_end": 253_402_300_800_000},
            {
                "permit_join": True,
                "permit_join_end": int(
                    (observed + timedelta(seconds=260)).timestamp()
                ),
            },
            {"permit_join": private_canary},
        )
        for payload in invalid_info:
            with self.subTest(payload=type(payload.get("permit_join"))):
                with self.assertRaises(mqtt.BridgeEventError) as error:
                    mqtt.parse_bridge_info(payload, observed_at=observed)
                self.assertNotIn(private_canary, str(error.exception))
        for payload in (
            "online",
            {"state": "unknown"},
            {"state": "online", "private": private_canary},
        ):
            with self.assertRaises(mqtt.BridgeEventError) as error:
                mqtt.parse_bridge_state(payload)
            self.assertNotIn(private_canary, str(error.exception))

        state = mqtt.BridgePermitState(
            online=True,
            online_generation=3,
            generation=4,
            observed_at=observed,
            permit_join=False,
            permit_join_end=None,
        )
        self.assertNotIn(private_canary, repr(state))
        self.assertNotIn("observed_at", repr(state))
        with self.assertRaises(FrozenInstanceError):
            state.permit_join = True

    def test_setup_order_and_global_close_barrier(self) -> None:
        broker = FakeBroker()
        observed_states = []

        async def exercise() -> None:
            client = await new_client(
                broker,
                lambda state, transaction: observed_states.append(
                    (state, transaction)
                ),
            )
            initial = client._current_permit_state()
            self.assertIsNotNone(initial)
            self.assertTrue(initial.retained)
            self.assertTrue(initial.initial_retained)
            self.assertIsNone(client.current_closed_baseline())
            await client.async_reconcile_join_closed("startup-transaction")
            self.assertIsNotNone(client.current_closed_baseline())
            await client.async_open_join(60, "open-transaction")
            self.assertIsNone(client.current_closed_baseline())
            await client.async_close_join("close-transaction")
            await client.async_shutdown()

        with fake_home_assistant(broker):
            asyncio.run(exercise())
        self.assertEqual(
            broker.subscribed,
            [
                "zigbee2mqtt/bridge/state",
                "zigbee2mqtt/bridge/info",
                "zigbee2mqtt/bridge/response/permit_join",
                "zigbee2mqtt/bridge/event",
            ],
        )
        self.assertEqual([item[1]["time"] for item in broker.published], [0, 60, 0])
        self.assertTrue(all(item[2] == 1 for item in broker.published))
        self.assertTrue(all(item[3] is False for item in broker.published))
        self.assertEqual(broker.unsubscribed, list(reversed(broker.subscribed)))
        self.assertTrue(any(transaction == "open-transaction" for _, transaction in observed_states))

    def test_prior_closed_info_and_ack_alone_do_not_prove_closure(self) -> None:
        broker = FakeBroker()

        def ack_only(request: dict[str, Any]) -> None:
            broker.fire(
                "bridge/response/permit_join",
                {
                    "status": "ok",
                    "data": {"time": 0},
                    "transaction": request["transaction"],
                },
            )

        broker.publish_handler = ack_only

        async def exercise() -> None:
            client = await new_client(broker)
            with self.assertRaises(mqtt.JoinRequestError):
                await client.async_reconcile_join_closed("close-without-new-info")
            self.assertIsNone(client.current_closed_baseline())
            await client.async_shutdown()

        with (
            fake_home_assistant(broker),
            patch.object(mqtt, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
            patch.object(mqtt, "PERMIT_JOIN_RECONCILE_SECONDS", 0.02),
        ):
            asyncio.run(exercise())

    def test_wrong_ack_open_info_and_offline_state_all_fail_closed(self) -> None:
        scenarios = ("wrong_transaction", "wrong_time", "error", "open", "offline")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                broker = FakeBroker()

                def respond(request: dict[str, Any], scenario=scenario) -> None:
                    response = {
                        "status": "error" if scenario == "error" else "ok",
                        "data": {"time": 1 if scenario == "wrong_time" else 0},
                        "transaction": (
                            "different-transaction"
                            if scenario == "wrong_transaction"
                            else request["transaction"]
                        ),
                        "error": "private-ack-canary",
                    }
                    broker.fire("bridge/response/permit_join", response)
                    if scenario == "open":
                        broker.fire("bridge/info", {"permit_join": True})
                    elif scenario == "offline":
                        broker.fire("bridge/state", {"state": "offline"})

                broker.publish_handler = respond

                async def exercise() -> None:
                    client = await new_client(broker)
                    with self.assertRaises(mqtt.JoinRequestError) as error:
                        await client.async_reconcile_join_closed(
                            f"close-{scenario}"
                        )
                    self.assertNotIn("private-ack-canary", str(error.exception))
                    await client.async_shutdown()

                with (
                    fake_home_assistant(broker),
                    patch.object(mqtt, "PERMIT_JOIN_RESPONSE_SECONDS", 0.01),
                    patch.object(mqtt, "PERMIT_JOIN_RECONCILE_SECONDS", 0.02),
                ):
                    asyncio.run(exercise())

    def test_retained_or_missing_retain_info_never_proves_closure(self) -> None:
        scenarios = ("replayed", "delayed_initial", "missing_metadata")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                broker = FakeBroker(
                    retained_info=None if scenario == "delayed_initial" else DEFAULT_RETAINED
                )

                def respond(request: dict[str, Any], scenario=scenario) -> None:
                    broker.fire(
                        "bridge/response/permit_join",
                        {
                            "status": "ok",
                            "data": {"time": 0},
                            "transaction": request["transaction"],
                        },
                    )
                    broker.fire(
                        "bridge/info",
                        {"permit_join": False},
                        retain=scenario != "missing_metadata",
                        include_retain=scenario != "missing_metadata",
                    )

                broker.publish_handler = respond

                async def exercise() -> None:
                    client = await new_client(broker)
                    with self.assertRaises(mqtt.JoinRequestError):
                        await client.async_reconcile_join_closed(
                            f"close-{scenario}"
                        )
                    self.assertIsNone(client.current_closed_baseline())
                    await client.async_shutdown()

                with fake_home_assistant(broker):
                    asyncio.run(exercise())

    def test_repeated_online_invalidates_idle_proof_before_recovery(self) -> None:
        broker = FakeBroker()
        observations = []

        async def exercise() -> None:
            client = await new_client(
                broker,
                lambda state, transaction: observations.append((state, transaction)),
            )
            await client.async_reconcile_join_closed("initial-close")
            self.assertIsNotNone(client.current_closed_baseline())
            broker.fire("bridge/state", {"state": "online"})
            self.assertIsNone(client.current_closed_baseline())
            self.assertIsNone(observations[-1][0])
            await client.async_reconcile_join_closed("restart-close")
            self.assertIsNotNone(client.current_closed_baseline())
            self.assertTrue(all(item[1]["time"] == 0 for item in broker.published))
            await client.async_shutdown()

        with fake_home_assistant(broker):
            asyncio.run(exercise())

    def test_positive_info_before_or_after_ack_requires_both_before_success(self) -> None:
        for scenario in ("info_before_ack", "ack_before_info"):
            with self.subTest(scenario=scenario):
                broker = FakeBroker()
                observed_states = []

                async def exercise() -> None:
                    client = await new_client(
                        broker,
                        lambda state, transaction: observed_states.append(
                            (state, transaction)
                        ),
                    )
                    await client.async_reconcile_join_closed("initial-close")
                    request: dict[str, Any] = {}

                    def respond(published: dict[str, Any]) -> None:
                        request.update(published)
                        expected_end = int(
                            client._open_expected_end.timestamp() * 1000
                        )
                        if scenario == "info_before_ack":
                            broker.fire(
                                "bridge/info",
                                {
                                    "permit_join": True,
                                    "permit_join_end": expected_end,
                                },
                            )
                        else:
                            broker.fire(
                                "bridge/response/permit_join",
                                {
                                    "status": "ok",
                                    "data": {"time": published["time"]},
                                    "transaction": published["transaction"],
                                },
                            )

                    broker.publish_handler = respond
                    task = asyncio.create_task(
                        client.async_open_join(60, f"open-{scenario}")
                    )
                    await asyncio.sleep(0)
                    self.assertFalse(task.done())
                    self.assertFalse(
                        any(
                            transaction == f"open-{scenario}"
                            for _state, transaction in observed_states
                        )
                    )
                    expected_end = int(
                        client._open_expected_end.timestamp() * 1000
                    )
                    if scenario == "info_before_ack":
                        broker.fire(
                            "bridge/response/permit_join",
                            {
                                "status": "ok",
                                "data": {"time": request["time"]},
                                "transaction": request["transaction"],
                            },
                        )
                    else:
                        broker.fire(
                            "bridge/info",
                            {
                                "permit_join": True,
                                "permit_join_end": expected_end,
                            },
                        )
                    await task
                    self.assertTrue(
                        any(
                            transaction == f"open-{scenario}"
                            for _state, transaction in observed_states
                        )
                    )
                    broker.publish_handler = broker.acknowledge_and_report
                    await client.async_close_join(f"close-{scenario}")
                    await client.async_shutdown()

                with fake_home_assistant(broker):
                    asyncio.run(exercise())

    def test_invalid_or_multiple_provisional_open_info_fails_closed(self) -> None:
        for scenario in ("invalid_end", "multiple"):
            with self.subTest(scenario=scenario):
                broker = FakeBroker()
                observed_states = []

                async def exercise() -> None:
                    client = await new_client(
                        broker,
                        lambda state, transaction: observed_states.append(
                            (state, transaction)
                        ),
                    )
                    await client.async_reconcile_join_closed("initial-close")
                    request: dict[str, Any] = {}

                    def respond(published: dict[str, Any]) -> None:
                        request.update(published)
                        expected_end = int(
                            client._open_expected_end.timestamp() * 1000
                        )
                        info = {
                            "permit_join": True,
                            "permit_join_end": (
                                expected_end - 6_000
                                if scenario == "invalid_end"
                                else expected_end
                            ),
                        }
                        broker.fire("bridge/info", info)
                        if scenario == "multiple":
                            broker.fire(
                                "bridge/info",
                                {
                                    "permit_join": True,
                                    "permit_join_end": expected_end - 1_000,
                                },
                            )

                    broker.publish_handler = respond
                    task = asyncio.create_task(
                        client.async_open_join(60, f"open-{scenario}")
                    )
                    await asyncio.sleep(0)
                    self.assertFalse(task.done())
                    if scenario == "multiple":
                        self.assertIsNone(observed_states[-1][0])
                    broker.fire(
                        "bridge/response/permit_join",
                        {
                            "status": "ok",
                            "data": {"time": request["time"]},
                            "transaction": request["transaction"],
                        },
                    )
                    with self.assertRaises(mqtt.JoinRequestError):
                        await task
                    await client.async_shutdown()

                with fake_home_assistant(broker):
                    asyncio.run(exercise())

    def test_wrong_or_error_ack_rejects_provisional_open_synchronously(self) -> None:
        for scenario in ("wrong_transaction", "error"):
            with self.subTest(scenario=scenario):
                broker = FakeBroker()
                observed_states = []

                async def exercise() -> None:
                    client = await new_client(
                        broker,
                        lambda state, transaction: observed_states.append(
                            (state, transaction)
                        ),
                    )
                    await client.async_reconcile_join_closed("initial-close")

                    def respond(request: dict[str, Any]) -> None:
                        broker.fire(
                            "bridge/info",
                            {
                                "permit_join": True,
                                "permit_join_end": int(
                                    client._open_expected_end.timestamp() * 1000
                                ),
                            },
                        )
                        broker.fire(
                            "bridge/response/permit_join",
                            {
                                "status": "error" if scenario == "error" else "ok",
                                "data": {"time": request["time"]},
                                "transaction": (
                                    "wrong-transaction"
                                    if scenario == "wrong_transaction"
                                    else request["transaction"]
                                ),
                                "error": "private-open-ack-canary",
                            },
                        )
                        self.assertIsNone(observed_states[-1][0])

                    broker.publish_handler = respond
                    with self.assertRaises(mqtt.JoinRequestError) as error:
                        await client.async_open_join(60, f"open-{scenario}")
                    self.assertNotIn(
                        "private-open-ack-canary",
                        str(error.exception),
                    )
                    await client.async_shutdown()

                with fake_home_assistant(broker):
                    asyncio.run(exercise())

    def test_post_ack_positive_info_requires_deadlines_and_expected_end(self) -> None:
        scenarios = ("after_deadline", "mismatched_end")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                broker = FakeBroker()

                async def exercise() -> None:
                    client = await new_client(broker)
                    await client.async_reconcile_join_closed("initial-close")

                    def respond(request: dict[str, Any]) -> None:
                        acknowledged = {
                            "status": "ok",
                            "data": {"time": request["time"]},
                            "transaction": request["transaction"],
                        }
                        expected_end = int(datetime.now(UTC).timestamp() * 1000) + (
                            request["time"] * 1000
                        )
                        info = {
                            "permit_join": True,
                            "permit_join_end": (
                                expected_end - 6_000
                                if scenario == "mismatched_end"
                                else expected_end
                            ),
                        }
                        broker.fire("bridge/response/permit_join", acknowledged)
                        if scenario == "after_deadline":
                            client._open_attribution_deadline = (
                                client.hass.loop.time() - 1
                            )
                        broker.fire("bridge/info", info)

                    broker.publish_handler = respond
                    with self.assertRaises(mqtt.JoinRequestError):
                        await client.async_open_join(60, f"open-{scenario}")
                    await client.async_shutdown()

                with fake_home_assistant(broker):
                    asyncio.run(exercise())

    def test_partial_setup_unsubscribe_failure_is_retryable_without_duplicates(self) -> None:
        broker = FakeBroker()
        broker.subscribe_failure_topic = "zigbee2mqtt/bridge/response/permit_join"
        broker.unsubscribe_failures["zigbee2mqtt/bridge/info"] = 1

        async def exercise() -> None:
            client = create_client(broker)
            with self.assertRaisesRegex(RuntimeError, "could not be installed"):
                await client.async_setup()
            self.assertTrue(client.has_subscriptions)
            self.assertEqual(
                [subscription.role for subscription in client._subscriptions],
                ["state", "info"],
            )
            subscribed = list(broker.subscribed)
            with self.assertRaisesRegex(RuntimeError, "already installed"):
                await client.async_setup()
            self.assertEqual(broker.subscribed, subscribed)
            await client.async_shutdown()
            self.assertFalse(client.has_subscriptions)
            self.assertEqual(
                broker.unsubscribe_attempts.count("zigbee2mqtt/bridge/info"),
                2,
            )
            self.assertEqual(
                broker.unsubscribe_attempts.count("zigbee2mqtt/bridge/state"),
                1,
            )

        with fake_home_assistant(broker):
            asyncio.run(exercise())

    def test_shutdown_unsubscribe_failure_retains_failed_and_unattempted_handles(self) -> None:
        broker = FakeBroker()

        async def exercise() -> None:
            client = await new_client(broker)
            await client.async_reconcile_join_closed("initial-close")
            broker.unsubscribe_failures["zigbee2mqtt/bridge/event"] = 1
            with self.assertRaisesRegex(RuntimeError, "could not be removed"):
                await client.async_shutdown()
            self.assertTrue(client.has_subscriptions)
            self.assertEqual(len(client._subscriptions), 4)
            self.assertTrue(client.has_shutdown_safety_coverage)
            subscribed = list(broker.subscribed)
            await client.async_shutdown()
            self.assertFalse(client.has_subscriptions)
            self.assertEqual(broker.subscribed, subscribed)
            self.assertEqual(
                broker.unsubscribe_attempts.count("zigbee2mqtt/bridge/event"),
                2,
            )

        with fake_home_assistant(broker):
            asyncio.run(exercise())

    def test_customer_join_window_is_bounded_before_publish(self) -> None:
        client = mqtt.Zigbee2MqttClient(
            None,
            "zigbee2mqtt/",
            lambda _event: None,
            lambda _coroutine, _name: None,
        )
        self.assertEqual(
            client.permit_join_topic,
            "zigbee2mqtt/bridge/request/permit_join",
        )
        with self.assertRaises(ValueError):
            asyncio.run(client.async_open_join(254, "transaction"))

    def test_invalid_base_topic_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            mqtt.Zigbee2MqttClient(
                None,
                "zigbee2mqtt/#",
                lambda _event: None,
                lambda _coroutine, _name: None,
            )


if __name__ == "__main__":
    unittest.main()
