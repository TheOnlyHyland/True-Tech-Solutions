"""Protocol tests for the integration's lazy Home Assistant MQTT adapter."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
import types
from typing import Any
import unittest


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

    def test_non_bridge_event_is_rejected(self) -> None:
        with self.assertRaises(mqtt.BridgeEventError):
            mqtt.parse_bridge_event(
                {"type": "permit_join", "data": {"ieee_address": "0x1234"}}
            )

    def test_invalid_json_is_rejected(self) -> None:
        with self.assertRaises(mqtt.BridgeEventError):
            mqtt.parse_bridge_event("not-json")

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
            import asyncio

            asyncio.run(client.async_open_join(254, "transaction"))

    def test_open_and_close_require_matching_bridge_acknowledgements(self) -> None:
        import asyncio

        published = []
        callbacks = {}

        async def async_subscribe(_hass, topic, callback):
            callbacks[topic] = callback
            return lambda: None

        async def async_publish(_hass, topic, payload, qos, retain):
            published.append((topic, json.loads(payload), qos, retain))
            request = json.loads(payload)
            callbacks["zigbee2mqtt/bridge/response/permit_join"](
                types.SimpleNamespace(
                    payload=json.dumps(
                        {
                            "status": "ok",
                            "data": {"time": request["time"]},
                            "transaction": request["transaction"],
                        }
                    )
                )
            )

        mqtt_module = types.ModuleType("homeassistant.components.mqtt")
        setattr(mqtt_module, "async_subscribe", async_subscribe)
        setattr(mqtt_module, "async_publish", async_publish)
        setattr(
            mqtt_module,
            "async_wait_for_mqtt_client",
            lambda _hass: _completed_wait(),
        )
        components_module = types.ModuleType("homeassistant.components")
        setattr(components_module, "mqtt", mqtt_module)
        core_module = types.ModuleType("homeassistant.core")
        setattr(core_module, "callback", lambda func: func)
        homeassistant_module = types.ModuleType("homeassistant")
        setattr(homeassistant_module, "components", components_module)
        sys.modules["homeassistant"] = homeassistant_module
        sys.modules["homeassistant.components"] = components_module
        sys.modules["homeassistant.components.mqtt"] = mqtt_module
        sys.modules["homeassistant.core"] = core_module

        class FakeHass:
            loop: Any = None

        async def _completed_wait():
            return True

        async def exercise():
            hass = FakeHass()
            hass.loop = asyncio.get_running_loop()
            client = mqtt.Zigbee2MqttClient(
                hass,
                "zigbee2mqtt",
                lambda _event: None,
                lambda _coroutine, _name: None,
            )
            await client.async_setup()
            await client.async_open_join(60, "open-transaction")
            await client.async_close_join("close-transaction")
            await client.async_shutdown()

        asyncio.run(exercise())
        self.assertEqual([item[1]["time"] for item in published], [60, 0])
        self.assertTrue(all(item[2] == 1 for item in published))
        self.assertTrue(all(item[3] is False for item in published))

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
