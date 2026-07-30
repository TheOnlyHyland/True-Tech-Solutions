"""Acknowledged Zigbee2MQTT bridge adapter for guarded valve pairing."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import dataclass, replace
from datetime import UTC, datetime
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
RESPONSE_SECONDS = 10
IEEE_PATTERN = re.compile(r"^0x[0-9a-f]{16}$")


class BridgeEventError(ValueError):
    """Raised when a Zigbee2MQTT bridge event is malformed."""


class JoinRequestError(RuntimeError):
    """Raised when Zigbee2MQTT does not acknowledge a join-state request."""


def validate_base_topic(value: Any) -> str:
    """Validate one concrete MQTT root at both config and runtime boundaries."""

    if not isinstance(value, str):
        raise ValueError("Zigbee2MQTT base topic must be a string.")
    topic = value.strip().strip("/")
    try:
        encoded = topic.encode("utf-8")
    except UnicodeError as err:
        raise ValueError("Zigbee2MQTT base topic must be valid UTF-8.") from err
    if not encoded or len(encoded) + len("/bridge/response/permit_join") > 65535:
        raise ValueError("Zigbee2MQTT base topic has an invalid length.")
    if "+" in topic or "#" in topic:
        raise ValueError("Zigbee2MQTT base topic cannot use wildcards.")
    for character in topic:
        codepoint = ord(character)
        if (
            codepoint < 32
            or 0x7F <= codepoint <= 0x9F
            or 0xD800 <= codepoint <= 0xDFFF
            or 0xFDD0 <= codepoint <= 0xFDEF
            or codepoint & 0xFFFF in {0xFFFE, 0xFFFF}
        ):
            raise ValueError("Zigbee2MQTT base topic contains invalid characters.")
    return topic


@dataclass(frozen=True, slots=True)
class BridgeEvent:
    """Normalized subset of a Zigbee2MQTT bridge event."""

    event_type: str
    ieee_address: str
    friendly_name: str
    interview_status: str | None = None
    supported: bool | None = None
    model: str | None = None
    manufacturer: str | None = None
    received_at: datetime | None = None


def parse_bridge_event(payload: str | bytes | Mapping[str, Any]) -> BridgeEvent:
    """Parse documented join, announce, and interview bridge events."""

    decoded = _decode_object(payload, "Bridge event")
    event_type = decoded.get("type")
    if event_type not in {"device_joined", "device_interview", "device_announce"}:
        raise BridgeEventError(f"Unsupported bridge event type: {event_type!r}.")
    data = decoded.get("data")
    if not isinstance(data, dict):
        raise BridgeEventError("Bridge event data must be an object.")

    ieee_address = data.get("ieee_address")
    friendly_name = data.get("friendly_name", ieee_address)
    if not isinstance(ieee_address, str) or not IEEE_PATTERN.fullmatch(
        ieee_address.lower()
    ):
        raise BridgeEventError("Bridge event has no valid IEEE address.")
    if not isinstance(friendly_name, str) or not friendly_name:
        raise BridgeEventError("Bridge event has no friendly name.")

    definition = data.get("definition") or {}
    if not isinstance(definition, dict):
        raise BridgeEventError("Bridge event definition must be an object.")
    return BridgeEvent(
        event_type=event_type,
        ieee_address=ieee_address.lower(),
        friendly_name=friendly_name,
        interview_status=data.get("status"),
        supported=data.get("supported"),
        model=definition.get("model"),
        manufacturer=definition.get("vendor"),
    )


def _decode_object(
    payload: str | bytes | Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        try:
            decoded: Any = json.loads(payload)
        except json.JSONDecodeError as err:
            raise BridgeEventError(f"{label} is not valid JSON.") from err
    else:
        decoded = dict(payload)
    if not isinstance(decoded, dict):
        raise BridgeEventError(f"{label} must be an object.")
    return decoded


TaskFactory = Callable[[Coroutine[Any, Any, None], str], asyncio.Task]


class Zigbee2MqttClient:
    """Subscribe before publishing and require permit-join acknowledgements."""

    def __init__(
        self,
        hass: HomeAssistant,
        base_topic: str,
        event_handler: Callable[[BridgeEvent], Coroutine[Any, Any, None]],
        task_factory: TaskFactory,
    ) -> None:
        self.hass = hass
        self.base_topic = validate_base_topic(base_topic)
        self._event_handler = event_handler
        self._task_factory = task_factory
        self._subscriptions: list[Callable[[], None]] = []
        self._pending: dict[str, tuple[int, asyncio.Future[datetime]]] = {}

    @property
    def event_topic(self) -> str:
        """Return the documented Zigbee2MQTT bridge event topic."""

        return f"{self.base_topic}/bridge/event"

    @property
    def permit_join_topic(self) -> str:
        """Return the documented Zigbee2MQTT permit-join request topic."""

        return f"{self.base_topic}/bridge/request/permit_join"

    @property
    def permit_join_response_topic(self) -> str:
        """Return the documented permit-join response topic."""

        return f"{self.base_topic}/bridge/response/permit_join"

    async def async_setup(self) -> None:
        """Install event and response subscriptions before any request."""

        from homeassistant.components import mqtt
        from homeassistant.core import callback

        if not await mqtt.async_wait_for_mqtt_client(self.hass):
            raise RuntimeError("Home Assistant MQTT client is not ready.")

        @callback
        def bridge_event_received(message: Any) -> None:
            try:
                event = parse_bridge_event(message.payload)
            except BridgeEventError as err:
                _LOGGER.debug("Ignoring Zigbee2MQTT bridge event: %s", err)
                return
            self._task_factory(
                self._event_handler(replace(event, received_at=datetime.now(UTC))),
                "True Family Zigbee2MQTT bridge event",
            )

        @callback
        def join_response_received(message: Any) -> None:
            try:
                response = _decode_object(message.payload, "Permit-join response")
            except BridgeEventError as err:
                _LOGGER.warning("Ignoring malformed permit-join response: %s", err)
                return
            transaction = response.get("transaction")
            if not isinstance(transaction, str) or transaction not in self._pending:
                return
            expected_seconds, future = self._pending[transaction]
            if future.done():
                return
            data = response.get("data")
            acknowledged_seconds = data.get("time") if isinstance(data, dict) else None
            if response.get("status") != "ok" or acknowledged_seconds != expected_seconds:
                future.set_exception(
                    JoinRequestError(
                        str(response.get("error") or "Unexpected permit-join response.")
                    )
                )
                return
            future.set_result(datetime.now(UTC))

        subscriptions: list[Callable[[], None]] = []
        try:
            subscriptions.append(
                await mqtt.async_subscribe(
                    self.hass,
                    self.event_topic,
                    bridge_event_received,
                )
            )
            subscriptions.append(
                await mqtt.async_subscribe(
                    self.hass,
                    self.permit_join_response_topic,
                    join_response_received,
                )
            )
        except BaseException:
            while subscriptions:
                subscriptions.pop()()
            raise
        self._subscriptions.extend(subscriptions)

    async def async_open_join(self, seconds: int, transaction: str) -> datetime:
        """Open joining only after Zigbee2MQTT acknowledges the bounded request."""

        if seconds < 15 or seconds > 60:
            raise ValueError("Customer pairing must use a 15 to 60 second window.")
        return await self._async_request_join(seconds, transaction)

    async def async_close_join(self, transaction: str) -> datetime:
        """Close joining and require Zigbee2MQTT acknowledgement."""

        return await self._async_request_join(0, transaction)

    async def _async_request_join(self, seconds: int, transaction: str) -> datetime:
        """Validate at the publish sink and correlate the bridge response."""

        from homeassistant.components import mqtt

        if seconds != 0 and not 15 <= seconds <= 60:
            raise ValueError("Permit-join request exceeded the product safety window.")
        if not transaction or transaction in self._pending:
            raise ValueError("A unique permit-join transaction is required.")

        future = self.hass.loop.create_future()
        self._pending[transaction] = (seconds, future)
        payload = json.dumps({"time": seconds, "transaction": transaction})
        try:
            await mqtt.async_publish(
                self.hass,
                self.permit_join_topic,
                payload,
                qos=1,
                retain=False,
            )
            return await asyncio.wait_for(future, timeout=RESPONSE_SECONDS)
        except TimeoutError as err:
            raise JoinRequestError("Zigbee2MQTT did not acknowledge permit-join.") from err
        finally:
            self._pending.pop(transaction, None)

    async def async_shutdown(self) -> None:
        """Remove subscriptions and fail any pending requests."""

        while self._subscriptions:
            self._subscriptions.pop()()
        for _seconds, future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
