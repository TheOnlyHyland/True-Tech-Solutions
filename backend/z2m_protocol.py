"""Documented Zigbee2MQTT message shapes used by the prototype."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from backend.models import CommandIntent


BASE_TOPIC = "zigbee2mqtt"
BRIDGE_EVENT_TOPIC = f"{BASE_TOPIC}/bridge/event"
PERMIT_JOIN_REQUEST_TOPIC = f"{BASE_TOPIC}/bridge/request/permit_join"
DEVICE_RENAME_REQUEST_TOPIC = f"{BASE_TOPIC}/bridge/request/device/rename"


class BridgeEventError(ValueError):
    """Raised when a bridge event is malformed or unsupported."""


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


def permit_join_intent(seconds: int, transaction: str) -> CommandIntent:
    """Build, but do not publish, a timed permit-to-join request."""

    if seconds < 0 or seconds > 254:
        raise ValueError("Permit-to-join duration must be between 0 and 254 seconds.")
    return CommandIntent(
        topic=PERMIT_JOIN_REQUEST_TOPIC,
        payload={"time": seconds, "transaction": transaction},
    )


def close_join_intent(transaction: str) -> CommandIntent:
    """Build a request that immediately closes Zigbee joining."""

    return permit_join_intent(0, transaction)


def rename_device_intent(
    source: str,
    destination: str,
    transaction: str,
) -> CommandIntent:
    """Build a staging rename request without changing HA entity IDs."""

    if not source or not destination:
        raise ValueError("Both source and destination device names are required.")
    return CommandIntent(
        topic=DEVICE_RENAME_REQUEST_TOPIC,
        payload={
            "from": source,
            "to": destination,
            "homeassistant_rename": False,
            "transaction": transaction,
        },
    )


def parse_bridge_event(payload: str | bytes | Mapping[str, Any]) -> BridgeEvent:
    """Parse a documented `bridge/event` payload and reject weak identities."""

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        try:
            decoded: Any = json.loads(payload)
        except json.JSONDecodeError as err:
            raise BridgeEventError("Bridge event is not valid JSON.") from err
    else:
        decoded = dict(payload)

    if not isinstance(decoded, dict):
        raise BridgeEventError("Bridge event must be a JSON object.")

    event_type = decoded.get("type")
    if event_type not in {"device_joined", "device_interview", "device_announce"}:
        raise BridgeEventError(f"Unsupported bridge event type: {event_type!r}.")

    data = decoded.get("data")
    if not isinstance(data, dict):
        raise BridgeEventError("Bridge event data must be an object.")

    ieee_address = data.get("ieee_address")
    friendly_name = data.get("friendly_name", ieee_address)
    if not isinstance(ieee_address, str) or not ieee_address.startswith("0x"):
        raise BridgeEventError("Bridge event does not contain a valid IEEE address.")
    if not isinstance(friendly_name, str) or not friendly_name:
        raise BridgeEventError("Bridge event does not contain a friendly name.")

    definition = data.get("definition") or {}
    if not isinstance(definition, dict):
        raise BridgeEventError("Bridge event definition must be an object.")

    return BridgeEvent(
        event_type=event_type,
        ieee_address=ieee_address,
        friendly_name=friendly_name,
        interview_status=data.get("status"),
        supported=data.get("supported"),
        model=definition.get("model"),
        manufacturer=definition.get("vendor"),
    )
