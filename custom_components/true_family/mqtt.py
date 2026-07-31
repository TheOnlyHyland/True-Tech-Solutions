"""Acknowledged Zigbee2MQTT bridge adapter for guarded valve pairing."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Callable

from .const import (
    PERMIT_JOIN_BASELINE_MAX_AGE_SECONDS,
    PERMIT_JOIN_END_CLOCK_SKEW_SECONDS,
    PERMIT_JOIN_END_MAX_SECONDS,
    PERMIT_JOIN_OPEN_INFO_SECONDS,
    PERMIT_JOIN_RECONCILE_SECONDS,
    PERMIT_JOIN_RESPONSE_SECONDS,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
IEEE_PATTERN = re.compile(r"^0x[0-9a-f]{16}$")
TRANSACTION_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_UNIX_SECONDS = 253402300799
_MIN_UNIX_MILLISECONDS = 1_000_000_000_000
_MAX_UNIX_MILLISECONDS = _MAX_UNIX_SECONDS * 1000 + 999
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class BridgeEventError(ValueError):
    """Raised when a Zigbee2MQTT bridge event is malformed."""


class JoinRequestError(RuntimeError):
    """Raised when Zigbee2MQTT does not prove a safe join state."""


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


@dataclass(frozen=True, slots=True, repr=False)
class BridgePermitState:
    """Payload-hidden projection of current Zigbee2MQTT permit state."""

    online: bool
    online_generation: int
    generation: int
    observed_at: datetime
    permit_join: bool
    permit_join_end: datetime | None
    retained: bool = False
    initial_retained: bool = False

    def __repr__(self) -> str:
        """Return state evidence without reproducing any bridge payload."""

        return (
            "<BridgePermitState "
            f"online={self.online} permit_join={self.permit_join} "
            f"generation={self.generation}>"
        )


@dataclass(slots=True)
class _SubscriptionHandle:
    role: str
    unsubscribe: Callable[[], None]


def parse_bridge_event(payload: str | bytes | Mapping[str, Any]) -> BridgeEvent:
    """Parse documented join, announce, and interview bridge events."""

    decoded = _decode_object(payload, "Bridge event")
    event_type = decoded.get("type")
    if event_type not in {"device_joined", "device_interview", "device_announce"}:
        raise BridgeEventError("Bridge event type is unsupported.")
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


def parse_bridge_info(
    payload: str | bytes | Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
    online: bool = False,
    online_generation: int = 0,
    generation: int = 0,
    retained: bool = False,
    initial_retained: bool = False,
) -> BridgePermitState:
    """Project strict permit state from a potentially large bridge/info payload."""

    decoded = _decode_object(payload, "Bridge info")
    permit_join = decoded.get("permit_join")
    if type(permit_join) is not bool:
        raise BridgeEventError("Bridge info has no valid permit-join state.")

    observed = observed_at or datetime.now(UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise BridgeEventError("Bridge info observation time must be timezone-aware.")
    observed = observed.astimezone(UTC)
    permit_join_end = None
    if "permit_join_end" in decoded:
        raw_end = decoded["permit_join_end"]
        if not permit_join or type(raw_end) is not int:
            raise BridgeEventError("Bridge info has no valid permit-join end.")
        if 0 <= raw_end <= _MAX_UNIX_SECONDS:
            end_delta = timedelta(seconds=raw_end)
        elif _MIN_UNIX_MILLISECONDS <= raw_end <= _MAX_UNIX_MILLISECONDS:
            end_delta = timedelta(milliseconds=raw_end)
        else:
            raise BridgeEventError("Bridge info permit-join end is out of range.")
        try:
            permit_join_end = _UNIX_EPOCH + end_delta
        except (OSError, OverflowError, ValueError) as err:
            raise BridgeEventError(
                "Bridge info permit-join end is out of range."
            ) from err
        remaining = (permit_join_end - observed).total_seconds()
        if not (
            -PERMIT_JOIN_END_CLOCK_SKEW_SECONDS
            <= remaining
            <= PERMIT_JOIN_END_MAX_SECONDS + PERMIT_JOIN_END_CLOCK_SKEW_SECONDS
        ):
            raise BridgeEventError("Bridge info permit-join end is not bounded.")
    return BridgePermitState(
        online=online,
        online_generation=online_generation,
        generation=generation,
        observed_at=observed,
        permit_join=permit_join,
        permit_join_end=permit_join_end,
        retained=retained,
        initial_retained=initial_retained,
    )


def parse_bridge_state(payload: str | bytes | Mapping[str, Any]) -> bool:
    """Parse the exact documented online/offline bridge/state payload."""

    decoded = _decode_object(payload, "Bridge state")
    if set(decoded) != {"state"}:
        raise BridgeEventError("Bridge state must contain only its state field.")
    state = decoded["state"]
    if type(state) is not str or state not in {"online", "offline"}:
        raise BridgeEventError("Bridge state is not recognized.")
    return state == "online"


def _decode_object(
    payload: str | bytes | Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeError as err:
            raise BridgeEventError(f"{label} is not valid UTF-8.") from err
    if isinstance(payload, str):
        try:
            decoded: Any = json.loads(payload)
        except (json.JSONDecodeError, UnicodeError) as err:
            raise BridgeEventError(f"{label} is not valid JSON.") from err
    elif isinstance(payload, Mapping):
        decoded = dict(payload)
    else:
        raise BridgeEventError(f"{label} must be an object.")
    if not isinstance(decoded, dict):
        raise BridgeEventError(f"{label} must be an object.")
    return decoded


TaskFactory = Callable[[Coroutine[Any, Any, None], str], asyncio.Task]
PermitStateHandler = Callable[[BridgePermitState | None, str | None], None]


class Zigbee2MqttClient:
    """Track bridge state and prove every global permit-join transition."""

    def __init__(
        self,
        hass: HomeAssistant,
        base_topic: str,
        event_handler: Callable[[BridgeEvent], Coroutine[Any, Any, None]],
        task_factory: TaskFactory,
        permit_state_handler: PermitStateHandler | None = None,
    ) -> None:
        self.hass = hass
        self.base_topic = validate_base_topic(base_topic)
        self._event_handler = event_handler
        self._task_factory = task_factory
        self._permit_state_handler = permit_state_handler
        self._subscriptions: list[_SubscriptionHandle] = []
        self._pending: dict[str, tuple[int, asyncio.Future[datetime]]] = {}
        self._state_changed = asyncio.Event()
        self._subscribed = False
        self._generation = 0
        self._setup_generation = 0
        self._unsafe_generation = 0
        self._unattributed_open_generation = 0
        self._online: bool | None = None
        self._online_generation = 0
        self._bridge_state_invalid = False
        self._permit_join: bool | None = None
        self._permit_join_end: datetime | None = None
        self._permit_retained = False
        self._permit_initial_retained = False
        self._bridge_info_seen = False
        self._permit_generation = 0
        self._permit_observed_at: datetime | None = None
        self._permit_observed_monotonic: float | None = None
        self._closed_proof_generation = 0
        self._active_close_request_generation: int | None = None
        self._open_transaction: str | None = None
        self._open_request_generation = 0
        self._open_request_started_at: datetime | None = None
        self._open_request_started_monotonic = 0.0
        self._open_acknowledged = False
        self._open_acknowledged_at: datetime | None = None
        self._open_expected_end: datetime | None = None
        self._open_attribution_deadline = 0.0
        self._open_window_deadline = 0.0
        self._open_info_generation = 0
        self._open_provisional_state: BridgePermitState | None = None

    @property
    def event_topic(self) -> str:
        """Return the documented Zigbee2MQTT bridge event topic."""

        return f"{self.base_topic}/bridge/event"

    @property
    def bridge_info_topic(self) -> str:
        """Return the documented Zigbee2MQTT bridge info topic."""

        return f"{self.base_topic}/bridge/info"

    @property
    def bridge_state_topic(self) -> str:
        """Return the documented Zigbee2MQTT bridge state topic."""

        return f"{self.base_topic}/bridge/state"

    @property
    def permit_join_topic(self) -> str:
        """Return the documented Zigbee2MQTT permit-join request topic."""

        return f"{self.base_topic}/bridge/request/permit_join"

    @property
    def permit_join_response_topic(self) -> str:
        """Return the documented permit-join response topic."""

        return f"{self.base_topic}/bridge/response/permit_join"

    async def async_setup(self) -> None:
        """Install every bridge subscription before any request is published."""

        from homeassistant.components import mqtt
        from homeassistant.core import callback

        if self._subscribed or self._subscriptions:
            raise RuntimeError("Zigbee2MQTT subscriptions are already installed.")
        if not await mqtt.async_wait_for_mqtt_client(self.hass):
            raise RuntimeError("Home Assistant MQTT client is not ready.")

        @callback
        def bridge_state_received(message: Any) -> None:
            generation = self._next_generation()
            try:
                self._strict_message_retain(message, "Bridge state")
                online = parse_bridge_state(message.payload)
            except BridgeEventError:
                _LOGGER.warning("Ignoring malformed Zigbee2MQTT bridge state.")
                self._online = None
                self._bridge_state_invalid = True
                self._mark_unsafe(generation)
                self._notify_permit_state(None, None)
                return
            was_online = self._online is True
            self._online = online
            self._online_generation = generation
            self._bridge_state_invalid = False
            if online and was_online:
                self._mark_unsafe(generation)
                self._notify_permit_state(None, None)
                return
            if not online:
                self._mark_unsafe(generation)
            self._state_changed.set()
            state = self._current_permit_state()
            self._notify_classified_permit_state(state)

        @callback
        def bridge_info_received(message: Any) -> None:
            observed_at = datetime.now(UTC)
            generation = self._next_generation()
            try:
                retained = self._strict_message_retain(message, "Bridge info")
                initial_retained = retained and not self._bridge_info_seen
                self._bridge_info_seen = True
                parsed = parse_bridge_info(
                    message.payload,
                    observed_at=observed_at,
                    online=self._online is True,
                    online_generation=self._online_generation,
                    generation=generation,
                    retained=retained,
                    initial_retained=initial_retained,
                )
            except BridgeEventError:
                self._bridge_info_seen = True
                _LOGGER.warning("Ignoring malformed Zigbee2MQTT bridge info.")
                self._permit_join = None
                self._permit_join_end = None
                self._permit_retained = False
                self._permit_initial_retained = False
                self._permit_generation = generation
                self._permit_observed_at = None
                self._permit_observed_monotonic = None
                self._mark_unsafe(generation)
                self._notify_permit_state(None, None)
                return
            self._permit_join = parsed.permit_join
            self._permit_join_end = parsed.permit_join_end
            self._permit_retained = parsed.retained
            self._permit_initial_retained = parsed.initial_retained
            self._permit_generation = generation
            self._permit_observed_at = parsed.observed_at
            self._permit_observed_monotonic = self.hass.loop.time()
            if parsed.permit_join:
                self._closed_proof_generation = 0
            self._state_changed.set()
            if parsed.retained and (
                not parsed.initial_retained
                or self._active_close_request_generation is not None
            ):
                self._mark_unsafe(generation)
                self._notify_permit_state(None, None)
                return
            state = self._current_permit_state()
            self._notify_classified_permit_state(state)

        @callback
        def bridge_event_received(message: Any) -> None:
            try:
                event = parse_bridge_event(message.payload)
            except BridgeEventError as err:
                _LOGGER.debug("Ignoring Zigbee2MQTT bridge event: %s", err)
                return
            self._task_factory(
                self._event_handler(
                    BridgeEvent(
                        event_type=event.event_type,
                        ieee_address=event.ieee_address,
                        friendly_name=event.friendly_name,
                        interview_status=event.interview_status,
                        supported=event.supported,
                        model=event.model,
                        manufacturer=event.manufacturer,
                        received_at=datetime.now(UTC),
                    )
                ),
                "True Family Zigbee2MQTT bridge event",
            )

        @callback
        def join_response_received(message: Any) -> None:
            try:
                response = _decode_object(message.payload, "Permit-join response")
            except BridgeEventError:
                _LOGGER.warning("Ignoring malformed permit-join response.")
                self._reject_provisional_open(fail_pending=True)
                return
            transaction = response.get("transaction")
            if type(transaction) is not str or transaction not in self._pending:
                self._reject_provisional_open(fail_pending=True)
                return
            expected_seconds, future = self._pending[transaction]
            if future.done():
                return
            try:
                retained = self._strict_message_retain(
                    message,
                    "Permit-join response",
                )
            except BridgeEventError:
                retained = True
            data = response.get("data")
            acknowledged_seconds = data.get("time") if isinstance(data, dict) else None
            if (
                response.get("status") != "ok"
                or retained
                or type(acknowledged_seconds) is not int
                or acknowledged_seconds != expected_seconds
            ):
                if expected_seconds > 0:
                    self._reject_provisional_open()
                future.set_exception(
                    JoinRequestError(
                        "Zigbee2MQTT returned an invalid permit-join acknowledgement."
                    )
                )
                return
            acknowledged_at = datetime.now(UTC)
            if expected_seconds > 0:
                if self._open_transaction != transaction:
                    self._reject_provisional_open()
                    future.set_exception(
                        JoinRequestError(
                            "Zigbee2MQTT permit-join ownership changed before ACK."
                        )
                    )
                    return
                self._open_acknowledged = True
                self._open_acknowledged_at = acknowledged_at
                self._commit_provisional_open(transaction)
            future.set_result(acknowledged_at)

        try:
            self._subscriptions.append(
                _SubscriptionHandle(
                    "state",
                    await mqtt.async_subscribe(
                        self.hass,
                        self.bridge_state_topic,
                        bridge_state_received,
                    ),
                )
            )
            self._subscriptions.append(
                _SubscriptionHandle(
                    "info",
                    await mqtt.async_subscribe(
                        self.hass,
                        self.bridge_info_topic,
                        bridge_info_received,
                    ),
                )
            )
            self._subscriptions.append(
                _SubscriptionHandle(
                    "response",
                    await mqtt.async_subscribe(
                        self.hass,
                        self.permit_join_response_topic,
                        join_response_received,
                    ),
                )
            )
            self._subscriptions.append(
                _SubscriptionHandle(
                    "event",
                    await mqtt.async_subscribe(
                        self.hass,
                        self.event_topic,
                        bridge_event_received,
                    ),
                )
            )
        except asyncio.CancelledError:
            try:
                self._unsubscribe_installed()
            except RuntimeError:
                pass
            if not self._subscriptions:
                self._reset_observations()
            raise
        except Exception:
            try:
                self._unsubscribe_installed()
            except RuntimeError:
                pass
            if not self._subscriptions:
                self._reset_observations()
            raise RuntimeError(
                "Zigbee2MQTT subscriptions could not be installed."
            ) from None
        self._subscribed = True
        self._setup_generation = self._generation

    @property
    def has_subscriptions(self) -> bool:
        """Return whether one or more installed callbacks still need cleanup."""

        return bool(self._subscriptions)

    @property
    def has_shutdown_safety_coverage(self) -> bool:
        """Return whether a fresh close barrier can still be observed."""

        if not self._subscribed:
            return False
        roles = {subscription.role for subscription in self._subscriptions}
        return {"state", "info", "response"}.issubset(roles)

    def current_closed_baseline(self) -> BridgePermitState | None:
        """Return current online/closed proof without mutating bridge state."""

        if (
            not self.has_shutdown_safety_coverage
            or self._closed_proof_generation <= self._setup_generation
        ):
            return None
        state = self._current_permit_state()
        observed_monotonic = self._permit_observed_monotonic
        if (
            state is None
            or not state.online
            or state.permit_join
            or state.retained
            or state.generation < self._closed_proof_generation
            or observed_monotonic is None
            or self.hass.loop.time() - observed_monotonic
            > PERMIT_JOIN_BASELINE_MAX_AGE_SECONDS
        ):
            return None
        return state

    async def async_open_join(self, seconds: int, transaction: str) -> datetime:
        """Open joining only from a current, globally proved closed baseline."""

        if seconds < 15 or seconds > 60:
            raise ValueError("Customer pairing must use a 15 to 60 second window.")
        if self.current_closed_baseline() is None:
            raise JoinRequestError(
                "A current online and closed Zigbee2MQTT baseline is required."
            )
        self._validate_transaction(transaction)
        request_generation = self._generation
        self._begin_open_attribution(transaction, seconds, request_generation)
        acknowledged_at, actual_request_generation = await self._async_request_join(
            seconds,
            transaction,
        )
        try:
            async with asyncio.timeout(PERMIT_JOIN_OPEN_INFO_SECONDS):
                while True:
                    if (
                        actual_request_generation != request_generation
                        or self._unsafe_generation > request_generation
                        or self._unattributed_open_generation > request_generation
                        or self._online is not True
                    ):
                        raise JoinRequestError(
                            "Zigbee2MQTT bridge state changed unsafely while "
                            "joining opened."
                        )
                    if (
                        self._open_acknowledged
                        and self._open_info_generation > request_generation
                    ):
                        return acknowledged_at
                    generation = self._generation
                    await self._async_wait_for_generation_after(generation)
        except TimeoutError as err:
            raise JoinRequestError(
                "Zigbee2MQTT did not provide attributable permit-open proof."
            ) from err

    async def async_close_join(self, transaction: str) -> datetime:
        """Close joining and require a fresh global bridge-state proof."""

        return await self.async_reconcile_join_closed(transaction)

    async def async_reconcile_join_closed(self, transaction: str) -> datetime:
        """Publish a global close and prove its ACK plus newer bridge/info state."""

        if not self.has_shutdown_safety_coverage:
            raise JoinRequestError("Zigbee2MQTT bridge subscriptions are unavailable.")
        self._validate_transaction(transaction)
        try:
            async with asyncio.timeout(PERMIT_JOIN_RECONCILE_SECONDS):
                generation = self._generation
                while self._online is None:
                    if self._bridge_state_invalid:
                        raise JoinRequestError(
                            "Zigbee2MQTT bridge state is not safe for reconciliation."
                        )
                    await self._async_wait_for_generation_after(generation)
                    generation = self._generation
                if self._online is not True:
                    raise JoinRequestError(
                        "Zigbee2MQTT bridge is offline; joining cannot be reconciled."
                    )

                self._active_close_request_generation = self._generation
                try:
                    _acknowledged_at, request_generation = (
                        await self._async_request_join(0, transaction)
                    )
                    while True:
                        if self._unsafe_generation > request_generation:
                            raise JoinRequestError(
                                "Zigbee2MQTT bridge state became unsafe during "
                                "closure."
                            )
                        state = self._current_permit_state()
                        if self._online is not True:
                            raise JoinRequestError(
                                "Zigbee2MQTT bridge went offline during closure."
                            )
                        if (
                            state is not None
                            and state.online
                            and state.generation > request_generation
                            and not state.permit_join
                            and not state.retained
                        ):
                            self._closed_proof_generation = state.generation
                            self._clear_open_attribution()
                            return state.observed_at
                        generation = self._generation
                        await self._async_wait_for_generation_after(generation)
                finally:
                    self._active_close_request_generation = None
        except TimeoutError as err:
            raise JoinRequestError(
                "Zigbee2MQTT did not provide fresh global join-closure proof."
            ) from err

    async def _async_request_join(
        self,
        seconds: int,
        transaction: str,
    ) -> tuple[datetime, int]:
        """Validate at the publish sink and correlate the exact bridge response."""

        from homeassistant.components import mqtt

        if seconds != 0 and not 15 <= seconds <= 60:
            raise ValueError("Permit-join request exceeded the product safety window.")
        self._validate_transaction(transaction)
        if transaction in self._pending:
            raise ValueError("A unique permit-join transaction is required.")

        future = self.hass.loop.create_future()
        self._pending[transaction] = (seconds, future)
        request_generation = self._generation
        payload = json.dumps(
            {"time": seconds, "transaction": transaction},
            separators=(",", ":"),
            sort_keys=True,
        )
        try:
            await mqtt.async_publish(
                self.hass,
                self.permit_join_topic,
                payload,
                qos=1,
                retain=False,
            )
            acknowledged_at = await asyncio.wait_for(
                future,
                timeout=PERMIT_JOIN_RESPONSE_SECONDS,
            )
            return acknowledged_at, request_generation
        except TimeoutError as err:
            raise JoinRequestError(
                "Zigbee2MQTT did not acknowledge the permit-join request."
            ) from err
        finally:
            self._pending.pop(transaction, None)

    async def _async_wait_for_generation_after(self, generation: int) -> None:
        while self._generation <= generation:
            self._state_changed.clear()
            if self._generation > generation:
                return
            await self._state_changed.wait()

    def _next_generation(self) -> int:
        self._generation += 1
        self._state_changed.set()
        return self._generation

    def _current_permit_state(self) -> BridgePermitState | None:
        if (
            self._online is None
            or self._permit_join is None
            or self._permit_observed_at is None
        ):
            return None
        return BridgePermitState(
            online=self._online,
            online_generation=self._online_generation,
            generation=self._permit_generation,
            observed_at=self._permit_observed_at,
            permit_join=self._permit_join,
            permit_join_end=self._permit_join_end,
            retained=self._permit_retained,
            initial_retained=self._permit_initial_retained,
        )

    def _mark_unsafe(self, generation: int) -> None:
        self._unsafe_generation = generation
        self._closed_proof_generation = 0
        self._clear_open_attribution()
        self._state_changed.set()

    def _begin_open_attribution(
        self,
        transaction: str,
        seconds: int,
        request_generation: int,
    ) -> None:
        request_started_at = datetime.now(UTC)
        request_started_monotonic = self.hass.loop.time()
        self._closed_proof_generation = 0
        self._open_transaction = transaction
        self._open_request_generation = request_generation
        self._open_request_started_at = request_started_at
        self._open_request_started_monotonic = request_started_monotonic
        self._open_acknowledged = False
        self._open_acknowledged_at = None
        self._open_expected_end = request_started_at + timedelta(seconds=seconds)
        self._open_attribution_deadline = (
            request_started_monotonic
            + PERMIT_JOIN_RESPONSE_SECONDS
            + PERMIT_JOIN_OPEN_INFO_SECONDS
        )
        self._open_window_deadline = (
            request_started_monotonic
            + seconds
            + PERMIT_JOIN_END_CLOCK_SKEW_SECONDS
        )
        self._open_info_generation = 0
        self._open_provisional_state = None

    def _notify_classified_permit_state(
        self,
        state: BridgePermitState | None,
    ) -> None:
        transaction, provisional = self._classify_open_state(state)
        if not provisional:
            self._notify_permit_state(state, transaction)

    def _classify_open_state(
        self,
        state: BridgePermitState | None,
    ) -> tuple[str | None, bool]:
        if state is None:
            return None, False
        if not state.online or not state.permit_join:
            provisional = self._open_provisional_state
            if provisional is not None and state.generation > provisional.generation:
                self._reject_open_state(state)
                return None, True
            return None, False
        transaction = self._open_transaction
        if transaction is None:
            self._unattributed_open_generation = max(
                self._unattributed_open_generation,
                state.generation,
            )
            return None, False
        if not self._open_acknowledged:
            if not self._is_provisional_open_candidate(state):
                self._reject_open_state(state)
                return None, True
            provisional = self._open_provisional_state
            if provisional is None:
                self._open_provisional_state = state
                return None, True
            if provisional.generation == state.generation:
                return None, True
            self._reject_open_state(state)
            return None, True
        if not self._is_valid_open_candidate(state):
            self._reject_open_state(state)
            return None, True
        # bridge/info has no writer identity. Matching around our exact ACK is
        # attributable only under the enforced single-writer broker contract.
        self._open_info_generation = state.generation
        return transaction, False

    def _is_provisional_open_candidate(self, state: BridgePermitState) -> bool:
        request_started_at = self._open_request_started_at
        return (
            request_started_at is not None
            and state.generation > self._open_request_generation
            and not state.retained
            and state.observed_at >= request_started_at
            and self.hass.loop.time() <= self._open_attribution_deadline
            and self.hass.loop.time() <= self._open_window_deadline
        )

    def _is_valid_open_candidate(self, state: BridgePermitState) -> bool:
        expected_end = self._open_expected_end
        return (
            self._is_provisional_open_candidate(state)
            and expected_end is not None
            and state.permit_join_end is not None
            and abs((state.permit_join_end - expected_end).total_seconds())
            <= PERMIT_JOIN_END_CLOCK_SKEW_SECONDS
        )

    def _commit_provisional_open(self, transaction: str) -> None:
        state = self._open_provisional_state
        if state is None:
            return
        self._open_provisional_state = None
        if (
            self._open_transaction != transaction
            or not self._is_valid_open_candidate(state)
        ):
            self._reject_open_state(state)
            return
        # This is the first point where pre-ACK bridge/info becomes accepted.
        self._open_info_generation = state.generation
        self._notify_permit_state(state, transaction)
        self._state_changed.set()

    def _reject_provisional_open(self, *, fail_pending: bool = False) -> None:
        state = self._open_provisional_state
        if state is not None:
            self._reject_open_state(state)
            if fail_pending:
                for seconds, future in self._pending.values():
                    if seconds > 0 and not future.done():
                        future.set_exception(
                            JoinRequestError(
                                "Zigbee2MQTT returned an invalid permit-join "
                                "acknowledgement."
                            )
                        )

    def _reject_open_state(self, state: BridgePermitState) -> None:
        self._unattributed_open_generation = max(
            self._unattributed_open_generation,
            state.generation,
        )
        self._open_provisional_state = None
        self._notify_permit_state(None, None)
        self._state_changed.set()

    def _clear_open_attribution(self) -> None:
        self._open_transaction = None
        self._open_request_generation = 0
        self._open_request_started_at = None
        self._open_request_started_monotonic = 0.0
        self._open_acknowledged = False
        self._open_acknowledged_at = None
        self._open_expected_end = None
        self._open_attribution_deadline = 0.0
        self._open_window_deadline = 0.0
        self._open_info_generation = 0
        self._open_provisional_state = None

    def _notify_permit_state(
        self,
        state: BridgePermitState | None,
        attributed_transaction: str | None,
    ) -> None:
        if self._permit_state_handler is None:
            return
        try:
            self._permit_state_handler(state, attributed_transaction)
        except Exception:
            _LOGGER.exception("True Family bridge-state listener failed")

    @staticmethod
    def _strict_message_retain(message: Any, label: str) -> bool:
        retain = getattr(message, "retain", None)
        if type(retain) is not bool:
            raise BridgeEventError(f"{label} retain metadata is invalid.")
        return retain

    @staticmethod
    def _validate_transaction(transaction: str) -> None:
        if type(transaction) is not str or not TRANSACTION_PATTERN.fullmatch(
            transaction
        ):
            raise ValueError("A bounded permit-join transaction is required.")

    async def async_shutdown(self) -> None:
        """Remove subscriptions and fail any pending requests."""

        for _seconds, future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
        self._unsubscribe_installed()
        self._subscribed = False
        self._reset_observations()

    def _unsubscribe_installed(self) -> None:
        while self._subscriptions:
            subscription = self._subscriptions[-1]
            try:
                subscription.unsubscribe()
            except Exception:
                raise RuntimeError(
                    "A Zigbee2MQTT subscription could not be removed."
                ) from None
            else:
                self._subscriptions.pop()

    def _reset_observations(self) -> None:
        self._generation = 0
        self._setup_generation = 0
        self._unsafe_generation = 0
        self._unattributed_open_generation = 0
        self._online = None
        self._online_generation = 0
        self._bridge_state_invalid = False
        self._permit_join = None
        self._permit_join_end = None
        self._permit_retained = False
        self._permit_initial_retained = False
        self._bridge_info_seen = False
        self._permit_generation = 0
        self._permit_observed_at = None
        self._permit_observed_monotonic = None
        self._closed_proof_generation = 0
        self._active_close_request_generation = None
        self._clear_open_attribution()
        self._state_changed.set()
