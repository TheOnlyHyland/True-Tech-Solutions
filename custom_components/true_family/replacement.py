"""Runtime manager for stable room bindings and guarded TRV replacement."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
import logging
import math
from typing import Any
from typing import TYPE_CHECKING
from uuid import uuid4

from homeassistant.components.climate.const import ClimateEntityFeature, HVACMode
from homeassistant.const import (
    ATTR_ENTITY_ID,
    STATE_UNAVAILABLE,
    STATE_UNKNOWN,
    UnitOfTemperature,
)
from homeassistant.core import Context, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.util.unit_conversion import TemperatureConverter

from .const import (
    CANDIDATE_DISCOVERY_SECONDS,
    CONF_BASE_TOPIC,
    CONF_ROOMS,
    DEFAULT_SAFE_TARGET,
    SIGNAL_SESSION_UPDATED,
    PAIRING_SECONDS,
    READBACK_SECONDS,
    READBACK_TOLERANCE,
)
from .models import (
    CandidateDevice,
    ReplacementPhase,
    ReplacementSession,
    RoomBinding,
    RoomSlot,
    rooms_as_dict,
)
from .mqtt import BridgeEvent, Zigbee2MqttClient

if TYPE_CHECKING:
    from .reference_migration_ha import HomeAssistantReferenceJournal

_LOGGER = logging.getLogger(__name__)

RoomListener = Callable[[], None]


class ReplacementError(HomeAssistantError):
    """Raised when a replacement transaction fails closed."""


class TrueFamilyRuntime:
    """Own stable room bindings and one acknowledged pairing transaction."""

    def __init__(self, hass: HomeAssistant, entry, rooms: dict[str, RoomSlot]) -> None:
        self.hass = hass
        self.entry = entry
        self.rooms = rooms
        self.reference_journal: HomeAssistantReferenceJournal | None = None
        self.sessions: dict[str, ReplacementSession] = {}
        self._mutation_lock = asyncio.Lock()
        self._shutdown_lock = asyncio.Lock()
        self._room_locks = {room_id: asyncio.Lock() for room_id in rooms}
        self._intended_targets: dict[str, float] = {}
        self._active_session_id: str | None = None
        self._join_owner_session_id: str | None = None
        self._timeout_tasks: dict[str, asyncio.Task] = {}
        self._operation_task: asyncio.Task | None = None
        self._tasks: set[asyncio.Task] = set()
        self._closing = False
        self._shutdown_complete = False
        self._room_listeners: dict[str, set[RoomListener]] = {
            room_id: set() for room_id in rooms
        }
        self._mqtt = Zigbee2MqttClient(
            hass,
            entry.data[CONF_BASE_TOPIC],
            self.async_handle_bridge_event,
            self._create_task,
        )

    async def async_setup(self) -> None:
        """Subscribe to bridge events and responses without publishing."""

        await self._mqtt.async_setup()

    async def async_shutdown(self) -> None:
        """Stop work, confirm join closure, and release MQTT subscriptions."""

        async with self._shutdown_lock:
            if self._shutdown_complete:
                return
            self._closing = True
            tasks = [task for task in self._tasks if not task.done()]
            for task in tasks:
                task.cancel("True Family config entry unloading")
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        _LOGGER.warning(
                            "Task failed during True Family unload: %s",
                            result,
                        )
            async with self._mutation_lock:
                pass
            for room_lock in self._room_locks.values():
                async with room_lock:
                    pass

            closure_errors = []
            for session in self.sessions.values():
                if not session.join_closed:
                    try:
                        await self._async_close_join_confirmed(session)
                    except Exception as err:
                        closure_errors.append(err)
            if closure_errors:
                raise ReplacementError(
                    "Zigbee joining closure could not be confirmed during unload."
                ) from closure_errors[0]
            await self._mqtt.async_shutdown()
            self._shutdown_complete = True

    @property
    def active_session(self) -> ReplacementSession | None:
        """Return the current mutable transaction, if any."""

        if self._active_session_id is None:
            return None
        return self.sessions.get(self._active_session_id)

    @callback
    def subscribe_room(self, room_id: str, listener: RoomListener) -> Callable[[], None]:
        """Subscribe a logical entity to binding changes for one room."""

        self._room_listeners[room_id].add(listener)

        @callback
        def unsubscribe() -> None:
            self._room_listeners[room_id].discard(listener)

        return unsubscribe

    def rooms_public_data(self) -> list[dict[str, Any]]:
        """Return room health without exposing full Zigbee identities."""

        result = []
        for room in self.rooms.values():
            entity_id = self.source_entity_id(room.room_id)
            state = self.hass.states.get(entity_id) if entity_id else None
            result.append(
                {
                    "room_id": room.room_id,
                    "display_name": room.display_name,
                    "revision": room.revision,
                    "bound": room.binding is not None,
                    "available": bool(
                        state
                        and state.state not in {STATE_UNKNOWN, STATE_UNAVAILABLE}
                    ),
                    "model": room.binding.model if room.binding else None,
                    "can_rollback": room.previous_binding is not None,
                }
            )
        return result

    async def async_start_pairing(
        self,
        room_id: str,
        operation: str,
    ) -> dict[str, Any]:
        """Run pairing startup as a retained config-entry task."""

        self._ensure_open()
        task = self._create_task(
            self._async_start_pairing(room_id, operation),
            "True Family pairing startup",
        )
        return await asyncio.shield(task)

    async def _async_start_pairing(
        self,
        room_id: str,
        operation: str,
    ) -> dict[str, Any]:
        """Open one acknowledged 60-second pairing window."""

        async with self._mutation_lock:
            self._ensure_open()
            if (
                self.active_session is not None
                or self._join_owner_session_id is not None
                or self._operation_running
            ):
                raise ReplacementError("Another valve replacement is already active.")
            try:
                room = self.rooms[room_id]
            except KeyError as err:
                raise ReplacementError("The selected heating room does not exist.") from err
            if operation not in {"replace", "repair"}:
                raise ReplacementError("Choose either replace or repair existing valve.")
            if operation == "repair" and room.binding is None:
                raise ReplacementError("An unbound room has no existing valve to repair.")

            now = datetime.now(UTC)
            session_id = uuid4().hex
            session = ReplacementSession(
                session_id=session_id,
                room_id=room_id,
                expected_revision=room.revision,
                started_at=now,
                pairing_deadline=now + timedelta(seconds=PAIRING_SECONDS),
                old_binding=room.binding,
                operation=operation,
            )
            session.record(f"Replacement started for {room.display_name}.")
            self.sessions[session_id] = session
            self._active_session_id = session_id
            self._join_owner_session_id = session_id
            try:
                opened_at = await self._mqtt.async_open_join(
                    PAIRING_SECONDS,
                    session_id,
                )
            except Exception as err:
                session.failure_reason = "Zigbee joining could not be acknowledged."
                session.record(f"Replacement failed: {session.failure_reason}")
                if not await self._async_attempt_close(session, force=True):
                    self._create_task(
                        self._async_retry_close(session.session_id),
                        "True Family ambiguous join closure retry",
                    )
                self._set_terminal(session, ReplacementPhase.FAILED)
                self._emit_session(session)
                raise ReplacementError(session.failure_reason) from err

            if self._closing:
                await self._async_attempt_close(session, force=True)
                self._set_terminal(session, ReplacementPhase.FAILED)
                raise ReplacementError("True Family started unloading during pairing.")
            session.join_open_acknowledged = True
            session.join_opened_at = opened_at
            session.record("Zigbee2MQTT acknowledged the 60-second pairing window.")
            self._timeout_tasks[session_id] = self._create_task(
                self._async_pairing_timeout(session_id),
                "True Family pairing timeout",
            )
            self._emit_session(session)
            return session.public_data()

    async def async_handle_bridge_event(self, event: BridgeEvent) -> None:
        """Accept one newly joined approved valve from the acknowledged window."""

        should_resolve = False
        async with self._mutation_lock:
            if self._closing:
                return
            session = self.active_session
            if session is None:
                return
            if (
                not session.join_open_acknowledged
                or session.join_opened_at is None
                or event.received_at is None
                or event.received_at < session.join_opened_at
            ):
                return
            if session.join_closed_at and event.received_at > session.join_closed_at:
                return
            if datetime.now(UTC) >= session.pairing_deadline:
                await self._async_fail(session, "The pairing window expired.")
                return

            if event.event_type == "device_joined":
                session.joined_ieee_addresses.add(event.ieee_address)
                if (
                    session.candidate
                    and session.candidate.ieee_address == event.ieee_address
                ):
                    return
                if (
                    session.operation == "repair"
                    and (
                        session.old_binding is None
                        or session.old_binding.ieee_address != event.ieee_address
                    )
                ):
                    session.requires_remediation = True
                    await self._async_fail(
                        session,
                        "A different device joined an existing-valve repair session.",
                    )
                    return
                if self._identity_reserved(
                    event.ieee_address,
                    session.room_id,
                    allow_selected_current=session.operation == "repair",
                ):
                    session.requires_remediation = True
                    await self._async_fail(
                        session,
                        "A valve already known to True Family attempted to join.",
                    )
                    return
                if session.candidate and session.candidate.ieee_address != event.ieee_address:
                    session.requires_remediation = True
                    await self._async_fail(
                        session,
                        "More than one device joined the pairing window.",
                    )
                    return
                try:
                    session.candidate = CandidateDevice(
                        ieee_address=event.ieee_address,
                        friendly_name=event.friendly_name,
                    )
                except ValueError:
                    session.requires_remediation = True
                    await self._async_fail(session, "The joined device identity was invalid.")
                    return
                session.phase = ReplacementPhase.INTERVIEWING
                session.record("One new candidate joined; waiting for interview.")
                self._emit_session(session)
                return

            room = self.rooms[session.room_id]
            if event.event_type == "device_announce":
                current = room.binding
                if (
                    session.phase
                    not in {
                        ReplacementPhase.AWAITING_PAIRING,
                        ReplacementPhase.INTERVIEWING,
                    }
                    or current is None
                    or current.ieee_address != event.ieee_address
                    or session.operation != "repair"
                ):
                    return
                session.candidate = CandidateDevice(
                    ieee_address=current.ieee_address,
                    friendly_name=current.z2m_friendly_name,
                    model=current.model,
                    manufacturer=current.manufacturer,
                    supported=True,
                )
                session.candidate_binding = current
                try:
                    await self._async_close_join_confirmed(session)
                except Exception:
                    await self._async_fail(
                        session,
                        "Zigbee joining closure could not be confirmed.",
                    )
                    return
                session.phase = ReplacementPhase.READY_TO_COMMIT
                session.record("Existing room valve announced and is ready to test.")
                self._emit_session(session)
                return

            if session.phase not in {
                ReplacementPhase.AWAITING_PAIRING,
                ReplacementPhase.INTERVIEWING,
            }:
                return

            if event.event_type != "device_interview" or session.candidate is None:
                return
            if session.candidate.ieee_address != event.ieee_address:
                return
            if event.interview_status == "started":
                session.record("Candidate interview started.")
                self._emit_session(session)
                return
            if event.interview_status != "successful":
                session.requires_remediation = True
                await self._async_fail(session, "The candidate interview failed.")
                return

            session.candidate = CandidateDevice(
                ieee_address=event.ieee_address,
                friendly_name=event.friendly_name,
                model=event.model,
                manufacturer=event.manufacturer,
                supported=event.supported,
            )
            if event.supported is not True:
                session.requires_remediation = True
                await self._async_fail(session, "The joined device is not supported.")
                return
            if event.model not in room.allowed_models:
                session.requires_remediation = True
                await self._async_fail(
                    session,
                    f"Model {event.model or 'unknown'} is not approved for this room.",
                )
                return
            if event.manufacturer not in room.allowed_manufacturers:
                session.requires_remediation = True
                await self._async_fail(
                    session,
                    f"Manufacturer {event.manufacturer or 'unknown'} is not approved.",
                )
                return
            try:
                await self._async_close_join_confirmed(session)
            except Exception:
                await self._async_fail(
                    session,
                    "Zigbee joining closure could not be confirmed.",
                )
                return
            session.phase = ReplacementPhase.VERIFYING
            session.record("Approved model interviewed; locating its climate entity.")
            self._emit_session(session)
            should_resolve = True

        if should_resolve:
            await self._async_wait_for_candidate_binding(session.session_id)

    async def async_commit(self, session_id: str, context: Context) -> dict[str, Any]:
        """Test the candidate first, then atomically persist the verified binding."""

        async with self._mutation_lock:
            self._ensure_open()
            session = self._session(session_id)
            if session.phase is not ReplacementPhase.READY_TO_COMMIT:
                raise ReplacementError("The replacement is not ready to commit.")
            room = self.rooms[session.room_id]
            self._validate_plan(room, session)
            if session.candidate_binding is None:
                raise ReplacementError("The candidate climate entity is not ready.")
            self._assert_binding_available(session.candidate_binding, room.room_id)
            session.phase = ReplacementPhase.TESTING
            session.record("Starting a two-step fresh-state connectivity test.")
            self._emit_session(session)
            task = self._create_task(
                self._async_test_and_commit(session_id, context),
                "True Family valve test and commit",
            )
            self._operation_task = task
            task.add_done_callback(self._operation_finished)

        return await asyncio.shield(task)

    async def async_cancel(self, session_id: str) -> dict[str, Any]:
        """Run cancellation as a retained config-entry task."""

        self._ensure_open()
        task = self._create_task(
            self._async_cancel(session_id),
            "True Family pairing cancellation",
        )
        return await asyncio.shield(task)

    async def _async_cancel(self, session_id: str) -> dict[str, Any]:
        """Cancel a transaction before candidate testing starts."""

        async with self._mutation_lock:
            session = self._session(session_id)
            if session.phase in {
                ReplacementPhase.TESTING,
                ReplacementPhase.COMPLETE,
                ReplacementPhase.FAILED,
                ReplacementPhase.CANCELLED,
                ReplacementPhase.ROLLED_BACK,
            }:
                raise ReplacementError("This replacement can no longer be cancelled.")
            closed = await self._async_attempt_close(session)
            if not closed and session.join_open_acknowledged:
                session.failure_reason = "Cancellation could not confirm join closure."
                session.record(f"Replacement failed: {session.failure_reason}")
                self._create_task(
                    self._async_retry_close(session.session_id),
                    "True Family cancelled join closure retry",
                )
                self._set_terminal(session, ReplacementPhase.FAILED)
            else:
                session.record(
                    "Replacement cancelled without changing the room binding."
                )
                self._set_terminal(session, ReplacementPhase.CANCELLED)
            self._emit_session(session)
            return session.public_data()

    async def async_rollback_room(
        self,
        room_id: str,
        expected_revision: int,
        context: Context,
    ) -> dict[str, Any]:
        """Verify and restore a persisted previous binding after restart if needed."""

        async with self._mutation_lock:
            self._ensure_open()
            if self.active_session is not None or self._operation_running:
                raise ReplacementError("Another valve operation is already active.")
            try:
                room = self.rooms[room_id]
            except KeyError as err:
                raise ReplacementError("The selected heating room does not exist.") from err
            if room.revision != expected_revision:
                raise ReplacementError("The rollback request is stale.")
            if room.binding is None or room.previous_binding is None:
                raise ReplacementError("This room has no previous binding to restore.")
            self._assert_binding_available(room.previous_binding, room_id)
            current = room.binding
            previous = room.previous_binding
            task = self._create_task(
                self._async_test_and_rollback(
                    room_id,
                    expected_revision,
                    current,
                    previous,
                    context,
                ),
                "True Family valve rollback",
            )
            self._operation_task = task
            task.add_done_callback(self._operation_finished)

        return await asyncio.shield(task)

    async def async_set_temperature(
        self,
        room_id: str,
        temperature: float,
        context: Context,
    ) -> None:
        """Forward a logical room target through Home Assistant's climate service."""

        self._ensure_open()
        async with self._room_locks[room_id]:
            self._ensure_open()
            entity_id = self.source_entity_id(room_id)
            if entity_id is None:
                raise ReplacementError("This room has no physical valve binding.")
            state = self.hass.states.get(entity_id)
            if state is None or state.state in {STATE_UNKNOWN, STATE_UNAVAILABLE}:
                raise ReplacementError("The physical valve is not available.")
            if not math.isfinite(temperature):
                raise ReplacementError("The target temperature must be finite.")
            minimum, maximum, _step = self._temperature_limits(state)
            if not minimum <= temperature <= maximum:
                raise ReplacementError(
                    f"The target must be between {minimum:g} and {maximum:g}."
                )
            await self._async_call_physical(entity_id, temperature, context)
            self._intended_targets[room_id] = temperature

    def source_entity_id(self, room_id: str) -> str | None:
        """Resolve by immutable registry entry ID, never friendly name."""

        room = self.rooms[room_id]
        if room.binding is None:
            return None
        try:
            return self._resolve_binding_entity_id(room.binding)
        except ReplacementError:
            return None

    async def _async_test_and_commit(
        self,
        session_id: str,
        context: Context,
    ) -> dict[str, Any]:
        session = self._session(session_id)
        room = self.rooms[session.room_id]
        binding = session.candidate_binding
        assert binding is not None
        async with self._room_locks[room.room_id]:
            intended_target = self._intended_targets.get(
                room.room_id,
                self._intended_target(session.old_binding),
            )
            session.intended_target = intended_target
            try:
                challenge_target = await self._async_test_binding(
                    binding,
                    intended_target,
                    context,
                )
                session.challenge_target = challenge_target
            except Exception as err:
                async with self._mutation_lock:
                    session.requires_remediation = True
                    session.failure_reason = "The candidate failed its fresh-state test."
                    session.record(f"Replacement failed: {session.failure_reason}")
                    self._set_terminal(session, ReplacementPhase.FAILED)
                    self._emit_session(session)
                raise ReplacementError(session.failure_reason) from err

            async with self._mutation_lock:
                room = self.rooms[session.room_id]
                if session.phase is not ReplacementPhase.TESTING:
                    raise ReplacementError(
                        "The replacement changed while the valve was being tested."
                    )
                old_binding = room.binding
                old_previous = room.previous_binding
                old_revision = room.revision
                try:
                    self._validate_plan(room, session)
                    refreshed_binding = self._resolve_candidate_binding(session)
                    if (
                        refreshed_binding is None
                        or refreshed_binding.registry_entry_id
                        != binding.registry_entry_id
                        or refreshed_binding.ieee_address != binding.ieee_address
                    ):
                        raise ReplacementError(
                            "The candidate identity changed during testing."
                        )
                    binding = refreshed_binding
                    session.candidate_binding = binding
                    self._assert_binding_available(binding, room.room_id)
                    if (
                        old_binding
                        and old_binding.registry_entry_id
                        == binding.registry_entry_id
                    ):
                        session.committed_revision = room.revision
                        session.record("Existing room valve reconnected and verified.")
                        self._set_terminal(session, ReplacementPhase.COMPLETE)
                        self._emit_room(room.room_id)
                        self._emit_session(session)
                        return session.public_data()
                    room.previous_binding = room.binding
                    room.binding = binding
                    room.revision += 1
                    self._persist_rooms()
                except Exception as err:
                    room.binding = old_binding
                    room.previous_binding = old_previous
                    room.revision = old_revision
                    session.failure_reason = (
                        "The verified binding could not be persisted."
                    )
                    self._set_terminal(session, ReplacementPhase.FAILED)
                    self._emit_session(session)
                    raise ReplacementError(session.failure_reason) from err
                session.committed_revision = room.revision
                session.record("Verified binding committed after target restoration.")
                self._set_terminal(session, ReplacementPhase.COMPLETE)
                self._emit_room(room.room_id)
                self._emit_session(session)
                return session.public_data()

    async def _async_test_and_rollback(
        self,
        room_id: str,
        expected_revision: int,
        current: RoomBinding,
        previous: RoomBinding,
        context: Context,
    ) -> dict[str, Any]:
        async with self._room_locks[room_id]:
            intended_target = self._intended_targets.get(
                room_id,
                self._binding_target(current),
            )
            await self._async_test_binding(
                previous,
                intended_target,
                context,
            )
            async with self._mutation_lock:
                room = self.rooms[room_id]
                if (
                    room.revision != expected_revision
                    or room.binding != current
                    or room.previous_binding != previous
                ):
                    raise ReplacementError("The rollback plan changed during testing.")
                self._resolve_binding_entity_id(previous)
                self._assert_binding_available(previous, room_id)
                old_revision = room.revision
                room.binding, room.previous_binding = previous, current
                room.revision += 1
                try:
                    self._persist_rooms()
                except Exception as err:
                    room.binding, room.previous_binding = current, previous
                    room.revision = old_revision
                    raise ReplacementError("The rollback could not be persisted.") from err
                self._emit_room(room_id)
                return self._room_public_data(room)

    async def _async_test_binding(
        self,
        binding: RoomBinding,
        intended_target: float,
        context: Context,
    ) -> float:
        entity_id = self._resolve_binding_entity_id(binding)
        state = self.hass.states.get(entity_id)
        if state is None or state.state in {STATE_UNKNOWN, STATE_UNAVAILABLE}:
            raise ReplacementError("The candidate climate entity is unavailable.")
        minimum, maximum, _step = self._temperature_limits(state)
        if not minimum <= intended_target <= maximum:
            raise ReplacementError(
                "The intended target is outside the candidate valve limits."
            )
        challenge = self._challenge_target(state, intended_target)
        restore_confirmed = False
        try:
            challenge_started = datetime.now(UTC)
            await self._async_call_physical(entity_id, challenge, context)
            if not await self._async_wait_for_fresh_readback(
                entity_id,
                challenge,
                challenge_started,
            ):
                raise ReplacementError("The challenge target was not freshly reported.")

            restore_started = datetime.now(UTC)
            await self._async_call_physical(entity_id, intended_target, context)
            restore_confirmed = await self._async_wait_for_fresh_readback(
                entity_id,
                intended_target,
                restore_started,
            )
            if not restore_confirmed:
                raise ReplacementError("The intended target was not restored.")
        finally:
            if not restore_confirmed:
                try:
                    recovery_started = datetime.now(UTC)
                    await self._async_call_physical(
                        entity_id,
                        intended_target,
                        context,
                    )
                    restore_confirmed = await self._async_wait_for_fresh_readback(
                        entity_id,
                        intended_target,
                        recovery_started,
                    )
                    if not restore_confirmed:
                        raise ReplacementError(
                            "Candidate target recovery was not confirmed."
                        )
                except Exception:
                    _LOGGER.exception("Failed to restore candidate target after test")
        return challenge

    async def _async_call_physical(
        self,
        entity_id: str,
        temperature: float,
        context: Context,
    ) -> None:
        await self.hass.services.async_call(
            "climate",
            "set_temperature",
            {ATTR_ENTITY_ID: entity_id, "temperature": temperature},
            blocking=True,
            context=context,
        )

    async def _async_wait_for_fresh_readback(
        self,
        entity_id: str,
        target: float,
        command_started: datetime,
    ) -> bool:
        for _ in range(READBACK_SECONDS):
            state = self.hass.states.get(entity_id)
            if state and state.last_updated > command_started:
                try:
                    if (
                        abs(float(state.attributes.get("temperature")) - target)
                        <= READBACK_TOLERANCE
                    ):
                        return True
                except (TypeError, ValueError):
                    pass
            await asyncio.sleep(1)
        return False

    async def _async_pairing_timeout(self, session_id: str) -> None:
        try:
            await asyncio.sleep(PAIRING_SECONDS)
            async with self._mutation_lock:
                session = self.sessions.get(session_id)
                if session and session.phase in {
                    ReplacementPhase.AWAITING_PAIRING,
                    ReplacementPhase.INTERVIEWING,
                }:
                    await self._async_fail(session, "The pairing window expired.")
        except asyncio.CancelledError:
            return

    async def _async_wait_for_candidate_binding(self, session_id: str) -> None:
        for _ in range(CANDIDATE_DISCOVERY_SECONDS):
            async with self._mutation_lock:
                if self._closing:
                    return
                session = self.sessions.get(session_id)
                if session is None or session.phase is not ReplacementPhase.VERIFYING:
                    return
                binding = self._resolve_candidate_binding(session)
                if binding:
                    try:
                        self._assert_binding_available(binding, session.room_id)
                    except ReplacementError as err:
                        await self._async_fail(session, str(err))
                        return
                    session.candidate_binding = binding
                    session.phase = ReplacementPhase.READY_TO_COMMIT
                    session.record("Candidate climate entity verified and ready.")
                    self._emit_session(session)
                    return
            await asyncio.sleep(1)
        async with self._mutation_lock:
            session = self.sessions.get(session_id)
            if session and session.phase is ReplacementPhase.VERIFYING:
                session.requires_remediation = True
                await self._async_fail(
                    session,
                    "Home Assistant did not discover one MQTT climate entity.",
                )

    def _resolve_candidate_binding(
        self,
        session: ReplacementSession,
    ) -> RoomBinding | None:
        candidate = session.candidate
        if candidate is None or candidate.model is None:
            return None
        device = dr.async_get(self.hass).async_get_device(
            identifiers={("mqtt", f"zigbee2mqtt_{candidate.ieee_address}")}
        )
        if device is None:
            return None
        expected_identifier = f"zigbee2mqtt_{candidate.ieee_address}"
        mqtt_identifiers = sorted(
            value for domain, value in device.identifiers if domain == "mqtt"
        )
        if mqtt_identifiers != [expected_identifier]:
            return None
        if device.model_id != candidate.model:
            return None
        if device.manufacturer != candidate.manufacturer:
            return None
        if device.name != candidate.friendly_name:
            return None
        entity_registry = er.async_get(self.hass)
        climate_entries = [
            entry
            for entry in er.async_entries_for_device(entity_registry, device.id)
            if entry.domain == "climate"
            and entry.platform == "mqtt"
            and entry.disabled_by is None
        ]
        if len(climate_entries) != 1:
            return None
        entity_entry = climate_entries[0]
        mqtt_unique_id = f"{candidate.ieee_address}_climate_zigbee2mqtt"
        if entity_entry.unique_id != mqtt_unique_id:
            return None
        state = self.hass.states.get(entity_entry.entity_id)
        if not self._candidate_meets_contract(state):
            return None
        return RoomBinding(
            registry_entry_id=entity_entry.id,
            climate_entity_id=entity_entry.entity_id,
            mqtt_unique_id=mqtt_unique_id,
            device_identifier=expected_identifier,
            ieee_address=candidate.ieee_address,
            model=candidate.model,
            manufacturer=candidate.manufacturer or "Unknown",
            z2m_friendly_name=candidate.friendly_name,
        )

    @classmethod
    def _candidate_meets_contract(cls, state) -> bool:
        if state is None or state.state in {STATE_UNKNOWN, STATE_UNAVAILABLE}:
            return False
        attributes = state.attributes
        try:
            supported = ClimateEntityFeature(
                int(attributes.get("supported_features", 0))
            )
            cls._temperature_limits(state)
            return bool(supported & ClimateEntityFeature.TARGET_TEMPERATURE) and (
                HVACMode.HEAT in attributes.get("hvac_modes", [])
            )
        except (ReplacementError, TypeError, ValueError):
            return False

    @staticmethod
    def _temperature_limits(state) -> tuple[float, float, float]:
        try:
            minimum = float(state.attributes["min_temp"])
            maximum = float(state.attributes["max_temp"])
            step = float(state.attributes["target_temp_step"])
        except (KeyError, TypeError, ValueError) as err:
            raise ReplacementError(
                "The candidate did not report valid temperature limits."
            ) from err
        if (
            not all(math.isfinite(value) for value in (minimum, maximum, step))
            or minimum >= maximum
            or step <= 0
        ):
            raise ReplacementError(
                "The candidate reported unsafe temperature limits."
            )
        return minimum, maximum, step

    async def _async_fail(
        self,
        session: ReplacementSession,
        reason: str,
    ) -> None:
        closed = await self._async_attempt_close(session)
        if not closed and session.join_open_acknowledged:
            reason = f"{reason} Join closure is not yet confirmed."
            self._create_task(
                self._async_retry_close(session.session_id),
                "True Family join closure retry",
            )
        session.failure_reason = reason
        session.record(f"Replacement failed: {reason}")
        self._set_terminal(session, ReplacementPhase.FAILED)
        self._emit_session(session)

    async def _async_attempt_close(
        self,
        session: ReplacementSession,
        force: bool = False,
    ) -> bool:
        if session.join_closed or (
            not session.join_open_acknowledged and not force
        ):
            return session.join_closed
        try:
            await self._async_close_join_confirmed(session)
        except Exception as err:
            session.record(f"Join closure request failed: {err}")
            _LOGGER.warning("Could not confirm Zigbee join closure: %s", err)
            return False
        return True

    async def _async_retry_close(self, session_id: str) -> None:
        session = self.sessions[session_id]
        while not self._closing and not session.join_closed:
            if datetime.now(UTC) > session.pairing_deadline + timedelta(seconds=5):
                session.record("The acknowledged pairing hard deadline elapsed.")
                self._emit_session(session)
                return
            await asyncio.sleep(2)
            if await self._async_attempt_close(session, force=True):
                session.record("Zigbee joining closure confirmed on retry.")
                self._emit_session(session)
                return

    async def _async_close_join_confirmed(
        self,
        session: ReplacementSession,
    ) -> None:
        if session.join_closed:
            return
        session.join_closed_at = await self._mqtt.async_close_join(session.session_id)
        session.join_closed = True
        timeout_task = self._timeout_tasks.pop(session.session_id, None)
        if timeout_task and timeout_task is not asyncio.current_task():
            timeout_task.cancel()
        if self._join_owner_session_id == session.session_id:
            self._join_owner_session_id = None

    def _validate_plan(self, room: RoomSlot, session: ReplacementSession) -> None:
        if room.revision != session.expected_revision or room.binding != session.old_binding:
            raise ReplacementError("The room binding changed during replacement.")

    def _assert_binding_available(self, binding: RoomBinding, room_id: str) -> None:
        for other_room in self.rooms.values():
            if other_room.room_id == room_id:
                continue
            for allocated in (
                other_room.binding,
                other_room.previous_binding,
                other_room.bootstrap_binding,
            ):
                if allocated and (
                    allocated.registry_entry_id == binding.registry_entry_id
                    or allocated.ieee_address == binding.ieee_address
                ):
                    raise ReplacementError(
                        "The valve is reserved by another room or rollback path."
                    )

    def _identity_reserved(
        self,
        ieee_address: str,
        selected_room_id: str,
        allow_selected_current: bool,
    ) -> bool:
        for room in self.rooms.values():
            if (
                allow_selected_current
                and room.room_id == selected_room_id
                and room.binding
                and room.binding.ieee_address == ieee_address
            ):
                return False
            for binding in (
                room.binding,
                room.previous_binding,
                room.bootstrap_binding,
            ):
                if binding and binding.ieee_address == ieee_address:
                    return True
        return False

    def _resolve_binding_entity_id(self, binding: RoomBinding) -> str:
        registry_entry = er.async_get(self.hass).async_get(binding.registry_entry_id)
        if (
            registry_entry is None
            or registry_entry.domain != "climate"
            or registry_entry.platform != "mqtt"
            or registry_entry.disabled_by is not None
            or registry_entry.entity_id.startswith("climate.true_family_")
            or registry_entry.device_id is None
            or registry_entry.unique_id != binding.mqtt_unique_id
        ):
            raise ReplacementError("The physical MQTT climate binding is invalid.")
        device = dr.async_get(self.hass).async_get(registry_entry.device_id)
        if device is None:
            raise ReplacementError("The physical valve identity no longer matches.")
        mqtt_identifiers = sorted(
            value for domain, value in device.identifiers if domain == "mqtt"
        )
        if mqtt_identifiers != [binding.device_identifier]:
            raise ReplacementError("The physical valve identity no longer matches.")
        if device.model_id != binding.model:
            raise ReplacementError("The physical valve model no longer matches.")
        if device.manufacturer != binding.manufacturer:
            raise ReplacementError("The physical valve manufacturer no longer matches.")
        if device.name != binding.z2m_friendly_name:
            raise ReplacementError("The physical valve friendly name no longer matches.")
        return registry_entry.entity_id

    def _intended_target(self, binding: RoomBinding | None) -> float:
        return self._binding_target(binding) if binding else self._default_safe_target()

    def _default_safe_target(self) -> float:
        return TemperatureConverter.convert(
            DEFAULT_SAFE_TARGET,
            UnitOfTemperature.CELSIUS,
            self.hass.config.units.temperature_unit,
        )

    def _binding_target(self, binding: RoomBinding) -> float:
        try:
            entity_id = self._resolve_binding_entity_id(binding)
        except ReplacementError:
            return self._default_safe_target()
        state = self.hass.states.get(entity_id)
        if state:
            try:
                return float(state.attributes["temperature"])
            except (KeyError, TypeError, ValueError):
                pass
        return self._default_safe_target()

    @staticmethod
    def _challenge_target(state, intended_target: float) -> float:
        minimum = float(state.attributes.get("min_temp", 0))
        maximum = float(state.attributes.get("max_temp", 35))
        current = float(state.attributes.get("temperature", intended_target))
        for candidate in (intended_target + 1, intended_target - 1, intended_target + 2):
            if (
                minimum <= candidate <= maximum
                and abs(candidate - intended_target) > READBACK_TOLERANCE
                and abs(candidate - current) > READBACK_TOLERANCE
            ):
                return candidate
        raise ReplacementError("No safe distinct challenge target is available.")

    def _room_public_data(self, room: RoomSlot) -> dict[str, Any]:
        return next(
            item
            for item in self.rooms_public_data()
            if item["room_id"] == room.room_id
        )

    @property
    def _operation_running(self) -> bool:
        return self._operation_task is not None and not self._operation_task.done()

    @callback
    def _operation_finished(self, task: asyncio.Task) -> None:
        if self._operation_task is task:
            self._operation_task = None

    def _ensure_open(self) -> None:
        if self._closing:
            raise ReplacementError("True Family is unloading.")

    def _set_terminal(
        self,
        session: ReplacementSession,
        phase: ReplacementPhase,
    ) -> None:
        session.phase = phase
        if self._active_session_id == session.session_id:
            self._active_session_id = None

    def _persist_rooms(self) -> None:
        data = dict(self.entry.data)
        data[CONF_ROOMS] = rooms_as_dict(self.rooms)
        self.hass.config_entries.async_update_entry(self.entry, data=data)

    def _session(self, session_id: str) -> ReplacementSession:
        try:
            return self.sessions[session_id]
        except KeyError as err:
            raise ReplacementError("Unknown replacement session.") from err

    @callback
    def _create_task(
        self,
        coroutine: Coroutine[Any, Any, Any],
        name: str,
    ) -> asyncio.Task:
        task = self.entry.async_create_task(self.hass, coroutine, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    @callback
    def _emit_session(self, session: ReplacementSession) -> None:
        payload = session.public_data()
        async_dispatcher_send(self.hass, SIGNAL_SESSION_UPDATED, payload)

    @callback
    def _emit_room(self, room_id: str) -> None:
        for listener in list(self._room_listeners[room_id]):
            try:
                listener()
            except Exception:
                _LOGGER.exception("True Family room listener failed")
