"""Guarded in-memory replacement engine with no external side effects."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from backend.models import (
    CommandIntent,
    DeviceBinding,
    DeviceIdentity,
    ReplacementPhase,
    ReplacementSession,
    RoomSlot,
)
from backend.z2m_protocol import BridgeEvent, close_join_intent, permit_join_intent


class ReplacementError(RuntimeError):
    """Base error for a rejected replacement operation."""


class StaleRevisionError(ReplacementError):
    """Raised when a room changed after the replacement plan was created."""


class ReplacementEngine:
    """Model a single network-wide pairing transaction and room binding swap."""

    def __init__(self, rooms: list[RoomSlot]) -> None:
        if len({room.room_id for room in rooms}) != len(rooms):
            raise ValueError("Room IDs must be unique.")
        self.rooms = {room.room_id: room for room in rooms}
        self.sessions: dict[str, ReplacementSession] = {}

    def start(
        self,
        room_id: str,
        now: datetime,
        pairing_seconds: int = 60,
    ) -> tuple[ReplacementSession, list[CommandIntent]]:
        """Start a transaction and return an unexecuted permit-join intent."""

        self._require_aware_time(now)
        if pairing_seconds < 15 or pairing_seconds > 60:
            raise ReplacementError("Customer pairing must use a 15 to 60 second window.")
        if self._active_session() is not None:
            raise ReplacementError("Another replacement transaction is already active.")
        try:
            room = self.rooms[room_id]
        except KeyError as err:
            raise ReplacementError(f"Unknown room: {room_id}.") from err

        session_id = uuid4().hex
        session = ReplacementSession(
            session_id=session_id,
            room_id=room_id,
            expected_revision=room.revision,
            started_at=now,
            pairing_deadline=now + timedelta(seconds=pairing_seconds),
            old_binding=room.binding,
        )
        session.record(f"Replacement started for {room.display_name}.")
        self.sessions[session_id] = session
        return session, [permit_join_intent(pairing_seconds, session_id)]

    def handle_bridge_event(
        self,
        event: BridgeEvent,
        now: datetime,
    ) -> list[CommandIntent]:
        """Advance the active session from a normalized Zigbee2MQTT event."""

        self._require_aware_time(now)
        session = self._active_session()
        if session is None:
            return []
        if (
            session.phase
            in {ReplacementPhase.AWAITING_PAIRING, ReplacementPhase.INTERVIEWING}
            and now >= session.pairing_deadline
        ):
            return self._fail(session, "The pairing window expired.")

        if event.event_type == "device_announce":
            return []

        if session.candidate and session.candidate.ieee_address != event.ieee_address:
            return self._fail(session, "More than one device joined the pairing window.")

        if event.event_type == "device_joined":
            session.candidate = DeviceIdentity(
                ieee_address=event.ieee_address,
                friendly_name=event.friendly_name,
            )
            session.phase = ReplacementPhase.INTERVIEWING
            session.record("One candidate joined; waiting for its interview.")
            return []

        if event.event_type != "device_interview":
            return []

        if session.candidate is None:
            session.candidate = DeviceIdentity(
                ieee_address=event.ieee_address,
                friendly_name=event.friendly_name,
            )
        session.phase = ReplacementPhase.INTERVIEWING

        if event.interview_status == "started":
            session.record("Candidate interview started.")
            return []
        if event.interview_status != "successful":
            return self._fail(session, "The candidate interview failed.")

        session.candidate = DeviceIdentity(
            ieee_address=event.ieee_address,
            friendly_name=event.friendly_name,
            model=event.model,
            manufacturer=event.manufacturer,
            supported=event.supported,
        )
        room = self.rooms[session.room_id]
        if event.supported is not True:
            return self._fail(session, "The joined device is not supported.")
        if event.model not in room.allowed_models:
            return self._fail(
                session,
                f"Model {event.model or 'unknown'} is not approved for this room.",
            )

        session.phase = ReplacementPhase.READY_TO_COMMIT
        session.join_closed = True
        session.record(f"Approved candidate verified as {event.model}.")
        return [close_join_intent(session.session_id)]

    def tick(self, now: datetime) -> list[CommandIntent]:
        """Expire an unattended pairing session."""

        self._require_aware_time(now)
        session = self._active_session()
        if session is None:
            return []
        if (
            session.phase
            in {ReplacementPhase.AWAITING_PAIRING, ReplacementPhase.INTERVIEWING}
            and now >= session.pairing_deadline
        ):
            return self._fail(session, "The pairing window expired.")
        return []

    def commit(
        self,
        session_id: str,
        registry_entry_id: str,
        climate_entity_id: str,
    ) -> ReplacementSession:
        """Commit a verified in-memory binding and enter the read-back stage."""

        session = self._session(session_id)
        if session.phase is not ReplacementPhase.READY_TO_COMMIT:
            raise ReplacementError("The replacement is not ready to commit.")
        room = self.rooms[session.room_id]
        if room.revision != session.expected_revision:
            self._fail(session, "The room binding changed during replacement.")
            raise StaleRevisionError("The room revision is stale.")
        if session.candidate is None or session.candidate.model is None:
            self._fail(session, "The candidate identity is incomplete.")
            raise ReplacementError("Candidate identity is incomplete.")
        if not climate_entity_id.startswith("climate."):
            self._fail(session, "The candidate does not expose a climate entity.")
            raise ReplacementError("Candidate entity must be in the climate domain.")

        for other_room in self.rooms.values():
            if other_room.room_id == room.room_id:
                continue
            if (
                other_room.binding.registry_entry_id == registry_entry_id
                or other_room.binding.ieee_address == session.candidate.ieee_address
            ):
                self._fail(session, "The candidate is already bound to another room.")
                raise ReplacementError("Candidate is already allocated.")

        room.binding = DeviceBinding(
            registry_entry_id=registry_entry_id,
            climate_entity_id=climate_entity_id,
            ieee_address=session.candidate.ieee_address,
            model=session.candidate.model,
            manufacturer=session.candidate.manufacturer or "Unknown",
            z2m_friendly_name=session.candidate.friendly_name,
        )
        room.revision += 1
        session.candidate_entity_id = climate_entity_id
        session.phase = ReplacementPhase.TESTING
        session.record("Candidate binding committed; awaiting setpoint read-back.")
        return session

    def confirm_readback(
        self,
        session_id: str,
        entity_id: str,
        expected_temperature: float,
        reported_temperature: float,
        tolerance: float = 0.1,
    ) -> bool:
        """Complete only when the new physical entity reports the test target."""

        session = self._session(session_id)
        if session.phase is not ReplacementPhase.TESTING:
            raise ReplacementError("The replacement is not awaiting read-back.")
        if entity_id != session.candidate_entity_id:
            self.rollback(session_id, "Read-back came from the wrong climate entity.")
            return False
        if abs(reported_temperature - expected_temperature) > tolerance:
            self.rollback(session_id, "The replacement did not confirm its test target.")
            return False

        session.phase = ReplacementPhase.COMPLETE
        session.record("Replacement completed after verified setpoint read-back.")
        return True

    def rollback(self, session_id: str, reason: str) -> ReplacementSession:
        """Restore the previous binding while preserving a new revision."""

        session = self._session(session_id)
        if session.phase not in {ReplacementPhase.TESTING, ReplacementPhase.COMPLETE}:
            raise ReplacementError("No committed binding is available to roll back.")
        room = self.rooms[session.room_id]
        room.binding = session.old_binding
        room.revision += 1
        session.failure_reason = reason
        session.phase = ReplacementPhase.ROLLED_BACK
        session.record(f"Previous binding restored: {reason}")
        return session

    def _fail(
        self,
        session: ReplacementSession,
        reason: str,
    ) -> list[CommandIntent]:
        session.phase = ReplacementPhase.FAILED
        session.failure_reason = reason
        session.record(f"Replacement failed: {reason}")
        if session.join_closed:
            return []
        session.join_closed = True
        return [close_join_intent(session.session_id)]

    def _active_session(self) -> ReplacementSession | None:
        active_phases = {
            ReplacementPhase.AWAITING_PAIRING,
            ReplacementPhase.INTERVIEWING,
            ReplacementPhase.READY_TO_COMMIT,
            ReplacementPhase.TESTING,
        }
        return next(
            (session for session in self.sessions.values() if session.phase in active_phases),
            None,
        )

    def _session(self, session_id: str) -> ReplacementSession:
        try:
            return self.sessions[session_id]
        except KeyError as err:
            raise ReplacementError("Unknown replacement session.") from err

    @staticmethod
    def _require_aware_time(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Replacement timestamps must include a timezone.")
