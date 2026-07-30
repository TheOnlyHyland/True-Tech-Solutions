"""Pure data models for the isolated TRV replacement prototype."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class ReplacementPhase(StrEnum):
    """Phases in a guarded replacement transaction."""

    AWAITING_PAIRING = "awaiting_pairing"
    INTERVIEWING = "interviewing"
    READY_TO_COMMIT = "ready_to_commit"
    TESTING = "testing"
    COMPLETE = "complete"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class DeviceBinding:
    """A verified physical device bound to a permanent room slot."""

    registry_entry_id: str
    climate_entity_id: str
    ieee_address: str
    model: str
    manufacturer: str
    z2m_friendly_name: str


@dataclass(slots=True)
class RoomSlot:
    """A permanent room identity whose physical binding can change."""

    room_id: str
    display_name: str
    allowed_models: tuple[str, ...]
    binding: DeviceBinding
    revision: int = 0


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Identity learned from Zigbee2MQTT during pairing and interview."""

    ieee_address: str
    friendly_name: str
    model: str | None = None
    manufacturer: str | None = None
    supported: bool | None = None


@dataclass(frozen=True, slots=True)
class CommandIntent:
    """An MQTT command represented as data and never published by the prototype."""

    topic: str
    payload: dict[str, Any]


@dataclass(slots=True)
class ReplacementSession:
    """Runtime transaction state for one room replacement."""

    session_id: str
    room_id: str
    expected_revision: int
    started_at: datetime
    pairing_deadline: datetime
    old_binding: DeviceBinding
    phase: ReplacementPhase = ReplacementPhase.AWAITING_PAIRING
    candidate: DeviceIdentity | None = None
    candidate_entity_id: str | None = None
    failure_reason: str | None = None
    join_closed: bool = False
    audit: list[str] = field(default_factory=list)

    def record(self, message: str) -> None:
        """Append a concise event to the in-memory audit trail."""

        self.audit.append(message)
