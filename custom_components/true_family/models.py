"""Serializable data models for True Family logical heating rooms."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import re
from typing import Any, Mapping

from .const import (
    DEFAULT_ALLOWED_MANUFACTURERS,
    DEFAULT_ALLOWED_MODELS,
    DEFAULT_ROOM_NAMES,
)

IEEE_PATTERN = re.compile(r"^0x[0-9a-f]{16}$")


class ReplacementPhase(StrEnum):
    """Phases exposed to the customer replacement wizard."""

    AWAITING_PAIRING = "awaiting_pairing"
    INTERVIEWING = "interviewing"
    VERIFYING = "verifying"
    READY_TO_COMMIT = "ready_to_commit"
    TESTING = "testing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class RoomBinding:
    """Registry-first identity of the physical climate behind a room slot."""

    registry_entry_id: str
    climate_entity_id: str
    mqtt_unique_id: str
    device_identifier: str
    ieee_address: str
    model: str
    manufacturer: str
    z2m_friendly_name: str

    def __post_init__(self) -> None:
        """Reject malformed or recursive persisted bindings."""

        for field_name in (
            "registry_entry_id",
            "climate_entity_id",
            "mqtt_unique_id",
            "device_identifier",
            "ieee_address",
            "model",
            "manufacturer",
            "z2m_friendly_name",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"Binding field {field_name} must be canonical text.")
        if not self.climate_entity_id.startswith("climate."):
            raise ValueError("A binding must reference a climate entity.")
        if self.climate_entity_id.startswith("climate.true_family_"):
            raise ValueError("A logical True Family valve cannot bind to itself.")
        if not IEEE_PATTERN.fullmatch(self.ieee_address):
            raise ValueError("A binding must contain a normalized Zigbee IEEE address.")
        if self.mqtt_unique_id != f"{self.ieee_address}_climate_zigbee2mqtt":
            raise ValueError("A binding MQTT unique ID must match its IEEE address.")
        if self.device_identifier != f"zigbee2mqtt_{self.ieee_address}":
            raise ValueError("A binding device identifier must match its IEEE address.")

    def as_dict(self) -> dict[str, str]:
        """Return JSON-serializable config-entry data."""

        return {
            "registry_entry_id": self.registry_entry_id,
            "climate_entity_id": self.climate_entity_id,
            "mqtt_unique_id": self.mqtt_unique_id,
            "device_identifier": self.device_identifier,
            "ieee_address": self.ieee_address,
            "model": self.model,
            "manufacturer": self.manufacturer,
            "z2m_friendly_name": self.z2m_friendly_name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RoomBinding:
        """Create a binding from persisted config-entry data."""

        if not isinstance(data, Mapping):
            raise ValueError("A persisted binding must be a mapping.")
        expected_fields = {
            "registry_entry_id",
            "climate_entity_id",
            "mqtt_unique_id",
            "device_identifier",
            "ieee_address",
            "model",
            "manufacturer",
            "z2m_friendly_name",
        }
        if set(data) != expected_fields:
            raise ValueError("A persisted binding has missing or unexpected fields.")
        return cls(
            registry_entry_id=data["registry_entry_id"],
            climate_entity_id=data["climate_entity_id"],
            mqtt_unique_id=data["mqtt_unique_id"],
            device_identifier=data["device_identifier"],
            ieee_address=data["ieee_address"],
            model=data["model"],
            manufacturer=data["manufacturer"],
            z2m_friendly_name=data["z2m_friendly_name"],
        )


@dataclass(slots=True)
class RoomSlot:
    """A permanent room identity with a replaceable physical binding."""

    room_id: str
    display_name: str
    allowed_models: tuple[str, ...] = DEFAULT_ALLOWED_MODELS
    allowed_manufacturers: tuple[str, ...] = DEFAULT_ALLOWED_MANUFACTURERS
    binding: RoomBinding | None = None
    previous_binding: RoomBinding | None = None
    bootstrap_binding: RoomBinding | None = None
    revision: int = 0

    def __post_init__(self) -> None:
        """Validate the immutable logical room contract."""

        if not self.room_id or not self.display_name:
            raise ValueError("Room ID and display name are required.")
        if not self.allowed_models or any(not model for model in self.allowed_models):
            raise ValueError("At least one approved TRV model is required.")
        if not self.allowed_manufacturers or any(
            not manufacturer for manufacturer in self.allowed_manufacturers
        ):
            raise ValueError("At least one approved TRV manufacturer is required.")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise ValueError("Room revision must be an integer.")
        if self.revision < 0:
            raise ValueError("Room revision cannot be negative.")

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-serializable config-entry data."""

        return {
            "room_id": self.room_id,
            "display_name": self.display_name,
            "allowed_models": list(self.allowed_models),
            "allowed_manufacturers": list(self.allowed_manufacturers),
            "binding": self.binding.as_dict() if self.binding else None,
            "previous_binding": (
                self.previous_binding.as_dict() if self.previous_binding else None
            ),
            "bootstrap_binding": (
                self.bootstrap_binding.as_dict() if self.bootstrap_binding else None
            ),
            "revision": self.revision,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RoomSlot:
        """Create a room slot from persisted config-entry data."""

        if not isinstance(data, Mapping):
            raise ValueError("A persisted room must be a mapping.")
        expected_fields = {
            "room_id",
            "display_name",
            "allowed_models",
            "allowed_manufacturers",
            "binding",
            "previous_binding",
            "bootstrap_binding",
            "revision",
        }
        if set(data) != expected_fields:
            raise ValueError("A persisted room has missing or unexpected fields.")
        binding = data["binding"]
        previous_binding = data["previous_binding"]
        bootstrap_binding = data["bootstrap_binding"]
        revision = data["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise ValueError("A persisted room revision must be an integer.")
        for field_name in ("room_id", "display_name"):
            value = data[field_name]
            if not isinstance(value, str) or not value:
                raise ValueError(f"Persisted room {field_name} must be text.")
        for field_name in ("allowed_models", "allowed_manufacturers"):
            value = data[field_name]
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item for item in value
            ):
                raise ValueError(f"Persisted room {field_name} must be a text list.")
        return cls(
            room_id=data["room_id"],
            display_name=data["display_name"],
            allowed_models=tuple(data["allowed_models"]),
            allowed_manufacturers=tuple(data["allowed_manufacturers"]),
            binding=RoomBinding.from_dict(binding) if binding is not None else None,
            previous_binding=(
                RoomBinding.from_dict(previous_binding)
                if previous_binding is not None
                else None
            ),
            bootstrap_binding=(
                RoomBinding.from_dict(bootstrap_binding)
                if bootstrap_binding is not None
                else None
            ),
            revision=revision,
        )


@dataclass(frozen=True, slots=True)
class CandidateDevice:
    """A candidate learned from one Zigbee2MQTT pairing transaction."""

    ieee_address: str
    friendly_name: str
    model: str | None = None
    manufacturer: str | None = None
    supported: bool | None = None

    def __post_init__(self) -> None:
        """Require a normalized Zigbee identity."""

        if not IEEE_PATTERN.fullmatch(self.ieee_address):
            raise ValueError("A candidate must contain a normalized Zigbee IEEE address.")
        if not self.friendly_name:
            raise ValueError("A candidate friendly name is required.")

    @property
    def masked_identity(self) -> str:
        """Return only a small suffix suitable for the customer UI."""

        return f"...{self.ieee_address[-4:].upper()}"


@dataclass(slots=True)
class ReplacementSession:
    """One guarded pairing and room-binding transaction."""

    session_id: str
    room_id: str
    expected_revision: int
    started_at: datetime
    pairing_deadline: datetime
    old_binding: RoomBinding | None
    operation: str = "replace"
    phase: ReplacementPhase = ReplacementPhase.AWAITING_PAIRING
    candidate: CandidateDevice | None = None
    candidate_binding: RoomBinding | None = None
    failure_reason: str | None = None
    join_closed: bool = False
    join_open_acknowledged: bool = False
    join_opened_at: datetime | None = None
    join_closed_at: datetime | None = None
    joined_ieee_addresses: set[str] = field(default_factory=set)
    requires_remediation: bool = False
    intended_target: float | None = None
    challenge_target: float | None = None
    committed_revision: int | None = None
    audit: list[str] = field(default_factory=list)

    def record(self, message: str) -> None:
        """Append an event to the in-memory session audit."""

        self.audit.append(message)

    def public_data(self) -> dict[str, Any]:
        """Return a sanitized payload for the frontend."""

        candidate = None
        if self.candidate:
            candidate = {
                "identity": self.candidate.masked_identity,
                "model": self.candidate.model,
                "manufacturer": self.candidate.manufacturer,
                "supported": self.candidate.supported,
            }
        return {
            "session_id": self.session_id,
            "room_id": self.room_id,
            "operation": self.operation,
            "expected_revision": self.expected_revision,
            "phase": self.phase,
            "started_at": self.started_at.isoformat(),
            "pairing_deadline": self.pairing_deadline.isoformat(),
            "candidate": candidate,
            "failure_reason": self.failure_reason,
            "requires_remediation": self.requires_remediation,
            "joined_device_count": len(self.joined_ieee_addresses),
            "audit": list(self.audit),
        }


def default_rooms() -> dict[str, RoomSlot]:
    """Create the seven unbound central-heating room identities."""

    return {
        room_id: RoomSlot(room_id=room_id, display_name=display_name)
        for room_id, display_name in DEFAULT_ROOM_NAMES
    }


def rooms_as_dict(rooms: Mapping[str, RoomSlot]) -> dict[str, dict[str, Any]]:
    """Serialize all room slots for config-entry storage."""

    return {room_id: room.as_dict() for room_id, room in rooms.items()}


def rooms_from_dict(data: Mapping[str, Mapping[str, Any]]) -> dict[str, RoomSlot]:
    """Load room slots and reject duplicate or mismatched room IDs."""

    expected_room_ids = {room_id for room_id, _name in DEFAULT_ROOM_NAMES}
    if set(data) != expected_room_ids:
        raise ValueError("Persisted rooms must match the canonical seven-room set.")
    rooms: dict[str, RoomSlot] = {}
    for stored_room_id, room_data in data.items():
        room = RoomSlot.from_dict(room_data)
        if room.room_id != stored_room_id:
            raise ValueError("Stored room ID does not match its room payload.")
        if room.room_id in rooms:
            raise ValueError(f"Duplicate room ID: {room.room_id}.")
        rooms[room.room_id] = room

    registry_owners: dict[str, str] = {}
    ieee_owners: dict[str, str] = {}
    for room in rooms.values():
        for binding in (
            room.binding,
            room.previous_binding,
            room.bootstrap_binding,
        ):
            if binding is None:
                continue
            registry_owner = registry_owners.setdefault(
                binding.registry_entry_id,
                room.room_id,
            )
            ieee_owner = ieee_owners.setdefault(binding.ieee_address, room.room_id)
            if registry_owner != room.room_id or ieee_owner != room.room_id:
                raise ValueError("A physical valve is allocated to multiple rooms.")
    return rooms
