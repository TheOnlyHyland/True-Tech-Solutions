"""Strict Home Assistant-independent resolver for initial room bindings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
from typing import Any, cast

from .const import DEFAULT_ROOM_NAMES


CANONICAL_ROOM_IDS = tuple(room_id for room_id, _name in DEFAULT_ROOM_NAMES)
MAPPED_STATE = "mapped"
TARGET_TEMPERATURE_FEATURE = 1

_APPROVED_MODEL = "BRT-100-TRV"
_APPROVED_MANUFACTURER = "Moes"
_MQTT_UNIQUE_ID_SUFFIX = "_climate_zigbee2mqtt"
_IEEE_PATTERN = re.compile(r"^0x[0-9a-f]{16}$")
_MQTT_UNIQUE_ID_PATTERN = re.compile(
    rf"^(0x[0-9a-f]{{16}}){_MQTT_UNIQUE_ID_SUFFIX}$"
)
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CLIMATE_ENTITY_PATTERN = re.compile(r"^climate\.[a-z0-9_]+$")
_EVIDENCE_FIELDS = frozenset(
    {
        "room_id",
        "legacy_entity_id",
        "registry_entry_id",
        "mqtt_unique_id",
        "device_id",
        "device_identifier",
        "ieee_address",
        "model",
        "manufacturer",
        "z2m_friendly_name",
    }
)
_RECORD_FIELDS = frozenset({"state", "rooms", "evidence_digest"})


class BootstrapError(ValueError):
    """Raised when bootstrap evidence cannot be proven or restored."""


@dataclass(frozen=True, slots=True)
class RoomEntityMapping:
    """One explicit room-to-source assignment; names are never inferred."""

    room_id: str
    legacy_entity_id: str


@dataclass(frozen=True, slots=True)
class RegistryEntityData:
    """Entity-registry fields required by the bootstrap resolver."""

    registry_entry_id: str
    entity_id: str
    domain: str
    platform: str
    unique_id: str | None
    device_id: str | None
    disabled_by: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceRegistryData:
    """Device-registry fields required by the bootstrap resolver."""

    device_id: str
    identifiers: Iterable[tuple[str, str]]
    model: str | None
    manufacturer: str | None
    name: str | None


@dataclass(frozen=True, slots=True)
class ClimateStateData:
    """State-machine fields required to verify a climate entity."""

    entity_id: str
    state: str
    attributes: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class BootstrapAdapterData:
    """Plain snapshots suitable for a later Home Assistant adapter."""

    entity_registry: Mapping[str, RegistryEntityData]
    device_registry: Mapping[str, DeviceRegistryData]
    states: Mapping[str, ClimateStateData]


@dataclass(frozen=True, slots=True)
class BootstrapEvidence:
    """Immutable physical identity evidence for one canonical room."""

    room_id: str
    legacy_entity_id: str
    registry_entry_id: str
    mqtt_unique_id: str
    device_id: str
    device_identifier: str
    ieee_address: str
    model: str
    manufacturer: str
    z2m_friendly_name: str

    def __post_init__(self) -> None:
        """Reject malformed or internally inconsistent evidence."""

        for field_name in _EVIDENCE_FIELDS:
            _require_text(getattr(self, field_name), field_name)
        if self.room_id not in CANONICAL_ROOM_IDS:
            raise BootstrapError(f"Unknown bootstrap room: {self.room_id}.")
        _validate_source_entity_id(self.legacy_entity_id)
        if not _IEEE_PATTERN.fullmatch(self.ieee_address):
            raise BootstrapError("The IEEE address is not normalized.")
        if self.mqtt_unique_id != (
            f"{self.ieee_address}{_MQTT_UNIQUE_ID_SUFFIX}"
        ):
            raise BootstrapError("The MQTT unique ID does not match the IEEE address.")
        if self.device_identifier != f"zigbee2mqtt_{self.ieee_address}":
            raise BootstrapError("The MQTT device identifier does not match the IEEE address.")
        if self.model != _APPROVED_MODEL:
            raise BootstrapError("The bootstrap source is not an approved TRV model.")
        if self.manufacturer != _APPROVED_MANUFACTURER:
            raise BootstrapError("The bootstrap source is not from an approved manufacturer.")

    @property
    def masked_identity(self) -> str:
        """Return a short identity suffix suitable for public output."""

        return f"...{self.ieee_address[-4:].upper()}"

    def as_dict(self) -> dict[str, str]:
        """Return canonical persistence fields."""

        return {
            "room_id": self.room_id,
            "legacy_entity_id": self.legacy_entity_id,
            "registry_entry_id": self.registry_entry_id,
            "mqtt_unique_id": self.mqtt_unique_id,
            "device_id": self.device_id,
            "device_identifier": self.device_identifier,
            "ieee_address": self.ieee_address,
            "model": self.model,
            "manufacturer": self.manufacturer,
            "z2m_friendly_name": self.z2m_friendly_name,
        }

    def public_data(self) -> dict[str, str]:
        """Return evidence without registry, entity, device, or full IEEE IDs."""

        return {
            "room_id": self.room_id,
            "identity": self.masked_identity,
            "model": self.model,
            "manufacturer": self.manufacturer,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BootstrapEvidence:
        """Load strict persisted evidence without coercing values."""

        _require_exact_fields(data, _EVIDENCE_FIELDS, "bootstrap evidence")
        return cls(**{field_name: data[field_name] for field_name in _EVIDENCE_FIELDS})


@dataclass(frozen=True, slots=True)
class BootstrapRecord:
    """Canonical mapped bootstrap record protected by an evidence digest."""

    state: str
    rooms: tuple[BootstrapEvidence, ...]
    evidence_digest: str

    def __post_init__(self) -> None:
        """Verify canonical order, identities, and digest on every construction."""

        if self.state != MAPPED_STATE:
            raise BootstrapError("A bootstrap record must have state mapped.")
        if not isinstance(self.rooms, tuple):
            raise BootstrapError("Bootstrap room evidence must be an immutable tuple.")
        _validate_evidence_collection(self.rooms, require_canonical_order=True)
        if not isinstance(self.evidence_digest, str) or not _DIGEST_PATTERN.fullmatch(
            self.evidence_digest
        ):
            raise BootstrapError("The bootstrap evidence digest is malformed.")
        expected_digest = _calculate_evidence_digest(self.rooms)
        if not hmac.compare_digest(self.evidence_digest, expected_digest):
            raise BootstrapError("The bootstrap evidence digest does not match.")

    @classmethod
    def mapped(cls, evidence: Iterable[BootstrapEvidence]) -> BootstrapRecord:
        """Create a mapped record in canonical room order."""

        supplied = tuple(evidence)
        _validate_evidence_collection(supplied, require_canonical_order=False)
        by_room = {item.room_id: item for item in supplied}
        rooms = tuple(by_room[room_id] for room_id in CANONICAL_ROOM_IDS)
        return cls(
            state=MAPPED_STATE,
            rooms=rooms,
            evidence_digest=_calculate_evidence_digest(rooms),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BootstrapRecord:
        """Restore a strict canonical record and verify tamper evidence."""

        _require_exact_fields(data, _RECORD_FIELDS, "bootstrap record")
        raw_rooms = data["rooms"]
        if not isinstance(raw_rooms, list):
            raise BootstrapError("Stored bootstrap rooms must be a list.")
        rooms = tuple(BootstrapEvidence.from_dict(item) for item in raw_rooms)
        return cls(
            state=data["state"],
            rooms=rooms,
            evidence_digest=data["evidence_digest"],
        )

    def as_dict(self) -> dict[str, Any]:
        """Return the complete JSON-serializable persistence record."""

        return {
            "state": self.state,
            "rooms": [evidence.as_dict() for evidence in self.rooms],
            "evidence_digest": self.evidence_digest,
        }

    def canonical_evidence_json(self) -> str:
        """Return the exact canonical evidence bytes represented as JSON text."""

        return _canonical_json([evidence.as_dict() for evidence in self.rooms])

    def canonical_json(self) -> str:
        """Return a deterministic serialization of the complete record."""

        return _canonical_json(self.as_dict())

    def public_data(self) -> dict[str, Any]:
        """Return mapped status and masked room evidence for UI consumers."""

        return {
            "state": self.state,
            "rooms": [evidence.public_data() for evidence in self.rooms],
        }


def resolve_bootstrap(
    room_entities: Mapping[str, str] | Iterable[RoomEntityMapping],
    adapter: BootstrapAdapterData,
) -> BootstrapRecord:
    """Resolve seven explicit room sources without friendly-name guessing."""

    assignments = _normalize_room_assignments(room_entities)
    _require_adapter_mappings(adapter)
    evidence = []
    for room_id in CANONICAL_ROOM_IDS:
        legacy_entity_id = assignments[room_id]
        _validate_source_entity_id(legacy_entity_id)
        entity = _mapping_value(
            adapter.entity_registry,
            legacy_entity_id,
            "entity registry entry",
            RegistryEntityData,
        )
        if entity.entity_id != legacy_entity_id:
            raise BootstrapError("The entity-registry key does not match its entity ID.")
        if entity.domain != "climate" or entity.platform != "mqtt":
            raise BootstrapError("A bootstrap source must be an MQTT climate entity.")
        if entity.disabled_by is not None:
            raise BootstrapError("A bootstrap source must be enabled.")
        _require_text(entity.registry_entry_id, "registry_entry_id")
        if not isinstance(entity.unique_id, str):
            raise BootstrapError("The MQTT climate entity requires a unique ID.")
        unique_id_match = _MQTT_UNIQUE_ID_PATTERN.fullmatch(entity.unique_id)
        if unique_id_match is None:
            raise BootstrapError("The MQTT climate unique ID is malformed.")
        ieee_address = unique_id_match.group(1)
        if entity.unique_id != f"{ieee_address}{_MQTT_UNIQUE_ID_SUFFIX}":
            raise BootstrapError("The MQTT climate unique ID is not canonical.")
        if not isinstance(entity.device_id, str):
            raise BootstrapError("The MQTT climate entity must belong to a device.")
        _require_text(entity.device_id, "device_id")

        device = _mapping_value(
            adapter.device_registry,
            entity.device_id,
            "device registry entry",
            DeviceRegistryData,
        )
        if device.device_id != entity.device_id:
            raise BootstrapError("The device-registry key does not match its device ID.")
        device_identifier = f"zigbee2mqtt_{ieee_address}"
        mqtt_identifiers = _mqtt_device_identifiers(device.identifiers)
        if mqtt_identifiers != [device_identifier]:
            raise BootstrapError(
                "The device must have exactly one matching Zigbee2MQTT identifier."
            )
        if device.model != _APPROVED_MODEL:
            raise BootstrapError("The bootstrap source is not an approved TRV model.")
        if device.manufacturer != _APPROVED_MANUFACTURER:
            raise BootstrapError("The bootstrap source manufacturer is not approved.")
        _require_text(device.name, "Zigbee2MQTT friendly name")

        state = _mapping_value(
            adapter.states,
            legacy_entity_id,
            "climate state",
            ClimateStateData,
        )
        if state.entity_id != legacy_entity_id:
            raise BootstrapError("The state key does not match its entity ID.")
        _validate_climate_state(state)
        evidence.append(
            BootstrapEvidence(
                room_id=room_id,
                legacy_entity_id=legacy_entity_id,
                registry_entry_id=entity.registry_entry_id,
                mqtt_unique_id=entity.unique_id,
                device_id=device.device_id,
                device_identifier=device_identifier,
                ieee_address=ieee_address,
                model=device.model,
                manufacturer=device.manufacturer,
                z2m_friendly_name=cast(str, device.name),
            )
        )
    return BootstrapRecord.mapped(evidence)


def _normalize_room_assignments(
    room_entities: Mapping[str, str] | Iterable[RoomEntityMapping],
) -> dict[str, str]:
    if isinstance(room_entities, Mapping):
        mapped_entities = cast(Mapping[str, str], room_entities)
        supplied = tuple(
            RoomEntityMapping(room_id=room_id, legacy_entity_id=entity_id)
            for room_id, entity_id in mapped_entities.items()
        )
    else:
        try:
            supplied = tuple(room_entities)
        except TypeError as err:
            raise BootstrapError("Bootstrap room assignments must be iterable.") from err

    assignments: dict[str, str] = {}
    for assignment in supplied:
        if not isinstance(assignment, RoomEntityMapping):
            raise BootstrapError("Each bootstrap assignment must be explicit room data.")
        _require_text(assignment.room_id, "room_id")
        _require_text(assignment.legacy_entity_id, "legacy_entity_id")
        if assignment.room_id in assignments:
            raise BootstrapError(f"Duplicate bootstrap room: {assignment.room_id}.")
        assignments[assignment.room_id] = assignment.legacy_entity_id

    expected = set(CANONICAL_ROOM_IDS)
    actual = set(assignments)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        raise BootstrapError(
            f"Bootstrap rooms must be the canonical seven; missing: {missing}; extra: {extra}."
        )
    return assignments


def _require_adapter_mappings(adapter: BootstrapAdapterData) -> None:
    if not isinstance(adapter, BootstrapAdapterData):
        raise BootstrapError("Bootstrap adapter data is required.")
    for field_name in ("entity_registry", "device_registry", "states"):
        if not isinstance(getattr(adapter, field_name), Mapping):
            raise BootstrapError(f"Adapter {field_name} data must be a mapping.")


def _mapping_value[T](
    values: Mapping[str, T],
    key: str,
    label: str,
    expected_type: type[T],
) -> T:
    try:
        value = values[key]
    except KeyError as err:
        raise BootstrapError(f"No exact {label} exists for {key}.") from err
    if not isinstance(value, expected_type):
        raise BootstrapError(f"The supplied {label} has the wrong data type.")
    return value


def _validate_source_entity_id(entity_id: str) -> None:
    _require_text(entity_id, "legacy_entity_id")
    if not _CLIMATE_ENTITY_PATTERN.fullmatch(entity_id):
        raise BootstrapError("A bootstrap source must have a valid climate entity ID.")
    if entity_id.startswith("climate.true_family"):
        raise BootstrapError("A True Family logical climate cannot bootstrap itself.")


def _mqtt_device_identifiers(identifiers: Iterable[tuple[str, str]]) -> list[str]:
    if isinstance(identifiers, (str, bytes)):
        raise BootstrapError("Device identifiers must be identifier pairs.")
    try:
        supplied = tuple(identifiers)
    except TypeError as err:
        raise BootstrapError("Device identifiers must be iterable.") from err
    mqtt_identifiers = []
    for identifier in supplied:
        if not isinstance(identifier, (tuple, list)) or len(identifier) != 2:
            raise BootstrapError("Every device identifier must be a two-part pair.")
        integration, value = identifier
        _require_text(integration, "identifier integration")
        _require_text(value, "identifier value")
        if integration == "mqtt":
            mqtt_identifiers.append(value)
    return mqtt_identifiers


def _validate_climate_state(state: ClimateStateData) -> None:
    _require_text(state.state, "state")
    if not isinstance(state.attributes, Mapping):
        raise BootstrapError("Climate state attributes must be a mapping.")
    if state.state == "unavailable":
        return
    if state.state == "unknown":
        raise BootstrapError("An unknown climate state cannot prove bootstrap capability.")

    hvac_modes = state.attributes.get("hvac_modes")
    if not isinstance(hvac_modes, Iterable) or isinstance(hvac_modes, (str, bytes)):
        raise BootstrapError("The climate entity did not report HVAC modes.")
    supports_heat = "heat" in hvac_modes
    if not supports_heat:
        raise BootstrapError("The climate entity does not support heat mode.")

    supported_features = state.attributes.get("supported_features")
    if (
        not isinstance(supported_features, int)
        or isinstance(supported_features, bool)
        or not supported_features & TARGET_TEMPERATURE_FEATURE
    ):
        raise BootstrapError("The climate entity lacks target-temperature support.")

    minimum = _finite_temperature_attribute(state.attributes, "min_temp")
    maximum = _finite_temperature_attribute(state.attributes, "max_temp")
    step = _finite_temperature_attribute(state.attributes, "target_temp_step")
    if minimum >= maximum:
        raise BootstrapError("The climate temperature range is invalid.")
    if step <= 0:
        raise BootstrapError("The climate target-temperature step must be positive.")


def _finite_temperature_attribute(attributes: Mapping[str, Any], name: str) -> float:
    value = attributes.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BootstrapError(f"Climate attribute {name} must be numeric.")
    result = float(value)
    if not math.isfinite(result):
        raise BootstrapError(f"Climate attribute {name} must be finite.")
    return result


def _validate_evidence_collection(
    evidence: tuple[BootstrapEvidence, ...],
    *,
    require_canonical_order: bool,
) -> None:
    room_ids = []
    seen_rooms = set()
    seen_entities = set()
    seen_registry_entries = set()
    seen_devices = set()
    seen_ieee_addresses = set()
    for item in evidence:
        if not isinstance(item, BootstrapEvidence):
            raise BootstrapError("Bootstrap room evidence has the wrong data type.")
        if item.room_id in seen_rooms:
            raise BootstrapError(f"Duplicate bootstrap room: {item.room_id}.")
        for value, seen, label in (
            (item.legacy_entity_id, seen_entities, "entity"),
            (item.registry_entry_id, seen_registry_entries, "registry entry"),
            (item.device_id, seen_devices, "device"),
            (item.ieee_address, seen_ieee_addresses, "IEEE address"),
        ):
            if value in seen:
                raise BootstrapError(f"A bootstrap {label} is allocated more than once.")
            seen.add(value)
        seen_rooms.add(item.room_id)
        room_ids.append(item.room_id)

    if set(room_ids) != set(CANONICAL_ROOM_IDS) or len(room_ids) != len(
        CANONICAL_ROOM_IDS
    ):
        raise BootstrapError("Bootstrap evidence must contain exactly seven canonical rooms.")
    if require_canonical_order and tuple(room_ids) != CANONICAL_ROOM_IDS:
        raise BootstrapError("Stored bootstrap rooms are not in canonical order.")


def _calculate_evidence_digest(evidence: tuple[BootstrapEvidence, ...]) -> str:
    serialized = _canonical_json([item.as_dict() for item in evidence])
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _canonical_json(data: Any) -> str:
    return json.dumps(
        data,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _require_text(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BootstrapError(f"{label} must be a non-empty canonical string.")


def _require_exact_fields(
    data: Mapping[str, Any],
    expected_fields: frozenset[str],
    label: str,
) -> None:
    if not isinstance(data, Mapping):
        raise BootstrapError(f"Stored {label} must be a mapping.")
    if set(data) != expected_fields:
        raise BootstrapError(f"Stored {label} fields are malformed.")
