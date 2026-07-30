"""Home Assistant registry adapter for one-time True Family bootstrap."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .bootstrap import (
    BootstrapAdapterData,
    BootstrapError,
    BootstrapRecord,
    ClimateStateData,
    DeviceRegistryData,
    RegistryEntityData,
    resolve_bootstrap,
)
from .const import CONF_BOOTSTRAP, CONF_ROOMS, DOMAIN
from .models import RoomBinding, default_rooms, rooms_as_dict, rooms_from_dict

_BOOTSTRAP_PLAN_DATA = f"{DOMAIN}_bootstrap_plans"


@dataclass(frozen=True, slots=True)
class HomeAssistantBootstrapPlan:
    """One coordinator-issued, registry-derived bootstrap plan."""

    plan_id: str
    evidence_digest: str
    entry_fingerprint: str
    room_entities: tuple[tuple[str, str], ...]
    public_data: dict[str, Any]


class HomeAssistantBootstrapCoordinator:
    """Plan and commit exactly one seven-room registry bootstrap."""

    def __init__(self, hass: HomeAssistant, entry) -> None:
        self.hass = hass
        self.entry = entry
        self._plans = hass.data.setdefault(_BOOTSTRAP_PLAN_DATA, {})

    def create_plan(
        self,
        room_entities: dict[str, str],
    ) -> HomeAssistantBootstrapPlan:
        """Resolve current registries without mutating config-entry data."""

        self._ensure_ready_for_bootstrap()
        record = resolve_bootstrap(
            room_entities,
            snapshot_home_assistant(self.hass, room_entities),
        )
        entry_fingerprint = _entry_fingerprint(self.entry.data)
        plan_id = hashlib.sha256(
            (
                f"true-family-bootstrap:{record.evidence_digest}:"
                f"{entry_fingerprint}"
            ).encode("utf-8")
        ).hexdigest()
        plan = HomeAssistantBootstrapPlan(
            plan_id=plan_id,
            evidence_digest=record.evidence_digest,
            entry_fingerprint=entry_fingerprint,
            room_entities=tuple(
                (evidence.room_id, evidence.legacy_entity_id)
                for evidence in record.rooms
            ),
            public_data={
                **record.public_data(),
                "plan_id": plan_id,
            },
        )
        self._plans[self.entry.entry_id] = (plan, record)
        return plan

    def commit(self, plan_id: str) -> BootstrapRecord:
        """Re-resolve and atomically store an issued bootstrap plan."""

        self._ensure_ready_for_bootstrap()
        try:
            plan, planned_record = self._plans[self.entry.entry_id]
        except KeyError as err:
            raise BootstrapError("The bootstrap plan is unknown or expired.") from err
        if plan.plan_id != plan_id:
            raise BootstrapError("The bootstrap plan is unknown or expired.")
        room_entities = dict(plan.room_entities)
        if _entry_fingerprint(self.entry.data) != plan.entry_fingerprint:
            raise BootstrapError("The config entry changed after bootstrap planning.")
        current_record = resolve_bootstrap(
            room_entities,
            snapshot_home_assistant(self.hass, room_entities),
        )
        if current_record != planned_record:
            raise BootstrapError("The bootstrap registry evidence changed before commit.")

        raw_rooms = self.entry.data.get(CONF_ROOMS)
        existing_rooms = rooms_from_dict(raw_rooms) if raw_rooms else default_rooms()
        if any(
            room.binding is not None or room.previous_binding is not None
            for room in existing_rooms.values()
        ):
            raise BootstrapError("Bootstrap cannot overwrite existing room bindings.")

        mapped_rooms = default_rooms()
        for evidence in current_record.rooms:
            mapped_rooms[evidence.room_id].binding = RoomBinding(
                registry_entry_id=evidence.registry_entry_id,
                climate_entity_id=evidence.legacy_entity_id,
                mqtt_unique_id=evidence.mqtt_unique_id,
                device_identifier=evidence.device_identifier,
                ieee_address=evidence.ieee_address,
                model=evidence.model,
                manufacturer=evidence.manufacturer,
                z2m_friendly_name=evidence.z2m_friendly_name,
            )
            mapped_rooms[evidence.room_id].bootstrap_binding = mapped_rooms[
                evidence.room_id
            ].binding

        data = dict(self.entry.data)
        data[CONF_BOOTSTRAP] = current_record.as_dict()
        data[CONF_ROOMS] = rooms_as_dict(mapped_rooms)
        self.hass.config_entries.async_update_entry(self.entry, data=data)
        self._plans.pop(self.entry.entry_id, None)
        if not self._plans:
            self.hass.data.pop(_BOOTSTRAP_PLAN_DATA, None)
        return current_record

    def _ensure_ready_for_bootstrap(self) -> None:
        if CONF_BOOTSTRAP in self.entry.data:
            raise BootstrapError("True Family bootstrap has already been completed.")
        if self.entry.state is not ConfigEntryState.NOT_LOADED:
            raise BootstrapError("True Family must be unloaded before bootstrap.")


def snapshot_home_assistant(
    hass: HomeAssistant,
    room_entities: dict[str, str],
) -> BootstrapAdapterData:
    """Capture only supported entity, device, and state registry evidence."""

    if not isinstance(room_entities, dict):
        raise BootstrapError("Bootstrap room selections must be a mapping.")
    entity_registry = er.async_get(hass)
    device_registry = dr.async_get(hass)
    entities: dict[str, RegistryEntityData] = {}
    devices: dict[str, DeviceRegistryData] = {}
    states: dict[str, ClimateStateData] = {}
    for entity_id in room_entities.values():
        if not isinstance(entity_id, str):
            raise BootstrapError("Bootstrap entity IDs must be strings.")
        entity = entity_registry.async_get(entity_id)
        if entity is None:
            raise BootstrapError(f"No entity registry entry exists for {entity_id}.")
        entities[entity_id] = RegistryEntityData(
            registry_entry_id=entity.id,
            entity_id=entity.entity_id,
            domain=entity.domain,
            platform=entity.platform,
            unique_id=entity.unique_id,
            device_id=entity.device_id,
            disabled_by=(
                str(entity.disabled_by) if entity.disabled_by is not None else None
            ),
        )
        if entity.device_id is None:
            raise BootstrapError(f"Bootstrap entity {entity_id} has no device.")
        device = device_registry.async_get(entity.device_id)
        if device is None:
            raise BootstrapError(f"No device registry entry exists for {entity_id}.")
        model = device.model_id
        devices[device.id] = DeviceRegistryData(
            device_id=device.id,
            identifiers=tuple(sorted(device.identifiers)),
            model=model,
            manufacturer=device.manufacturer,
            name=device.name,
        )
        state = hass.states.get(entity_id)
        states[entity_id] = ClimateStateData(
            entity_id=entity_id,
            state=state.state if state is not None else "unavailable",
            attributes=dict(state.attributes) if state is not None else {},
        )
    return BootstrapAdapterData(
        entity_registry=entities,
        device_registry=devices,
        states=states,
    )


def validate_bootstrap_rooms(record: BootstrapRecord, rooms: dict) -> None:
    """Cross-check revision-zero active bindings against mapped evidence."""

    for evidence in record.rooms:
        room = rooms[evidence.room_id]
        binding = room.binding
        if binding is None:
            raise BootstrapError("A mapped bootstrap room cannot be unbound.")
        expected = RoomBinding(
            registry_entry_id=evidence.registry_entry_id,
            climate_entity_id=evidence.legacy_entity_id,
            mqtt_unique_id=evidence.mqtt_unique_id,
            device_identifier=evidence.device_identifier,
            ieee_address=evidence.ieee_address,
            model=evidence.model,
            manufacturer=evidence.manufacturer,
            z2m_friendly_name=evidence.z2m_friendly_name,
        )
        if room.bootstrap_binding != expected:
            raise BootstrapError("Bootstrap evidence does not match its room anchor.")
        if room.revision == 0 and (
            binding != expected or room.previous_binding is not None
        ):
            raise BootstrapError("Bootstrap evidence does not match active room bindings.")
        if room.revision == 1 and room.previous_binding != expected:
            raise BootstrapError("The first replacement does not descend from bootstrap.")
        if room.revision > 0 and (
            room.previous_binding is None or binding == room.previous_binding
        ):
            raise BootstrapError("A replaced room has an invalid binding lineage.")


def _entry_fingerprint(data) -> str:
    rendered = json.dumps(
        dict(data),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()
