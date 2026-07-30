"""Stable logical climate proxies for replaceable radiator valves."""

from __future__ import annotations

from typing import Any

from homeassistant.components.climate import ATTR_TEMPERATURE, ClimateEntity
from homeassistant.components.climate.const import (
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import (
    async_track_entity_registry_updated_event,
    async_track_state_change_event,
)

from .const import DOMAIN
from .replacement import ReplacementError, TrueFamilyRuntime


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create all seven immutable logical valve entities."""

    runtime: TrueFamilyRuntime = entry.runtime_data
    async_add_entities(
        TrueFamilyValve(runtime, room_id) for room_id in runtime.rooms
    )


class TrueFamilyValve(ClimateEntity):
    """Mirror and control the physical climate currently bound to one room."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_should_poll = False
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_hvac_modes = [HVACMode.HEAT]

    def __init__(self, runtime: TrueFamilyRuntime, room_id: str) -> None:
        self.runtime = runtime
        self.room_id = room_id
        room = runtime.rooms[room_id]
        self._attr_unique_id = f"logical_valve_{room_id}"
        self._attr_suggested_object_id = f"true_family_{room_id}_valve"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, room_id)},
            name=f"{room.display_name} Heating",
            manufacturer="True Family",
            model="Logical Radiator Valve",
        )
        self._unsubscribe_source = None
        self._unsubscribe_registry = None

    @property
    def available(self) -> bool:
        """Report unavailable rather than preserving stale heating state."""

        state = self._source_state
        return bool(state and state.state not in {STATE_UNKNOWN, STATE_UNAVAILABLE})

    @property
    def temperature_unit(self) -> str:
        """Return the Home Assistant system temperature unit."""

        return self.hass.config.units.temperature_unit

    @property
    def current_temperature(self) -> float | None:
        """Mirror the source current temperature from memory."""

        return self._float_attribute("current_temperature")

    @property
    def target_temperature(self) -> float | None:
        """Mirror the source target temperature from memory."""

        return self._float_attribute("temperature")

    @property
    def min_temp(self) -> float:
        """Mirror the physical valve's minimum in the configured unit system."""

        return self._float_attribute("min_temp") or 0

    @property
    def max_temp(self) -> float:
        """Mirror the physical valve's maximum in the configured unit system."""

        return self._float_attribute("max_temp") or 35

    @property
    def target_temperature_step(self) -> float:
        """Mirror the physical valve's target increment."""

        return self._float_attribute("target_temp_step") or 1

    @property
    def hvac_mode(self) -> HVACMode:
        """Expose the approved physical-valve heat contract."""

        return HVACMode.HEAT

    @property
    def hvac_action(self) -> HVACAction | None:
        """Mirror a valid source HVAC action."""

        state = self._source_state
        value = state.attributes.get("hvac_action") if state else None
        try:
            return HVACAction(value) if value else None
        except ValueError:
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose only useful logical binding health, not the Zigbee identity."""

        room = self.runtime.rooms[self.room_id]
        return {"binding_revision": room.revision}

    async def async_added_to_hass(self) -> None:
        """Subscribe to the current physical source and future rebindings."""

        await super().async_added_to_hass()
        self.async_on_remove(
            self.runtime.subscribe_room(self.room_id, self._binding_changed)
        )
        self._subscribe_source()

    async def async_will_remove_from_hass(self) -> None:
        """Remove the dynamic source listener."""

        self._unsubscribe_source_listeners()
        await super().async_will_remove_from_hass()

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Forward a target without optimistic logical state."""

        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            raise ReplacementError("A target temperature is required.")
        await self.runtime.async_set_temperature(
            self.room_id,
            float(temperature),
            self._context,
        )

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Accept the only supported valve mode without changing global heating."""

        if HVACMode(hvac_mode) is not HVACMode.HEAT:
            raise ReplacementError("Logical radiator valves support heat mode only.")

    @property
    def _source_state(self):
        entity_id = self.runtime.source_entity_id(self.room_id)
        return self.hass.states.get(entity_id) if entity_id else None

    def _float_attribute(self, name: str) -> float | None:
        state = self._source_state
        value = state.attributes.get(name) if state else None
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @callback
    def _binding_changed(self) -> None:
        self._subscribe_source()
        self.async_write_ha_state()

    @callback
    def _source_changed(self, _event: Event) -> None:
        self.async_write_ha_state()

    @callback
    def _source_registry_changed(self, _event: Event) -> None:
        self._subscribe_source()
        self.async_write_ha_state()

    def _subscribe_source(self) -> None:
        self._unsubscribe_source_listeners()
        entity_id = self.runtime.source_entity_id(self.room_id)
        if entity_id:
            self._unsubscribe_source = async_track_state_change_event(
                self.hass,
                [entity_id],
                self._source_changed,
            )
            self._unsubscribe_registry = async_track_entity_registry_updated_event(
                self.hass,
                entity_id,
                self._source_registry_changed,
            )

    @callback
    def _unsubscribe_source_listeners(self) -> None:
        if self._unsubscribe_source:
            self._unsubscribe_source()
            self._unsubscribe_source = None
        if self._unsubscribe_registry:
            self._unsubscribe_registry()
            self._unsubscribe_registry = None
