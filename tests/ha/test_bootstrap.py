"""Test strict one-time bootstrap against real HA registries."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_registry import RegistryEntryDisabler
from homeassistant.helpers import entity_registry as er
import pytest

from custom_components.true_family import get_runtime
from custom_components.true_family.bootstrap import BootstrapError
from custom_components.true_family.bootstrap_ha import (
    HomeAssistantBootstrapCoordinator,
)
from custom_components.true_family.const import CONF_BOOTSTRAP, CONF_ROOMS
from custom_components.true_family.models import RoomBinding
from custom_components.true_family.replacement import ReplacementError

from helpers import create_physical_climate


ROOM_IDS = (
    "living_room",
    "kitchen",
    "downstairs_bathroom",
    "guest_room",
    "our_bedroom",
    "clarks_room",
    "upstairs_bathroom",
)


def create_seven_sources(hass: HomeAssistant, mqtt_entry) -> dict[str, str]:
    """Create seven synthetic physical registry identities."""

    assignments = {}
    for index, room_id in enumerate(ROOM_IDS, start=1):
        binding = create_physical_climate(
            hass,
            mqtt_entry=mqtt_entry,
            ieee_address=f"0xa4c138{index:010x}",
            object_id=f"bootstrap_{room_id}_radiator",
        )
        assignments[room_id] = binding.climate_entity_id
    return assignments


async def test_bootstrap_plan_commits_all_seven_and_survives_setup(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Persist one complete registry plan and load seven available proxies."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    original_data = dict(true_family_entry.data)

    plan = coordinator.create_plan(assignments)
    assert true_family_entry.data == original_data
    assert plan.public_data["plan_id"] == plan.plan_id
    assert "0xa4c138" not in str(plan.public_data)
    assert len(plan.public_data["rooms"]) == 7
    assert all("legacy_entity_id" not in room for room in plan.public_data["rooms"])

    record = coordinator.commit(plan.plan_id)
    assert true_family_entry.data[CONF_BOOTSTRAP] == record.as_dict()
    assert all(
        room["binding"] is not None
        for room in true_family_entry.data[CONF_ROOMS].values()
    )
    with pytest.raises(BootstrapError):
        coordinator.commit(plan.plan_id)

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    assert get_runtime(hass) is true_family_entry.runtime_data
    logical_entries = [
        entry
        for entry in er.async_entries_for_config_entry(
            er.async_get(hass),
            true_family_entry.entry_id,
        )
        if entry.platform == "true_family"
    ]
    assert len(logical_entries) == 7
    assert all(hass.states.get(entry.entity_id).state == "heat" for entry in logical_entries)


async def test_bootstrap_commit_rejects_registry_drift_without_writing(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Invalidate an issued plan when one selected entity becomes disabled."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    plan = coordinator.create_plan(assignments)
    entity_registry = er.async_get(hass)
    entity_registry.async_update_entity(
        assignments["guest_room"],
        disabled_by=RegistryEntryDisabler.USER,
    )

    with pytest.raises(BootstrapError):
        coordinator.commit(plan.plan_id)
    assert CONF_BOOTSTRAP not in true_family_entry.data
    assert all(
        room["binding"] is None
        for room in true_family_entry.data[CONF_ROOMS].values()
    )


async def test_bootstrap_accepts_registry_proven_unavailable_source(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Map a failed valve when immutable registry evidence remains intact."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    hass.states.async_remove(assignments["guest_room"])
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)

    plan = coordinator.create_plan(assignments)
    record = coordinator.commit(plan.plan_id)

    assert record.state == "mapped"
    assert true_family_entry.data[CONF_ROOMS]["guest_room"]["binding"] is not None


async def test_bootstrap_is_blocked_while_config_entry_is_loaded(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Prevent persisted mappings from diverging from a loaded runtime."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    plan = coordinator.create_plan(assignments)
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()

    with pytest.raises(BootstrapError):
        coordinator.commit(plan.plan_id)


async def test_new_bootstrap_plan_supersedes_older_browser_plan(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Allow only the coordinator's latest reviewed mapping to commit."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    first = coordinator.create_plan(assignments)
    replacement = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0xa4c1380000000099",
        object_id="corrected_guest_room_radiator",
    )
    corrected = dict(assignments)
    corrected["guest_room"] = replacement.climate_entity_id
    second_coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    second = second_coordinator.create_plan(corrected)

    with pytest.raises(BootstrapError):
        coordinator.commit(first.plan_id)
    record = second_coordinator.commit(second.plan_id)
    assert next(
        room for room in record.rooms if room.room_id == "guest_room"
    ).legacy_entity_id == replacement.climate_entity_id


async def test_setup_rejects_bootstrap_binding_permutation(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Refuse a valid record paired with different revision-zero room bindings."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    plan = coordinator.create_plan(assignments)
    coordinator.commit(plan.plan_id)
    data = dict(true_family_entry.data)
    rooms = {room_id: dict(room) for room_id, room in data[CONF_ROOMS].items()}
    rooms["guest_room"]["binding"], rooms["clarks_room"]["binding"] = (
        rooms["clarks_room"]["binding"],
        rooms["guest_room"]["binding"],
    )
    rooms["guest_room"]["revision"] = 1
    rooms["clarks_room"]["revision"] = 1
    data[CONF_ROOMS] = rooms
    hass.config_entries.async_update_entry(true_family_entry, data=data)

    assert not await hass.config_entries.async_setup(true_family_entry.entry_id)


async def test_setup_accepts_anchored_post_bootstrap_replacement_lineage(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Keep immutable bootstrap evidence while the current valve advances."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = create_seven_sources(hass, mqtt_entry)
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    plan = coordinator.create_plan(assignments)
    coordinator.commit(plan.plan_id)
    replacement = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0xa4c1380000000088",
        object_id="replacement_guest_room_radiator",
    )
    second_replacement = create_physical_climate(
        hass,
        mqtt_entry=mqtt_entry,
        ieee_address="0xa4c1380000000077",
        object_id="second_replacement_guest_room_radiator",
    )
    data = dict(true_family_entry.data)
    rooms = {room_id: dict(room) for room_id, room in data[CONF_ROOMS].items()}
    original = rooms["guest_room"]["binding"]
    rooms["guest_room"]["binding"] = second_replacement.as_dict()
    rooms["guest_room"]["previous_binding"] = replacement.as_dict()
    rooms["guest_room"]["revision"] = 2
    data[CONF_ROOMS] = rooms
    hass.config_entries.async_update_entry(true_family_entry, data=data)

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    runtime = get_runtime(hass)
    with pytest.raises(ReplacementError):
        runtime._assert_binding_available(
            RoomBinding.from_dict(original),
            "clarks_room",
        )
