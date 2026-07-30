"""Test the worker-thread Home Assistant migration authority."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler
import pytest

from custom_components.true_family.bootstrap import CANONICAL_ROOM_IDS
from custom_components.true_family.bootstrap_ha import (
    HomeAssistantBootstrapCoordinator,
)
from custom_components.true_family.const import CONF_BOOTSTRAP, DOMAIN
from custom_components.true_family.reference_migration import (
    TRUE_FAMILY_PROVIDER_MANIFEST,
)
from custom_components.true_family.reference_migration_ha import (
    FacadeRegistryIdentity,
    HomeAssistantMigrationAuthority,
    HomeAssistantMigrationTargetPolicy,
    MigrationAuthorityError,
    MigrationAuthorityPolicyError,
    MigrationAuthorityThreadError,
    MigrationTargetRole,
    ProviderTargetPolicy,
    RoomMigrationTargetPolicy,
)

from helpers import create_physical_climate


PROVIDERS = tuple(sorted(TRUE_FAMILY_PROVIDER_MANIFEST))


def migration_policy(
    *,
    facade_room: str | None = None,
    facade: FacadeRegistryIdentity | None = None,
    facade_providers: frozenset[str] = frozenset(),
) -> HomeAssistantMigrationTargetPolicy:
    """Build one fully explicit canonical seven-room policy."""

    rooms = []
    for room_id in CANONICAL_ROOM_IDS:
        targets = []
        for provider in PROVIDERS:
            use_facade = room_id == facade_room and provider in facade_providers
            targets.append(
                ProviderTargetPolicy(
                    provider=provider,
                    role=(
                        MigrationTargetRole.FACADE
                        if use_facade
                        else MigrationTargetRole.LOGICAL_VALVE
                    ),
                    facade=facade if use_facade else None,
                )
            )
        rooms.append(
            RoomMigrationTargetPolicy(
                room_id=room_id,
                provider_targets=tuple(targets),
            )
        )
    return HomeAssistantMigrationTargetPolicy(rooms=tuple(rooms))


async def async_bootstrap_and_load(
    hass: HomeAssistant,
    true_family_entry,
) -> dict[str, str]:
    """Bootstrap seven synthetic MQTT climates and load True Family."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = {}
    for index, room_id in enumerate(CANONICAL_ROOM_IDS, start=1):
        binding = create_physical_climate(
            hass,
            mqtt_entry=mqtt_entry,
            ieee_address=f"0xa4c138{index:010x}",
            object_id=f"authority_{room_id}_radiator",
        )
        assignments[room_id] = binding.climate_entity_id
    coordinator = HomeAssistantBootstrapCoordinator(hass, true_family_entry)
    plan = coordinator.create_plan(assignments)
    coordinator.commit(plan.plan_id)
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    return assignments


def create_facade(
    hass: HomeAssistant,
    room_id: str,
    *,
    object_id: str | None = None,
) -> tuple[FacadeRegistryIdentity, str]:
    """Create one enabled synthetic climate facade and its policy identity."""

    registry_entry = er.async_get(hass).async_get_or_create(
        "climate",
        "generic_thermostat",
        f"authority_facade_{room_id}",
        suggested_object_id=object_id or f"authority_{room_id}_facade",
        supported_features=1,
    )
    hass.states.async_set(
        registry_entry.entity_id,
        "heat",
        {
            "hvac_modes": ["heat"],
            "min_temp": 5,
            "max_temp": 30,
            "target_temp_step": 0.5,
            "temperature": 20,
            "supported_features": 1,
        },
    )
    identity = FacadeRegistryIdentity(
        registry_entry_id=registry_entry.id,
        platform=registry_entry.platform,
        unique_id=registry_entry.unique_id,
    )
    return identity, registry_entry.entity_id


async def resolve_subject(
    hass: HomeAssistant,
    authority: HomeAssistantMigrationAuthority,
    room_id: str,
):
    """Run the synchronous authority contract in Home Assistant's executor."""

    return await hass.async_add_executor_job(authority.resolve_subject, room_id)


async def test_direct_room_authority_returns_exact_logical_targets(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Resolve a direct room only from persisted, runtime, and registry state."""

    assignments = await async_bootstrap_and_load(hass, true_family_entry)
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(),
    )

    subject = await resolve_subject(hass, authority, "guest_room")
    logical_entity_id = er.async_get(hass).async_get_entity_id(
        "climate",
        DOMAIN,
        "logical_valve_guest_room",
    )

    assert subject.room_id == "guest_room"
    assert subject.room_revision == 0
    assert subject.old_entity_id == assignments["guest_room"]
    assert subject.logical_unique_id == "logical_valve_guest_room"
    assert subject.provider_targets == tuple(
        (provider, logical_entity_id) for provider in PROVIDERS
    )


async def test_facade_specific_provider_targets_are_explicit(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Keep selected provider references on an allowlisted room facade."""

    await async_bootstrap_and_load(hass, true_family_entry)
    facade, facade_entity_id = create_facade(hass, "living_room")
    facade_providers = frozenset({"config_entry", "lovelace", "scheduler"})
    policy = migration_policy(
        facade_room="living_room",
        facade=facade,
        facade_providers=facade_providers,
    )
    authority = HomeAssistantMigrationAuthority(hass, true_family_entry, policy)

    subject = await resolve_subject(hass, authority, "living_room")
    logical_entity_id = er.async_get(hass).async_get_entity_id(
        "climate",
        DOMAIN,
        "logical_valve_living_room",
    )

    assert dict(subject.provider_targets) == {
        provider: (
            facade_entity_id if provider in facade_providers else logical_entity_id
        )
        for provider in PROVIDERS
    }
    assert tuple(provider for provider, _target in subject.provider_targets) == PROVIDERS


async def test_kitchen_facade_name_may_extend_physical_entity_name(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Treat the real Kitchen-style longer facade as a distinct registry entity."""

    assignments = await async_bootstrap_and_load(hass, true_family_entry)
    old_entity_id = assignments["kitchen"]
    facade, facade_entity_id = create_facade(
        hass,
        "kitchen",
        object_id=f"{old_entity_id.removeprefix('climate.')}_with_term",
    )
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(
            facade_room="kitchen",
            facade=facade,
            facade_providers=frozenset({"lovelace"}),
        ),
    )

    subject = await resolve_subject(hass, authority, "kitchen")

    assert facade_entity_id.startswith(old_entity_id)
    assert facade_entity_id != old_entity_id
    assert dict(subject.provider_targets)["lovelace"] == facade_entity_id


async def test_physical_logical_and_facade_renames_are_followed(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Return current entity IDs while retaining immutable registry identities."""

    await async_bootstrap_and_load(hass, true_family_entry)
    facade, facade_entity_id = create_facade(hass, "living_room")
    facade_providers = frozenset({"lovelace", "scheduler"})
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(
            facade_room="living_room",
            facade=facade,
            facade_providers=facade_providers,
        ),
    )
    before = await resolve_subject(hass, authority, "living_room")
    logical_entity_id = dict(before.provider_targets)["active_yaml"]
    entity_registry = er.async_get(hass)

    renamed_physical = "climate.authority_renamed_physical"
    renamed_logical = "climate.authority_renamed_logical"
    renamed_facade = "climate.authority_renamed_facade"
    entity_registry.async_update_entity(
        before.old_entity_id,
        new_entity_id=renamed_physical,
    )
    entity_registry.async_update_entity(
        logical_entity_id,
        new_entity_id=renamed_logical,
    )
    entity_registry.async_update_entity(
        facade_entity_id,
        new_entity_id=renamed_facade,
    )
    await hass.async_block_till_done()

    after = await resolve_subject(hass, authority, "living_room")
    assert after.old_entity_id == renamed_physical
    assert dict(after.provider_targets) == {
        provider: (
            renamed_facade if provider in facade_providers else renamed_logical
        )
        for provider in PROVIDERS
    }


async def test_disabled_or_reidentified_registry_entries_fail_closed(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject disabled entries and identity replacement behind stable IDs."""

    await async_bootstrap_and_load(hass, true_family_entry)
    facade, facade_entity_id = create_facade(hass, "living_room")
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(
            facade_room="living_room",
            facade=facade,
            facade_providers=frozenset({"lovelace"}),
        ),
    )
    subject = await resolve_subject(hass, authority, "living_room")
    logical_entity_id = dict(subject.provider_targets)["active_yaml"]
    registry = er.async_get(hass)

    registry.async_update_entity(
        subject.old_entity_id,
        disabled_by=RegistryEntryDisabler.USER,
    )
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "living_room")
    registry.async_update_entity(subject.old_entity_id, disabled_by=None)

    physical = registry.async_get(subject.old_entity_id)
    assert physical is not None
    physical_unique_id = physical.unique_id
    registry.async_update_entity(
        subject.old_entity_id,
        new_unique_id="replacement_physical_identity",
    )
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "living_room")
    registry.async_update_entity(
        subject.old_entity_id,
        new_unique_id=physical_unique_id,
    )

    registry.async_update_entity(
        logical_entity_id,
        disabled_by=RegistryEntryDisabler.USER,
    )
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "living_room")
    registry.async_update_entity(logical_entity_id, disabled_by=None)

    registry.async_update_entity(
        facade_entity_id,
        disabled_by=RegistryEntryDisabler.USER,
    )
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "living_room")
    registry.async_update_entity(facade_entity_id, disabled_by=None)
    registry.async_update_entity(
        facade_entity_id,
        new_unique_id="replacement_facade_identity",
    )
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "living_room")


async def test_room_revision_drift_from_loaded_runtime_is_rejected(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Require persisted room revisions to match the captured live runtime."""

    await async_bootstrap_and_load(hass, true_family_entry)
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(),
    )
    runtime = true_family_entry.runtime_data
    runtime.rooms["guest_room"].revision += 1

    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "guest_room")


async def test_resolution_requires_bootstrap_and_loaded_runtime_identity(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject missing bootstrap data, unload, and a replacement runtime."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    unbootstrapped = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(),
    )
    assert CONF_BOOTSTRAP not in true_family_entry.data
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, unbootstrapped, "guest_room")

    assert await hass.config_entries.async_unload(true_family_entry.entry_id)
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, unbootstrapped, "guest_room")


async def test_authority_does_not_follow_a_config_entry_reload(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Bind one authority instance to exactly one loaded runtime object."""

    await async_bootstrap_and_load(hass, true_family_entry)
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(),
    )
    captured_runtime = true_family_entry.runtime_data

    assert await hass.config_entries.async_reload(true_family_entry.entry_id)
    await hass.async_block_till_done()
    assert true_family_entry.runtime_data is not captured_runtime
    with pytest.raises(MigrationAuthorityError):
        await resolve_subject(hass, authority, "guest_room")


async def test_direct_event_loop_resolution_is_rejected(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Never deadlock Home Assistant's loop with a synchronous resolution."""

    await async_bootstrap_and_load(hass, true_family_entry)
    authority = HomeAssistantMigrationAuthority(
        hass,
        true_family_entry,
        migration_policy(),
    )

    with pytest.raises(MigrationAuthorityThreadError):
        authority.resolve_subject("guest_room")


def test_target_policy_requires_exact_rooms_and_providers() -> None:
    """Reject mutable, partial, or implicit server target policy."""

    complete = migration_policy()
    with pytest.raises(MigrationAuthorityPolicyError):
        HomeAssistantMigrationTargetPolicy(rooms=complete.rooms[:-1])
    with pytest.raises(MigrationAuthorityPolicyError):
        RoomMigrationTargetPolicy(
            room_id="guest_room",
            provider_targets=complete.rooms[3].provider_targets[:-1],
        )
    with pytest.raises(MigrationAuthorityPolicyError):
        HomeAssistantMigrationTargetPolicy(rooms=list(complete.rooms))  # type: ignore[arg-type]
