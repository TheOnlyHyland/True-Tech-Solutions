"""Test the reference journal adapter and its production durable backend."""

from __future__ import annotations

from copy import deepcopy
import asyncio
import secrets
import threading
from typing import Any
from unittest.mock import AsyncMock, patch

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import true_family as true_family_integration
from custom_components.true_family.const import (
    CONF_BASE_TOPIC,
    CONF_REFERENCE_JOURNAL_ID,
    CONF_ROOMS,
    DEFAULT_BASE_TOPIC,
    DOMAIN,
)
from custom_components.true_family.models import default_rooms, rooms_as_dict
from custom_components.true_family import reference_migration as migration
from custom_components.true_family import reference_migration_ha as journal_ha
from custom_components.true_family import reference_journal_discovery as discovery
from custom_components.true_family import reference_journal_file as journal_file
from custom_components.true_family import reference_journal_remote as journal_remote
from custom_components.true_family.replacement import ReplacementError


JOURNAL_ID = "true-family-reference-journal-ha-test"
PLAN_ID = f"tf-reference-{'1' * 24}"
MANIFEST_DIGEST = "a" * 64
OLD_ENTITY = "climate.guest_room_radiator"
TARGET_ENTITY = "climate.true_family_guest_room"
KITCHEN_ENTITY = "climate.kitchen_radiator"
KITCHEN_FACADE = "climate.kitchen_radiator_with_term"
KITCHEN_LOGICAL = "climate.true_family_kitchen_valve"
EXECUTION_BINDING = journal_ha.ReferencePlanExecutionBinding(
    execution_scope_digest="b" * 64,
    recorder_id="true-family-reference-recorder-v1",
    journal_id=JOURNAL_ID,
    provider_bridge_ids=tuple(
        (provider, f"true-family-{provider}-bridge-v1")
        for provider in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    ),
)
TEST_DURABILITY_PROOF = journal_ha.ReferenceJournalTestDurabilityProof.create(
    "true-family-tests/in-memory-store-barrier/v1"
)


def unique_journal_id(label: str) -> str:
    """Return an isolated production-backend identity for one test."""

    return f"{label}-{secrets.token_hex(12)}"


def execution_binding_for(
    journal_id: str,
) -> journal_ha.ReferencePlanExecutionBinding:
    """Bind the standard test bridge identities to one isolated journal."""

    return journal_ha.ReferencePlanExecutionBinding(
        execution_scope_digest=EXECUTION_BINDING.execution_scope_digest,
        recorder_id=EXECUTION_BINDING.recorder_id,
        journal_id=journal_id,
        provider_bridge_ids=EXECUTION_BINDING.provider_bridge_ids,
    )


class FakeStore:
    """Deterministic Store double that can swallow writes like HA Store does."""

    def __init__(self, data: dict[str, Any] | None) -> None:
        self.data = deepcopy(data)
        self.save_calls = 0
        self.swallow_writes = False

    async def async_load(self) -> dict[str, Any] | None:
        return deepcopy(self.data)

    async def async_save(self, data: dict[str, Any]) -> None:
        self.save_calls += 1
        if not self.swallow_writes:
            self.data = deepcopy(data)


class FakeDurabilityBarrier:
    """Explicit nominal test proof; never used as a production guarantee."""

    @property
    def durability_proof(self) -> journal_ha.ReferenceJournalTestDurabilityProof:
        return TEST_DURABILITY_PROOF

    async def async_barrier(self) -> None:
        return None


class FakeOwnedStore(FakeStore):
    """Owned backend-neutral store used to inspect production factory wiring."""

    def __init__(self, data: dict[str, Any] | None) -> None:
        super().__init__(data)
        self.close_calls = 0

    @property
    def durability_proof(self) -> journal_ha.ReferenceJournalTestDurabilityProof:
        return TEST_DURABILITY_PROOF

    async def async_barrier(self) -> None:
        return None

    async def async_close(self) -> None:
        self.close_calls += 1


async def open_raw_backend(
    hass: HomeAssistant,
    journal_id: str = JOURNAL_ID,
    *,
    failpoint=None,
) -> journal_file.CrashDurableReferenceJournalStore:
    """Open the raw backend only for explicit isolation tests."""

    return await journal_file.CrashDurableReferenceJournalStore.async_open(
        config_dir=hass.config.config_dir,
        journal_id=journal_id,
        filesystem_policy=hass.data.get(
            journal_ha.REFERENCE_JOURNAL_FILESYSTEM_POLICY_DATA
        ),
        filesystem_certification=hass.data.get(
            journal_ha.REFERENCE_JOURNAL_FILESYSTEM_CERTIFICATION_DATA
        ),
        failpoint=failpoint,
    )


def completed_fixture():
    """Create a valid completion with the current pure migration core."""

    providers = []
    for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST):
        documents = []
        if provider_name == "active_yaml":
            documents.append(
                migration.ReferenceDocument(
                    provider=provider_name,
                    object_id="guest_room_actuator",
                    revision=4,
                    payload={"target": OLD_ENTITY},
                    writable=True,
                )
            )
        providers.append(migration.InMemoryReferenceProvider(provider_name, documents))
    targets = tuple(
        (provider_name, TARGET_ENTITY)
        for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    )
    authority = migration.InMemoryMigrationAuthority(
        [
            migration.MigrationSubject(
                room_id="guest_room",
                room_revision=7,
                old_entity_id=OLD_ENTITY,
                logical_unique_id="logical_valve_guest_room",
                provider_targets=targets,
            )
        ]
    )
    source_journal = migration.InMemoryReferenceJournal()
    coordinator = migration.ReferenceMigrationCoordinator(
        providers,
        source_journal,
        authority,
    )
    plan = coordinator.create_plan(
        room_id="guest_room",
        room_revision=7,
        old_entity_id=OLD_ENTITY,
        logical_unique_id="logical_valve_guest_room",
        target_entity_id=TARGET_ENTITY,
        required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
        references_expected=True,
    )
    coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
    return (
        source_journal.completion_for(plan.plan_id),
        source_journal.originals_for(plan.plan_id)[0],
    )


def unchanged_completed_fixture() -> migration.JournaledCompletion:
    """Create a valid explicit no-write completion."""

    providers = [
        migration.InMemoryReferenceProvider(provider_name)
        for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    ]
    targets = tuple(
        (provider_name, TARGET_ENTITY)
        for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    )
    journal = migration.InMemoryReferenceJournal()
    coordinator = migration.ReferenceMigrationCoordinator(
        providers,
        journal,
        migration.InMemoryMigrationAuthority(
            (
                migration.MigrationSubject(
                    room_id="guest_room",
                    room_revision=7,
                    old_entity_id=OLD_ENTITY,
                    logical_unique_id="logical_valve_guest_room",
                    provider_targets=targets,
                ),
            )
        ),
    )
    plan = coordinator.create_plan(
        room_id="guest_room",
        room_revision=7,
        old_entity_id=OLD_ENTITY,
        logical_unique_id="logical_valve_guest_room",
        target_entity_id=TARGET_ENTITY,
        required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
        references_expected=False,
    )
    coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
    return journal.completion_for(plan.plan_id)


def kitchen_completed_fixture():
    """Create a completion with heterogeneous logical and facade targets."""

    providers = []
    for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST):
        documents = []
        if provider_name == "active_yaml":
            documents.append(
                migration.ReferenceDocument(
                    provider=provider_name,
                    object_id="kitchen_actuator",
                    revision="yaml-4",
                    payload={
                        "value_template": (
                            "{{ state_attr('climate.kitchen_radiator', "
                            "'hvac_action') }}"
                        )
                    },
                    writable=True,
                )
            )
        if provider_name == "lovelace":
            documents.append(
                migration.ReferenceDocument(
                    provider=provider_name,
                    object_id="kitchen_card",
                    revision="dashboard-7",
                    payload={"entity": KITCHEN_ENTITY},
                    writable=True,
                )
            )
        providers.append(migration.InMemoryReferenceProvider(provider_name, documents))
    targets = {
        provider_name: KITCHEN_LOGICAL
        for provider_name in migration.TRUE_FAMILY_PROVIDER_MANIFEST
    }
    targets["lovelace"] = KITCHEN_FACADE
    subject = migration.MigrationSubject(
        room_id="kitchen",
        room_revision=3,
        old_entity_id=KITCHEN_ENTITY,
        logical_unique_id="logical_valve_kitchen",
        provider_targets=tuple(sorted(targets.items())),
    )
    source_journal = migration.InMemoryReferenceJournal()
    coordinator = migration.ReferenceMigrationCoordinator(
        providers,
        source_journal,
        migration.InMemoryMigrationAuthority((subject,)),
    )
    plan = coordinator.create_plan(
        room_id="kitchen",
        room_revision=3,
        old_entity_id=KITCHEN_ENTITY,
        logical_unique_id="logical_valve_kitchen",
        target_entity_id=None,
        provider_targets=targets,
        required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
        references_expected=True,
    )
    coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
    return (
        source_journal.completion_for(plan.plan_id),
        source_journal.originals_for(plan.plan_id),
    )


async def worker_call(hass: HomeAssistant, function, *args):
    """Invoke journal methods only on their dedicated worker."""

    owner = getattr(function, "__self__", None)
    if isinstance(owner, journal_ha.HomeAssistantReferenceJournal):
        return await owner.async_run(function, *args)
    return await hass.async_add_executor_job(function, *args)


async def test_harness_backend_round_trip_survives_adapter_restart(
    hass: HomeAssistant,
) -> None:
    """Persist and restart through the ordinary test harness backend."""

    journal_id = unique_journal_id("round-trip")
    execution_binding = execution_binding_for(journal_id)
    completion = unchanged_completed_fixture()
    plan_id = completion.plan.plan_id
    await journal_ha.async_provision_reference_journal(
        hass,
        journal_id=journal_id,
    )
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=journal_id,
    )

    await worker_call(hass, journal.set_state, plan_id, migration.MigrationState.PLANNED)
    await worker_call(
        hass,
        journal.record_plan,
        completion.plan,
        MANIFEST_DIGEST,
        execution_binding,
    )
    await worker_call(hass, journal.set_state, plan_id, migration.MigrationState.APPLYING)
    await worker_call(hass, journal.record_completion, completion)
    await worker_call(hass, journal.set_state, plan_id, migration.MigrationState.COMPLETE)
    with pytest.raises(ValueError):
        await worker_call(
            hass,
            journal.set_state,
            plan_id,
            migration.MigrationState.APPLYING,
        )
    await journal.async_close()

    restarted = await journal_ha.async_load_reference_journal(
        hass,
        journal_id=journal_id,
    )
    assert await worker_call(hass, restarted.completed_plan_ids) == (plan_id,)
    assert await worker_call(hass, restarted.incomplete_plan_ids) == ()
    assert await worker_call(hass, restarted.originals_for, plan_id) == ()
    assert await worker_call(hass, restarted.completion_for, plan_id) == completion
    assert await worker_call(hass, restarted.plan_for, plan_id) == completion.plan
    assert await worker_call(hass, restarted.manifest_digest_for, plan_id) == (
        MANIFEST_DIGEST
    )
    assert await worker_call(hass, restarted.execution_binding_for, plan_id) == (
        execution_binding
    )
    assert await worker_call(hass, restarted.expected_writes_for, plan_id) == ()
    assert await worker_call(hass, restarted.state, plan_id) == (
        migration.MigrationState.COMPLETE,
        None,
    )
    await restarted.async_close()

    store = await journal_ha._new_store(hass, journal_id)
    stored = await store.async_load()
    verified = journal_ha.decode_reference_journal_data(
        stored,
        expected_journal_id=journal_id,
    )
    assert verified["generation"] == 5
    await store.async_close()


async def test_kitchen_mixed_targets_survive_journal_reload(
    hass: HomeAssistant,
) -> None:
    """Persist the real physical/facade prefix distinction without ambiguity."""

    completion, _originals = kitchen_completed_fixture()
    plan_id = completion.plan.plan_id
    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    await journal.async_run(
        journal.set_state,
        plan_id,
        migration.MigrationState.PLANNED,
    )
    await journal.async_run(
        journal.record_plan,
        completion.plan,
        MANIFEST_DIGEST,
        EXECUTION_BINDING,
    )
    await journal.async_close()

    restarted = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    restored = await restarted.async_run(restarted.plan_for, plan_id)
    await restarted.async_close()

    assert restored == completion.plan
    assert restored.target_entity_id is None
    assert dict(restored.provider_targets)["active_yaml"] == KITCHEN_LOGICAL
    assert dict(restored.provider_targets)["lovelace"] == KITCHEN_FACADE


async def test_pure_coordinator_runs_in_worker_and_replays_after_reload(
    hass: HomeAssistant,
) -> None:
    """Use the Store adapter through the complete synchronous core contract."""

    journal_id = unique_journal_id("coordinator")
    execution_binding = execution_binding_for(journal_id)
    providers = []
    for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST):
        providers.append(migration.InMemoryReferenceProvider(provider_name))
    targets = tuple(
        (provider_name, TARGET_ENTITY)
        for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    )
    authority = migration.InMemoryMigrationAuthority(
        [
            migration.MigrationSubject(
                room_id="guest_room",
                room_revision=7,
                old_entity_id=OLD_ENTITY,
                logical_unique_id="logical_valve_guest_room",
                provider_targets=targets,
            )
        ]
    )
    await journal_ha.async_provision_reference_journal(
        hass,
        journal_id=journal_id,
    )
    journal = await journal_ha.async_load_reference_journal(
        hass,
        journal_id=journal_id,
    )

    def apply_migration():
        coordinator = migration.ReferenceMigrationCoordinator(
            providers,
            journal,
            authority,
        )
        plan = coordinator.create_plan(
            room_id="guest_room",
            room_revision=7,
            old_entity_id=OLD_ENTITY,
            logical_unique_id="logical_valve_guest_room",
            target_entity_id=TARGET_ENTITY,
            required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
            references_expected=False,
        )
        journal.record_plan(plan, MANIFEST_DIGEST, execution_binding)
        return plan, coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

    plan, result = await journal.async_run(apply_migration)
    assert result.state is migration.MigrationState.COMPLETE
    assert result.idempotent is False
    await journal.async_close()

    restarted_journal = await journal_ha.async_load_reference_journal(
        hass,
        journal_id=journal_id,
    )

    def replay_migration():
        coordinator = migration.ReferenceMigrationCoordinator(
            providers,
            restarted_journal,
            authority,
        )
        return coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

    replay = await restarted_journal.async_run(replay_migration)
    assert replay.idempotent is True
    assert replay.state is migration.MigrationState.COMPLETE
    await restarted_journal.async_close()


async def test_production_factory_uses_only_the_discovered_remote_owned_store(
    hass: HomeAssistant,
    production_reference_journal_backend: None,
) -> None:
    """Open the App client and select that exact object as its barrier."""

    endpoint = journal_remote.RemoteJournalEndpoint(
        full_slug="8c9c720e_true_family_journal",
        boot_id="a" * 32,
        hmac_key="b" * 64,
    )
    discovery.cache_reference_journal_endpoint(hass, endpoint)
    owned = journal_remote.RemoteReferenceJournalStore(
        loop=asyncio.get_running_loop(),
        session=AsyncMock(),
        journal_id=JOURNAL_ID,
        endpoint=endpoint,
    )
    owned._store_id = "0" * 32
    owned._capabilities = journal_remote.REMOTE_JOURNAL_CAPABILITIES
    with (
        patch.object(
            journal_remote.RemoteReferenceJournalStore,
            "async_open",
            AsyncMock(return_value=owned),
        ) as remote_open,
        patch.object(
            journal_file.CrashDurableReferenceJournalStore,
            "async_open",
            AsyncMock(side_effect=AssertionError("raw backend must stay isolated")),
        ) as raw_open,
    ):
        selected = await journal_ha._new_store(hass, JOURNAL_ID)
        barrier = journal_ha._select_durability_barrier(
            selected,
            None,
            owns_store=True,
        )
        await journal_ha._async_close_owned_backend(selected)

    assert selected is owned
    assert barrier is owned
    assert owned._closed
    remote_open.assert_awaited_once_with(
        hass,
        journal_id=JOURNAL_ID,
        endpoint=endpoint,
    )
    raw_open.assert_not_awaited()


async def test_production_proof_is_sealed_and_bound_to_exact_remote_backend(
    hass: HomeAssistant,
    production_reference_journal_backend: None,
) -> None:
    """Reject public proof minting and reuse by an arbitrary no-op barrier."""

    endpoint = journal_remote.RemoteJournalEndpoint(
        full_slug="8c9c720e_true_family_journal",
        boot_id="a" * 32,
        hmac_key="b" * 64,
    )
    backend = journal_remote.RemoteReferenceJournalStore(
        loop=asyncio.get_running_loop(),
        session=AsyncMock(),
        journal_id=JOURNAL_ID,
        endpoint=endpoint,
    )
    backend._store_id = "0" * 32
    backend._capabilities = journal_remote.REMOTE_JOURNAL_CAPABILITIES
    proof = backend.durability_proof
    assert proof.guarantee == "sqlite-wal-full-process-crash-cas/v1"
    assert proof.scope is journal_ha.ReferenceJournalDurabilityScope.PROCESS_CRASH_ONLY
    assert not hasattr(journal_ha.ReferenceJournalDurabilityProof, "create")
    with pytest.raises(TypeError):
        journal_ha.ReferenceJournalDurabilityProof(
            provider_id=proof.provider_id,
            guarantee=proof.guarantee,
            scope=proof.scope,
            identity_digest=proof.identity_digest,
            _backend=backend,
        )

    class NoOpBarrier:
        @property
        def durability_proof(self):
            return proof

        async def async_barrier(self) -> None:
            return None

    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        journal_ha._require_strong_durability_barrier(
            NoOpBarrier(),
            allow_test=False,
        )
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        journal_ha._select_durability_barrier(
            FakeStore(None),
            backend,
            allow_test=True,
        )
    with pytest.raises(ValueError):
        journal_ha.ReferenceJournalTestDurabilityProof.create(
            "true-family-tests/forged-sqlite",
            "sqlite-wal-full-process-crash-cas/v1",
        )
    assert TEST_DURABILITY_PROOF.scope is (
        journal_ha.ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION
    )
    await backend.async_close()


async def test_production_remote_default_rejects_test_durability_proof(
    hass: HomeAssistant,
    production_reference_journal_backend: None,
) -> None:
    """Never authorize a test proof on the production remote factory path."""

    assert journal_ha.REFERENCE_JOURNAL_FILESYSTEM_POLICY_DATA not in hass.data
    endpoint = journal_remote.RemoteJournalEndpoint(
        full_slug="8c9c720e_true_family_journal",
        boot_id="a" * 32,
        hmac_key="b" * 64,
    )
    discovery.cache_reference_journal_endpoint(hass, endpoint)
    owned = journal_remote.RemoteReferenceJournalStore(
        loop=asyncio.get_running_loop(),
        session=AsyncMock(),
        journal_id=JOURNAL_ID,
        endpoint=endpoint,
    )
    owned._store_id = "0" * 32
    owned._capabilities = journal_remote.REMOTE_JOURNAL_CAPABILITIES
    owned._durability_proof = TEST_DURABILITY_PROOF  # type: ignore[assignment]

    with patch.object(
        journal_remote.RemoteReferenceJournalStore,
        "async_open",
        AsyncMock(return_value=owned),
    ) as remote_open:
        with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
            await journal_ha.HomeAssistantReferenceJournal.async_create(
                hass,
                journal_id=JOURNAL_ID,
            )

    assert owned._closed
    remote_open.assert_awaited_once_with(
        hass,
        journal_id=JOURNAL_ID,
        endpoint=endpoint,
    )


@pytest.mark.parametrize(
    ("failure", "mutation", "expected_type"),
    (
        (
            journal_remote.RemoteJournalUnavailableError("http://secret-host/body"),
            False,
            journal_ha.ReferenceJournalIOError,
        ),
        (
            journal_remote.RemoteJournalTimeoutError("secret timeout body"),
            False,
            journal_ha.ReferenceJournalIOError,
        ),
        (
            journal_remote.RemoteJournalAuthenticationError("secret key"),
            False,
            journal_ha.ReferenceJournalIOError,
        ),
        (
            journal_remote.RemoteJournalAuthenticationError("stale mutation key"),
            True,
            journal_ha.ReferenceJournalIOError,
        ),
        (
            journal_remote.RemoteJournalProtocolError("secret protocol body"),
            False,
            journal_ha.ReferenceJournalCodecError,
        ),
        (
            journal_remote.RemoteJournalCorruptionError("secret corrupt body"),
            False,
            journal_ha.ReferenceJournalCorruptionError,
        ),
        (
            journal_remote.RemoteJournalConflictError("secret stale body"),
            False,
            journal_ha.ReferenceJournalConflictError,
        ),
        (
            journal_remote.RemoteJournalAmbiguousMutationError("secret save body"),
            False,
            journal_ha.ReferenceJournalDurabilityError,
        ),
        (
            journal_remote.RemoteJournalPoisonedError("secret poison body"),
            False,
            journal_ha.ReferenceJournalDurabilityError,
        ),
        (
            journal_remote.RemoteJournalUnavailableError("secret save URL"),
            True,
            journal_ha.ReferenceJournalDurabilityError,
        ),
    ),
)
def test_remote_errors_normalize_without_endpoint_key_or_body(
    failure: BaseException,
    mutation: bool,
    expected_type: type[BaseException],
) -> None:
    """Map every remote failure class to a stable sanitized adapter error."""

    normalized = journal_ha._normalized_backend_error(failure, mutation=mutation)
    assert type(normalized) is expected_type
    rendered = repr(normalized)
    for sensitive in ("secret", "http://", "body", "URL", "key"):
        assert sensitive not in rendered


def test_owned_store_protocol_is_runtime_checkable_and_backend_neutral() -> None:
    """Recognize lifecycle shape without naming either production backend."""

    owned = FakeOwnedStore(None)
    assert isinstance(owned, journal_ha.ReferenceJournalStore)
    assert isinstance(owned, journal_ha.ReferenceJournalDurabilityBarrier)
    assert isinstance(owned, journal_ha.ReferenceJournalOwnedStore)


async def test_harness_provisioning_is_idempotent_only_while_exactly_empty(
    hass: HomeAssistant,
) -> None:
    """Accept an exact retry, but never overwrite a journal containing state."""

    journal_id = unique_journal_id("idempotent")
    await journal_ha.async_provision_reference_journal(hass, journal_id=journal_id)
    await journal_ha.async_provision_reference_journal(hass, journal_id=journal_id)
    journal = await journal_ha.async_load_reference_journal(
        hass,
        journal_id=journal_id,
    )
    assert journal._root == journal_ha.empty_reference_journal_data(journal_id)
    await journal.async_run(
        journal.set_state,
        PLAN_ID,
        migration.MigrationState.PLANNED,
    )
    await journal.async_close()

    with pytest.raises(journal_ha.ReferenceJournalAlreadyProvisionedError):
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=journal_id,
        )
    reopened = await journal_ha._new_store(hass, journal_id)
    stored = await reopened.async_load()
    assert stored is not None
    assert stored["generation"] == 1
    await reopened.async_close()


async def test_owned_backend_requires_its_exact_barrier_and_raw_is_explicit(
    hass: HomeAssistant,
) -> None:
    """Reject a decoupled owned barrier while preserving explicit raw tests."""

    journal_id = unique_journal_id("barrier-identity")
    await journal_ha.async_provision_reference_journal(hass, journal_id=journal_id)
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal_ha.async_load_reference_journal(
            hass,
            journal_id=journal_id,
            durability_barrier=FakeDurabilityBarrier(),
        )

    raw_journal_id = unique_journal_id("explicit-raw")
    backend = await open_raw_backend(hass, raw_journal_id)
    try:
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=raw_journal_id,
            store=backend,
            durability_barrier=backend,
        )
        journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=raw_journal_id,
            store=backend,
            durability_barrier=backend,
        )
        assert journal._owns_store is False
        assert journal.durability_scope is (
            journal_ha.ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION
        )
        assert journal.host_mutation_authorized
        await journal.async_close()
    finally:
        await backend.async_close()


async def test_adapter_owns_factory_backend_until_close_and_closes_it_once(
    hass: HomeAssistant,
) -> None:
    """Keep the flock through worker shutdown and close one owned backend once."""

    journal_id = unique_journal_id("adapter-close")
    backend = await open_raw_backend(hass, journal_id)
    await journal_ha.async_provision_reference_journal(
        hass,
        journal_id=journal_id,
        store=backend,
        durability_barrier=backend,
    )
    original_close = backend.async_close
    close_spy = AsyncMock(wraps=original_close)
    backend.async_close = close_spy

    async def return_backend(
        _hass: HomeAssistant,
        _journal_id: str,
    ) -> journal_file.CrashDurableReferenceJournalStore:
        return backend

    with patch.object(journal_ha, "_new_store", return_backend):
        journal = await journal_ha.async_load_reference_journal(
            hass,
            journal_id=journal_id,
        )
        with pytest.raises(journal_file.ReferenceJournalBusyError):
            await open_raw_backend(hass, journal_id)
        await journal.async_close()
        await journal.async_close()

    close_spy.assert_awaited_once()
    reopened = await open_raw_backend(hass, journal_id)
    assert await reopened.async_load() == journal_ha.empty_reference_journal_data(
        journal_id
    )
    await reopened.async_close()


async def test_harness_absent_load_releases_owned_backend_for_provisioning(
    hass: HomeAssistant,
) -> None:
    """Close a failed owned load so the same journal can then be provisioned."""

    journal_id = unique_journal_id("load-failure")
    with pytest.raises(journal_ha.ReferenceJournalNotProvisionedError):
        await journal_ha.async_load_reference_journal(
            hass,
            journal_id=journal_id,
        )
    await journal_ha.async_provision_reference_journal(hass, journal_id=journal_id)
    loaded = await journal_ha.async_load_reference_journal(
        hass,
        journal_id=journal_id,
    )
    await loaded.async_close()


async def test_raw_busy_open_is_normalized_without_leaking_identity(
    hass: HomeAssistant,
) -> None:
    """Expose a typed retryable error without retaining raw backend detail."""

    journal_id = unique_journal_id("load-busy")
    with patch.object(
        journal_ha,
        "_new_store",
        AsyncMock(
            side_effect=journal_file.ReferenceJournalBusyError(
                "raw lock /unsafe/config"
            )
        ),
    ):
        with pytest.raises(journal_ha.ReferenceJournalBusyError) as raised:
            await journal_ha.async_load_reference_journal(
                hass,
                journal_id=journal_id,
            )
    assert journal_id not in str(raised.value)
    assert hass.config.config_dir not in str(raised.value)
    assert "/unsafe/config" not in str(raised.value)


@pytest.mark.parametrize(
    ("backend_failure", "expected_type"),
    (
        (
            journal_file.ReferenceJournalUnsupportedFilesystemError(
                "injected raw path /unsafe/config"
            ),
            journal_ha.ReferenceJournalUnsupportedFilesystemError,
        ),
        (
            journal_file.ReferenceJournalIOError(
                "injected raw path /unsafe/config"
            ),
            journal_ha.ReferenceJournalIOError,
        ),
        (
            journal_file.ReferenceJournalSecurityError(
                "injected raw path /unsafe/config"
            ),
            journal_ha.ReferenceJournalSecurityError,
        ),
    ),
)
async def test_injected_factory_open_normalizes_backend_errors(
    hass: HomeAssistant,
    backend_failure: Exception,
    expected_type: type[Exception],
) -> None:
    """Translate injected factory failures to stable errors with safe messages."""

    journal_id = unique_journal_id("normalized-open-error")
    with patch.object(
        journal_ha,
        "_new_store",
        AsyncMock(side_effect=backend_failure),
    ):
        with pytest.raises(expected_type) as raised:
            await journal_ha.async_load_reference_journal(
                hass,
                journal_id=journal_id,
            )
    assert "/unsafe/config" not in str(raised.value)
    assert journal_id not in str(raised.value)


async def test_provisioning_cancellation_drains_and_closes_factory_backend(
    hass: HomeAssistant,
) -> None:
    """Finish save, barrier, and read-back before surfacing caller cancellation."""

    journal_id = unique_journal_id("cancelled-provision")
    entered = threading.Event()
    release = threading.Event()

    def failpoint(event: str) -> None:
        if event == "before_barrier_directory_fsync":
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signalled")

    backend = await open_raw_backend(
        hass,
        journal_id,
        failpoint=failpoint,
    )

    async def return_backend(
        _hass: HomeAssistant,
        _journal_id: str,
    ) -> journal_file.CrashDurableReferenceJournalStore:
        return backend

    with patch.object(journal_ha, "_new_store", return_backend):
        provisioning = asyncio.create_task(
            journal_ha.async_provision_reference_journal(
                hass,
                journal_id=journal_id,
            )
        )
        assert await hass.async_add_executor_job(entered.wait, 5)
        provisioning.cancel()
        await asyncio.sleep(0)
        provisioning.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await provisioning

    reopened = await open_raw_backend(hass, journal_id)
    assert await reopened.async_load() == journal_ha.empty_reference_journal_data(
        journal_id
    )
    await reopened.async_close()


@pytest.mark.parametrize(
    ("failure", "expected_type", "safe_message"),
    (
        (
            journal_ha.ReferenceJournalBusyError("raw busy detail"),
            ConfigEntryNotReady,
            "Reference journal storage is temporarily unavailable.",
        ),
        (
            journal_ha.ReferenceJournalCertificationError(
                "raw certification detail"
            ),
            ConfigEntryNotReady,
            "Reference journal storage is temporarily unavailable.",
        ),
        (
            journal_ha.ReferenceJournalIOError("raw I/O detail"),
            ConfigEntryNotReady,
            "Reference journal storage is temporarily unavailable.",
        ),
        (
            journal_ha.ReferenceJournalCorruptionError("raw corrupt detail"),
            ConfigEntryError,
            "True Family persisted setup data is invalid.",
        ),
        (
            journal_ha.ReferenceJournalCodecError("signed protocol shape detail"),
            ConfigEntryError,
            "True Family persisted setup data is invalid.",
        ),
        (
            journal_ha.ReferenceJournalSecurityError("raw security detail"),
            ConfigEntryError,
            "True Family persisted setup data is invalid.",
        ),
        (
            journal_ha.ReferenceJournalUnsupportedFilesystemError(
                "raw unsupported detail"
            ),
            ConfigEntryError,
            "True Family persisted setup data is invalid.",
        ),
    ),
)
async def test_setup_maps_typed_journal_failures(
    hass: HomeAssistant,
    failure: Exception,
    expected_type: type[Exception],
    safe_message: str,
) -> None:
    """Map retryable storage failures separately from permanent unsafe data."""

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_REFERENCE_JOURNAL_ID: JOURNAL_ID},
    )
    with patch.object(
        true_family_integration,
        "async_load_reference_journal",
        AsyncMock(side_effect=failure),
    ):
        with pytest.raises(expected_type) as raised:
            await true_family_integration.async_setup_entry(hass, entry)
    assert str(raised.value) == safe_message
    assert "raw" not in str(raised.value)


async def test_existing_entry_without_discovered_app_is_not_ready(
    hass: HomeAssistant,
    production_reference_journal_backend: None,
) -> None:
    """Treat an absent companion App endpoint as setup-retryable."""

    journal_id = unique_journal_id("undiscovered-setup")
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID: journal_id,
            CONF_ROOMS: rooms_as_dict(default_rooms()),
        },
    )
    entry.add_to_hass(hass)

    with pytest.raises(ConfigEntryNotReady) as raised:
        await true_family_integration.async_setup_entry(hass, entry)

    assert str(raised.value) == (
        "Reference journal storage is temporarily unavailable."
    )


async def test_partial_setup_and_unload_close_journal_exactly_once(
    hass: HomeAssistant,
) -> None:
    """Close on partial setup and successful unload, but retain failed unload."""

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID: JOURNAL_ID,
            CONF_ROOMS: rooms_as_dict(default_rooms()),
        },
    )
    partial_journal = AsyncMock()
    with (
        patch.object(
            true_family_integration,
            "async_load_reference_journal",
            AsyncMock(return_value=partial_journal),
        ),
        patch.object(
            true_family_integration.TrueFamilyRuntime,
            "async_setup",
            AsyncMock(side_effect=RuntimeError("injected setup failure")),
        ),
        patch.object(
            true_family_integration.TrueFamilyRuntime,
            "async_shutdown",
            AsyncMock(),
        ),
    ):
        with pytest.raises(ConfigEntryNotReady):
            await true_family_integration.async_setup_entry(hass, entry)
    partial_journal.async_close.assert_awaited_once()

    runtime = AsyncMock()
    runtime.reference_journal = AsyncMock()
    entry.runtime_data = runtime
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime
    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        AsyncMock(return_value=True),
    ):
        assert await true_family_integration.async_unload_entry(hass, entry)
    runtime.reference_journal.async_close.assert_awaited_once()
    assert entry.entry_id not in hass.data[DOMAIN]

    retained = AsyncMock()
    retained.async_shutdown.side_effect = ReplacementError("join remains open")
    retained.reference_journal = AsyncMock()
    entry.runtime_data = retained
    hass.data[DOMAIN][entry.entry_id] = retained
    assert not await true_family_integration.async_unload_entry(hass, entry)
    retained.reference_journal.async_close.assert_not_awaited()
    assert hass.data[DOMAIN][entry.entry_id] is retained


@pytest.mark.parametrize("bad_base_topic", (None, "zigbee2mqtt/#"))
async def test_runtime_constructor_failure_releases_journal_for_immediate_retry(
    hass: HomeAssistant,
    bad_base_topic: str | None,
) -> None:
    """Close constructor failures so corrected config can own the journal at once."""

    journal_id = unique_journal_id("runtime-constructor")
    await journal_ha.async_provision_reference_journal(
        hass,
        journal_id=journal_id,
    )
    data = {
        CONF_REFERENCE_JOURNAL_ID: journal_id,
        CONF_ROOMS: rooms_as_dict(default_rooms()),
    }
    if bad_base_topic is not None:
        data[CONF_BASE_TOPIC] = bad_base_topic
    entry = MockConfigEntry(domain=DOMAIN, data=data)
    entry.add_to_hass(hass)

    with pytest.raises(ConfigEntryError):
        await true_family_integration.async_setup_entry(hass, entry)

    assert journal_ha._journal_runtime(hass)["owner"] is None
    assert entry.entry_id not in hass.data.get(DOMAIN, {})
    hass.config_entries.async_update_entry(
        entry,
        data={
            CONF_BASE_TOPIC: DEFAULT_BASE_TOPIC,
            CONF_REFERENCE_JOURNAL_ID: journal_id,
            CONF_ROOMS: rooms_as_dict(default_rooms()),
        },
    )

    with (
        patch.object(
            true_family_integration.TrueFamilyRuntime,
            "async_setup",
            AsyncMock(),
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            AsyncMock(),
        ),
    ):
        assert await true_family_integration.async_setup_entry(hass, entry)

    runtime = entry.runtime_data
    assert hass.data[DOMAIN][entry.entry_id] is runtime
    assert journal_ha._journal_runtime(hass)["owner"] is not None
    with (
        patch.object(runtime, "async_shutdown", AsyncMock()),
        patch.object(
            hass.config_entries,
            "async_unload_platforms",
            AsyncMock(return_value=True),
        ),
    ):
        assert await true_family_integration.async_unload_entry(hass, entry)
    assert journal_ha._journal_runtime(hass)["owner"] is None


async def test_factory_rejects_absent_or_corrupt_data_without_writing(
    hass: HomeAssistant,
) -> None:
    """Never turn a missing or malformed journal into a new empty journal."""

    absent = FakeStore(None)
    with pytest.raises(journal_ha.ReferenceJournalNotProvisionedError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=absent,
            durability_barrier=FakeDurabilityBarrier(),
        )
    assert absent.save_calls == 0

    malformed_root = journal_ha.empty_reference_journal_data(JOURNAL_ID)
    malformed_root["content_digest"] = "0" * 64
    corrupt = FakeStore(malformed_root)
    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=corrupt,
            durability_barrier=FakeDurabilityBarrier(),
        )
    assert corrupt.save_calls == 0

    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=JOURNAL_ID,
            store=corrupt,
            durability_barrier=FakeDurabilityBarrier(),
        )
    assert corrupt.save_calls == 0


async def test_swallowed_store_write_is_detected_by_exact_read_back(
    hass: HomeAssistant,
) -> None:
    """Fail closed when async_save returns but the old generation remains."""

    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    plan = unchanged_completed_fixture().plan
    await worker_call(
        hass,
        journal.set_state,
        plan.plan_id,
        migration.MigrationState.PLANNED,
    )
    await worker_call(
        hass,
        journal.record_plan,
        plan,
        MANIFEST_DIGEST,
        EXECUTION_BINDING,
    )
    fake.swallow_writes = True

    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await worker_call(
            hass,
            journal.set_state,
            plan.plan_id,
            migration.MigrationState.APPLYING,
        )

    assert fake.save_calls == 3
    assert fake.data is not None
    assert fake.data["generation"] == 2
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await worker_call(hass, journal.incomplete_plan_ids)
    await journal.async_close()


async def test_synchronous_methods_reject_event_loop_thread(
    hass: HomeAssistant,
) -> None:
    """Protect the HA loop from a run_coroutine_threadsafe deadlock."""

    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )

    with pytest.raises(journal_ha.ReferenceJournalThreadError):
        journal.incomplete_plan_ids()
    assert fake.save_calls == 0
    await journal.async_close()


async def test_single_process_owner_rejects_second_and_stale_adapters(
    hass: HomeAssistant,
) -> None:
    """Allow exactly one Store adapter to own journal mutations."""

    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    first = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    with pytest.raises(journal_ha.ReferenceJournalOwnershipError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=fake,
            durability_barrier=FakeDurabilityBarrier(),
        )
    await first.async_close()
    second = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    with pytest.raises(journal_ha.ReferenceJournalOwnershipError):
        await first.async_run(first.incomplete_plan_ids)
    assert await second.async_run(second.incomplete_plan_ids) == ()
    await second.async_close()


async def test_cancelled_caller_waits_for_durable_worker_completion(
    hass: HomeAssistant,
) -> None:
    """Shield a coordinator worker from caller cancellation."""

    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    entered = threading.Event()
    release = threading.Event()
    plan = unchanged_completed_fixture().plan
    await journal.async_run(journal.set_state, plan.plan_id, migration.MigrationState.PLANNED)
    await journal.async_run(
        journal.record_plan,
        plan,
        MANIFEST_DIGEST,
        EXECUTION_BINDING,
    )

    def operation() -> None:
        entered.set()
        release.wait()
        journal.set_state(plan.plan_id, migration.MigrationState.APPLYING)

    task = asyncio.create_task(journal.async_run(operation))
    await hass.async_add_executor_job(entered.wait)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await journal.async_run(journal.incomplete_plan_ids) == (plan.plan_id,)
    await journal.async_close()


async def test_failed_plan_can_return_to_planned_after_adapter_reload(
    hass: HomeAssistant,
) -> None:
    """Permit deterministic retry of a persisted failed plan after restart."""

    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    first = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    await first.async_run(first.set_state, PLAN_ID, migration.MigrationState.PLANNED)
    await first.async_run(first.set_state, PLAN_ID, migration.MigrationState.FAILED)
    await first.async_close()

    second = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    await second.async_run(second.set_state, PLAN_ID, migration.MigrationState.PLANNED)
    await second.async_close()
    assert fake.data is not None
    assert fake.data["content"]["states"][PLAN_ID]["state"] == (
        migration.MigrationState.PLANNED.value
    )


async def test_cancelled_close_drains_worker_and_releases_owner(
    hass: HomeAssistant,
) -> None:
    """Repeated cancellation cannot release ownership before worker shutdown."""

    fake = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    first = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    entered = threading.Event()
    release = threading.Event()

    def operation() -> None:
        entered.set()
        release.wait()

    running = asyncio.create_task(first.async_run(operation))
    await hass.async_add_executor_job(entered.wait)
    closing = asyncio.create_task(first.async_close())
    await asyncio.sleep(0)
    closing.cancel()
    await asyncio.sleep(0)
    closing.cancel()
    discovery.mark_reference_journal_reload_pending(
        hass,
        "closing-reference-journal-entry",
        first,
    )
    assert discovery.reference_journal_reload_is_pending(
        hass,
        "closing-reference-journal-entry",
    )
    with pytest.raises(journal_ha.ReferenceJournalOwnershipError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=fake,
            durability_barrier=FakeDurabilityBarrier(),
        )
    release.set()
    await running
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert not discovery.reference_journal_reload_is_pending(
        hass,
        "closing-reference-journal-entry",
    )

    second = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=fake,
        durability_barrier=FakeDurabilityBarrier(),
    )
    await second.async_close()


async def test_explicit_provisioning_detects_a_swallowed_write(
    hass: HomeAssistant,
) -> None:
    """Require exact generation-zero read-back during explicit provisioning."""

    fake = FakeStore(None)
    fake.swallow_writes = True

    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal_ha.async_provision_reference_journal(
            hass,
            journal_id=JOURNAL_ID,
            store=fake,
            durability_barrier=FakeDurabilityBarrier(),
        )
    assert fake.save_calls == 1
    assert fake.data is None
