"""Disposable Home Assistant tests for the sanitized setup manager."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import re
from typing import cast
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Context, HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry
import pytest

from custom_components.true_family import setup_manager as setup
from custom_components.true_family import reference_migration as migration
from custom_components.true_family import reference_migration_ha as journal_ha
from custom_components.true_family import reference_transaction as transaction
from custom_components.true_family.bootstrap import CANONICAL_ROOM_IDS
from custom_components.true_family.const import CONF_BOOTSTRAP, DOMAIN
from custom_components.true_family.reference_migration import (
    MigrationPlan,
    MigrationResult,
    MigrationState,
    PlannedDocument,
)
from custom_components.true_family import reference_providers_ha as providers

from helpers import create_physical_climate


TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def create_seven_sources(hass: HomeAssistant) -> dict[str, str]:
    """Create seven registry-proven MQTT climates for bootstrap."""

    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = {}
    for index, room_id in enumerate(CANONICAL_ROOM_IDS, start=1):
        binding = create_physical_climate(
            hass,
            mqtt_entry=mqtt_entry,
            ieee_address=f"0xa4c138{index:010x}",
            object_id=f"manager_{room_id}_radiator",
        )
        assignments[room_id] = binding.climate_entity_id
    return assignments


def expected_manifest(*, populated: bool = False):
    """Build a server-owned five-provider manifest with leakage canaries."""

    return providers.ExpectedObjectManifest.from_mapping(
        "server-manifest-revision-canary",
        {
            provider: ((f"{provider}:private-object-key-canary",) if populated else ())
            for provider in providers.PROVIDER_NAMES
        },
    )


def exact_inventories(expected):
    """Return exact payload-free inventories for a supplied manifest."""

    return tuple(
        providers.ProviderInventory.readable(
            item.provider,
            (
                providers.InventoryObject(object_key, revision=1)
                for object_key in item.object_keys
            ),
        )
        for item in expected.providers
    )


def bridge_id(provider: str) -> str:
    return f"bridge-{provider}-v1"


def readiness_revision(provider: str) -> str:
    return f"readiness-{provider}-v1"


def inventory_revision(expected, provider: str) -> str:
    expected_provider = expected.for_provider(provider)
    return providers.ProviderInventory.readable(
        provider,
        (
            providers.InventoryObject(key, revision=1)
            for key in expected_provider.object_keys
        ),
    ).revision_digest


def execution_scope(expected) -> setup.MigrationExecutionScope:
    return setup.MigrationExecutionScope(
        expected_manifest_digest=expected.digest,
        providers=tuple(
            setup.ProviderExecutionBinding(
                provider=provider,
                bridge_id=bridge_id(provider),
                readiness_revision=readiness_revision(provider),
                inventory_revision=inventory_revision(expected, provider),
            )
            for provider in providers.PROVIDER_NAMES
        ),
        transaction_recorder=setup.TransactionRecorderCoverage(
            recorder_id="nonsecret-reference-recorder-v1",
            journal_id="nonsecret-reference-journal-v1",
            providers=providers.PROVIDER_NAMES,
        ),
    )


def durable_execution_binding(
    scope: setup.MigrationExecutionScope,
) -> journal_ha.ReferencePlanExecutionBinding:
    """Build the exact Store identity expected for one execution scope."""

    coverage = scope.transaction_recorder
    return journal_ha.ReferencePlanExecutionBinding(
        execution_scope_digest=scope.digest,
        recorder_id=coverage.recorder_id,
        journal_id=coverage.journal_id,
        provider_bridge_ids=tuple(
            (provider, scope.for_provider(provider).bridge_id)
            for provider in sorted(providers.PROVIDER_NAMES)
        ),
    )


def canonical_plan() -> MigrationPlan:
    old_entity_id = "climate.private_old_entity_canary"
    provider_targets = tuple(
        (
            provider,
            f"climate.private_{provider}_target_canary",
        )
        for provider in providers.PROVIDER_NAMES
    )
    provider_objects = []
    for provider in providers.PROVIDER_NAMES:
        documents = ()
        if provider == "active_yaml":
            documents = (
                migration.ReferenceDocument(
                    provider=provider,
                    object_id="private-provider-object-key-canary",
                    revision="private-object-revision-canary",
                    payload={"entity_id": old_entity_id},
                    writable=True,
                ),
            )
        provider_objects.append(migration.InMemoryReferenceProvider(provider, documents))
    authority = migration.InMemoryMigrationAuthority(
        (
            migration.MigrationSubject(
                room_id="guest_room",
                room_revision=0,
                old_entity_id=old_entity_id,
                logical_unique_id="logical_valve_private_canary",
                provider_targets=provider_targets,
            ),
        )
    )
    coordinator = migration.ReferenceMigrationCoordinator(
        provider_objects,
        migration.InMemoryReferenceJournal(),
        authority,
    )
    return coordinator.create_plan(
        room_id="guest_room",
        room_revision=0,
        old_entity_id=old_entity_id,
        logical_unique_id="logical_valve_private_canary",
        target_entity_id=None,
        provider_targets=dict(provider_targets),
        required_providers=set(providers.PROVIDER_NAMES),
        references_expected=True,
    )


def complete_result(
    plan: MigrationPlan,
    *,
    idempotent: bool = False,
) -> MigrationResult:
    """Return the exact complete result for a canonical plan."""

    return MigrationResult(
        plan_id=plan.plan_id,
        digest=plan.digest,
        state=MigrationState.COMPLETE,
        changed_documents=sum(bool(item.exact_paths) for item in plan.documents),
        exact_replacements=plan.exact_replacements,
        idempotent=idempotent,
    )


def durable_outcome(
    plan: MigrationPlan,
    binding: journal_ha.ReferencePlanExecutionBinding,
    state: MigrationState,
    result: MigrationResult | None,
) -> setup.MigrationDurableOutcome:
    """Build exact terminal Store evidence for the fake executor."""

    return setup.MigrationDurableOutcome(
        plan_id=plan.plan_id,
        plan_digest=plan.digest,
        execution_binding=binding,
        state=state,
        result=result,
    )


def external_proof(expected):
    """Return a current external-writer attestation and verifier."""

    now = datetime.now(UTC)
    external = expected.for_provider("external_writers")
    fence = providers.WriterFenceMetadata(
        provider="external_writers",
        writer_id="private-writer-id-canary",
        fence_token_digest=transaction.derive_fence_token_digest(
            "private-fence-token-canary"
        ),
        fence_epoch=4,
        fence_revision=4,
        scope_digest=external.digest,
        acquired_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(hours=1),
    )
    attestation = providers.SignedExternalWriterAttestation(
        provider="external_writers",
        issuer="private-issuer-canary",
        key_id="private-key-id-canary",
        attestation_id="private-attestation-id-canary",
        writer_id=fence.writer_id,
        expected_manifest_digest=expected.digest,
        object_keys=external.object_keys,
        inventory_revision=1,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=30),
        fence=fence,
        signature=b"private-signature-canary",
    )

    class Verifier:
        def verify(self, _attestation, _payload) -> bool:
            return True

    return attestation, Verifier()


class ReadyBridge:
    """Readiness-only test bridge whose mutation methods are canaries."""

    def __init__(self, expected, provider: str) -> None:
        self.name = provider
        self.bridge_id = bridge_id(provider)
        self.expected = expected
        self.readiness_revision = readiness_revision(provider)
        self.readiness_calls = 0
        self.mutation_calls = []

    async def async_readiness(self, expected):
        self.readiness_calls += 1
        assert expected is self.expected
        provider = expected.for_provider(self.name)
        return providers.BridgeReadiness(
            provider=self.name,
            available=True,
            capabilities=providers.ProviderCapabilities(
                True,
                True,
                True,
                True,
                True,
                True,
            ),
            object_count=provider.count,
            expected_manifest_digest=expected.digest,
            object_manifest_digest=provider.digest,
            inventory_revision=providers.ProviderInventory.readable(
                self.name,
                (
                    providers.InventoryObject(key, revision=1)
                    for key in provider.object_keys
                ),
            ).revision_digest,
            bridge_id=self.bridge_id,
            readiness_revision=self.readiness_revision,
        )

    async def async_acquire_writer_fence(self, **_kwargs):
        self.mutation_calls.append("acquire")
        raise AssertionError("The setup manager must not acquire writer fences")

    async def async_compare_and_swap(
        self,
        _operation,
        _authorization,
        *,
        payload,
    ):
        self.mutation_calls.append("write")
        raise AssertionError("The setup manager must not write provider objects")

    async def async_rollback(
        self,
        _operation,
        _authorization,
        *,
        payload,
        write_receipt,
    ):
        self.mutation_calls.append("rollback")
        raise AssertionError("The setup manager must not roll back provider objects")

    async def async_reconcile_operation(self, _operation, _authorization):
        self.mutation_calls.append("reconcile_operation")
        raise AssertionError("The setup manager must not reconcile provider writes")

    async def async_reconcile_fence_acquisition(self, *_args, **_kwargs):
        self.mutation_calls.append("reconcile_acquisition")
        raise AssertionError("The setup manager must not reconcile fence acquisition")

    async def async_reconcile_fence_release(self, *_args, **_kwargs):
        self.mutation_calls.append("reconcile_release")
        raise AssertionError("The setup manager must not reconcile fence release")

    async def async_release_writer_fence(self, *_args, **_kwargs):
        self.mutation_calls.append("release")
        raise AssertionError("The setup manager must not release writer fences")

    async def async_observe_object(self, *_args, **_kwargs):
        self.mutation_calls.append("observe")
        raise AssertionError("The setup manager must not observe provider objects")

    async def async_fence_authority_snapshot(self, *_args, **_kwargs):
        self.mutation_calls.append("fence_state")
        raise AssertionError("The setup manager must not read host fence state")

    async def async_reserve_next_fence_epoch(self, *_args, **_kwargs):
        self.mutation_calls.append("reserve_epoch")
        raise AssertionError("The setup manager must not reserve host epochs")


def ready_manager_parts():
    """Build all explicit production-readiness injections."""

    expected = expected_manifest(populated=True)
    bridges = {
        provider: ReadyBridge(expected, provider)
        for provider in providers.PROVIDER_NAMES
    }
    attestation, verifier = external_proof(expected)
    return expected, bridges, attestation, verifier


async def bootstrap_and_load(hass, entry) -> None:
    """Prepare a real loaded, bootstrapped runtime for migration tests."""

    manager = setup.SetupManager(hass, expected_manifest=expected_manifest())
    planned = await manager.async_plan_bootstrap(create_seven_sources(hass))
    await manager.async_commit_bootstrap(planned["token"])
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


class FakeExecutor:
    """Opaque async executor carrying deliberately sensitive plan fields."""

    def __init__(self) -> None:
        self.bridge_registry = {}
        self.execution_scope = execution_scope(expected_manifest(populated=True))
        self.plan = canonical_plan()
        self.durable_plans = {self.plan.plan_id: self.plan}
        self.execution_bindings = {
            self.plan.plan_id: durable_execution_binding(self.execution_scope)
        }
        self.terminal_outcomes: dict[str, setup.MigrationDurableOutcome] = {}
        self.bind_planned_scope = True
        self.auto_commit_terminal_outcome = True
        self.auto_recovery_terminal_outcome = True
        self.planned_rooms = []
        self.committed_plans = []
        self.commit_contexts = []
        self.recovered_plan_ids = []
        self.recovery_contexts = []
        self.incomplete_plan_ids: tuple[str, ...] = ()
        self.recovery_mode = "complete"
        self.recovery_result: MigrationResult | None = None
        self.recovery_provider_names = ("scheduler",)
        self.recovery_required_capabilities = tuple(
            sorted(
                (
                    providers.BridgeRecoveryCapability.OBJECT_LEDGER,
                    providers.BridgeRecoveryCapability.OBJECT_OBSERVATION,
                ),
                key=lambda item: item.value,
            )
        )
        self.recovery_available_capabilities = self.recovery_required_capabilities

    async def async_plan(self, room_id: str) -> MigrationPlan:
        self.planned_rooms.append(room_id)
        self.durable_plans[self.plan.plan_id] = self.plan
        if self.bind_planned_scope:
            self.execution_bindings[self.plan.plan_id] = durable_execution_binding(
                self.execution_scope
            )
        self.terminal_outcomes.pop(self.plan.plan_id, None)
        return self.plan

    async def async_execution_binding(
        self,
        plan_id: str,
    ) -> journal_ha.ReferencePlanExecutionBinding | None:
        return self.execution_bindings.get(plan_id)

    async def async_recovery_plan(self, plan_id: str) -> MigrationPlan:
        return self.durable_plans[plan_id]

    async def async_terminal_outcome(
        self,
        plan_id: str,
    ) -> setup.MigrationDurableOutcome:
        return cast(
            setup.MigrationDurableOutcome,
            self.terminal_outcomes.get(plan_id),
        )

    async def async_commit(
        self,
        plan: MigrationPlan,
        context: Context,
    ) -> MigrationResult:
        self.committed_plans.append(plan)
        self.commit_contexts.append(context)
        result = complete_result(plan)
        if self.auto_commit_terminal_outcome:
            self.terminal_outcomes[plan.plan_id] = durable_outcome(
                plan,
                self.execution_bindings[plan.plan_id],
                MigrationState.COMPLETE,
                result,
            )
        return result

    async def async_recover(
        self,
        plan_id: str,
        context: Context,
    ) -> MigrationResult | None:
        self.recovered_plan_ids.append(plan_id)
        self.recovery_contexts.append(context)
        if self.recovery_mode == "complete":
            self.incomplete_plan_ids = tuple(
                item for item in self.incomplete_plan_ids if item != plan_id
            )
        elif self.recovery_mode == "partial":
            self.incomplete_plan_ids = (plan_id,)
        if self.auto_recovery_terminal_outcome:
            terminal_result = (
                None
                if self.recovery_result is None
                else replace(self.recovery_result, idempotent=False)
            )
            self.terminal_outcomes[plan_id] = durable_outcome(
                self.durable_plans[plan_id],
                self.execution_bindings[plan_id],
                (
                    MigrationState.FAILED
                    if self.recovery_result is None
                    else MigrationState.COMPLETE
                ),
                terminal_result,
            )
        return self.recovery_result

    async def async_incomplete_plan_ids(self) -> tuple[str, ...]:
        return self.incomplete_plan_ids

    async def async_recovery_readiness(
        self,
        plan_id: str,
    ) -> setup.MigrationRecoveryReadiness:
        coverage = self.execution_scope.transaction_recorder
        return setup.MigrationRecoveryReadiness(
            plan_id=plan_id,
            execution_scope_digest=self.execution_scope.digest,
            recorder_id=coverage.recorder_id,
            journal_id=coverage.journal_id,
            journal_readable=True,
            providers=tuple(
                setup.ProviderRecoveryReadiness(
                    provider=provider,
                    journal_bridge_id=self.execution_scope.for_provider(
                        provider
                    ).bridge_id,
                    required_capabilities=self.recovery_required_capabilities,
                    available_capabilities=self.recovery_available_capabilities,
                )
                for provider in self.recovery_provider_names
            ),
        )


async def test_unloaded_bootstrap_plan_and_commit_stay_unloaded(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Plan and commit exactly seven mappings without loading the entry."""

    assignments = create_seven_sources(hass)
    original_data = deepcopy(dict(true_family_entry.data))
    manager = setup.SetupManager(hass, expected_manifest=expected_manifest())

    planned = await manager.async_plan_bootstrap(assignments)

    assert TOKEN_PATTERN.fullmatch(planned["token"])
    assert planned["room_count"] == 7
    assert [room["room_id"] for room in planned["rooms"]] == list(
        CANONICAL_ROOM_IDS
    )
    assert all(
        set(room) == {"room_id", "display_name", "revision"}
        for room in planned["rooms"]
    )
    assert true_family_entry.data == original_data
    assert true_family_entry.state is ConfigEntryState.NOT_LOADED
    rendered = json.dumps(planned, sort_keys=True)
    assert not any(entity_id in rendered for entity_id in assignments.values())
    assert "0xa4c138" not in rendered

    committed = await manager.async_commit_bootstrap(planned["token"])

    assert committed["state"] == "complete"
    assert committed["room_count"] == 7
    assert CONF_BOOTSTRAP in true_family_entry.data
    assert true_family_entry.state is ConfigEntryState.NOT_LOADED


async def test_newest_bootstrap_token_supersedes_prior_manager_call(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Invalidate an older public token even when its internal plan is equal."""

    manager = setup.SetupManager(hass, expected_manifest=expected_manifest())
    assignments = create_seven_sources(hass)
    first = await manager.async_plan_bootstrap(assignments)
    second = await manager.async_plan_bootstrap(assignments)

    assert first["token"] != second["token"]
    with pytest.raises(setup.SetupManagerError) as error:
        await manager.async_commit_bootstrap(first["token"])
    assert error.value.code == "plan_unknown"
    assert await manager.async_commit_bootstrap(second["token"])


async def test_loaded_entry_rejects_bootstrap_without_automatic_unload(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Leave a loaded entry untouched rather than unloading it for commit."""

    manager = setup.SetupManager(hass, expected_manifest=expected_manifest())
    planned = await manager.async_plan_bootstrap(create_seven_sources(hass))
    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()

    with pytest.raises(setup.SetupManagerError) as error:
        await manager.async_commit_bootstrap(planned["token"])

    assert error.value.as_dict() == {
        "code": "entry_not_unloaded",
        "message": "True Family must be unloaded for bootstrap.",
    }
    assert true_family_entry.state is ConfigEntryState.LOADED
    assert CONF_BOOTSTRAP not in true_family_entry.data


async def test_errors_and_singleton_discovery_are_fixed_and_sanitized(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Never return registry evidence or backend exception text in errors."""

    manager = setup.SetupManager(hass, expected_manifest=expected_manifest())
    assignments = create_seven_sources(hass)
    private_canary = "climate.private_registry_error_canary"
    assignments["guest_room"] = private_canary

    with pytest.raises(setup.SetupManagerError) as error:
        await manager.async_plan_bootstrap(assignments)

    assert error.value.as_dict() == {
        "code": "bootstrap_invalid",
        "message": "The bootstrap selection could not be verified.",
    }
    assert private_canary not in str(error.value)
    assert private_canary not in json.dumps(error.value.as_dict())

    second = MockConfigEntry(
        domain=DOMAIN,
        title="Private duplicate title canary",
        unique_id="private-duplicate-id-canary",
        data={},
    )
    second.add_to_hass(hass)
    with pytest.raises(setup.SetupManagerError) as singleton_error:
        await manager.async_status()
    assert singleton_error.value.code == "entry_not_singleton"
    assert "private-duplicate" not in str(singleton_error.value)


async def test_readiness_is_read_only_and_blocks_without_bridges(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Inventory all five providers but stay blocked with no write bridges."""

    await bootstrap_and_load(hass, true_family_entry)
    expected = expected_manifest(populated=True)
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
    )
    inventories = exact_inventories(expected)

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=inventories),
    ) as probe:
        readiness = await manager.async_check_migration_readiness()
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_plan_migration("guest_room", 0)

    assert readiness["ready"] is False
    assert [item["provider"] for item in readiness["providers"]] == list(
        providers.PROVIDER_NAMES
    )
    assert all(item["status"] != "ready" for item in readiness["providers"])
    assert error.value.code == "migration_executor_missing"
    assert probe.await_count == 1
    rendered = json.dumps(readiness, sort_keys=True)
    assert "private-object-key-canary" not in rendered
    assert expected.digest not in rendered


async def test_migration_requires_an_explicit_executor_even_when_bridges_ready(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Fail closed before planning when no executor was server-injected."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ) as probe:
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_plan_migration("guest_room", 0)

    assert error.value.code == "migration_executor_missing"
    probe.assert_not_awaited()
    assert all(bridge.readiness_calls == 0 for bridge in bridges.values())
    assert all(bridge.mutation_calls == [] for bridge in bridges.values())


async def test_injected_executor_keeps_internal_plan_fields_opaque(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Pass opaque plans by identity and map recovery through a random token."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    inventory_probe = AsyncMock(return_value=exact_inventories(expected))
    durable_binding = durable_execution_binding(executor.execution_scope)
    coverage = executor.execution_scope.transaction_recorder
    hidden = (
        executor.plan.plan_id,
        executor.plan.digest,
        executor.execution_scope.digest,
        durable_binding.digest,
        coverage.recorder_id,
        coverage.journal_id,
        *(bridge_id for _provider, bridge_id in durable_binding.provider_bridge_ids),
        "climate.private_old_entity_canary",
        "logical_valve_private_canary",
        "private-provider-object-key-canary",
        "private-object-revision-canary",
        executor.plan.documents[0].fingerprint,
        executor.plan.documents[0].post_fingerprint,
        "private-writer-id-canary",
        "private-fence-token-canary",
        "private-attestation-id-canary",
        *(target for _provider, target in executor.plan.provider_targets),
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        inventory_probe,
    ):
        status = await manager.async_status()
        first = await manager.async_plan_migration("guest_room", 0)
        second = await manager.async_plan_migration("guest_room", 0)
        with pytest.raises(setup.SetupManagerError) as old_token_error:
            await manager.async_commit_migration(first["token"], Context())
        committed = await manager.async_commit_migration(second["token"], Context())
        recovery_plan = await manager.async_plan_migration("guest_room", 0)
        executor.incomplete_plan_ids = (executor.plan.plan_id,)
        recovery_status = await manager.async_status()
        recovery_token = recovery_status["migration"]["recovery_tokens"][0]
        recovered = await manager.async_recover_migration(
            recovery_token,
            Context(),
        )

    assert set(status) == {
        "entry_state",
        "bootstrap_complete",
        "bootstrap_plan_pending",
        "migration",
    }
    assert set(status["migration"]) == {
        "ready",
        "providers_ready",
        "executor_configured",
        "plan_pending",
        "recovery_pending",
        "recovery_checked",
        "recovery_tokens",
        "providers",
    }
    assert status["migration"]["ready"] is True
    assert old_token_error.value.code == "plan_unknown"
    assert TOKEN_PATTERN.fullmatch(second["token"])
    assert executor.committed_plans == [executor.plan]
    assert executor.committed_plans[0] is executor.plan
    assert executor.recovered_plan_ids == [executor.plan.plan_id]
    assert committed == {
        "state": "complete",
        "room": {
            "room_id": "guest_room",
            "display_name": "Guest Room",
            "revision": 0,
        },
        "provider_count": 5,
        "changed_document_count": 1,
        "replacement_count": 1,
    }
    assert recovered["state"] == "recovered"
    assert all(bridge.mutation_calls == [] for bridge in bridges.values())

    for public_value in (status, first, second, committed, recovery_plan, recovered):
        rendered = json.dumps(public_value, sort_keys=True)
        assert all(canary not in rendered for canary in hidden)


async def test_executor_exception_and_busy_operation_use_fixed_errors(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject concurrent calls and suppress an executor's private exception."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingExecutor(FakeExecutor):
        async def async_plan(self, room_id: str) -> MigrationPlan:
            entered.set()
            await release.wait()
            raise RuntimeError("private-executor-exception-canary")

    executor = BlockingExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planning = asyncio.create_task(
            manager.async_plan_migration("guest_room", 0)
        )
        await entered.wait()
        with pytest.raises(setup.SetupManagerError) as busy_error:
            await manager.async_status()
        release.set()
        with pytest.raises(setup.SetupManagerError) as plan_error:
            await planning

    assert busy_error.value.as_dict() == {
        "code": "busy",
        "message": "Another True Family setup operation is in progress.",
    }
    assert plan_error.value.code == "migration_plan_failed"
    assert "private-executor" not in str(plan_error.value)


async def test_process_restart_accepts_none_only_after_durable_recovery_completes(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Recover with reconstructed scope objects without exposing durable state."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    prior_process = FakeExecutor()
    prior_process.incomplete_plan_ids = (prior_process.plan.plan_id,)
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.plan = replace(prior_process.plan)
    executor.durable_plans = {executor.plan.plan_id: executor.plan}
    executor.execution_bindings = dict(prior_process.execution_bindings)
    executor.incomplete_plan_ids = prior_process.incomplete_plan_ids
    assert executor.execution_scope is not prior_process.execution_scope
    assert durable_execution_binding(executor.execution_scope) == (
        prior_process.execution_bindings[prior_process.plan.plan_id]
    )
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        result = await manager.async_recover_migration(recovery_token, Context())

    assert TOKEN_PATTERN.fullmatch(recovery_token)
    assert executor.plan.plan_id not in json.dumps(status)
    assert executor.recovery_result is None
    assert result == {"state": "recovered"}
    assert executor.recovered_plan_ids == [executor.plan.plan_id]
    terminal = executor.terminal_outcomes[executor.plan.plan_id]
    assert terminal.state is MigrationState.FAILED
    assert terminal.result is None


async def test_process_restart_rejects_store_binding_from_substituted_scope(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject a restarted executor whose bridge scope differs from Store."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    durable_binding = executor.execution_bindings[executor.plan.plan_id]
    substituted_scheduler = ReadyBridge(expected, "scheduler")
    substituted_scheduler.bridge_id = "bridge-scheduler-substituted-v2"
    substituted_bridges = {
        **bridges,
        "scheduler": substituted_scheduler,
    }
    executor.execution_scope = replace(
        executor.execution_scope,
        providers=tuple(
            replace(binding, bridge_id=substituted_scheduler.bridge_id)
            if binding.provider == "scheduler"
            else binding
            for binding in executor.execution_scope.providers
        ),
    )
    executor.bridge_registry = substituted_bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=substituted_bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_not_ready"
    assert executor.recovered_plan_ids == []
    rendered = json.dumps(status, sort_keys=True)
    assert durable_binding.execution_scope_digest not in rendered
    assert substituted_scheduler.bridge_id not in rendered


async def test_recovery_accepts_idempotent_replay_with_canonical_durable_result(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Allow replay metadata to differ while durable effect fields stay canonical."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    executor.recovery_result = complete_result(executor.plan, idempotent=True)
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        result = await manager.async_recover_migration(recovery_token, Context())

    assert result == {"state": "recovered"}
    assert executor.recovered_plan_ids == [executor.plan.plan_id]
    assert executor.incomplete_plan_ids == ()
    terminal = executor.terminal_outcomes[executor.plan.plan_id]
    assert terminal.state is MigrationState.COMPLETE
    assert executor.recovery_result is not None
    assert terminal.result is not None
    assert executor.recovery_result.idempotent is True
    assert terminal.result == replace(executor.recovery_result, idempotent=False)
    assert terminal.result.idempotent is False


async def test_recovery_rejects_noncanonical_durable_plan_before_execution(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Fail closed when Store returns a plan with an invalid canonical digest."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    executor.durable_plans[executor.plan.plan_id] = replace(
        executor.plan,
        digest="0" * 64,
    )
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_recovery_failed"
    assert executor.recovered_plan_ids == []
    assert executor.incomplete_plan_ids == (executor.plan.plan_id,)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("digest", "0" * 64),
        ("state", MigrationState.BLOCKED),
        ("changed_documents", 99),
        ("exact_replacements", 99),
        ("exact_replacements", -1),
        ("exact_replacements", True),
    ),
)
async def test_recovery_rejects_malformed_complete_result(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    field: str,
    value: object,
) -> None:
    """Apply the complete commit-result validator to recovery results."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    executor.recovery_result = replace(
        complete_result(executor.plan),
        **{field: value},
    )
    executor.auto_recovery_terminal_outcome = False
    executor.terminal_outcomes[executor.plan.plan_id] = durable_outcome(
        executor.plan,
        executor.execution_bindings[executor.plan.plan_id],
        MigrationState.COMPLETE,
        complete_result(executor.plan),
    )
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_recovery_failed"
    assert executor.recovered_plan_ids == [executor.plan.plan_id]


async def test_recovery_rejects_missing_terminal_record_after_effect(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Never infer restored failure from deletion or incomplete-set absence."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    executor.auto_recovery_terminal_outcome = False
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_recovery_failed"
    assert executor.incomplete_plan_ids == ()
    assert executor.plan.plan_id not in executor.terminal_outcomes


async def test_recovery_rejects_deleted_execution_binding_after_effect(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Require the exact active Store binding after recovery has effects."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    original_recover = executor.async_recover

    async def delete_binding(plan_id: str, context: Context):
        result = await original_recover(plan_id, context)
        executor.execution_bindings.pop(plan_id)
        return result

    executor.async_recover = delete_binding
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_recovery_failed"
    assert executor.recovered_plan_ids == [executor.plan.plan_id]


@pytest.mark.parametrize(
    "returned_result",
    ("none_with_complete", "result_with_failed"),
)
async def test_recovery_requires_terminal_state_matching_return_value(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    returned_result: str,
) -> None:
    """Bind None to restored failure and results to complete outcomes only."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    executor.auto_recovery_terminal_outcome = False
    complete = complete_result(executor.plan)
    if returned_result == "none_with_complete":
        executor.recovery_result = None
        state = MigrationState.COMPLETE
        terminal_result = complete
    else:
        executor.recovery_result = complete
        state = MigrationState.FAILED
        terminal_result = None
    executor.terminal_outcomes[executor.plan.plan_id] = durable_outcome(
        executor.plan,
        executor.execution_bindings[executor.plan.plan_id],
        state,
        terminal_result,
    )
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_recovery_failed"
    assert executor.recovered_plan_ids == [executor.plan.plan_id]


async def test_recovery_ignores_expired_attestation_and_unrelated_providers(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Use only journal-selected bridges instead of ordinary readiness."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    now = datetime.now(UTC)
    expired_attestation = replace(
        attestation,
        expires_at=now - timedelta(seconds=30),
        fence=replace(
            attestation.fence,
            expires_at=now - timedelta(seconds=15),
        ),
    )
    executor = FakeExecutor()
    executor.bridge_registry = {"scheduler": bridges["scheduler"]}
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=executor.bridge_registry,
        external_attestation=expired_attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    probe = AsyncMock(return_value=exact_inventories(expected))

    with patch.object(setup, "async_probe_home_assistant_inventory", probe):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        readiness_calls = bridges["scheduler"].readiness_calls
        result = await manager.async_recover_migration(recovery_token, Context())

    assert status["migration"]["providers_ready"] is False
    assert result == {"state": "recovered"}
    assert bridges["scheduler"].readiness_calls == readiness_calls
    assert probe.await_count == 1
    assert bridges["scheduler"].mutation_calls == []
    assert all(
        bridge.readiness_calls == 0
        for provider, bridge in bridges.items()
        if provider != "scheduler"
    )


async def test_recovery_rechecks_store_binding_after_recovery_readiness(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Catch execution-scope substitution during recovery readiness."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    original_readiness = executor.async_recovery_readiness

    async def substitute_binding(plan_id: str):
        readiness = await original_readiness(plan_id)
        binding = executor.execution_bindings[plan_id]
        executor.execution_bindings[plan_id] = replace(
            binding,
            recorder_id="substituted-recovery-recorder-v2",
        )
        return readiness

    executor.async_recovery_readiness = substitute_binding
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_not_ready"
    assert executor.recovered_plan_ids == []


async def test_noop_recovery_retains_token_and_fails_closed(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Never report recovery when the selected durable plan remains incomplete."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.incomplete_plan_ids = (executor.plan.plan_id,)
    executor.recovery_mode = "noop"
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        recovery_token = status["migration"]["recovery_tokens"][0]
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())
        after = await manager.async_status()

    assert error.value.code == "migration_recovery_failed"
    assert after["migration"]["recovery_tokens"] == [recovery_token]
    assert executor.incomplete_plan_ids == (executor.plan.plan_id,)


async def test_partial_recovery_retains_selected_token_and_fails_closed(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Removing other incomplete work cannot complete the selected plan."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    unrelated_plan_id = "tf-reference-unrelated-incomplete-plan"
    executor.incomplete_plan_ids = (executor.plan.plan_id, unrelated_plan_id)
    executor.recovery_mode = "partial"
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        await manager.async_status()
        recovery_token = next(
            token
            for token, plan_id in manager._recovery_plan_ids.items()
            if plan_id == executor.plan.plan_id
        )
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_recover_migration(recovery_token, Context())

    assert error.value.code == "migration_recovery_failed"
    assert manager._recovery_plan_ids[recovery_token] == executor.plan.plan_id
    assert unrelated_plan_id not in manager._recovery_plan_ids.values()
    assert executor.incomplete_plan_ids == (executor.plan.plan_id,)


async def test_runtime_reload_invalidates_pending_migration_plan(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject a token planned against a previous loaded runtime object."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    probe = AsyncMock(return_value=exact_inventories(expected))

    with patch.object(setup, "async_probe_home_assistant_inventory", probe):
        planned = await manager.async_plan_migration("guest_room", 0)
        assert await hass.config_entries.async_reload(true_family_entry.entry_id)
        await hass.async_block_till_done()
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_revision_stale"
    assert executor.committed_plans == []


async def test_unreadable_recovery_state_blocks_new_planning(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Fail closed when durable incomplete-plan discovery is unavailable."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.async_incomplete_plan_ids = AsyncMock(
        side_effect=RuntimeError("private-journal-read-canary")
    )
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        status = await manager.async_status()
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_plan_migration("guest_room", 0)

    assert status["migration"]["ready"] is False
    assert status["migration"]["recovery_checked"] is False
    assert error.value.code == "migration_recovery_required"
    assert executor.planned_rooms == []
    assert "private-journal-read-canary" not in json.dumps(status)


async def test_executor_bridge_substitution_is_rejected_after_construction(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Keep readiness and execution bound to the same five bridge objects."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    executor.bridge_registry = {
        **bridges,
        "scheduler": ReadyBridge(expected, "scheduler"),
    }

    with pytest.raises(setup.SetupManagerError) as error:
        await manager.async_plan_migration("guest_room", 0)

    assert error.value.code == "migration_executor_missing"
    assert executor.planned_rooms == []


async def test_executor_execution_scope_substitution_is_rejected(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Keep each plan bound to the exact immutable scope object."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    executor.execution_scope = replace(executor.execution_scope)

    with pytest.raises(setup.SetupManagerError) as error:
        await manager.async_plan_migration("guest_room", 0)

    assert error.value.code == "migration_executor_missing"
    assert executor.planned_rooms == []


async def test_readiness_revision_drift_blocks_execution_scope(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject a current bridge proof outside the immutable execution revision."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    bridges["scheduler"].readiness_revision = "readiness-scheduler-v2"

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_plan_migration("guest_room", 0)

    assert error.value.code == "migration_not_ready"
    assert executor.planned_rooms == []


async def test_noncanonical_executor_plan_is_rejected(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Validate the full canonical plan digest instead of trusting its shape."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.plan = replace(executor.plan, digest="0" * 64)
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_plan_migration("guest_room", 0)

    assert error.value.code == "migration_plan_failed"
    assert executor.planned_rooms == ["guest_room"]


@pytest.mark.parametrize(
    "binding_field",
    (
        "execution_scope_digest",
        "recorder_id",
        "journal_id",
        "provider_bridge_ids",
    ),
)
async def test_plan_requires_exact_store_execution_binding(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    binding_field: str,
) -> None:
    """Reject every mismatched component of the Store-bound plan identity."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.bind_planned_scope = False
    binding = executor.execution_bindings[executor.plan.plan_id]
    if binding_field == "provider_bridge_ids":
        replacement = tuple(
            (
                provider,
                "bridge-scheduler-store-substituted-v2"
                if provider == "scheduler"
                else current_bridge_id,
            )
            for provider, current_bridge_id in binding.provider_bridge_ids
        )
    elif binding_field == "execution_scope_digest":
        replacement = "0" * 64
    else:
        replacement = f"substituted-{binding_field}-v2"
    executor.execution_bindings[executor.plan.plan_id] = replace(
        binding,
        **{binding_field: replacement},
    )
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_plan_migration("guest_room", 0)

    assert error.value.code == "migration_plan_failed"
    assert executor.planned_rooms == ["guest_room"]
    assert manager._migration_token is None


async def test_commit_requires_store_binding_before_readiness(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Do not start readiness if the pending plan lost its durable binding."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)

    binding = executor.execution_bindings[executor.plan.plan_id]
    executor.execution_bindings[executor.plan.plan_id] = replace(
        binding,
        journal_id="substituted-journal-before-commit-v2",
    )
    probe = AsyncMock(return_value=exact_inventories(expected))
    with patch.object(setup, "async_probe_home_assistant_inventory", probe):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_commit_failed"
    probe.assert_not_awaited()
    assert executor.committed_plans == []


async def test_commit_rechecks_store_binding_after_readiness_await(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Catch durable binding substitution performed during readiness."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)

    async def substitute_binding(*_args, **_kwargs):
        binding = executor.execution_bindings[executor.plan.plan_id]
        executor.execution_bindings[executor.plan.plan_id] = replace(
            binding,
            recorder_id="substituted-recorder-during-readiness-v2",
        )
        return exact_inventories(expected)

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        side_effect=substitute_binding,
    ):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_commit_failed"
    assert executor.committed_plans == []


async def test_commit_rejects_missing_terminal_record_after_effect(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Do not report a valid return value without a durable terminal record."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.auto_commit_terminal_outcome = False
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_commit_failed"
    assert executor.committed_plans == [executor.plan]
    assert executor.plan.plan_id not in executor.terminal_outcomes


async def test_commit_rejects_substituted_execution_binding_after_effect(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Re-read and reject a changed Store binding after provider effects."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    original_commit = executor.async_commit

    async def substitute_binding(plan: MigrationPlan, context: Context):
        result = await original_commit(plan, context)
        executor.execution_bindings[plan.plan_id] = replace(
            executor.execution_bindings[plan.plan_id],
            journal_id="substituted-journal-after-effect-v2",
        )
        return result

    executor.async_commit = substitute_binding
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_commit_failed"
    assert executor.committed_plans == [executor.plan]


@pytest.mark.parametrize(
    "terminal_mismatch",
    (
        "failed_state",
        "different_complete_result",
        "substituted_outcome_binding",
    ),
)
async def test_commit_requires_terminal_outcome_matching_returned_result(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    terminal_mismatch: str,
) -> None:
    """Require exact state and result equality in terminal Store evidence."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    executor.auto_commit_terminal_outcome = False
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )
    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)
        if terminal_mismatch == "failed_state":
            state = MigrationState.FAILED
            terminal_result = None
        else:
            state = MigrationState.COMPLETE
            terminal_result = complete_result(executor.plan)
            if terminal_mismatch == "different_complete_result":
                terminal_result = replace(
                    terminal_result,
                    changed_documents=99,
                )
        terminal_binding = executor.execution_bindings[executor.plan.plan_id]
        if terminal_mismatch == "substituted_outcome_binding":
            terminal_binding = replace(
                terminal_binding,
                recorder_id="substituted-terminal-recorder-v2",
            )
        executor.terminal_outcomes[executor.plan.plan_id] = durable_outcome(
            executor.plan,
            terminal_binding,
            state,
            terminal_result,
        )
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_commit_failed"
    assert executor.committed_plans == [executor.plan]


async def test_commit_revalidates_revision_after_readiness_await(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Close the revision race between asynchronous readiness and execution."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)

    async def mutate_revision(*args, **kwargs):
        data = deepcopy(dict(true_family_entry.data))
        data["rooms"]["guest_room"]["revision"] = 1
        hass.config_entries.async_update_entry(true_family_entry, data=data)
        return exact_inventories(expected)

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        side_effect=mutate_revision,
    ):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_revision_stale"
    assert executor.committed_plans == []


async def test_commit_revalidates_bridges_after_readiness_await(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
) -> None:
    """Reject bridge substitution performed during asynchronous readiness."""

    await bootstrap_and_load(hass, true_family_entry)
    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    manager = setup.SetupManager(
        hass,
        expected_manifest=expected,
        bridge_registry=bridges,
        external_attestation=attestation,
        external_verifier=verifier,
        migration_executor=executor,
    )

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        AsyncMock(return_value=exact_inventories(expected)),
    ):
        planned = await manager.async_plan_migration("guest_room", 0)

    async def substitute_bridge(*args, **kwargs):
        executor.bridge_registry = {
            **bridges,
            "scheduler": ReadyBridge(expected, "scheduler"),
        }
        return exact_inventories(expected)

    with patch.object(
        setup,
        "async_probe_home_assistant_inventory",
        side_effect=substitute_bridge,
    ):
        with pytest.raises(setup.SetupManagerError) as error:
            await manager.async_commit_migration(planned["token"], Context())

    assert error.value.code == "migration_executor_missing"
    assert executor.committed_plans == []


def test_production_scope_requires_full_transaction_recorder_coverage() -> None:
    """Keep the legacy direct-write coordinator outside production execution."""

    with pytest.raises(ValueError):
        setup.TransactionRecorderCoverage(
            recorder_id="nonsecret-reference-recorder-v1",
            journal_id="nonsecret-reference-journal-v1",
            providers=providers.PROVIDER_NAMES[:-1],
        )


def test_terminal_outcome_contract_rejects_nonterminal_or_ambiguous_records() -> None:
    """Keep restored failure explicit and distinct from missing completion data."""

    plan = canonical_plan()
    binding = durable_execution_binding(execution_scope(expected_manifest(populated=True)))
    with pytest.raises(TypeError):
        durable_outcome(plan, binding, MigrationState.COMPLETE, None)
    with pytest.raises(ValueError):
        durable_outcome(
            plan,
            binding,
            MigrationState.FAILED,
            complete_result(plan),
        )
    with pytest.raises(ValueError):
        durable_outcome(plan, binding, MigrationState.BLOCKED, None)
    with pytest.raises(ValueError):
        durable_outcome(
            plan,
            binding,
            MigrationState.COMPLETE,
            replace(complete_result(plan), exact_replacements=-1),
        )
    with pytest.raises(ValueError):
        durable_outcome(
            plan,
            binding,
            MigrationState.COMPLETE,
            replace(complete_result(plan), exact_replacements=True),
        )
    with pytest.raises(ValueError):
        durable_outcome(
            plan,
            binding,
            MigrationState.COMPLETE,
            complete_result(plan, idempotent=True),
        )


def test_migration_result_rejects_boolean_exact_replacements() -> None:
    """Require an exact built-in nonnegative replacement count."""

    plan = canonical_plan()
    assert not setup._valid_migration_result(
        replace(complete_result(plan), exact_replacements=True),
        plan,
    )


@pytest.mark.parametrize(
    "missing_method",
    (
        "async_execution_binding",
        "async_recovery_plan",
        "async_terminal_outcome",
    ),
)
def test_executor_contract_requires_durable_plan_accessors(
    hass: HomeAssistant,
    missing_method: str,
) -> None:
    """Reject executors that cannot expose exact Store-bound recovery state."""

    expected, bridges, attestation, verifier = ready_manager_parts()
    executor = FakeExecutor()
    executor.bridge_registry = bridges
    setattr(executor, missing_method, None)

    with pytest.raises(TypeError):
        setup.SetupManager(
            hass,
            expected_manifest=expected,
            bridge_registry=bridges,
            external_attestation=attestation,
            external_verifier=verifier,
            migration_executor=executor,
        )
