"""Test durable bridge transaction records in Home Assistant Store."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
import secrets
from typing import Any, cast

from homeassistant.core import HomeAssistant
import pytest

from custom_components.true_family import reference_migration as migration
from custom_components.true_family import reference_migration_ha as journal_ha
from custom_components.true_family import reference_transaction as transaction


JOURNAL_ID = "true-family-bridge-transaction-ha-test"
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
MAX_AGE_SECONDS = 10
OLD_ENTITY = "climate.guest_room_radiator"
TARGET_ENTITY = "climate.true_family_guest_room"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


MANIFEST_DIGEST = digest("bridge-transaction-manifest")
EXECUTION_BINDING = journal_ha.ReferencePlanExecutionBinding(
    execution_scope_digest=digest("bridge-transaction-execution-scope"),
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


def execution_binding_for(
    journal_id: str,
) -> journal_ha.ReferencePlanExecutionBinding:
    return journal_ha.ReferencePlanExecutionBinding(
        execution_scope_digest=EXECUTION_BINDING.execution_scope_digest,
        recorder_id=EXECUTION_BINDING.recorder_id,
        journal_id=journal_id,
        provider_bridge_ids=EXECUTION_BINDING.provider_bridge_ids,
    )


def build_plan(
    documents: tuple[tuple[str, str | int], ...] = (
        ("profile.guest_room_monday", 7),
    ),
) -> migration.MigrationPlan:
    providers = []
    for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST):
        provider_documents = (
            tuple(
                migration.ReferenceDocument(
                    provider="scheduler",
                    object_id=object_id,
                    revision=revision,
                    payload={"entity_id": OLD_ENTITY},
                    writable=True,
                )
                for object_id, revision in documents
            )
            if provider_name == "scheduler"
            else ()
        )
        providers.append(
            migration.InMemoryReferenceProvider(provider_name, provider_documents)
        )
    targets = tuple(
        (provider_name, TARGET_ENTITY)
        for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    )
    coordinator = migration.ReferenceMigrationCoordinator(
        providers,
        migration.InMemoryReferenceJournal(),
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
    return coordinator.create_plan(
        room_id="guest_room",
        room_revision=7,
        old_entity_id=OLD_ENTITY,
        logical_unique_id="logical_valve_guest_room",
        target_entity_id=TARGET_ENTITY,
        required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
        references_expected=True,
    )


PLAN = build_plan()
PLAN_ID = PLAN.plan_id
PLAN_DIGEST = PLAN.digest
PLAN_DOCUMENT = next(item for item in PLAN.documents if item.exact_paths)
PRE_FINGERPRINT = PLAN_DOCUMENT.fingerprint
POST_FINGERPRINT = PLAN_DOCUMENT.post_fingerprint


class FakeStore:
    def __init__(self, data: dict[str, Any] | None) -> None:
        self.data = deepcopy(data)
        self.swallow_writes = False
        self.raise_writes = False
        self.save_calls = 0

    async def async_load(self) -> dict[str, Any] | None:
        return deepcopy(self.data)

    async def async_save(self, data: dict[str, Any]) -> None:
        self.save_calls += 1
        if self.raise_writes:
            raise OSError("injected Store write failure")
        if not self.swallow_writes:
            self.data = deepcopy(data)


class FakeDurabilityBarrier:
    def __init__(self) -> None:
        self.calls = 0
        self.fail = False

    @property
    def durability_proof(self) -> journal_ha.ReferenceJournalTestDurabilityProof:
        return TEST_DURABILITY_PROOF

    async def async_barrier(self) -> None:
        self.calls += 1
        if self.fail:
            raise RuntimeError("injected post-save barrier failure")


def expected_write() -> transaction.BridgeExpectedWrite:
    return transaction.BridgeExpectedWrite(
        provider=PLAN_DOCUMENT.provider,
        object_key=PLAN_DOCUMENT.object_id,
        expected_revision=PLAN_DOCUMENT.revision,
        pre_fingerprint=PLAN_DOCUMENT.fingerprint,
        post_fingerprint=PLAN_DOCUMENT.post_fingerprint,
    )


def attempt() -> transaction.BridgeOperationAttempt:
    return transaction.BridgeOperationAttempt.open(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        max_observation_age_seconds=MAX_AGE_SECONDS,
        expected_writes=(expected_write(),),
    )


def original_document() -> migration.ReferenceDocument:
    return migration.ReferenceDocument(
        provider=PLAN_DOCUMENT.provider,
        object_id=PLAN_DOCUMENT.object_id,
        revision=PLAN_DOCUMENT.revision,
        payload={"entity_id": OLD_ENTITY},
        writable=True,
    )


def completion() -> migration.JournaledCompletion:
    return migration.JournaledCompletion(
        plan=PLAN,
        result=migration.MigrationResult(
            plan_id=PLAN_ID,
            digest=PLAN_DIGEST,
            state=migration.MigrationState.COMPLETE,
            changed_documents=1,
            exact_replacements=PLAN.exact_replacements,
            idempotent=False,
        ),
        documents=tuple(
            migration._DocumentSnapshot(
                provider=document.provider,
                object_id=document.object_id,
                revision=(
                    8
                    if document.provider == PLAN_DOCUMENT.provider
                    and document.object_id == PLAN_DOCUMENT.object_id
                    else document.revision
                ),
                writable=document.writable,
                fingerprint=document.post_fingerprint,
            )
            for document in PLAN.documents
        ),
    )


def acquisition_intent() -> transaction.FenceAcquisitionIntent:
    return transaction.FenceAcquisitionIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        provider="scheduler",
        writer_id="true-family-reference-writer",
        expected_inventory_revision="scheduler-inventory-10",
        scope_digest=digest("scheduler-scope"),
        epoch=4,
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
    )


def acquisition_receipt(
    intent: transaction.FenceAcquisitionIntent,
) -> transaction.FenceAcquisitionReceipt:
    return transaction.FenceAcquisitionReceipt.create(
        intent,
        acquired_inventory_revision=intent.expected_inventory_revision,
        fence_revision="fence-revision-4",
        token_digest=transaction.derive_fence_token_digest("fence-token-4"),
        acquired_at=NOW + timedelta(seconds=1),
        acknowledged_at=NOW + timedelta(seconds=2),
        durable_at=NOW + timedelta(seconds=3),
    )


def intent(
    acquisition: transaction.FenceAcquisitionReceipt,
) -> transaction.BridgeOperationIntent:
    expected = expected_write()
    return transaction.BridgeOperationIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        sequence=1,
        kind=transaction.BridgeOperationKind.WRITE,
        provider=expected.provider,
        object_key=expected.object_key,
        expected_revision=expected.expected_revision,
        pre_fingerprint=expected.pre_fingerprint,
        post_fingerprint=expected.post_fingerprint,
        fence=acquisition.binding,
    )


def dispatch_authorization(
    operation: transaction.BridgeOperationIntent,
    *,
    observed_at: datetime = NOW + timedelta(seconds=3),
    authorized_at: datetime = NOW + timedelta(seconds=3),
) -> transaction.BridgeDispatchAuthorization:
    return transaction.BridgeDispatchAuthorization.create(
        operation,
        observation(operation, None, observed_at=observed_at),
        authorized_at=authorized_at,
    )


def receipt(
    operation: transaction.BridgeOperationIntent,
    authorization: transaction.BridgeDispatchAuthorization | None = None,
) -> transaction.BridgeOperationReceipt:
    authorization = authorization or dispatch_authorization(operation)
    return transaction.BridgeOperationReceipt.create(
        operation,
        authorization,
        previous_revision=7,
        result_revision=8,
        outcome=transaction.BridgeReceiptOutcome.APPLIED,
        evidence=transaction.BridgeReceiptEvidence.DISPATCH_ACK,
        effect_at=NOW + timedelta(seconds=4),
        acknowledged_at=NOW + timedelta(seconds=5),
        durable_at=NOW + timedelta(seconds=6),
    )


def observation(
    operation: transaction.BridgeOperationIntent,
    operation_receipt: transaction.BridgeOperationReceipt | None,
    *,
    observed_at: datetime = NOW + timedelta(seconds=7),
) -> transaction.BridgeObjectObservation:
    return transaction.BridgeObjectObservation(
        provider=operation.provider,
        object_key=operation.object_key,
        revision=(
            operation.expected_revision
            if operation_receipt is None
            else operation_receipt.result_revision
        ),
        fingerprint=(
            operation.pre_fingerprint
            if operation_receipt is None
            else operation_receipt.result_fingerprint
        ),
        observed_at=observed_at,
    )


def verification(
    operation: transaction.BridgeOperationIntent,
    operation_receipt: transaction.BridgeOperationReceipt,
) -> transaction.BridgeOperationVerification:
    return transaction.BridgeOperationVerification.create(
        operation,
        operation_receipt,
        observation(operation, operation_receipt),
        verified_at=NOW + timedelta(seconds=7),
    )


def release_intent(
    acquisition: transaction.FenceAcquisitionIntent,
    acquisition_ack: transaction.FenceAcquisitionReceipt,
) -> transaction.FenceReleaseIntent:
    record = (
        transaction.FenceAcquisitionRecord.recorded(acquisition)
        .arm()
        .acknowledge(acquisition_ack)
    )
    return transaction.FenceReleaseIntent.create(
        record,
        expected_inventory_revision=8,
        requested_at=NOW + timedelta(seconds=8),
    )


def release_receipt(
    release: transaction.FenceReleaseIntent,
) -> transaction.FenceReleaseReceipt:
    return transaction.FenceReleaseReceipt.create(
        release,
        final_inventory_revision=8,
        released_at=NOW + timedelta(seconds=9),
        acknowledged_at=NOW + timedelta(seconds=10),
        durable_at=NOW + timedelta(seconds=11),
    )


async def prepare_journal(
    hass: HomeAssistant,
    store: FakeStore | None = None,
    *,
    include_attempt: bool = True,
    plan: migration.MigrationPlan = PLAN,
    manifest_digest: str = MANIFEST_DIGEST,
    durability_barrier: FakeDurabilityBarrier | None = None,
    journal_id: str = JOURNAL_ID,
    execution_binding: journal_ha.ReferencePlanExecutionBinding = EXECUTION_BINDING,
) -> journal_ha.HomeAssistantReferenceJournal:
    if store is None:
        assert durability_barrier is None
        journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
        )
    else:
        durability_barrier = durability_barrier or FakeDurabilityBarrier()
        journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=journal_id,
            store=store,
            durability_barrier=durability_barrier,
        )
    await journal.async_run(
        journal.set_state,
        plan.plan_id,
        migration.MigrationState.PLANNED,
    )
    await journal.async_run(
        journal.record_plan,
        plan,
        manifest_digest,
        execution_binding,
    )
    await journal.async_run(
        journal.set_state,
        plan.plan_id,
        migration.MigrationState.APPLYING,
    )
    if include_attempt:
        if plan != PLAN or manifest_digest != MANIFEST_DIGEST:
            raise ValueError("The default attempt fixture requires the default plan.")
        await journal.async_run(journal.append_attempt, attempt())
    return journal


async def advance_acquisition(
    journal: journal_ha.HomeAssistantReferenceJournal,
) -> tuple[transaction.FenceAcquisitionIntent, transaction.FenceAcquisitionReceipt]:
    acquisition = acquisition_intent()
    acquisition_ack = acquisition_receipt(acquisition)
    await journal.async_run(journal.record_acquisition_intent, acquisition)
    await journal.async_run(journal.arm_acquisition, acquisition.operation_id)
    await journal.async_run(journal.record_acquisition_receipt, acquisition_ack)
    return acquisition, acquisition_ack


async def advance_operation(
    journal: journal_ha.HomeAssistantReferenceJournal,
    stage: transaction.BridgeOperationState,
) -> tuple[
    transaction.FenceAcquisitionIntent,
    transaction.FenceAcquisitionReceipt,
    transaction.BridgeOperationIntent,
]:
    acquisition, acquisition_ack = await advance_acquisition(journal)
    operation = intent(acquisition_ack)
    await journal.async_run(journal.record_intent, operation)
    await journal.async_run(
        journal.record_original,
        PLAN_ID,
        original_document(),
        POST_FINGERPRINT,
    )
    if stage is transaction.BridgeOperationState.INTENT_RECORDED:
        return acquisition, acquisition_ack, operation
    await journal.async_run(
        journal.arm_operation,
        operation.operation_id,
        dispatch_authorization(operation),
    )
    if stage is transaction.BridgeOperationState.DISPATCH_ARMED:
        return acquisition, acquisition_ack, operation
    operation_receipt = receipt(operation)
    await journal.async_run(journal.record_receipt, operation_receipt)
    if stage is transaction.BridgeOperationState.ACKNOWLEDGED:
        return acquisition, acquisition_ack, operation
    await journal.async_run(
        journal.record_verification,
        verification(operation, operation_receipt),
    )
    return acquisition, acquisition_ack, operation


async def advance_release(
    journal: journal_ha.HomeAssistantReferenceJournal,
) -> tuple[transaction.FenceReleaseIntent, transaction.FenceReleaseReceipt]:
    acquisition, acquisition_ack, _operation = await advance_operation(
        journal,
        transaction.BridgeOperationState.VERIFIED,
    )
    release = release_intent(acquisition, acquisition_ack)
    release_ack = release_receipt(release)
    await journal.async_run(journal.record_release_intent, release)
    await journal.async_run(journal.arm_release, release.operation_id)
    await journal.async_run(journal.record_release_receipt, release_ack)
    return release, release_ack


async def test_harness_store_transaction_survives_every_lifecycle_checkpoint(
    hass: HomeAssistant,
) -> None:
    journal_id = f"bridge-transaction-{secrets.token_hex(12)}"
    execution_binding = execution_binding_for(journal_id)
    await journal_ha.async_provision_reference_journal(
        hass,
        journal_id=journal_id,
    )
    journal = await prepare_journal(
        hass,
        journal_id=journal_id,
        execution_binding=execution_binding,
    )
    release, _release_ack = await advance_release(journal)
    await journal.async_run(
        lambda: journal.set_attempt_state(
            PLAN_ID,
            1,
            transaction.BridgeAttemptState.COMMITTED,
            terminal_at=NOW + timedelta(seconds=12),
        )
    )
    await journal.async_run(journal.record_completion, completion())
    await journal.async_run(
        journal.set_state,
        PLAN_ID,
        migration.MigrationState.COMPLETE,
    )
    before = await journal.async_run(journal.attempts_for, PLAN_ID)
    operation_id = before[0].operations[0].intent.operation_id
    acquisition_id = before[0].acquisitions[0].intent.operation_id
    await journal.async_close()

    restarted = await journal_ha.HomeAssistantReferenceJournal.async_load(
        hass,
        journal_id=journal_id,
    )
    after = await restarted.async_run(restarted.attempts_for, PLAN_ID)
    operation_record = await restarted.async_run(
        restarted.get_operation,
        operation_id,
    )
    acquisition_record = await restarted.async_run(
        restarted.get_acquisition,
        acquisition_id,
    )
    release_record = await restarted.async_run(
        restarted.get_release,
        release.operation_id,
    )
    restored_plan = await restarted.async_run(restarted.plan_for, PLAN_ID)
    restored_manifest = await restarted.async_run(
        restarted.manifest_digest_for,
        PLAN_ID,
    )
    restored_execution_binding = await restarted.async_run(
        restarted.execution_binding_for,
        PLAN_ID,
    )
    restored_expected = await restarted.async_run(
        restarted.expected_writes_for,
        PLAN_ID,
    )
    epoch_high_water = await restarted.async_run(
        restarted.provider_epoch_high_water,
        "scheduler",
    )
    await restarted.async_close()

    assert after == before
    assert after[0].state is transaction.BridgeAttemptState.COMMITTED
    assert after[0].terminal_at == NOW + timedelta(seconds=12)
    assert acquisition_record.state is transaction.FenceLifecycleState.ACKNOWLEDGED
    assert operation_record.state is transaction.BridgeOperationState.VERIFIED
    assert release_record.state is transaction.FenceLifecycleState.ACKNOWLEDGED
    assert acquisition_record.receipt is not None
    assert operation_record.receipt is not None
    assert release_record.receipt is not None
    assert restored_plan == PLAN
    assert restored_manifest == MANIFEST_DIGEST
    assert restored_execution_binding == execution_binding
    assert restored_expected == (expected_write(),)
    assert epoch_high_water == 4
    operation_ids = {
        acquisition_record.intent.operation_id,
        operation_record.intent.operation_id,
        release_record.intent.operation_id,
    }
    receipt_ids = {
        acquisition_record.receipt.receipt_id,
        operation_record.receipt.receipt_id,
        release_record.receipt.receipt_id,
    }
    assert len(operation_ids) == 3
    assert len(receipt_ids) == 3


@pytest.mark.parametrize(
    ("stage", "expected"),
    (
        (
            transaction.BridgeOperationState.INTENT_RECORDED,
            transaction.BridgeReconciliationAction.DISPATCH,
        ),
        (
            transaction.BridgeOperationState.DISPATCH_ARMED,
            transaction.BridgeReconciliationAction.QUERY_RECEIPT,
        ),
        (
            transaction.BridgeOperationState.ACKNOWLEDGED,
            transaction.BridgeReconciliationAction.VERIFY_RECEIPT,
        ),
        (
            transaction.BridgeOperationState.VERIFIED,
            transaction.BridgeReconciliationAction.COMPLETE,
        ),
    ),
)
async def test_restart_reconciliation_never_blindly_redispatches(
    hass: HomeAssistant,
    stage: transaction.BridgeOperationState,
    expected: transaction.BridgeReconciliationAction,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    _acquisition, acquisition_ack, operation = await advance_operation(journal, stage)
    operation_receipt = (
        None
        if stage in {
            transaction.BridgeOperationState.INTENT_RECORDED,
            transaction.BridgeOperationState.DISPATCH_ARMED,
        }
        else receipt(operation)
    )
    await journal.async_close()

    restarted = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    authority = transaction.InMemoryFenceAuthority((acquisition_ack.binding,))
    recorder = transaction.BridgeTransactionRecorder(
        restarted,
        authority,
        max_observation_age=timedelta(seconds=MAX_AGE_SECONDS),
    )
    observed = observation(operation, operation_receipt)
    action = await restarted.async_run(
        lambda: recorder.reconcile(
            operation.operation_id,
            observed,
            at=observed.observed_at,
        )
    )
    durable_record = await restarted.async_run(
        restarted.get_operation,
        operation.operation_id,
    )
    await restarted.async_close()

    assert action is expected
    if stage is transaction.BridgeOperationState.INTENT_RECORDED:
        assert durable_record.state is transaction.BridgeOperationState.DISPATCH_ARMED
    else:
        assert durable_record.state is stage


async def test_arm_requires_durable_original_across_reload(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    _acquisition, acquisition_ack = await advance_acquisition(journal)
    operation = intent(acquisition_ack)
    authorization = dispatch_authorization(operation)
    await journal.async_run(journal.record_intent, operation)
    await journal.async_close()

    missing_original = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    save_calls_before_arm = store.save_calls
    with pytest.raises(
        transaction.BridgeJournalConflict,
        match="exact durable JournaledOriginal",
    ):
        await missing_original.async_run(
            missing_original.arm_operation,
            operation.operation_id,
            authorization,
        )
    rejected = await missing_original.async_run(
        missing_original.get_operation,
        operation.operation_id,
    )
    assert store.save_calls == save_calls_before_arm
    assert rejected.state is transaction.BridgeOperationState.INTENT_RECORDED
    assert rejected.authorization is None

    await missing_original.async_run(
        missing_original.record_original,
        PLAN_ID,
        original_document(),
        POST_FINGERPRINT,
    )
    assert store.save_calls == save_calls_before_arm + 1
    await missing_original.async_close()

    durable_original = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    armed = await durable_original.async_run(
        durable_original.arm_operation,
        operation.operation_id,
        authorization,
    )
    assert armed.state is transaction.BridgeOperationState.DISPATCH_ARMED
    assert armed.authorization == authorization
    assert store.save_calls == save_calls_before_arm + 2
    await durable_original.async_close()


@pytest.mark.parametrize("corruption", ("removed", "tampered"))
async def test_reload_rejects_authorized_operation_without_exact_original(
    hass: HomeAssistant,
    corruption: str,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    _acquisition, _acquisition_ack, operation = await advance_operation(
        journal,
        transaction.BridgeOperationState.DISPATCH_ARMED,
    )
    await journal.async_run(
        journal.block_operation,
        operation.operation_id,
        transaction.BridgeBlockReason.STALE_OBSERVATION,
    )
    await journal.async_close()

    assert store.data is not None
    damaged = deepcopy(store.data)
    if corruption == "removed":
        damaged["content"]["originals"].pop(PLAN_ID)
    else:
        damaged["content"]["originals"][PLAN_ID][0]["post_fingerprint"] = (
            digest("tampered-original-postimage")
        )
    store.data = redigest_root(damaged)

    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=store,
            durability_barrier=FakeDurabilityBarrier(),
        )


async def test_armed_fence_lifecycle_restarts_only_query_host_ledgers(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    acquisition = acquisition_intent()
    await journal.async_run(journal.record_acquisition_intent, acquisition)
    await journal.async_run(journal.arm_acquisition, acquisition.operation_id)
    await journal.async_close()

    authority = transaction.InMemoryFenceAuthority()
    acquisition_ack = authority.acquire(
        acquisition,
        acquired_inventory_revision=acquisition.expected_inventory_revision,
        fence_revision="fence-revision-4",
        token_digest=transaction.derive_fence_token_digest("fence-token-4"),
        acquired_at=NOW + timedelta(seconds=1),
        acknowledged_at=NOW + timedelta(seconds=2),
        durable_at=NOW + timedelta(seconds=3),
    )
    restarted = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    recorder = transaction.BridgeTransactionRecorder(
        restarted,
        authority,
        max_observation_age=timedelta(seconds=MAX_AGE_SECONDS),
    )
    acquisition_action = await restarted.async_run(
        lambda: recorder.reconcile_acquisition(
            acquisition.operation_id,
            at=NOW + timedelta(seconds=4),
        )
    )
    assert acquisition_action is transaction.BridgeReconciliationAction.QUERY_RECEIPT
    await restarted.async_run(
        recorder.acknowledge_acquisition,
        acquisition_ack,
    )

    operation = intent(acquisition_ack)
    authorization = dispatch_authorization(operation)
    operation_ack = receipt(operation, authorization)
    await restarted.async_run(restarted.record_intent, operation)
    await restarted.async_run(
        restarted.record_original,
        PLAN_ID,
        original_document(),
        POST_FINGERPRINT,
    )
    await restarted.async_run(
        restarted.arm_operation,
        operation.operation_id,
        authorization,
    )
    await restarted.async_run(restarted.record_receipt, operation_ack)
    await restarted.async_run(
        restarted.record_verification,
        verification(operation, operation_ack),
    )
    release = release_intent(acquisition, acquisition_ack)
    await restarted.async_run(recorder.prepare_release, release)
    assert (
        await restarted.async_run(
            lambda: recorder.reconcile_release(
                release.operation_id,
                at=NOW + timedelta(seconds=8),
            )
        )
        is transaction.BridgeReconciliationAction.DISPATCH
    )
    release_ack = authority.release(
        release,
        final_inventory_revision=8,
        released_at=NOW + timedelta(seconds=9),
        acknowledged_at=NOW + timedelta(seconds=10),
        durable_at=NOW + timedelta(seconds=11),
    )
    await restarted.async_close()

    final = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    final_recorder = transaction.BridgeTransactionRecorder(
        final,
        authority,
        max_observation_age=timedelta(seconds=MAX_AGE_SECONDS),
    )
    release_action = await final.async_run(
        lambda: final_recorder.reconcile_release(
            release.operation_id,
            at=NOW + timedelta(seconds=12),
        )
    )
    durable_release = await final.async_run(final.get_release, release.operation_id)
    await final.async_close()

    assert release_ack == authority.release_receipt(release.operation_id)
    assert release_action is transaction.BridgeReconciliationAction.QUERY_RECEIPT
    assert durable_release.state is transaction.FenceLifecycleState.DISPATCH_ARMED


async def test_acquisition_no_effect_and_epoch_high_water_survive_reload(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    acquisition = acquisition_intent()
    tombstone = transaction.FenceAcquisitionNoEffectReceipt.create(
        acquisition,
        acknowledged_at=acquisition.expires_at,
        durable_at=acquisition.expires_at + timedelta(seconds=1),
    )
    await journal.async_run(journal.record_acquisition_intent, acquisition)
    await journal.async_run(journal.arm_acquisition, acquisition.operation_id)
    await journal.async_run(journal.record_acquisition_receipt, tombstone)
    await journal.async_close()

    restarted = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    restored = await restarted.async_run(
        restarted.get_acquisition,
        acquisition.operation_id,
    )
    assert restored.state is transaction.FenceLifecycleState.NO_EFFECT
    assert restored.receipt == tombstone
    assert await restarted.async_run(
        restarted.provider_epoch_high_water,
        acquisition.provider,
    ) == acquisition.epoch
    await restarted.async_close()


async def test_release_no_effect_survives_reload(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    acquisition, acquisition_ack, _operation = await advance_operation(
        journal,
        transaction.BridgeOperationState.VERIFIED,
    )
    acquired = (
        transaction.FenceAcquisitionRecord.recorded(acquisition)
        .arm()
        .acknowledge(acquisition_ack)
    )
    release = transaction.FenceReleaseIntent.create(
        acquired,
        expected_inventory_revision=acquisition_ack.acquired_inventory_revision,
        requested_at=NOW + timedelta(seconds=8),
    )
    tombstone = transaction.FenceReleaseNoEffectReceipt.create(
        release,
        acknowledged_at=NOW + timedelta(seconds=9),
        durable_at=NOW + timedelta(seconds=10),
    )
    await journal.async_run(journal.record_release_intent, release)
    await journal.async_run(journal.arm_release, release.operation_id)
    await journal.async_run(journal.record_release_receipt, tombstone)
    await journal.async_close()

    restarted = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    restored = await restarted.async_run(restarted.get_release, release.operation_id)
    assert restored.state is transaction.FenceLifecycleState.NO_EFFECT
    assert restored.receipt == tombstone
    await restarted.async_close()


async def test_restored_retry_arms_with_advanced_revision_and_same_original(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    acquisition, acquisition_ack, operation = await advance_operation(
        journal,
        transaction.BridgeOperationState.VERIFIED,
    )

    first_release = release_intent(acquisition, acquisition_ack)
    first_release_ack = release_receipt(first_release)
    await journal.async_run(journal.record_release_intent, first_release)
    await journal.async_run(journal.arm_release, first_release.operation_id)
    await journal.async_run(journal.record_release_receipt, first_release_ack)

    recovery_acquisition = transaction.FenceAcquisitionIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        provider=PLAN_DOCUMENT.provider,
        writer_id="true-family-reference-writer",
        expected_inventory_revision=8,
        scope_digest=digest("scheduler-scope"),
        epoch=5,
        requested_at=NOW + timedelta(seconds=12),
        expires_at=NOW + timedelta(seconds=72),
    )
    recovery_acquisition_ack = transaction.FenceAcquisitionReceipt.create(
        recovery_acquisition,
        acquired_inventory_revision=8,
        fence_revision="fence-revision-5",
        token_digest=transaction.derive_fence_token_digest("fence-token-5"),
        acquired_at=NOW + timedelta(seconds=13),
        acknowledged_at=NOW + timedelta(seconds=14),
        durable_at=NOW + timedelta(seconds=15),
    )
    await journal.async_run(
        journal.record_acquisition_intent,
        recovery_acquisition,
    )
    await journal.async_run(
        journal.arm_acquisition,
        recovery_acquisition.operation_id,
    )
    await journal.async_run(
        journal.record_acquisition_receipt,
        recovery_acquisition_ack,
    )

    rollback = transaction.BridgeOperationIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        sequence=2,
        kind=transaction.BridgeOperationKind.ROLLBACK,
        provider=operation.provider,
        object_key=operation.object_key,
        expected_revision=8,
        pre_fingerprint=operation.post_fingerprint,
        post_fingerprint=operation.pre_fingerprint,
        fence=recovery_acquisition_ack.binding,
        parent_operation_id=operation.operation_id,
    )
    rollback_authorization = dispatch_authorization(
        rollback,
        observed_at=NOW + timedelta(seconds=15),
        authorized_at=NOW + timedelta(seconds=15),
    )
    rollback_receipt = transaction.BridgeOperationReceipt.create(
        rollback,
        rollback_authorization,
        previous_revision=8,
        result_revision=9,
        outcome=transaction.BridgeReceiptOutcome.APPLIED,
        evidence=transaction.BridgeReceiptEvidence.DISPATCH_ACK,
        effect_at=NOW + timedelta(seconds=16),
        acknowledged_at=NOW + timedelta(seconds=17),
        durable_at=NOW + timedelta(seconds=18),
    )
    rollback_verification = transaction.BridgeOperationVerification.create(
        rollback,
        rollback_receipt,
        observation(
            rollback,
            rollback_receipt,
            observed_at=NOW + timedelta(seconds=19),
        ),
        verified_at=NOW + timedelta(seconds=19),
    )
    await journal.async_run(journal.record_intent, rollback)
    await journal.async_run(
        journal.arm_operation,
        rollback.operation_id,
        rollback_authorization,
    )
    await journal.async_run(journal.record_receipt, rollback_receipt)
    await journal.async_run(
        journal.record_verification,
        rollback_verification,
    )

    recovery_acquisition_record = (
        transaction.FenceAcquisitionRecord.recorded(recovery_acquisition)
        .arm()
        .acknowledge(recovery_acquisition_ack)
    )
    recovery_release = transaction.FenceReleaseIntent.create(
        recovery_acquisition_record,
        expected_inventory_revision=9,
        requested_at=NOW + timedelta(seconds=20),
    )
    recovery_release_ack = transaction.FenceReleaseReceipt.create(
        recovery_release,
        final_inventory_revision=9,
        released_at=NOW + timedelta(seconds=21),
        acknowledged_at=NOW + timedelta(seconds=22),
        durable_at=NOW + timedelta(seconds=23),
    )
    await journal.async_run(journal.record_release_intent, recovery_release)
    await journal.async_run(journal.arm_release, recovery_release.operation_id)
    await journal.async_run(
        journal.record_release_receipt,
        recovery_release_ack,
    )
    await journal.async_run(
        lambda: journal.set_attempt_state(
            PLAN_ID,
            1,
            transaction.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=24),
        )
    )

    retry = transaction.BridgeOperationAttempt.open(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=2,
        max_observation_age_seconds=MAX_AGE_SECONDS,
        expected_writes=(
            transaction.BridgeExpectedWrite(
                provider=PLAN_DOCUMENT.provider,
                object_key=PLAN_DOCUMENT.object_id,
                expected_revision=9,
                pre_fingerprint=PRE_FINGERPRINT,
                post_fingerprint=POST_FINGERPRINT,
            ),
        ),
    )
    await journal.async_run(journal.append_attempt, retry)
    retry_acquisition = transaction.FenceAcquisitionIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=2,
        provider=PLAN_DOCUMENT.provider,
        writer_id="true-family-reference-writer",
        expected_inventory_revision=9,
        scope_digest=digest("scheduler-scope"),
        epoch=6,
        requested_at=NOW + timedelta(seconds=25),
        expires_at=NOW + timedelta(seconds=85),
    )
    retry_acquisition_ack = transaction.FenceAcquisitionReceipt.create(
        retry_acquisition,
        acquired_inventory_revision=9,
        fence_revision="fence-revision-6",
        token_digest=transaction.derive_fence_token_digest("fence-token-6"),
        acquired_at=NOW + timedelta(seconds=26),
        acknowledged_at=NOW + timedelta(seconds=27),
        durable_at=NOW + timedelta(seconds=28),
    )
    await journal.async_run(journal.record_acquisition_intent, retry_acquisition)
    await journal.async_run(
        journal.arm_acquisition,
        retry_acquisition.operation_id,
    )
    await journal.async_run(
        journal.record_acquisition_receipt,
        retry_acquisition_ack,
    )
    retry_operation = transaction.BridgeOperationIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=2,
        sequence=1,
        kind=transaction.BridgeOperationKind.WRITE,
        provider=PLAN_DOCUMENT.provider,
        object_key=PLAN_DOCUMENT.object_id,
        expected_revision=9,
        pre_fingerprint=PRE_FINGERPRINT,
        post_fingerprint=POST_FINGERPRINT,
        fence=retry_acquisition_ack.binding,
    )
    retry_authorization = dispatch_authorization(
        retry_operation,
        observed_at=NOW + timedelta(seconds=29),
        authorized_at=NOW + timedelta(seconds=29),
    )
    await journal.async_run(journal.record_intent, retry_operation)
    armed = await journal.async_run(
        journal.arm_operation,
        retry_operation.operation_id,
        retry_authorization,
    )
    assert armed.state is transaction.BridgeOperationState.DISPATCH_ARMED
    originals = await journal.async_run(journal.originals_for, PLAN_ID)
    assert len(originals) == 1
    assert originals[0].document.revision == PLAN_DOCUMENT.revision
    await journal.async_close()

    assert store.data is not None
    assert store.data["schema"] == 4
    restarted = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    restored_retry = await restarted.async_run(
        restarted.get_operation,
        retry_operation.operation_id,
    )
    assert restored_retry.state is transaction.BridgeOperationState.DISPATCH_ARMED
    assert restored_retry.authorization == retry_authorization
    await restarted.async_close()


async def test_blocked_restart_recovery_restores_before_failed_disposition(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    acquisition, acquisition_ack, operation = await advance_operation(
        journal,
        transaction.BridgeOperationState.VERIFIED,
    )
    await journal.async_run(
        journal.block_operation,
        operation.operation_id,
        transaction.BridgeBlockReason.VERIFIED_DRIFT,
    )
    await journal.async_run(
        journal.set_state,
        PLAN_ID,
        migration.MigrationState.BLOCKED,
        "verified_drift",
    )
    await journal.async_close()

    recovering = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    blocked_attempt = await recovering.async_run(recovering.get_attempt, PLAN_ID, 1)
    assert blocked_attempt.state is transaction.BridgeAttemptState.BLOCKED
    forbidden_write = transaction.BridgeOperationIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        sequence=2,
        kind=transaction.BridgeOperationKind.WRITE,
        provider=operation.provider,
        object_key=operation.object_key,
        expected_revision=8,
        pre_fingerprint=operation.pre_fingerprint,
        post_fingerprint=operation.post_fingerprint,
        fence=acquisition_ack.binding,
    )
    with pytest.raises(transaction.BridgeJournalConflict):
        await recovering.async_run(recovering.record_intent, forbidden_write)

    first_release = release_intent(acquisition, acquisition_ack)
    first_release_ack = release_receipt(first_release)
    await recovering.async_run(recovering.record_release_intent, first_release)
    await recovering.async_run(recovering.arm_release, first_release.operation_id)
    await recovering.async_run(
        recovering.record_release_receipt,
        first_release_ack,
    )

    recovery_acquisition = transaction.FenceAcquisitionIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        provider="scheduler",
        writer_id="true-family-reference-writer",
        expected_inventory_revision=8,
        scope_digest=digest("scheduler-scope"),
        epoch=5,
        requested_at=NOW + timedelta(seconds=12),
        expires_at=NOW + timedelta(seconds=72),
    )
    recovery_acquisition_ack = transaction.FenceAcquisitionReceipt.create(
        recovery_acquisition,
        acquired_inventory_revision=8,
        fence_revision="fence-revision-5",
        token_digest=transaction.derive_fence_token_digest("fence-token-5"),
        acquired_at=NOW + timedelta(seconds=13),
        acknowledged_at=NOW + timedelta(seconds=14),
        durable_at=NOW + timedelta(seconds=15),
    )
    await recovering.async_run(
        recovering.record_acquisition_intent,
        recovery_acquisition,
    )
    await recovering.async_run(
        recovering.arm_acquisition,
        recovery_acquisition.operation_id,
    )
    await recovering.async_run(
        recovering.record_acquisition_receipt,
        recovery_acquisition_ack,
    )

    rollback = transaction.BridgeOperationIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        sequence=2,
        kind=transaction.BridgeOperationKind.ROLLBACK,
        provider=operation.provider,
        object_key=operation.object_key,
        expected_revision=8,
        pre_fingerprint=operation.post_fingerprint,
        post_fingerprint=operation.pre_fingerprint,
        fence=recovery_acquisition_ack.binding,
        parent_operation_id=operation.operation_id,
    )
    rollback_authorization = dispatch_authorization(
        rollback,
        observed_at=NOW + timedelta(seconds=15),
        authorized_at=NOW + timedelta(seconds=15),
    )
    rollback_receipt = transaction.BridgeOperationReceipt.create(
        rollback,
        rollback_authorization,
        previous_revision=8,
        result_revision=9,
        outcome=transaction.BridgeReceiptOutcome.APPLIED,
        evidence=transaction.BridgeReceiptEvidence.DISPATCH_ACK,
        effect_at=NOW + timedelta(seconds=16),
        acknowledged_at=NOW + timedelta(seconds=17),
        durable_at=NOW + timedelta(seconds=18),
    )
    rollback_verification = transaction.BridgeOperationVerification.create(
        rollback,
        rollback_receipt,
        observation(
            rollback,
            rollback_receipt,
            observed_at=NOW + timedelta(seconds=19),
        ),
        verified_at=NOW + timedelta(seconds=19),
    )
    await recovering.async_run(recovering.record_intent, rollback)
    await recovering.async_run(
        recovering.arm_operation,
        rollback.operation_id,
        rollback_authorization,
    )
    await recovering.async_run(recovering.record_receipt, rollback_receipt)
    await recovering.async_run(
        recovering.record_verification,
        rollback_verification,
    )

    recovery_acquisition_record = (
        transaction.FenceAcquisitionRecord.recorded(recovery_acquisition)
        .arm()
        .acknowledge(recovery_acquisition_ack)
    )
    recovery_release = transaction.FenceReleaseIntent.create(
        recovery_acquisition_record,
        expected_inventory_revision=9,
        requested_at=NOW + timedelta(seconds=20),
    )
    recovery_release_ack = transaction.FenceReleaseReceipt.create(
        recovery_release,
        final_inventory_revision=9,
        released_at=NOW + timedelta(seconds=21),
        acknowledged_at=NOW + timedelta(seconds=22),
        durable_at=NOW + timedelta(seconds=23),
    )
    await recovering.async_run(recovering.record_release_intent, recovery_release)
    await recovering.async_run(recovering.arm_release, recovery_release.operation_id)
    await recovering.async_run(
        recovering.record_release_receipt,
        recovery_release_ack,
    )
    await recovering.async_run(
        lambda: recovering.set_attempt_state(
            PLAN_ID,
            1,
            transaction.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=24),
        )
    )
    await recovering.async_close()

    restored = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    assert await restored.async_run(restored.state, PLAN_ID) == (
        migration.MigrationState.BLOCKED,
        "verified_drift",
    )
    restored_attempt = await restored.async_run(restored.get_attempt, PLAN_ID, 1)
    assert restored_attempt.state is transaction.BridgeAttemptState.RESTORED

    retry = transaction.BridgeOperationAttempt.open(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=2,
        max_observation_age_seconds=MAX_AGE_SECONDS,
        expected_writes=(
            transaction.BridgeExpectedWrite(
                provider=PLAN_DOCUMENT.provider,
                object_key=PLAN_DOCUMENT.object_id,
                expected_revision=9,
                pre_fingerprint=PRE_FINGERPRINT,
                post_fingerprint=POST_FINGERPRINT,
            ),
        ),
    )
    with pytest.raises(ValueError):
        await restored.async_run(restored.append_attempt, retry)
    await restored.async_run(
        restored.set_state,
        PLAN_ID,
        migration.MigrationState.FAILED,
        "recovered_after_verified_drift",
    )
    await restored.async_close()

    final = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    assert await final.async_run(final.state, PLAN_ID) == (
        migration.MigrationState.FAILED,
        "recovered_after_verified_drift",
    )
    assert (
        await final.async_run(final.get_attempt, PLAN_ID, 1)
    ).state is transaction.BridgeAttemptState.RESTORED
    assert await final.async_run(final.incomplete_plan_ids) == ()
    await final.async_close()


@pytest.mark.parametrize(
    "stage",
    (
        "attempt",
        "acquisition_intent",
        "acquisition_arm",
        "acquisition_receipt",
        "object_intent",
        "object_arm",
        "object_receipt",
        "verification",
        "release_intent",
        "release_arm",
        "release_receipt",
        "terminal",
    ),
)
async def test_swallowed_lifecycle_checkpoint_poisoned_adapter(
    hass: HomeAssistant,
    stage: str,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store, include_attempt=False)
    acquisition = acquisition_intent()
    acquisition_ack = acquisition_receipt(acquisition)
    operation = intent(acquisition_ack)
    operation_authorization = dispatch_authorization(operation)
    operation_ack = receipt(operation, operation_authorization)
    operation_verification = verification(operation, operation_ack)
    release = release_intent(acquisition, acquisition_ack)
    release_ack = release_receipt(release)

    steps: tuple[tuple[str, Any, tuple[Any, ...]], ...] = (
        ("attempt", journal.append_attempt, (attempt(),)),
        ("acquisition_intent", journal.record_acquisition_intent, (acquisition,)),
        ("acquisition_arm", journal.arm_acquisition, (acquisition.operation_id,)),
        ("acquisition_receipt", journal.record_acquisition_receipt, (acquisition_ack,)),
        ("object_intent", journal.record_intent, (operation,)),
        (
            "original",
            journal.record_original,
            (PLAN_ID, original_document(), POST_FINGERPRINT),
        ),
        (
            "object_arm",
            journal.arm_operation,
            (operation.operation_id, operation_authorization),
        ),
        ("object_receipt", journal.record_receipt, (operation_ack,)),
        ("verification", journal.record_verification, (operation_verification,)),
        ("release_intent", journal.record_release_intent, (release,)),
        ("release_arm", journal.arm_release, (release.operation_id,)),
        ("release_receipt", journal.record_release_receipt, (release_ack,)),
    )
    for step_name, function, arguments in steps:
        if step_name == stage:
            break
        await journal.async_run(function, *arguments)

    store.swallow_writes = True
    if stage == "terminal":
        call = lambda: journal.set_attempt_state(
            PLAN_ID,
            1,
            transaction.BridgeAttemptState.COMMITTED,
            terminal_at=NOW + timedelta(seconds=12),
        )
        with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
            await journal.async_run(call)
    else:
        _, function, arguments = next(item for item in steps if item[0] == stage)
        with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
            await journal.async_run(function, *arguments)
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal.async_run(journal.attempts_for, PLAN_ID)
    await journal.async_close()


def rebuilt_root(content: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": journal_ha.REFERENCE_JOURNAL_SCHEMA,
        "journal_id": JOURNAL_ID,
        "generation": 0,
        "content": content,
    }
    canonical = json.dumps(
        body,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return {**body, "content_digest": hashlib.sha256(canonical).hexdigest()}


def redigest_root(root: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": root["schema"],
        "journal_id": root["journal_id"],
        "generation": root["generation"],
        "content": root["content"],
    }
    canonical = json.dumps(
        body,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return {**body, "content_digest": hashlib.sha256(canonical).hexdigest()}


def test_schema_four_requires_plan_and_execution_bound_bridge_content() -> None:
    empty = journal_ha.empty_reference_journal_data(JOURNAL_ID)
    legacy = deepcopy(empty)
    legacy["schema"] = 3
    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        journal_ha.decode_reference_journal_data(legacy)

    missing = deepcopy(empty["content"])
    missing.pop("bridge_operations")
    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        journal_ha.decode_reference_journal_data(rebuilt_root(missing))

    orphan = deepcopy(empty["content"])
    orphan["bridge_operations"][PLAN_ID] = [
        transaction.encode_bridge_operation_attempt(attempt())
    ]
    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        journal_ha.decode_reference_journal_data(rebuilt_root(orphan))


async def test_changed_plan_requires_exact_execution_binding(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    await journal.async_run(
        journal.set_state,
        PLAN_ID,
        migration.MigrationState.PLANNED,
    )
    saves_before_binding = store.save_calls

    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal.async_run(journal.record_plan, PLAN, MANIFEST_DIGEST)
    wrong_journal = journal_ha.ReferencePlanExecutionBinding(
        execution_scope_digest=EXECUTION_BINDING.execution_scope_digest,
        recorder_id=EXECUTION_BINDING.recorder_id,
        journal_id="different-reference-journal",
        provider_bridge_ids=EXECUTION_BINDING.provider_bridge_ids,
    )
    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal.async_run(
            journal.record_plan,
            PLAN,
            MANIFEST_DIGEST,
            wrong_journal,
        )
    assert store.save_calls == saves_before_binding

    await journal.async_run(
        journal.record_plan,
        PLAN,
        MANIFEST_DIGEST,
        EXECUTION_BINDING,
    )
    assert await journal.async_run(journal.execution_binding_for, PLAN_ID) == (
        EXECUTION_BINDING
    )
    saves_after_binding = store.save_calls
    await journal.async_run(
        journal.record_plan,
        PLAN,
        MANIFEST_DIGEST,
        EXECUTION_BINDING,
    )
    substituted_scope = journal_ha.ReferencePlanExecutionBinding(
        execution_scope_digest=digest("substituted-execution-scope"),
        recorder_id=EXECUTION_BINDING.recorder_id,
        journal_id=JOURNAL_ID,
        provider_bridge_ids=EXECUTION_BINDING.provider_bridge_ids,
    )
    with pytest.raises(ValueError):
        await journal.async_run(
            journal.record_plan,
            PLAN,
            MANIFEST_DIGEST,
            substituted_scope,
        )
    assert store.save_calls == saves_after_binding
    await journal.async_close()


async def test_transaction_methods_require_worker_and_duplicates_do_not_write(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    saves_after_attempt = store.save_calls

    with pytest.raises(journal_ha.ReferenceJournalThreadError):
        journal.attempts_for(PLAN_ID)
    assert await journal.async_run(journal.append_attempt, attempt()) == attempt()
    assert store.save_calls == saves_after_attempt

    acquisition = acquisition_intent()
    await journal.async_run(journal.record_acquisition_intent, acquisition)
    saves_after_acquisition = store.save_calls
    acquisition_record = await journal.async_run(
        journal.record_acquisition_intent,
        acquisition,
    )
    assert acquisition_record.intent == acquisition
    assert store.save_calls == saves_after_acquisition
    await journal.async_close()


async def test_append_attempt_is_derived_from_exact_active_plan(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store, include_attempt=False)

    manifest_mismatch = transaction.BridgeOperationAttempt.open(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=digest("different-provider-manifest"),
        attempt=1,
        max_observation_age_seconds=MAX_AGE_SECONDS,
        expected_writes=(expected_write(),),
    )
    with pytest.raises(transaction.BridgeJournalConflict):
        await journal.async_run(journal.append_attempt, manifest_mismatch)

    expected = expected_write()
    stale_revision = transaction.BridgeOperationAttempt.open(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        max_observation_age_seconds=MAX_AGE_SECONDS,
        expected_writes=(
            transaction.BridgeExpectedWrite(
                provider=expected.provider,
                object_key=expected.object_key,
                expected_revision=8,
                pre_fingerprint=expected.pre_fingerprint,
                post_fingerprint=expected.post_fingerprint,
            ),
        ),
    )
    with pytest.raises(transaction.BridgeJournalConflict):
        await journal.async_run(journal.append_attempt, stale_revision)

    multi_plan = build_plan(
        (
            ("profile.guest_room_monday", 7),
            ("profile.guest_room_tuesday", 11),
        )
    )
    await journal.async_close()

    second_store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    second = await prepare_journal(
        hass,
        second_store,
        include_attempt=False,
        plan=multi_plan,
    )
    derived = await second.async_run(second.expected_writes_for, multi_plan.plan_id)
    omitted = transaction.BridgeOperationAttempt.open(
        plan_id=multi_plan.plan_id,
        plan_digest=multi_plan.digest,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        max_observation_age_seconds=MAX_AGE_SECONDS,
        expected_writes=derived[:1],
    )
    with pytest.raises(transaction.BridgeJournalConflict):
        await second.async_run(second.append_attempt, omitted)
    await second.async_close()


async def test_changed_completion_requires_committed_transaction_coverage(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store, include_attempt=False)
    await journal.async_run(
        journal.record_original,
        PLAN_ID,
        original_document(),
        POST_FINGERPRINT,
    )

    with pytest.raises(transaction.BridgeJournalConflict):
        await journal.async_run(journal.record_completion, completion())
    assert await journal.async_run(journal.state, PLAN_ID) == (
        migration.MigrationState.APPLYING,
        None,
    )
    await journal.async_close()


async def test_completion_execution_binding_digest_blocks_reload(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    await advance_release(journal)
    await journal.async_run(
        lambda: journal.set_attempt_state(
            PLAN_ID,
            1,
            transaction.BridgeAttemptState.COMMITTED,
            terminal_at=NOW + timedelta(seconds=12),
        )
    )
    await journal.async_run(journal.record_completion, completion())
    await journal.async_run(
        journal.set_state,
        PLAN_ID,
        migration.MigrationState.COMPLETE,
    )
    await journal.async_close()

    assert store.data is not None
    damaged = deepcopy(store.data)
    damaged["content"]["completions"][PLAN_ID]["execution_binding_digest"] = (
        digest("substituted-completion-execution-binding")
    )
    store.data = redigest_root(damaged)
    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=store,
            durability_barrier=FakeDurabilityBarrier(),
        )


async def test_post_save_barrier_failure_poisoned_adapter(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    barrier = FakeDurabilityBarrier()
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=barrier,
    )
    barrier.fail = True

    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal.async_run(
            journal.set_state,
            PLAN_ID,
            migration.MigrationState.PLANNED,
        )
    assert barrier.calls == 1
    assert store.data is not None
    assert store.data["generation"] == 1
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal.async_run(journal.state, PLAN_ID)
    await journal.async_close()


async def test_store_write_failure_poisoned_adapter(
    hass: HomeAssistant,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=store,
        durability_barrier=FakeDurabilityBarrier(),
    )
    store.raise_writes = True

    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal.async_run(
            journal.set_state,
            PLAN_ID,
            migration.MigrationState.PLANNED,
        )
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal.async_run(journal.state, PLAN_ID)
    await journal.async_close()


async def test_unbranded_test_barrier_fails_before_save(
    hass: HomeAssistant,
) -> None:
    class UnbrandedNoOpBarrier:
        async def async_barrier(self) -> None:
            return None

    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    with pytest.raises(journal_ha.ReferenceJournalDurabilityError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=store,
            durability_barrier=cast(
                journal_ha.ReferenceJournalDurabilityBarrier,
                UnbrandedNoOpBarrier(),
            ),
        )
    assert store.save_calls == 0


@pytest.mark.parametrize(
    "corruption",
    (
        "unknown_field",
        "planned_state",
        "missing_expected_write",
        "missing_plan",
        "stale_plan",
        "manifest_mismatch",
        "missing_execution_binding",
        "execution_binding_digest",
        "execution_journal_mismatch",
        "execution_scope_substitution",
    ),
)
async def test_corrupt_or_state_incompatible_transaction_blocks_reload(
    hass: HomeAssistant,
    corruption: str,
) -> None:
    store = FakeStore(journal_ha.empty_reference_journal_data(JOURNAL_ID))
    journal = await prepare_journal(hass, store)
    await advance_operation(journal, transaction.BridgeOperationState.INTENT_RECORDED)
    await journal.async_close()

    assert store.data is not None
    damaged = deepcopy(store.data)
    durable_attempt = damaged["content"]["bridge_operations"][PLAN_ID][0]["attempt"]
    if corruption == "unknown_field":
        durable_attempt["operations"][0]["unexpected"] = "blocked"
    elif corruption == "planned_state":
        damaged["content"]["states"][PLAN_ID]["state"] = (
            migration.MigrationState.PLANNED.value
        )
    elif corruption == "missing_expected_write":
        durable_attempt["expected_writes"] = []
    elif corruption == "missing_plan":
        del damaged["content"]["active_plans"][PLAN_ID]
    elif corruption == "stale_plan":
        stale = build_plan((("profile.guest_room_tuesday", 11),))
        damaged["content"]["active_plans"][PLAN_ID]["plan"] = (
            journal_ha.encode_migration_plan(stale)
        )
    elif corruption == "manifest_mismatch":
        durable_attempt["manifest_digest"] = digest("corrupt-manifest-binding")
    elif corruption == "missing_execution_binding":
        damaged["content"]["active_plans"][PLAN_ID]["execution_binding"] = None
    elif corruption == "execution_binding_digest":
        damaged["content"]["active_plans"][PLAN_ID]["execution_binding"][
            "execution_scope_digest"
        ] = digest("corrupt-execution-scope")
    elif corruption == "execution_journal_mismatch":
        wrong_binding = journal_ha.ReferencePlanExecutionBinding(
            execution_scope_digest=EXECUTION_BINDING.execution_scope_digest,
            recorder_id=EXECUTION_BINDING.recorder_id,
            journal_id="different-reference-journal",
            provider_bridge_ids=EXECUTION_BINDING.provider_bridge_ids,
        )
        encoded_binding = damaged["content"]["active_plans"][PLAN_ID][
            "execution_binding"
        ]
        encoded_binding["journal_id"] = wrong_binding.journal_id
        encoded_binding["binding_digest"] = wrong_binding.digest
    else:
        substituted_binding = journal_ha.ReferencePlanExecutionBinding(
            execution_scope_digest=digest("substituted-execution-scope"),
            recorder_id=EXECUTION_BINDING.recorder_id,
            journal_id=JOURNAL_ID,
            provider_bridge_ids=EXECUTION_BINDING.provider_bridge_ids,
        )
        encoded_binding = damaged["content"]["active_plans"][PLAN_ID][
            "execution_binding"
        ]
        encoded_binding["execution_scope_digest"] = (
            substituted_binding.execution_scope_digest
        )
        encoded_binding["binding_digest"] = substituted_binding.digest
    store.data = redigest_root(damaged)

    with pytest.raises(journal_ha.ReferenceJournalCodecError):
        await journal_ha.HomeAssistantReferenceJournal.async_create(
            hass,
            journal_id=JOURNAL_ID,
            store=store,
            durability_barrier=FakeDurabilityBarrier(),
        )
