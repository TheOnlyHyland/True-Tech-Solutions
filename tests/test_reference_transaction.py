"""Pure adversarial tests for reference bridge transaction recording."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
WINDOW = timedelta(seconds=10)


def load_module():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = sys.modules.get(PACKAGE_NAME)
    if package is None:
        package = types.ModuleType(PACKAGE_NAME)
        sys.modules[PACKAGE_NAME] = package
    package.__path__ = [str(PACKAGE_ROOT)]
    return importlib.import_module(f"{PACKAGE_NAME}.reference_transaction")


tx = load_module()


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def token_digest(label: str):
    return tx.derive_fence_token_digest(label)


PLAN_DIGEST = digest("reference-plan-body")
PLAN_HASH = hashlib.sha256(f"reference-plan:{PLAN_DIGEST}".encode()).hexdigest()
PLAN_ID = f"tf-reference-{PLAN_HASH[:24]}"
SECOND_PLAN_DIGEST = digest("second-reference-plan-body")
SECOND_PLAN_HASH = hashlib.sha256(
    f"reference-plan:{SECOND_PLAN_DIGEST}".encode()
).hexdigest()
SECOND_PLAN_ID = f"tf-reference-{SECOND_PLAN_HASH[:24]}"
MANIFEST_DIGEST = digest("provider-manifest")


def spec(
    provider: str = "scheduler",
    object_key: str = "profile.guest_room_monday",
    revision: str | int = 1,
    label: str = "guest-monday",
):
    return tx.BridgeExpectedWrite(
        provider=provider,
        object_key=object_key,
        expected_revision=revision,
        pre_fingerprint=digest(f"{label}-pre"),
        post_fingerprint=digest(f"{label}-post"),
    )


def acquisition_intent(
    *,
    provider: str = "scheduler",
    attempt: int = 1,
    epoch: int = 1,
    inventory_revision: str | int = "inventory-1",
    requested_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(seconds=60),
    plan_id: str = PLAN_ID,
    plan_digest: str = PLAN_DIGEST,
):
    return tx.FenceAcquisitionIntent.create(
        plan_id=plan_id,
        plan_digest=plan_digest,
        manifest_digest=MANIFEST_DIGEST,
        attempt=attempt,
        provider=provider,
        writer_id="true-family-reference-writer",
        expected_inventory_revision=inventory_revision,
        scope_digest=digest(f"{provider}-scope-{attempt}-{epoch}"),
        epoch=epoch,
        requested_at=requested_at,
        expires_at=expires_at,
    )


def acquisition_receipt(
    intent,
    *,
    acquired_at: datetime | None = None,
    acknowledged_at: datetime | None = None,
    durable_at: datetime | None = None,
):
    acquired_at = acquired_at or intent.requested_at + timedelta(seconds=1)
    acknowledged_at = acknowledged_at or acquired_at + timedelta(seconds=1)
    durable_at = durable_at or acknowledged_at + timedelta(seconds=1)
    return tx.FenceAcquisitionReceipt.create(
        intent,
        acquired_inventory_revision=intent.expected_inventory_revision,
        fence_revision=f"fence-{intent.provider}-{intent.epoch}",
        token_digest=token_digest(
            f"token-{intent.provider}-{intent.attempt}-{intent.epoch}"
        ),
        acquired_at=acquired_at,
        acknowledged_at=acknowledged_at,
        durable_at=durable_at,
    )


def acquisition_tombstone(intent, *, acknowledged_at=None, durable_at=None):
    acknowledged_at = acknowledged_at or intent.expires_at + timedelta(seconds=1)
    durable_at = durable_at or acknowledged_at + timedelta(seconds=1)
    return tx.FenceAcquisitionNoEffectReceipt.create(
        intent,
        acknowledged_at=acknowledged_at,
        durable_at=durable_at,
    )


def acquired_record(intent):
    receipt = acquisition_receipt(intent)
    return tx.FenceAcquisitionRecord.recorded(intent).arm().acknowledge(receipt)


def object_intent(
    expected,
    acquisition,
    *,
    sequence: int = 1,
    kind=None,
    expected_revision=None,
    pre_fingerprint: str | None = None,
    post_fingerprint: str | None = None,
    parent_operation_id: str | None = None,
):
    if kind is None:
        kind = tx.BridgeOperationKind.WRITE
    if expected_revision is None:
        expected_revision = expected.expected_revision
    return tx.BridgeOperationIntent.create(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=acquisition.intent.attempt,
        sequence=sequence,
        kind=kind,
        provider=expected.provider,
        object_key=expected.object_key,
        expected_revision=expected_revision,
        pre_fingerprint=(
            expected.pre_fingerprint
            if pre_fingerprint is None
            else pre_fingerprint
        ),
        post_fingerprint=(
            expected.post_fingerprint
            if post_fingerprint is None
            else post_fingerprint
        ),
        fence=acquisition.receipt.binding,
        parent_operation_id=parent_operation_id,
    )


def dispatch_authorization(
    operation,
    *,
    observed_at: datetime | None = None,
    authorized_at: datetime | None = None,
):
    observed_at = observed_at or (
        operation.fence.acquisition_durable_at + timedelta(seconds=1)
    )
    authorized_at = authorized_at or observed_at
    observed = tx.BridgeObjectObservation(
        provider=operation.provider,
        object_key=operation.object_key,
        revision=operation.expected_revision,
        fingerprint=operation.pre_fingerprint,
        observed_at=observed_at,
    )
    return tx.BridgeDispatchAuthorization.create(
        operation,
        observed,
        authorized_at=authorized_at,
    )


def applied_receipt(
    operation,
    *,
    authorization=None,
    result_revision: str | int = 2,
    effect_at: datetime | None = None,
    acknowledged_at: datetime | None = None,
    durable_at: datetime | None = None,
):
    authorization = authorization or dispatch_authorization(operation)
    effect_at = effect_at or operation.fence.acquired_at + timedelta(seconds=4)
    acknowledged_at = acknowledged_at or effect_at + timedelta(seconds=1)
    durable_at = durable_at or acknowledged_at + timedelta(seconds=1)
    return tx.BridgeOperationReceipt.create(
        operation,
        authorization,
        previous_revision=operation.expected_revision,
        result_revision=result_revision,
        outcome=tx.BridgeReceiptOutcome.APPLIED,
        evidence=tx.BridgeReceiptEvidence.DISPATCH_ACK,
        effect_at=effect_at,
        acknowledged_at=acknowledged_at,
        durable_at=durable_at,
    )


def no_effect_receipt(
    operation,
    *,
    authorization=None,
    acknowledged_at=None,
    durable_at=None,
):
    authorization = authorization or dispatch_authorization(operation)
    acknowledged_at = acknowledged_at or operation.fence.expires_at + timedelta(
        seconds=1
    )
    durable_at = durable_at or acknowledged_at + timedelta(seconds=1)
    return tx.BridgeOperationReceipt.create(
        operation,
        authorization,
        previous_revision=operation.expected_revision,
        result_revision=operation.expected_revision,
        outcome=tx.BridgeReceiptOutcome.NO_EFFECT,
        evidence=tx.BridgeReceiptEvidence.OPERATION_LEDGER,
        effect_at=None,
        acknowledged_at=acknowledged_at,
        durable_at=durable_at,
    )


def prewrite_observation(operation, *, observed_at=None):
    return tx.BridgeObjectObservation(
        provider=operation.provider,
        object_key=operation.object_key,
        revision=operation.expected_revision,
        fingerprint=operation.pre_fingerprint,
        observed_at=observed_at
        or operation.fence.acquisition_durable_at + timedelta(seconds=1),
    )


def observation(operation, receipt, *, observed_at=None, fingerprint=None, revision=None):
    observed_at = observed_at or receipt.durable_at + timedelta(seconds=1)
    return tx.BridgeObjectObservation(
        provider=operation.provider,
        object_key=operation.object_key,
        revision=receipt.result_revision if revision is None else revision,
        fingerprint=receipt.result_fingerprint if fingerprint is None else fingerprint,
        observed_at=observed_at,
    )


def verified_record(
    operation,
    receipt,
    *,
    authorization=None,
    observed_at=None,
    verified_at=None,
):
    authorization = authorization or dispatch_authorization(
        operation,
        observed_at=receipt.authorization_observed_at,
        authorized_at=receipt.authorized_at,
    )
    observed = observation(operation, receipt, observed_at=observed_at)
    verified_at = verified_at or observed.observed_at
    verification = tx.BridgeOperationVerification.create(
        operation,
        receipt,
        observed,
        verified_at=verified_at,
    )
    return (
        tx.BridgeOperationRecord.recorded(operation)
        .arm(authorization)
        .acknowledge(receipt)
        .verify(verification)
    )


def release_record(
    acquisition,
    *,
    revision="inventory-final",
    requested_at=None,
    release_attempt=1,
):
    requested_at = requested_at or NOW + timedelta(seconds=20)
    intent = tx.FenceReleaseIntent.create(
        acquisition,
        expected_inventory_revision=revision,
        requested_at=requested_at,
        release_attempt=release_attempt,
    )
    receipt = tx.FenceReleaseReceipt.create(
        intent,
        final_inventory_revision=revision,
        released_at=requested_at + timedelta(seconds=1),
        acknowledged_at=requested_at + timedelta(seconds=2),
        durable_at=requested_at + timedelta(seconds=3),
    )
    return tx.FenceReleaseRecord.recorded(intent).arm().acknowledge(receipt)


def release_tombstone(intent, *, acknowledged_at=None, durable_at=None):
    acknowledged_at = acknowledged_at or intent.requested_at + timedelta(seconds=1)
    durable_at = durable_at or acknowledged_at + timedelta(seconds=1)
    return tx.FenceReleaseNoEffectReceipt.create(
        intent,
        acknowledged_at=acknowledged_at,
        durable_at=durable_at,
    )


def committed_attempt():
    expected = spec()
    acquisition = acquired_record(acquisition_intent())
    operation = object_intent(expected, acquisition)
    receipt = applied_receipt(
        operation,
        effect_at=NOW + timedelta(seconds=6),
        acknowledged_at=NOW + timedelta(seconds=7),
        durable_at=NOW + timedelta(seconds=8),
    )
    write = verified_record(
        operation,
        receipt,
        observed_at=NOW + timedelta(seconds=9),
        verified_at=NOW + timedelta(seconds=9),
    )
    release = release_record(
        acquisition,
        requested_at=NOW + timedelta(seconds=10),
    )
    return tx.BridgeOperationAttempt(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        state=tx.BridgeAttemptState.COMMITTED,
        max_observation_age_seconds=10,
        expected_writes=(expected,),
        acquisitions=(acquisition,),
        operations=(write,),
        releases=(release,),
        release_phase_sequence=1,
        terminal_at=NOW + timedelta(seconds=14),
    )


def no_effect_restored_attempt():
    expected = spec()
    acquisition = acquired_record(acquisition_intent())
    operation = object_intent(expected, acquisition)
    receipt = no_effect_receipt(operation)
    write = verified_record(
        operation,
        receipt,
        observed_at=NOW + timedelta(seconds=63),
        verified_at=NOW + timedelta(seconds=63),
    )
    release = release_record(
        acquisition,
        requested_at=NOW + timedelta(seconds=64),
    )
    return tx.BridgeOperationAttempt(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        state=tx.BridgeAttemptState.RESTORED,
        max_observation_age_seconds=10,
        expected_writes=(expected,),
        acquisitions=(acquisition,),
        operations=(write,),
        releases=(release,),
        release_phase_sequence=1,
        terminal_at=NOW + timedelta(seconds=68),
    )


def applied_restored_attempt():
    expected = spec()
    first = acquired_record(acquisition_intent())
    write_intent = object_intent(expected, first)
    write_receipt = applied_receipt(write_intent)
    write = verified_record(
        write_intent,
        write_receipt,
        observed_at=NOW + timedelta(seconds=8),
    )
    second_intent = acquisition_intent(
        epoch=2,
        inventory_revision="inventory-2",
        requested_at=NOW + timedelta(seconds=15),
        expires_at=NOW + timedelta(seconds=120),
    )
    second = acquired_record(second_intent)
    rollback_intent = object_intent(
        expected,
        second,
        sequence=2,
        kind=tx.BridgeOperationKind.ROLLBACK,
        expected_revision=write_receipt.result_revision,
        pre_fingerprint=expected.post_fingerprint,
        post_fingerprint=expected.pre_fingerprint,
        parent_operation_id=write_intent.operation_id,
    )
    rollback_receipt = applied_receipt(
        rollback_intent,
        result_revision=3,
        effect_at=NOW + timedelta(seconds=24),
        acknowledged_at=NOW + timedelta(seconds=25),
        durable_at=NOW + timedelta(seconds=26),
    )
    rollback = verified_record(
        rollback_intent,
        rollback_receipt,
        observed_at=NOW + timedelta(seconds=27),
    )
    releases = (
        release_record(first, requested_at=NOW + timedelta(seconds=9)),
        release_record(second, requested_at=NOW + timedelta(seconds=28)),
    )
    return tx.BridgeOperationAttempt(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        state=tx.BridgeAttemptState.RESTORED,
        max_observation_age_seconds=10,
        expected_writes=(expected,),
        acquisitions=(first, second),
        operations=(write, rollback),
        releases=releases,
        release_phase_sequence=1,
        terminal_at=NOW + timedelta(seconds=32),
    )


def recorder_fixture(expected_writes=None):
    expected_writes = expected_writes or (spec(),)
    journal = tx.InMemoryBridgeOperationJournal()
    authority = tx.InMemoryFenceAuthority()
    recorder = tx.BridgeTransactionRecorder(
        journal,
        authority,
        max_observation_age=WINDOW,
    )
    recorder.begin_attempt(
        plan_id=PLAN_ID,
        plan_digest=PLAN_DIGEST,
        manifest_digest=MANIFEST_DIGEST,
        attempt=1,
        expected_writes=expected_writes,
    )
    return journal, authority, recorder


def acquire_for_recorder(journal, authority, recorder, intent):
    recorder.prepare_acquisition(intent)
    self_action = recorder.reconcile_acquisition(
        intent.operation_id,
        at=intent.requested_at,
    )
    if self_action is not tx.BridgeReconciliationAction.DISPATCH:
        raise AssertionError("fixture acquisition did not dispatch")
    receipt = authority.acquire(
        intent,
        acquired_inventory_revision=intent.expected_inventory_revision,
        fence_revision=f"fence-{intent.provider}-{intent.epoch}",
        token_digest=token_digest(f"token-{intent.provider}-{intent.epoch}"),
        acquired_at=intent.requested_at + timedelta(seconds=1),
        acknowledged_at=intent.requested_at + timedelta(seconds=2),
        durable_at=intent.requested_at + timedelta(seconds=3),
    )
    recorder.acknowledge_acquisition(receipt)
    return journal.get_acquisition(intent.operation_id)


class IdentityAndRevisionTests(unittest.TestCase):
    def test_all_operation_identities_are_deterministic(self) -> None:
        acquire = acquisition_intent()
        acquire_again = acquisition_intent()
        acquisition = acquired_record(acquire)
        expected = spec()
        operation = object_intent(expected, acquisition)
        operation_again = object_intent(expected, acquisition)
        release = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=20),
        )
        release_again = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=20),
        )

        self.assertEqual(acquire.operation_id, acquire_again.operation_id)
        self.assertEqual(operation.operation_id, operation_again.operation_id)
        self.assertEqual(release.operation_id, release_again.operation_id)
        self.assertRegex(acquire.operation_id, r"^tf-fence-acquire-[0-9a-f]{24}$")
        self.assertRegex(operation.operation_id, r"^tf-bridge-[0-9a-f]{24}$")
        self.assertRegex(release.operation_id, r"^tf-fence-release-[0-9a-f]{24}$")

    def test_revision_types_are_distinct_and_invalid_revisions_are_rejected(self) -> None:
        integer = spec(revision=1)
        string = spec(revision="1")
        first = acquired_record(acquisition_intent())
        self.assertNotEqual(
            object_intent(integer, first).operation_id,
            object_intent(string, first).operation_id,
        )

        invalid = (
            -1,
            True,
            "",
            " revision",
            "revision ",
            "rev 1",
            "rev\n1",
            "rev\u200b1",
            "x" * 257,
        )
        for revision in invalid:
            with self.subTest(revision=revision):
                with self.assertRaises((TypeError, ValueError)):
                    spec(revision=revision)

    def test_applied_outcome_requires_a_changed_typed_revision(self) -> None:
        expected = spec()
        acquisition = acquired_record(acquisition_intent())
        operation = object_intent(expected, acquisition)
        with self.assertRaises(ValueError):
            applied_receipt(operation, result_revision=1)

    def test_object_identity_changes_with_kind_sequence_attempt_and_epoch(self) -> None:
        expected = spec()
        first = acquired_record(acquisition_intent())
        base = object_intent(expected, first)
        rollback = object_intent(
            expected,
            first,
            kind=tx.BridgeOperationKind.ROLLBACK,
            parent_operation_id="tf-bridge-000000000000000000000000",
        )
        sequence = object_intent(expected, first, sequence=2)
        second_attempt = acquired_record(
            acquisition_intent(
                attempt=2,
                epoch=2,
                requested_at=NOW + timedelta(seconds=70),
                expires_at=NOW + timedelta(seconds=130),
            )
        )
        retry = object_intent(expected, second_attempt)
        newer_epoch = acquired_record(
            acquisition_intent(
                epoch=2,
                requested_at=NOW + timedelta(seconds=20),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        fenced = object_intent(expected, newer_epoch)
        self.assertEqual(
            len(
                {
                    item.operation_id
                    for item in (base, rollback, sequence, retry, fenced)
                }
            ),
            5,
        )


class TransitionTests(unittest.TestCase):
    def test_object_transition_matrix_is_exact(self) -> None:
        expected = spec()
        acquisition = acquired_record(acquisition_intent())
        operation = object_intent(expected, acquisition)
        authorization = dispatch_authorization(operation)
        receipt = applied_receipt(operation, authorization=authorization)
        verification = verified_record(
            operation,
            receipt,
            authorization=authorization,
        ).verification
        records = {
            tx.BridgeOperationState.INTENT_RECORDED: (
                tx.BridgeOperationRecord.recorded(operation)
            ),
            tx.BridgeOperationState.DISPATCH_ARMED: (
                tx.BridgeOperationRecord.recorded(operation).arm(authorization)
            ),
            tx.BridgeOperationState.ACKNOWLEDGED: (
                tx.BridgeOperationRecord.recorded(operation)
                .arm(authorization)
                .acknowledge(receipt)
            ),
            tx.BridgeOperationState.VERIFIED: verified_record(operation, receipt),
            tx.BridgeOperationState.BLOCKED: (
                tx.BridgeOperationRecord.recorded(operation).block(
                    tx.BridgeBlockReason.EXPLICIT_ABORT
                )
            ),
        }
        allowed = {
            tx.BridgeOperationState.INTENT_RECORDED: {
                tx.BridgeOperationState.DISPATCH_ARMED,
                tx.BridgeOperationState.BLOCKED,
            },
            tx.BridgeOperationState.DISPATCH_ARMED: {
                tx.BridgeOperationState.ACKNOWLEDGED,
                tx.BridgeOperationState.BLOCKED,
            },
            tx.BridgeOperationState.ACKNOWLEDGED: {
                tx.BridgeOperationState.VERIFIED,
                tx.BridgeOperationState.BLOCKED,
            },
            tx.BridgeOperationState.VERIFIED: {
                tx.BridgeOperationState.BLOCKED
            },
            tx.BridgeOperationState.BLOCKED: set(),
        }
        for source, record in records.items():
            for target in tx.BridgeOperationState:
                kwargs = {}
                if target is tx.BridgeOperationState.DISPATCH_ARMED:
                    kwargs["authorization"] = authorization
                elif target is tx.BridgeOperationState.ACKNOWLEDGED:
                    kwargs["receipt"] = receipt
                elif target is tx.BridgeOperationState.VERIFIED:
                    kwargs["verification"] = verification
                elif target is tx.BridgeOperationState.BLOCKED:
                    kwargs["reason_code"] = tx.BridgeBlockReason.EXPLICIT_ABORT
                with self.subTest(source=source, target=target):
                    if target in allowed[source]:
                        self.assertIs(record.transition(target, **kwargs).state, target)
                    else:
                        with self.assertRaises(tx.BridgeOperationTransitionError):
                            record.transition(target, **kwargs)


class FenceLifecycleTests(unittest.TestCase):
    def test_acquisition_crash_after_host_effect_queries_deterministic_receipt(self) -> None:
        journal, authority, recorder = recorder_fixture()
        intent = acquisition_intent()
        recorder.prepare_acquisition(intent)
        self.assertIs(
            recorder.reconcile_acquisition(intent.operation_id, at=NOW),
            tx.BridgeReconciliationAction.DISPATCH,
        )
        host_receipt = authority.acquire(
            intent,
            acquired_inventory_revision="inventory-1",
            fence_revision="fence-scheduler-1",
            token_digest=token_digest("host-token"),
            acquired_at=NOW + timedelta(seconds=1),
            acknowledged_at=NOW + timedelta(seconds=2),
            durable_at=NOW + timedelta(seconds=3),
        )

        recovered = tx.BridgeTransactionRecorder(
            journal,
            authority,
            max_observation_age=WINDOW,
        )
        self.assertIs(
            recovered.reconcile_acquisition(
                intent.operation_id,
                at=NOW + timedelta(seconds=4),
            ),
            tx.BridgeReconciliationAction.QUERY_RECEIPT,
        )
        self.assertEqual(authority.acquisition_receipt(intent.operation_id), host_receipt)
        first = recovered.acknowledge_acquisition(host_receipt)
        second = recovered.acknowledge_acquisition(host_receipt)
        self.assertIs(first, second)
        self.assertIs(
            recovered.reconcile_acquisition(
                intent.operation_id,
                at=NOW + timedelta(seconds=4),
            ),
            tx.BridgeReconciliationAction.COMPLETE,
        )

    def test_release_crash_after_host_effect_queries_deterministic_receipt(self) -> None:
        journal, authority, recorder = recorder_fixture()
        acquisition = acquire_for_recorder(
            journal,
            authority,
            recorder,
            acquisition_intent(),
        )
        release_intent = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=10),
        )
        recorder.prepare_release(release_intent)
        self.assertIs(
            recorder.reconcile_release(
                release_intent.operation_id,
                at=NOW + timedelta(seconds=10),
            ),
            tx.BridgeReconciliationAction.DISPATCH,
        )
        host_receipt = authority.release(
            release_intent,
            final_inventory_revision="inventory-final",
            released_at=NOW + timedelta(seconds=11),
            acknowledged_at=NOW + timedelta(seconds=12),
            durable_at=NOW + timedelta(seconds=13),
        )

        recovered = tx.BridgeTransactionRecorder(
            journal,
            authority,
            max_observation_age=WINDOW,
        )
        self.assertIs(
            recovered.reconcile_release(
                release_intent.operation_id,
                at=NOW + timedelta(seconds=14),
            ),
            tx.BridgeReconciliationAction.QUERY_RECEIPT,
        )
        first = recovered.acknowledge_release(host_receipt)
        second = recovered.acknowledge_release(host_receipt)
        self.assertIs(first, second)
        self.assertIsNone(authority.current_binding("scheduler"))

    def test_acquisition_tombstone_resolves_ambiguity_and_allows_new_intent(
        self,
    ) -> None:
        journal, authority, recorder = recorder_fixture()
        intent = acquisition_intent()
        recorder.prepare_acquisition(intent)
        self.assertIs(
            recorder.reconcile_acquisition(intent.operation_id, at=NOW),
            tx.BridgeReconciliationAction.DISPATCH,
        )
        self.assertIs(
            recorder.reconcile_acquisition(
                intent.operation_id,
                at=intent.expires_at + timedelta(hours=1),
            ),
            tx.BridgeReconciliationAction.QUERY_RECEIPT,
        )
        self.assertIsNone(journal.get_acquisition(intent.operation_id).receipt)

        tombstone = authority.tombstone_acquisition(
            intent,
            acknowledged_at=intent.expires_at + timedelta(seconds=1),
            durable_at=intent.expires_at + timedelta(seconds=2),
        )
        record = recorder.acknowledge_acquisition(tombstone)
        self.assertIs(record.state, tx.FenceLifecycleState.NO_EFFECT)
        self.assertIs(
            recorder.reconcile_acquisition(
                intent.operation_id,
                at=tombstone.durable_at,
            ),
            tx.BridgeReconciliationAction.COMPLETE,
        )
        self.assertIs(record.intent, intent)

        retry = acquisition_intent(
            epoch=2,
            inventory_revision="inventory-2",
            requested_at=tombstone.durable_at + timedelta(seconds=1),
            expires_at=tombstone.durable_at + timedelta(seconds=61),
        )
        self.assertEqual(recorder.prepare_acquisition(retry).intent, retry)
        self.assertEqual(journal.provider_epoch_high_water("scheduler"), 2)

    def test_release_tombstone_requires_new_contiguous_release_intent(self) -> None:
        journal, authority, recorder = recorder_fixture()
        acquisition = acquire_for_recorder(
            journal,
            authority,
            recorder,
            acquisition_intent(),
        )
        first = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=10),
        )
        recorder.prepare_release(first)
        self.assertIs(
            recorder.reconcile_release(
                first.operation_id,
                at=NOW + timedelta(seconds=10),
            ),
            tx.BridgeReconciliationAction.DISPATCH,
        )
        self.assertIs(
            recorder.reconcile_release(
                first.operation_id,
                at=NOW + timedelta(hours=1),
            ),
            tx.BridgeReconciliationAction.QUERY_RECEIPT,
        )
        tombstone = authority.tombstone_release(
            first,
            acknowledged_at=NOW + timedelta(seconds=11),
            durable_at=NOW + timedelta(seconds=12),
        )
        self.assertIs(
            recorder.acknowledge_release(tombstone).state,
            tx.FenceLifecycleState.NO_EFFECT,
        )
        self.assertEqual(authority.current_binding("scheduler"), acquisition.receipt.binding)

        with self.assertRaises(tx.BridgeJournalConflict):
            recorder.prepare_release(
                tx.FenceReleaseIntent.create(
                    acquisition,
                    expected_inventory_revision="inventory-final",
                    requested_at=NOW + timedelta(seconds=13),
                )
            )
        with self.assertRaises(tx.BridgeJournalConflict):
            recorder.prepare_release(
                tx.FenceReleaseIntent.create(
                    acquisition,
                    expected_inventory_revision="changed-inventory",
                    requested_at=NOW + timedelta(seconds=13),
                    release_attempt=2,
                )
            )
        second = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=13),
            release_attempt=2,
        )
        recorder.prepare_release(second)
        self.assertIs(
            recorder.reconcile_release(
                second.operation_id,
                at=NOW + timedelta(seconds=13),
            ),
            tx.BridgeReconciliationAction.DISPATCH,
        )
        applied = authority.release(
            second,
            final_inventory_revision="inventory-final",
            released_at=NOW + timedelta(seconds=14),
            acknowledged_at=NOW + timedelta(seconds=15),
            durable_at=NOW + timedelta(seconds=16),
        )
        recorder.acknowledge_release(applied)
        self.assertIsNone(authority.current_binding("scheduler"))

    def test_lifecycle_intent_must_be_armed_before_receipt(self) -> None:
        journal, _authority, recorder = recorder_fixture()
        intent = acquisition_intent()
        recorder.prepare_acquisition(intent)
        with self.assertRaises(tx.BridgeJournalConflict):
            recorder.acknowledge_acquisition(acquisition_receipt(intent))
        self.assertIs(
            journal.get_acquisition(intent.operation_id).state,
            tx.FenceLifecycleState.INTENT_RECORDED,
        )

    def test_authority_rejects_epoch_regression_even_after_release(self) -> None:
        authority = tx.InMemoryFenceAuthority()
        first_intent = acquisition_intent(epoch=3)
        first_receipt = authority.acquire(
            first_intent,
            acquired_inventory_revision="inventory-1",
            fence_revision="fence-3",
            token_digest=token_digest("epoch-3-token"),
            acquired_at=NOW + timedelta(seconds=1),
            acknowledged_at=NOW + timedelta(seconds=2),
            durable_at=NOW + timedelta(seconds=3),
        )
        acquisition = (
            tx.FenceAcquisitionRecord.recorded(first_intent)
            .arm()
            .acknowledge(first_receipt)
        )
        release_intent = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=10),
        )
        authority.release(
            release_intent,
            final_inventory_revision="inventory-final",
            released_at=NOW + timedelta(seconds=11),
            acknowledged_at=NOW + timedelta(seconds=12),
            durable_at=NOW + timedelta(seconds=13),
        )
        regressed = acquisition_intent(
            epoch=2,
            inventory_revision="inventory-2",
            requested_at=NOW + timedelta(seconds=20),
            expires_at=NOW + timedelta(seconds=80),
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            authority.acquire(
                regressed,
                acquired_inventory_revision="inventory-2",
                fence_revision="fence-2",
                token_digest=token_digest("epoch-2-token"),
                acquired_at=NOW + timedelta(seconds=21),
                acknowledged_at=NOW + timedelta(seconds=22),
                durable_at=NOW + timedelta(seconds=23),
            )

        reconstructed = tx.InMemoryFenceAuthority((first_receipt.binding,))
        with self.assertRaises(tx.BridgeJournalConflict):
            reconstructed.tombstone_acquisition(
                first_intent,
                acknowledged_at=first_intent.expires_at + timedelta(seconds=1),
                durable_at=first_intent.expires_at + timedelta(seconds=2),
            )


class ObjectRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = spec()
        self.journal, self.authority, self.recorder = recorder_fixture(
            (self.expected,)
        )
        self.acquisition = acquire_for_recorder(
            self.journal,
            self.authority,
            self.recorder,
            acquisition_intent(),
        )
        self.operation = object_intent(self.expected, self.acquisition)
        self.recorder.prepare(self.operation, at=NOW + timedelta(seconds=4))

    def test_dispatch_authorization_is_fresh_immutable_and_receipt_bound(self) -> None:
        stale = dispatch_authorization(
            self.operation,
            observed_at=NOW + timedelta(seconds=4),
            authorized_at=NOW + timedelta(seconds=15),
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            self.journal.arm_operation(self.operation.operation_id, stale)

        authorization = self.recorder.arm(
            self.operation.operation_id,
            prewrite_observation(self.operation),
            at=NOW + timedelta(seconds=4),
        ).authorization
        self.assertIsNotNone(authorization)
        encoded = tx.encode_bridge_dispatch_authorization(authorization)
        self.assertEqual(
            tx.decode_bridge_dispatch_authorization(encoded),
            authorization,
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            self.journal.arm_operation(
                self.operation.operation_id,
                dispatch_authorization(
                    self.operation,
                    observed_at=NOW + timedelta(seconds=5),
                    authorized_at=NOW + timedelta(seconds=5),
                ),
            )

        conflicting_authorization = dispatch_authorization(
            self.operation,
            observed_at=NOW + timedelta(seconds=5),
            authorized_at=NOW + timedelta(seconds=5),
        )
        conflicting_receipt = applied_receipt(
            self.operation,
            authorization=conflicting_authorization,
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            self.journal.record_receipt(conflicting_receipt)
        self.assertIs(
            self.journal.get_operation(self.operation.operation_id).state,
            tx.BridgeOperationState.DISPATCH_ARMED,
        )

    def test_prewrite_postimage_blocks_before_dispatch_authorization(self) -> None:
        observed = replace(
            prewrite_observation(self.operation),
            fingerprint=self.operation.post_fingerprint,
        )
        with self.assertRaises(tx.BridgeTransactionBlocked) as raised:
            self.recorder.arm(
                self.operation.operation_id,
                observed,
                at=observed.observed_at,
            )
        self.assertIs(
            raised.exception.reason_code,
            tx.BridgeBlockReason.LIFECYCLE_MISMATCH,
        )
        blocked = self.journal.get_operation(self.operation.operation_id)
        self.assertIs(blocked.state, tx.BridgeOperationState.BLOCKED)
        self.assertIs(
            blocked.blocked_from,
            tx.BridgeOperationState.INTENT_RECORDED,
        )
        self.assertIs(blocked.reason_code, tx.BridgeBlockReason.LIFECYCLE_MISMATCH)
        self.assertIsNone(blocked.authorization)
        self.assertIsNone(blocked.receipt)

    def test_reconcile_prioritizes_postimage_over_expired_fence(self) -> None:
        observed = replace(
            prewrite_observation(self.operation),
            fingerprint=self.operation.post_fingerprint,
            observed_at=self.operation.fence.expires_at + timedelta(seconds=1),
        )
        self.assertIs(
            self.recorder.reconcile(
                self.operation.operation_id,
                observed,
                at=observed.observed_at,
            ),
            tx.BridgeReconciliationAction.BLOCK,
        )
        blocked = self.journal.get_operation(self.operation.operation_id)
        self.assertIs(blocked.reason_code, tx.BridgeBlockReason.LIFECYCLE_MISMATCH)

    def test_armed_operation_queries_after_expiry_and_supersession(self) -> None:
        self.recorder.arm(
            self.operation.operation_id,
            prewrite_observation(self.operation),
            at=NOW + timedelta(seconds=4),
        )
        superseded = replace(
            self.operation.fence,
            epoch=2,
            token_digest=token_digest("superseding-token"),
        )
        self.authority.put(superseded)
        self.assertIs(
            self.recorder.reconcile(
                self.operation.operation_id,
                None,
                at=self.operation.fence.expires_at + timedelta(seconds=10),
            ),
            tx.BridgeReconciliationAction.QUERY_RECEIPT,
        )
        self.assertIs(
            self.journal.get_operation(self.operation.operation_id).state,
            tx.BridgeOperationState.DISPATCH_ARMED,
        )

    def test_acknowledged_and_verified_reads_ignore_current_fence(self) -> None:
        self.recorder.arm(
            self.operation.operation_id,
            prewrite_observation(self.operation),
            at=NOW + timedelta(seconds=4),
        )
        receipt = applied_receipt(self.operation)
        self.recorder.acknowledge(receipt)
        self.authority.put(
            replace(
                self.operation.fence,
                epoch=2,
                token_digest=token_digest("new-current-token"),
            )
        )
        observed = observation(self.operation, receipt)
        trusted_at = observed.observed_at + timedelta(seconds=1)
        self.assertIs(
            self.recorder.reconcile(
                self.operation.operation_id,
                observed,
                at=trusted_at,
            ),
            tx.BridgeReconciliationAction.VERIFY_RECEIPT,
        )
        self.recorder.verify_receipt(
            self.operation.operation_id,
            observed,
            at=trusted_at,
        )
        later = replace(observed, observed_at=trusted_at + timedelta(seconds=1))
        self.assertIs(
            self.recorder.reconcile(
                self.operation.operation_id,
                later,
                at=later.observed_at,
            ),
            tx.BridgeReconciliationAction.VERIFY_RECEIPT,
        )
        refreshed = self.recorder.verify_receipt(
            self.operation.operation_id,
            later,
            at=later.observed_at,
        )
        self.assertEqual(len(refreshed.verifications), 2)
        self.assertIs(
            self.recorder.reconcile(
                self.operation.operation_id,
                later,
                at=later.observed_at,
            ),
            tx.BridgeReconciliationAction.COMPLETE,
        )

    def test_delayed_no_effect_requires_operation_ledger_after_expiry(self) -> None:
        self.recorder.arm(
            self.operation.operation_id,
            prewrite_observation(self.operation),
            at=NOW + timedelta(seconds=4),
        )
        no_effect = no_effect_receipt(self.operation)
        self.recorder.acknowledge(no_effect)
        observed = observation(self.operation, no_effect)
        self.recorder.verify_receipt(
            self.operation.operation_id,
            observed,
            at=observed.observed_at,
        )
        record = self.journal.get_operation(self.operation.operation_id)
        self.assertIs(record.receipt.outcome, tx.BridgeReceiptOutcome.NO_EFFECT)
        self.assertIs(record.receipt.evidence, tx.BridgeReceiptEvidence.OPERATION_LEDGER)
        self.assertIsNone(record.receipt.effect_at)

        with self.assertRaises(ValueError):
            tx.BridgeOperationReceipt.create(
                self.operation,
                dispatch_authorization(self.operation),
                previous_revision=1,
                result_revision=1,
                outcome=tx.BridgeReceiptOutcome.NO_EFFECT,
                evidence=tx.BridgeReceiptEvidence.OPERATION_LEDGER,
                effect_at=None,
                acknowledged_at=self.operation.fence.expires_at - timedelta(seconds=1),
                durable_at=self.operation.fence.expires_at,
            )

    def test_applied_acknowledgement_cannot_be_backfilled_after_expiry(self) -> None:
        with self.assertRaises(ValueError):
            applied_receipt(
                self.operation,
                effect_at=NOW + timedelta(seconds=5),
                acknowledged_at=self.operation.fence.expires_at + timedelta(seconds=1),
                durable_at=self.operation.fence.expires_at + timedelta(seconds=2),
            )

    def test_exact_object_receipt_and_verification_replays_are_idempotent(self) -> None:
        self.recorder.arm(
            self.operation.operation_id,
            prewrite_observation(self.operation),
            at=NOW + timedelta(seconds=4),
        )
        receipt = applied_receipt(self.operation)
        first_receipt = self.recorder.acknowledge(receipt)
        second_receipt = self.recorder.acknowledge(receipt)
        self.assertIs(first_receipt, second_receipt)
        observed = observation(self.operation, receipt)
        trusted_at = observed.observed_at
        first_verification = self.recorder.verify_receipt(
            self.operation.operation_id,
            observed,
            at=trusted_at,
        )
        second_verification = self.journal.record_verification(
            first_verification.verification
        )
        self.assertIs(first_verification, second_verification)

        conflicting = tx.BridgeOperationReceipt.create(
            self.operation,
            dispatch_authorization(self.operation),
            previous_revision=1,
            result_revision=3,
            outcome=tx.BridgeReceiptOutcome.APPLIED,
            evidence=tx.BridgeReceiptEvidence.DISPATCH_ACK,
            effect_at=NOW + timedelta(seconds=6),
            acknowledged_at=NOW + timedelta(seconds=7),
            durable_at=NOW + timedelta(seconds=9),
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            self.journal.record_receipt(conflicting)

    def test_bare_armed_ambiguity_never_becomes_no_effect(self) -> None:
        self.recorder.arm(
            self.operation.operation_id,
            prewrite_observation(self.operation),
            at=NOW + timedelta(seconds=4),
        )
        for at in (
            self.operation.fence.expires_at,
            self.operation.fence.expires_at + timedelta(hours=1),
        ):
            self.assertIs(
                self.recorder.reconcile(self.operation.operation_id, None, at=at),
                tx.BridgeReconciliationAction.QUERY_RECEIPT,
            )
        self.assertIsNone(
            self.journal.get_operation(self.operation.operation_id).receipt
        )

    def test_missing_preimage_observation_requests_refresh_without_state_change(self) -> None:
        self.assertIs(
            self.recorder.reconcile(
                self.operation.operation_id,
                None,
                at=NOW + timedelta(seconds=4),
            ),
            tx.BridgeReconciliationAction.REFRESH_OBSERVATION,
        )
        self.assertIs(
            self.journal.get_operation(self.operation.operation_id).state,
            tx.BridgeOperationState.INTENT_RECORDED,
        )


class CoverageFreshnessAndRollbackTests(unittest.TestCase):
    def test_terminal_attempts_require_exact_expected_coverage_and_release(self) -> None:
        committed = committed_attempt()
        self.assertIs(committed.state, tx.BridgeAttemptState.COMMITTED)
        with self.assertRaises(ValueError):
            replace(
                committed,
                expected_writes=(
                    committed.expected_writes[0],
                    spec(
                        provider="lovelace",
                        object_key="dashboard.true_family",
                        label="dashboard",
                    ),
                ),
            )
        with self.assertRaises(ValueError):
            replace(committed, releases=())

    def test_committed_and_both_restored_forms_validate(self) -> None:
        self.assertIs(committed_attempt().state, tx.BridgeAttemptState.COMMITTED)
        self.assertIs(
            no_effect_restored_attempt().state,
            tx.BridgeAttemptState.RESTORED,
        )
        self.assertIs(
            applied_restored_attempt().state,
            tx.BridgeAttemptState.RESTORED,
        )

    def test_expected_writes_are_sorted_unique_and_write_is_exact(self) -> None:
        first = spec(provider="scheduler")
        second = spec(
            provider="active_yaml",
            object_key="automation.heating",
            label="automation",
        )
        with self.assertRaises(ValueError):
            tx.BridgeOperationAttempt.open(
                plan_id=PLAN_ID,
                plan_digest=PLAN_DIGEST,
                manifest_digest=MANIFEST_DIGEST,
                attempt=1,
                max_observation_age_seconds=10,
                expected_writes=(first, second),
            )

        journal, authority, recorder = recorder_fixture((first,))
        acquisition = acquire_for_recorder(
            journal,
            authority,
            recorder,
            acquisition_intent(),
        )
        outside = object_intent(
            spec(object_key="profile.unexpected", label="unexpected"),
            acquisition,
        )
        with self.assertRaises(ValueError):
            journal.record_intent(outside)

    def test_effect_phase_requires_acknowledged_fences_and_closes_normal_writes(
        self,
    ) -> None:
        first = spec(object_key="profile.first", label="first")
        second = spec(object_key="profile.second", label="second")
        journal, _authority, _recorder = recorder_fixture((first, second))
        acquisition = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(acquisition.intent)
        unacknowledged_write = object_intent(first, acquisition)
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_intent(unacknowledged_write)

        journal.arm_acquisition(acquisition.intent.operation_id)
        journal.record_acquisition_receipt(acquisition.receipt)
        write = object_intent(first, acquisition)
        journal.record_intent(write)
        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        receipt = applied_receipt(write)
        journal.record_receipt(receipt)
        journal.record_verification(verified_record(write, receipt).verification)

        release = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=10),
        )
        journal.record_release_intent(release)
        refreshed_observation = observation(
            write,
            receipt,
            observed_at=NOW + timedelta(seconds=9),
        )
        refreshed = tx.BridgeOperationVerification.create(
            write,
            receipt,
            refreshed_observation,
            verified_at=NOW + timedelta(seconds=9),
        )
        refreshed_record = journal.record_verification(refreshed)
        self.assertEqual(len(refreshed_record.verifications), 2)
        late_write = object_intent(second, acquisition, sequence=2)
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_intent(late_write)

    def test_post_release_verification_can_refresh_terminal_freshness(self) -> None:
        initial = committed_attempt()
        operation = initial.operations[0]
        refreshed_observation = observation(
            operation.intent,
            operation.receipt,
            observed_at=NOW + timedelta(seconds=20),
        )
        refreshed_verification = tx.BridgeOperationVerification.create(
            operation.intent,
            operation.receipt,
            refreshed_observation,
            verified_at=NOW + timedelta(seconds=20),
        )
        refreshed_operation = operation.refresh_verification(refreshed_verification)
        refreshed_attempt = replace(
            initial,
            operations=(refreshed_operation,),
            terminal_at=NOW + timedelta(seconds=21),
        )
        self.assertGreater(
            refreshed_operation.verification.verified_at,
            initial.releases[0].receipt.durable_at,
        )
        self.assertEqual(
            tx.decode_bridge_operation_attempt(
                tx.encode_bridge_operation_attempt(refreshed_attempt)
            ),
            refreshed_attempt,
        )

    def test_terminal_attempt_rejects_new_verification_history(self) -> None:
        attempt = committed_attempt()
        operation = attempt.operations[0]
        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(attempt)
        observed = observation(
            operation.intent,
            operation.receipt,
            observed_at=NOW + timedelta(seconds=10),
        )
        verification = tx.BridgeOperationVerification.create(
            operation.intent,
            operation.receipt,
            observed,
            verified_at=NOW + timedelta(seconds=10),
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_verification(verification)

    def test_release_phase_boundary_is_exact_and_codec_enforced(self) -> None:
        attempt = applied_restored_attempt()
        self.assertEqual(attempt.release_phase_sequence, 1)
        encoded = tx.encode_bridge_operation_attempt(attempt)
        for boundary in (0, 2):
            tampered = dict(encoded)
            tampered["release_phase_sequence"] = boundary
            with self.subTest(boundary=boundary):
                with self.assertRaises(tx.BridgeTransactionCodecError):
                    tx.decode_bridge_operation_attempt(tampered)

    def test_duplicate_write_for_one_expected_spec_is_rejected(self) -> None:
        expected = spec()
        journal, authority, recorder = recorder_fixture((expected,))
        acquisition = acquire_for_recorder(
            journal,
            authority,
            recorder,
            acquisition_intent(),
        )
        first = object_intent(expected, acquisition)
        journal.record_intent(first)
        duplicate = object_intent(expected, acquisition, sequence=2)
        with self.assertRaises(ValueError):
            journal.record_intent(duplicate)

    def test_stale_observation_is_rejected_but_armed_still_queries(self) -> None:
        expected = spec()
        journal, authority, recorder = recorder_fixture((expected,))
        acquisition = acquire_for_recorder(
            journal,
            authority,
            recorder,
            acquisition_intent(),
        )
        operation = object_intent(expected, acquisition)
        recorder.prepare(operation, at=NOW + timedelta(seconds=4))
        stale = tx.BridgeObjectObservation(
            provider=operation.provider,
            object_key=operation.object_key,
            revision=operation.expected_revision,
            fingerprint=operation.pre_fingerprint,
            observed_at=NOW,
        )
        self.assertIs(
            recorder.reconcile(
                operation.operation_id,
                stale,
                at=NOW + timedelta(seconds=20),
            ),
            tx.BridgeReconciliationAction.REFRESH_OBSERVATION,
        )
        self.assertIs(
            journal.get_operation(operation.operation_id).state,
            tx.BridgeOperationState.INTENT_RECORDED,
        )

        expected2 = spec(object_key="profile.second", label="second")
        journal2, authority2, recorder2 = recorder_fixture((expected2,))
        acquisition2 = acquire_for_recorder(
            journal2,
            authority2,
            recorder2,
            acquisition_intent(),
        )
        operation2 = object_intent(expected2, acquisition2)
        recorder2.prepare(operation2, at=NOW + timedelta(seconds=4))
        recorder2.arm(
            operation2.operation_id,
            prewrite_observation(operation2),
            at=NOW + timedelta(seconds=4),
        )
        self.assertIs(
            recorder2.reconcile(
                operation2.operation_id,
                stale,
                at=NOW + timedelta(hours=1),
            ),
            tx.BridgeReconciliationAction.QUERY_RECEIPT,
        )

    def test_prewrite_observation_must_follow_acquisition_receipt_durability(
        self,
    ) -> None:
        expected = spec()
        journal, authority, recorder = recorder_fixture((expected,))
        intent = acquisition_intent()
        recorder.prepare_acquisition(intent)
        self.assertIs(
            recorder.reconcile_acquisition(intent.operation_id, at=NOW),
            tx.BridgeReconciliationAction.DISPATCH,
        )
        receipt = authority.acquire(
            intent,
            acquired_inventory_revision="inventory-1",
            fence_revision="fence-scheduler-1",
            token_digest=token_digest("causal-fence-token"),
            acquired_at=NOW + timedelta(seconds=1),
            acknowledged_at=NOW + timedelta(seconds=2),
            durable_at=NOW + timedelta(seconds=10),
        )
        acquisition = recorder.acknowledge_acquisition(receipt)
        operation = object_intent(expected, acquisition)
        recorder.prepare(operation, at=NOW + timedelta(seconds=11))
        early = prewrite_observation(
            operation,
            observed_at=NOW + timedelta(seconds=9),
        )
        self.assertIs(
            recorder.reconcile(
                operation.operation_id,
                early,
                at=NOW + timedelta(seconds=11),
            ),
            tx.BridgeReconciliationAction.REFRESH_OBSERVATION,
        )
        with self.assertRaises(tx.BridgeTransactionBlocked) as blocked:
            recorder.arm(
                operation.operation_id,
                early,
                at=NOW + timedelta(seconds=11),
            )
        self.assertIs(
            blocked.exception.reason_code,
            tx.BridgeBlockReason.STALE_OBSERVATION,
        )
        with self.assertRaises(ValueError):
            applied_receipt(
                operation,
                effect_at=NOW + timedelta(seconds=9),
                acknowledged_at=NOW + timedelta(seconds=10),
                durable_at=NOW + timedelta(seconds=11),
            )
        causal = prewrite_observation(
            operation,
            observed_at=receipt.durable_at,
        )
        self.assertIs(
            recorder.arm(
                operation.operation_id,
                causal,
                at=NOW + timedelta(seconds=11),
            ).state,
            tx.BridgeOperationState.DISPATCH_ARMED,
        )

    def test_stale_receipt_verification_can_retry_with_fresh_observation(self) -> None:
        expected = spec()
        journal, authority, recorder = recorder_fixture((expected,))
        acquisition = acquire_for_recorder(
            journal,
            authority,
            recorder,
            acquisition_intent(),
        )
        operation = object_intent(expected, acquisition)
        recorder.prepare(operation, at=NOW + timedelta(seconds=4))
        recorder.arm(
            operation.operation_id,
            prewrite_observation(operation),
            at=NOW + timedelta(seconds=4),
        )
        receipt = applied_receipt(operation)
        recorder.acknowledge(receipt)
        stale = observation(operation, receipt, observed_at=NOW + timedelta(seconds=8))
        with self.assertRaises(tx.BridgeTransactionBlocked):
            recorder.verify_receipt(
                operation.operation_id,
                stale,
                at=NOW + timedelta(seconds=30),
            )
        self.assertIs(
            journal.get_operation(operation.operation_id).state,
            tx.BridgeOperationState.ACKNOWLEDGED,
        )
        fresh = observation(operation, receipt, observed_at=NOW + timedelta(seconds=31))
        recorder.verify_receipt(
            operation.operation_id,
            fresh,
            at=NOW + timedelta(seconds=31),
        )
        self.assertIs(
            journal.get_operation(operation.operation_id).state,
            tx.BridgeOperationState.VERIFIED,
        )

    def test_finish_rejects_stale_terminal_verification(self) -> None:
        complete = committed_attempt()
        open_complete = replace(
            complete,
            state=tx.BridgeAttemptState.OPEN,
            terminal_at=None,
        )
        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(open_complete)
        recorder = tx.BridgeTransactionRecorder(
            journal,
            tx.InMemoryFenceAuthority(),
            max_observation_age=WINDOW,
        )
        with self.assertRaises(ValueError):
            recorder.finish_attempt(
                PLAN_ID,
                1,
                tx.BridgeAttemptState.COMMITTED,
                at=NOW + timedelta(seconds=30),
            )
        finished = recorder.finish_attempt(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.COMMITTED,
            at=NOW + timedelta(seconds=14),
        )
        self.assertIs(finished.state, tx.BridgeAttemptState.COMMITTED)

    def test_refreshed_verification_is_append_only_and_terminal_uses_newest(
        self,
    ) -> None:
        expected = spec()
        acquisition = acquired_record(acquisition_intent())
        operation = object_intent(expected, acquisition)
        receipt = applied_receipt(
            operation,
            effect_at=NOW + timedelta(seconds=6),
            acknowledged_at=NOW + timedelta(seconds=7),
            durable_at=NOW + timedelta(seconds=8),
        )
        initial = verified_record(
            operation,
            receipt,
            observed_at=NOW + timedelta(seconds=9),
        )
        refreshed_observation = observation(
            operation,
            receipt,
            observed_at=NOW + timedelta(seconds=20),
        )
        refreshed_verification = tx.BridgeOperationVerification.create(
            operation,
            receipt,
            refreshed_observation,
            verified_at=NOW + timedelta(seconds=20),
        )
        refreshed = initial.refresh_verification(refreshed_verification)
        self.assertEqual(
            refreshed.verifications,
            (initial.verification, refreshed_verification),
        )
        release = release_record(
            acquisition,
            requested_at=NOW + timedelta(seconds=21),
        )
        attempt = tx.BridgeOperationAttempt(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=1,
            state=tx.BridgeAttemptState.COMMITTED,
            max_observation_age_seconds=10,
            expected_writes=(expected,),
            acquisitions=(acquisition,),
            operations=(refreshed,),
            releases=(release,),
            release_phase_sequence=1,
            terminal_at=NOW + timedelta(seconds=25),
        )
        encoded = tx.encode_bridge_operation_attempt(attempt)
        self.assertEqual(len(encoded["operations"][0]["verifications"]), 2)
        self.assertEqual(tx.decode_bridge_operation_attempt(encoded), attempt)
        with self.assertRaises(ValueError):
            replace(
                attempt,
                operations=(initial,),
            )

    def test_rollback_requires_verified_applied_parent_and_newer_fence(self) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        first = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(first.intent)
        journal.arm_acquisition(first.intent.operation_id)
        journal.record_acquisition_receipt(first.receipt)
        write = object_intent(expected, first)
        journal.record_intent(write)

        first_release = release_record(
            first,
            requested_at=NOW + timedelta(seconds=10),
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_release_intent(first_release.intent)

        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        write_receipt = applied_receipt(write)
        journal.record_receipt(write_receipt)
        journal.record_verification(
            verified_record(write, write_receipt).verification
        )
        journal.record_release_intent(first_release.intent)
        journal.arm_release(first_release.intent.operation_id)
        journal.record_release_receipt(first_release.receipt)

        second = acquired_record(
            acquisition_intent(
                epoch=2,
                inventory_revision="inventory-2",
                requested_at=NOW + timedelta(seconds=15),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        journal.record_acquisition_intent(second.intent)
        journal.arm_acquisition(second.intent.operation_id)
        journal.record_acquisition_receipt(second.receipt)
        rollback = object_intent(
            expected,
            second,
            sequence=2,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=2,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        self.assertEqual(journal.record_intent(rollback).intent, rollback)

        same_epoch = replace(second.receipt.binding, epoch=1)
        invalid = tx.BridgeOperationIntent.create(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=1,
            sequence=3,
            kind=tx.BridgeOperationKind.ROLLBACK,
            provider=expected.provider,
            object_key=expected.object_key,
            expected_revision=2,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            fence=same_epoch,
            parent_operation_id=write.operation_id,
        )
        with self.assertRaises(ValueError):
            replace(
                journal.get_attempt(PLAN_ID, 1),
                operations=journal.get_attempt(PLAN_ID, 1).operations
                + (tx.BridgeOperationRecord.recorded(invalid),),
            )


class BlockedCompensationAndEpochTests(unittest.TestCase):
    def test_expired_rollback_acquisition_can_retry_without_release(self) -> None:
        expected = spec()
        journal, _authority, recorder = recorder_fixture((expected,))
        first = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(first.intent)
        journal.arm_acquisition(first.intent.operation_id)
        journal.record_acquisition_receipt(first.receipt)
        write = object_intent(expected, first)
        journal.record_intent(write)
        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        write_receipt = applied_receipt(write)
        journal.record_receipt(write_receipt)
        journal.record_verification(verified_record(write, write_receipt).verification)
        journal.block_operation(write.operation_id, tx.BridgeBlockReason.VERIFIED_DRIFT)

        first_release = release_record(first, requested_at=NOW + timedelta(seconds=10))
        journal.record_release_intent(first_release.intent)
        journal.arm_release(first_release.intent.operation_id)
        journal.record_release_receipt(first_release.receipt)

        expired_intent = acquisition_intent(
            epoch=2,
            inventory_revision="inventory-2",
            requested_at=NOW + timedelta(seconds=15),
            expires_at=NOW + timedelta(seconds=20),
        )
        recorder.prepare_acquisition(expired_intent)
        self.assertIs(
            recorder.reconcile_acquisition(
                expired_intent.operation_id,
                at=expired_intent.expires_at,
            ),
            tx.BridgeReconciliationAction.BLOCK,
        )
        expired = journal.get_acquisition(expired_intent.operation_id)
        self.assertIs(expired.state, tx.FenceLifecycleState.BLOCKED)
        self.assertIs(
            expired.blocked_from,
            tx.FenceLifecycleState.INTENT_RECORDED,
        )
        self.assertIsNone(expired.receipt)

        newer = acquired_record(
            acquisition_intent(
                epoch=3,
                inventory_revision="inventory-3",
                requested_at=NOW + timedelta(seconds=25),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        journal.record_acquisition_intent(newer.intent)
        journal.arm_acquisition(newer.intent.operation_id)
        journal.record_acquisition_receipt(newer.receipt)
        rollback = object_intent(
            expected,
            newer,
            sequence=2,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        journal.record_intent(rollback)
        journal.arm_operation(
            rollback.operation_id,
            dispatch_authorization(rollback),
        )
        rollback_receipt = applied_receipt(
            rollback,
            result_revision=3,
            effect_at=NOW + timedelta(seconds=30),
            acknowledged_at=NOW + timedelta(seconds=31),
            durable_at=NOW + timedelta(seconds=32),
        )
        journal.record_receipt(rollback_receipt)
        journal.record_verification(
            verified_record(
                rollback,
                rollback_receipt,
                observed_at=NOW + timedelta(seconds=33),
            ).verification
        )
        newer_release = release_record(
            newer,
            revision=rollback_receipt.result_revision,
            requested_at=NOW + timedelta(seconds=34),
        )
        journal.record_release_intent(newer_release.intent)
        journal.arm_release(newer_release.intent.operation_id)
        journal.record_release_receipt(newer_release.receipt)
        restored = journal.set_attempt_state(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=38),
        )
        self.assertIs(restored.state, tx.BridgeAttemptState.RESTORED)
        self.assertFalse(
            any(
                item.intent.acquisition_operation_id == expired.intent.operation_id
                for item in restored.releases
            )
        )
        retry_expected = (replace(expected, expected_revision=3),)
        retry = tx.BridgeOperationAttempt.open(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=2,
            max_observation_age_seconds=10,
            expected_writes=retry_expected,
        )
        self.assertEqual(journal.append_attempt(retry), retry)

    def test_undispatched_rollback_can_retry_under_a_newer_fence(self) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        first = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(first.intent)
        journal.arm_acquisition(first.intent.operation_id)
        journal.record_acquisition_receipt(first.receipt)
        write = object_intent(expected, first)
        journal.record_intent(write)
        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        write_receipt = applied_receipt(write)
        journal.record_receipt(write_receipt)
        journal.record_verification(verified_record(write, write_receipt).verification)
        journal.block_operation(write.operation_id, tx.BridgeBlockReason.VERIFIED_DRIFT)

        first_release = release_record(first, requested_at=NOW + timedelta(seconds=10))
        journal.record_release_intent(first_release.intent)
        journal.arm_release(first_release.intent.operation_id)
        journal.record_release_receipt(first_release.receipt)
        second = acquired_record(
            acquisition_intent(
                epoch=2,
                inventory_revision="inventory-2",
                requested_at=NOW + timedelta(seconds=15),
                expires_at=NOW + timedelta(seconds=90),
            )
        )
        journal.record_acquisition_intent(second.intent)
        journal.arm_acquisition(second.intent.operation_id)
        journal.record_acquisition_receipt(second.receipt)
        rollback_one = object_intent(
            expected,
            second,
            sequence=2,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        journal.record_intent(rollback_one)
        blocked_rollback = journal.block_operation(
            rollback_one.operation_id,
            tx.BridgeBlockReason.EXPLICIT_ABORT,
        )
        self.assertIs(
            blocked_rollback.blocked_from,
            tx.BridgeOperationState.INTENT_RECORDED,
        )
        self.assertIsNone(blocked_rollback.authorization)

        second_release = release_record(
            second,
            revision="inventory-2",
            requested_at=NOW + timedelta(seconds=20),
        )
        journal.record_release_intent(second_release.intent)
        journal.arm_release(second_release.intent.operation_id)
        journal.record_release_receipt(second_release.receipt)
        third = acquired_record(
            acquisition_intent(
                epoch=3,
                inventory_revision="inventory-2",
                requested_at=NOW + timedelta(seconds=30),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        journal.record_acquisition_intent(third.intent)
        journal.arm_acquisition(third.intent.operation_id)
        journal.record_acquisition_receipt(third.receipt)
        rollback_two = object_intent(
            expected,
            third,
            sequence=3,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        journal.record_intent(rollback_two)
        journal.arm_operation(
            rollback_two.operation_id,
            dispatch_authorization(rollback_two),
        )
        rollback_receipt = applied_receipt(
            rollback_two,
            result_revision=3,
            effect_at=NOW + timedelta(seconds=35),
            acknowledged_at=NOW + timedelta(seconds=36),
            durable_at=NOW + timedelta(seconds=37),
        )
        journal.record_receipt(rollback_receipt)
        journal.record_verification(
            verified_record(
                rollback_two,
                rollback_receipt,
                observed_at=NOW + timedelta(seconds=38),
            ).verification
        )
        third_release = release_record(
            third,
            revision=rollback_receipt.result_revision,
            requested_at=NOW + timedelta(seconds=39),
        )
        journal.record_release_intent(third_release.intent)
        journal.arm_release(third_release.intent.operation_id)
        journal.record_release_receipt(third_release.receipt)
        restored = journal.set_attempt_state(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=43),
        )
        self.assertIs(restored.state, tx.BridgeAttemptState.RESTORED)
        self.assertEqual(restored.release_phase_sequence, 1)

    def test_untouched_provider_retries_after_exact_other_provider_compensation(
        self,
    ) -> None:
        expected_a = spec(
            provider="active_yaml",
            object_key="automation.heating",
            label="provider-a",
        )
        expected_b = spec(
            provider="scheduler",
            object_key="profile.guest_room_monday",
            label="provider-b",
        )
        journal, _authority, _recorder = recorder_fixture((expected_a, expected_b))
        first = acquired_record(acquisition_intent(provider="active_yaml"))
        journal.record_acquisition_intent(first.intent)
        journal.arm_acquisition(first.intent.operation_id)
        journal.record_acquisition_receipt(first.receipt)
        write = object_intent(expected_a, first)
        journal.record_intent(write)
        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        write_receipt = applied_receipt(write)
        journal.record_receipt(write_receipt)
        journal.record_verification(verified_record(write, write_receipt).verification)
        journal.block_operation(write.operation_id, tx.BridgeBlockReason.VERIFIED_DRIFT)

        first_release = release_record(first, requested_at=NOW + timedelta(seconds=10))
        journal.record_release_intent(first_release.intent)
        journal.arm_release(first_release.intent.operation_id)
        journal.record_release_receipt(first_release.receipt)
        newer = acquired_record(
            acquisition_intent(
                provider="active_yaml",
                epoch=2,
                inventory_revision="inventory-a-2",
                requested_at=NOW + timedelta(seconds=20),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        journal.record_acquisition_intent(newer.intent)
        journal.arm_acquisition(newer.intent.operation_id)
        journal.record_acquisition_receipt(newer.receipt)
        rollback = object_intent(
            expected_a,
            newer,
            sequence=2,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected_a.post_fingerprint,
            post_fingerprint=expected_a.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        journal.record_intent(rollback)
        journal.arm_operation(
            rollback.operation_id,
            dispatch_authorization(rollback),
        )
        rollback_receipt = applied_receipt(
            rollback,
            result_revision=3,
            effect_at=NOW + timedelta(seconds=25),
            acknowledged_at=NOW + timedelta(seconds=26),
            durable_at=NOW + timedelta(seconds=27),
        )
        journal.record_receipt(rollback_receipt)
        journal.record_verification(
            verified_record(
                rollback,
                rollback_receipt,
                observed_at=NOW + timedelta(seconds=28),
            ).verification
        )
        newer_release = release_record(
            newer,
            revision=rollback_receipt.result_revision,
            requested_at=NOW + timedelta(seconds=30),
        )
        journal.record_release_intent(newer_release.intent)
        journal.arm_release(newer_release.intent.operation_id)
        journal.record_release_receipt(newer_release.receipt)
        restored = journal.set_attempt_state(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=34),
        )
        self.assertIs(restored.state, tx.BridgeAttemptState.RESTORED)
        self.assertTrue(
            all(
                item.intent.provider == expected_a.provider
                for item in restored.acquisitions
            )
        )
        self.assertTrue(
            all(item.intent.provider == expected_a.provider for item in restored.operations)
        )

        retry_expected = (
            replace(expected_a, expected_revision=3),
            expected_b,
        )
        retry = tx.BridgeOperationAttempt.open(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=2,
            max_observation_age_seconds=10,
            expected_writes=retry_expected,
        )
        self.assertEqual(journal.append_attempt(retry), retry)
        self.assertEqual(retry.expected_writes[1], expected_b)

    def test_blocked_undispatched_write_restores_and_retries_unchanged(self) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        acquisition = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(acquisition.intent)
        journal.arm_acquisition(acquisition.intent.operation_id)
        journal.record_acquisition_receipt(acquisition.receipt)
        write = object_intent(expected, acquisition)
        journal.record_intent(write)
        blocked = journal.block_operation(
            write.operation_id,
            tx.BridgeBlockReason.EXPLICIT_ABORT,
        )
        self.assertIsNone(blocked.authorization)
        release = release_record(
            acquisition,
            requested_at=NOW + timedelta(seconds=10),
        )
        journal.record_release_intent(release.intent)
        journal.arm_release(release.intent.operation_id)
        journal.record_release_receipt(release.receipt)
        restored = journal.set_attempt_state(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=14),
        )
        retry = tx.BridgeOperationAttempt.open(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=2,
            max_observation_age_seconds=10,
            expected_writes=(expected,),
        )
        journal.append_attempt(retry)
        self.assertEqual(restored.operations[0].intent.expected_revision, 1)
        self.assertEqual(journal.get_attempt(PLAN_ID, 2).expected_writes, (expected,))

    def test_blocked_acquisition_restores_without_host_writes(self) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        intent = acquisition_intent()
        journal.record_acquisition_intent(intent)
        journal.block_acquisition(
            intent.operation_id,
            tx.BridgeBlockReason.EXPLICIT_ABORT,
        )
        restored = journal.set_attempt_state(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=1),
        )
        self.assertFalse(restored.operations)
        self.assertFalse(restored.releases)
        retry = tx.BridgeOperationAttempt.open(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=2,
            max_observation_age_seconds=10,
            expected_writes=(expected,),
        )
        journal.append_attempt(retry)
        self.assertEqual(journal.get_attempt(PLAN_ID, 2).expected_writes, (expected,))

    def test_blocked_attempt_restores_after_no_effect_rollback_retry_and_releases(
        self,
    ) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        first = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(first.intent)
        journal.arm_acquisition(first.intent.operation_id)
        journal.record_acquisition_receipt(first.receipt)
        write = object_intent(expected, first)
        journal.record_intent(write)
        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        write_receipt = applied_receipt(write)
        journal.record_receipt(write_receipt)
        journal.record_verification(verified_record(write, write_receipt).verification)
        journal.block_operation(write.operation_id, tx.BridgeBlockReason.VERIFIED_DRIFT)

        first_release = release_record(
            first,
            requested_at=NOW + timedelta(seconds=10),
        )
        journal.record_release_intent(first_release.intent)
        journal.arm_release(first_release.intent.operation_id)
        journal.record_release_receipt(first_release.receipt)

        second = acquired_record(
            acquisition_intent(
                epoch=2,
                inventory_revision="inventory-2",
                requested_at=NOW + timedelta(seconds=15),
                expires_at=NOW + timedelta(seconds=60),
            )
        )
        journal.record_acquisition_intent(second.intent)
        journal.arm_acquisition(second.intent.operation_id)
        journal.record_acquisition_receipt(second.receipt)
        rollback_one = object_intent(
            expected,
            second,
            sequence=2,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        journal.record_intent(rollback_one)
        journal.arm_operation(
            rollback_one.operation_id,
            dispatch_authorization(rollback_one),
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_acquisition_intent(
                acquisition_intent(
                    epoch=3,
                    inventory_revision="inventory-uncertain",
                    requested_at=NOW + timedelta(seconds=65),
                    expires_at=NOW + timedelta(seconds=125),
                )
            )

        rollback_one_receipt = no_effect_receipt(rollback_one)
        journal.record_receipt(rollback_one_receipt)
        journal.record_verification(
            verified_record(rollback_one, rollback_one_receipt).verification
        )
        second_release = release_record(
            second,
            revision=rollback_one_receipt.result_revision,
            requested_at=NOW + timedelta(seconds=64),
        )
        journal.record_release_intent(second_release.intent)
        journal.arm_release(second_release.intent.operation_id)
        journal.record_release_receipt(second_release.receipt)
        with self.assertRaises(ValueError):
            journal.set_attempt_state(
                PLAN_ID,
                1,
                tx.BridgeAttemptState.RESTORED,
                terminal_at=NOW + timedelta(seconds=68),
            )

        third = acquired_record(
            acquisition_intent(
                epoch=3,
                inventory_revision=rollback_one_receipt.result_revision,
                requested_at=NOW + timedelta(seconds=70),
                expires_at=NOW + timedelta(seconds=130),
            )
        )
        journal.record_acquisition_intent(third.intent)
        journal.arm_acquisition(third.intent.operation_id)
        journal.record_acquisition_receipt(third.receipt)
        rollback_two = object_intent(
            expected,
            third,
            sequence=3,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        journal.record_intent(rollback_two)
        journal.arm_operation(
            rollback_two.operation_id,
            dispatch_authorization(rollback_two),
        )
        rollback_two_receipt = applied_receipt(
            rollback_two,
            result_revision=3,
            effect_at=NOW + timedelta(seconds=75),
            acknowledged_at=NOW + timedelta(seconds=76),
            durable_at=NOW + timedelta(seconds=77),
        )
        journal.record_receipt(rollback_two_receipt)
        journal.record_verification(
            verified_record(
                rollback_two,
                rollback_two_receipt,
                observed_at=NOW + timedelta(seconds=78),
            ).verification
        )
        with self.assertRaises(ValueError):
            journal.set_attempt_state(
                PLAN_ID,
                1,
                tx.BridgeAttemptState.RESTORED,
                terminal_at=NOW + timedelta(seconds=80),
            )

        third_release = release_record(
            third,
            revision=rollback_two_receipt.result_revision,
            requested_at=NOW + timedelta(seconds=79),
        )
        journal.record_release_intent(third_release.intent)
        journal.arm_release(third_release.intent.operation_id)
        journal.record_release_receipt(third_release.receipt)
        restored = journal.set_attempt_state(
            PLAN_ID,
            1,
            tx.BridgeAttemptState.RESTORED,
            terminal_at=NOW + timedelta(seconds=83),
        )
        self.assertIs(restored.state, tx.BridgeAttemptState.RESTORED)
        self.assertIs(restored.reason_code, tx.BridgeBlockReason.VERIFIED_DRIFT)
        self.assertIs(
            journal.set_attempt_state(
                PLAN_ID,
                1,
                tx.BridgeAttemptState.RESTORED,
                terminal_at=NOW + timedelta(seconds=83),
            ),
            restored,
        )
        self.assertEqual(
            [item.receipt.outcome for item in restored.operations[1:]],
            [tx.BridgeReceiptOutcome.NO_EFFECT, tx.BridgeReceiptOutcome.APPLIED],
        )
        retry = tx.BridgeOperationAttempt.open(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=2,
            max_observation_age_seconds=10,
            expected_writes=(replace(expected, expected_revision=3),),
        )
        self.assertEqual(journal.append_attempt(retry), retry)

    def test_applied_write_can_be_compensated_after_other_provider_blocks(self) -> None:
        expected_a = spec(
            provider="active_yaml",
            object_key="automation.heating",
            label="provider-a",
        )
        expected_b = spec(
            provider="scheduler",
            object_key="profile.guest_room_monday",
            label="provider-b",
        )
        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(
            tx.BridgeOperationAttempt.open(
                plan_id=PLAN_ID,
                plan_digest=PLAN_DIGEST,
                manifest_digest=MANIFEST_DIGEST,
                attempt=1,
                max_observation_age_seconds=10,
                expected_writes=(expected_a, expected_b),
            )
        )
        acq_a = acquired_record(acquisition_intent(provider="active_yaml"))
        acq_b = acquired_record(acquisition_intent(provider="scheduler"))
        for item in (acq_a, acq_b):
            journal.record_acquisition_intent(item.intent)
            journal.arm_acquisition(item.intent.operation_id)
            journal.record_acquisition_receipt(item.receipt)

        write_a = object_intent(expected_a, acq_a, sequence=1)
        journal.record_intent(write_a)
        journal.arm_operation(write_a.operation_id, dispatch_authorization(write_a))
        receipt_a = applied_receipt(write_a)
        journal.record_receipt(receipt_a)
        journal.record_verification(verified_record(write_a, receipt_a).verification)

        write_b = object_intent(expected_b, acq_b, sequence=2)
        journal.record_intent(write_b)
        journal.block_operation(
            write_b.operation_id,
            tx.BridgeBlockReason.OBSERVATION_MISMATCH,
        )
        self.assertIs(
            journal.get_attempt(PLAN_ID, 1).state,
            tx.BridgeAttemptState.BLOCKED,
        )

        release_a = release_record(acq_a, requested_at=NOW + timedelta(seconds=10))
        release_b = release_record(acq_b, requested_at=NOW + timedelta(seconds=10))
        for item in (release_a, release_b):
            journal.record_release_intent(item.intent)
            journal.arm_release(item.intent.operation_id)
            journal.record_release_receipt(item.receipt)

        newer_a = acquired_record(
            acquisition_intent(
                provider="active_yaml",
                epoch=2,
                inventory_revision="inventory-a-2",
                requested_at=NOW + timedelta(seconds=20),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        journal.record_acquisition_intent(newer_a.intent)
        journal.arm_acquisition(newer_a.intent.operation_id)
        journal.record_acquisition_receipt(newer_a.receipt)
        rollback = object_intent(
            expected_a,
            newer_a,
            sequence=3,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=receipt_a.result_revision,
            pre_fingerprint=expected_a.post_fingerprint,
            post_fingerprint=expected_a.pre_fingerprint,
            parent_operation_id=write_a.operation_id,
        )
        journal.record_intent(rollback)
        journal.arm_operation(
            rollback.operation_id,
            dispatch_authorization(rollback),
        )
        rollback_receipt = applied_receipt(
            rollback,
            result_revision=3,
            effect_at=NOW + timedelta(seconds=25),
            acknowledged_at=NOW + timedelta(seconds=26),
            durable_at=NOW + timedelta(seconds=27),
        )
        journal.record_receipt(rollback_receipt)
        journal.record_verification(
            verified_record(rollback, rollback_receipt).verification
        )
        release_newer = release_record(
            newer_a,
            requested_at=NOW + timedelta(seconds=30),
        )
        journal.record_release_intent(release_newer.intent)
        journal.arm_release(release_newer.intent.operation_id)
        journal.record_release_receipt(release_newer.receipt)

        attempt = journal.get_attempt(PLAN_ID, 1)
        self.assertIs(attempt.state, tx.BridgeAttemptState.BLOCKED)
        self.assertIs(
            attempt.operations[-1].state,
            tx.BridgeOperationState.VERIFIED,
        )
        self.assertEqual(len(attempt.releases), 3)
        self.assertTrue(
            all(
                item.state is tx.FenceLifecycleState.ACKNOWLEDGED
                for item in attempt.releases
            )
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.append_attempt(
                tx.BridgeOperationAttempt.open(
                    plan_id=PLAN_ID,
                    plan_digest=PLAN_DIGEST,
                    manifest_digest=MANIFEST_DIGEST,
                    attempt=2,
                    max_observation_age_seconds=10,
                    expected_writes=(expected_a, expected_b),
                )
            )

    def test_epoch_rules_apply_within_and_across_attempts(self) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        first = acquisition_intent(epoch=3)
        journal.record_acquisition_intent(first)
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_acquisition_intent(
                acquisition_intent(
                    epoch=2,
                    inventory_revision="inventory-2",
                    requested_at=NOW + timedelta(seconds=10),
                    expires_at=NOW + timedelta(seconds=80),
                )
            )

        restored = no_effect_restored_attempt()
        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(restored)
        journal.append_attempt(
            tx.BridgeOperationAttempt.open(
                plan_id=PLAN_ID,
                plan_digest=PLAN_DIGEST,
                manifest_digest=MANIFEST_DIGEST,
                attempt=2,
                max_observation_age_seconds=10,
                expected_writes=restored.expected_writes,
            )
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_acquisition_intent(
                acquisition_intent(
                    attempt=2,
                    epoch=1,
                    inventory_revision="inventory-retry",
                    requested_at=NOW + timedelta(seconds=80),
                    expires_at=NOW + timedelta(seconds=140),
                )
            )
        newer = acquisition_intent(
            attempt=2,
            epoch=2,
            inventory_revision="inventory-retry",
            requested_at=NOW + timedelta(seconds=80),
            expires_at=NOW + timedelta(seconds=140),
        )
        self.assertEqual(journal.record_acquisition_intent(newer).intent, newer)
        journal.arm_acquisition(newer.operation_id)
        acquired = journal.record_acquisition_receipt(acquisition_receipt(newer))
        retry_write = object_intent(restored.expected_writes[0], acquired)
        self.assertEqual(journal.record_intent(retry_write).intent, retry_write)
        self.assertNotEqual(
            retry_write.operation_id,
            restored.operations[0].intent.operation_id,
        )

    def test_epoch_high_water_reconstructs_globally_across_plans_and_restart(
        self,
    ) -> None:
        expected = spec()
        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(
            tx.BridgeOperationAttempt.open(
                plan_id=PLAN_ID,
                plan_digest=PLAN_DIGEST,
                manifest_digest=MANIFEST_DIGEST,
                attempt=1,
                max_observation_age_seconds=10,
                expected_writes=(expected,),
            )
        )
        first = acquisition_intent(epoch=4)
        journal.record_acquisition_intent(first)
        journal.append_attempt(
            tx.BridgeOperationAttempt.open(
                plan_id=SECOND_PLAN_ID,
                plan_digest=SECOND_PLAN_DIGEST,
                manifest_digest=MANIFEST_DIGEST,
                attempt=1,
                max_observation_age_seconds=10,
                expected_writes=(expected,),
            )
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.record_acquisition_intent(
                acquisition_intent(
                    epoch=4,
                    requested_at=NOW + timedelta(seconds=10),
                    expires_at=NOW + timedelta(seconds=70),
                    plan_id=SECOND_PLAN_ID,
                    plan_digest=SECOND_PLAN_DIGEST,
                )
            )
        second = acquisition_intent(
            epoch=5,
            requested_at=NOW + timedelta(seconds=10),
            expires_at=NOW + timedelta(seconds=70),
            plan_id=SECOND_PLAN_ID,
            plan_digest=SECOND_PLAN_DIGEST,
        )
        journal.record_acquisition_intent(second)
        self.assertEqual(journal.provider_epoch_high_water("scheduler"), 5)

        restarted = tx.InMemoryBridgeOperationJournal()
        for plan_id in (SECOND_PLAN_ID, PLAN_ID):
            encoded = tx.encode_bridge_operation_attempt(
                journal.get_attempt(plan_id, 1)
            )
            restarted.append_attempt(tx.decode_bridge_operation_attempt(encoded))
        self.assertEqual(restarted.provider_epoch_high_water("scheduler"), 5)

        third_digest = digest("third-reference-plan-body")
        third_hash = hashlib.sha256(
            f"reference-plan:{third_digest}".encode()
        ).hexdigest()
        third_id = f"tf-reference-{third_hash[:24]}"
        restarted.append_attempt(
            tx.BridgeOperationAttempt.open(
                plan_id=third_id,
                plan_digest=third_digest,
                manifest_digest=MANIFEST_DIGEST,
                attempt=1,
                max_observation_age_seconds=10,
                expected_writes=(expected,),
            )
        )
        with self.assertRaises(tx.BridgeJournalConflict):
            restarted.record_acquisition_intent(
                acquisition_intent(
                    epoch=5,
                    requested_at=NOW + timedelta(seconds=20),
                    expires_at=NOW + timedelta(seconds=80),
                    plan_id=third_id,
                    plan_digest=third_digest,
                )
            )
        with self.assertRaises(tx.BridgeJournalConflict):
            restarted.record_acquisition_intent(
                acquisition_intent(
                    epoch=6,
                    requested_at=NOW + timedelta(seconds=5),
                    expires_at=NOW + timedelta(seconds=65),
                    plan_id=third_id,
                    plan_digest=third_digest,
                )
            )
        newest = acquisition_intent(
            epoch=6,
            requested_at=NOW + timedelta(seconds=20),
            expires_at=NOW + timedelta(seconds=80),
            plan_id=third_id,
            plan_digest=third_digest,
        )
        self.assertEqual(restarted.record_acquisition_intent(newest).intent, newest)

    def test_retry_coverage_advances_to_rollback_result_revision(self) -> None:
        restored = applied_restored_attempt()
        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(restored)
        revised = replace(
            restored.expected_writes[0],
            expected_revision=3,
        )
        second = tx.BridgeOperationAttempt.open(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=2,
            max_observation_age_seconds=10,
            expected_writes=(revised,),
        )
        self.assertEqual(journal.append_attempt(second), second)

        journal = tx.InMemoryBridgeOperationJournal()
        journal.append_attempt(restored)
        with self.assertRaises(tx.BridgeJournalConflict):
            journal.append_attempt(
                tx.BridgeOperationAttempt.open(
                    plan_id=PLAN_ID,
                    plan_digest=PLAN_DIGEST,
                    manifest_digest=MANIFEST_DIGEST,
                    attempt=2,
                    max_observation_age_seconds=10,
                    expected_writes=restored.expected_writes,
                )
            )

    def test_verified_write_remains_rollback_eligible_after_drift_block(self) -> None:
        expected = spec()
        journal, _authority, _recorder = recorder_fixture((expected,))
        first = acquired_record(acquisition_intent())
        journal.record_acquisition_intent(first.intent)
        journal.arm_acquisition(first.intent.operation_id)
        journal.record_acquisition_receipt(first.receipt)
        write = object_intent(expected, first)
        journal.record_intent(write)
        journal.arm_operation(write.operation_id, dispatch_authorization(write))
        write_receipt = applied_receipt(write)
        journal.record_receipt(write_receipt)
        journal.record_verification(verified_record(write, write_receipt).verification)
        journal.block_operation(write.operation_id, tx.BridgeBlockReason.VERIFIED_DRIFT)

        first_release = release_record(
            first,
            requested_at=NOW + timedelta(seconds=10),
        )
        journal.record_release_intent(first_release.intent)
        journal.arm_release(first_release.intent.operation_id)
        journal.record_release_receipt(first_release.receipt)

        second = acquired_record(
            acquisition_intent(
                epoch=2,
                inventory_revision="inventory-2",
                requested_at=NOW + timedelta(seconds=20),
                expires_at=NOW + timedelta(seconds=120),
            )
        )
        journal.record_acquisition_intent(second.intent)
        journal.arm_acquisition(second.intent.operation_id)
        journal.record_acquisition_receipt(second.receipt)
        rollback = object_intent(
            expected,
            second,
            sequence=2,
            kind=tx.BridgeOperationKind.ROLLBACK,
            expected_revision=write_receipt.result_revision,
            pre_fingerprint=expected.post_fingerprint,
            post_fingerprint=expected.pre_fingerprint,
            parent_operation_id=write.operation_id,
        )
        self.assertEqual(journal.record_intent(rollback).intent, rollback)


class CodecAndTamperingTests(unittest.TestCase):
    def codec_cases(self):
        attempt = committed_attempt()
        acquisition = attempt.acquisitions[0]
        operation = attempt.operations[0]
        release = attempt.releases[0]
        no_effect_acquisition_intent = acquisition_intent()
        no_effect_acquisition_receipt = acquisition_tombstone(
            no_effect_acquisition_intent
        )
        no_effect_acquisition = (
            tx.FenceAcquisitionRecord.recorded(no_effect_acquisition_intent)
            .arm()
            .acknowledge(no_effect_acquisition_receipt)
        )
        blocked_acquisition = (
            tx.FenceAcquisitionRecord.recorded(acquisition_intent(epoch=2))
            .arm()
            .block(tx.BridgeBlockReason.EXPLICIT_ABORT)
        )
        no_effect_release_intent = tx.FenceReleaseIntent.create(
            acquisition,
            expected_inventory_revision="inventory-final",
            requested_at=NOW + timedelta(seconds=20),
        )
        no_effect_release_receipt = release_tombstone(no_effect_release_intent)
        no_effect_release = (
            tx.FenceReleaseRecord.recorded(no_effect_release_intent)
            .arm()
            .acknowledge(no_effect_release_receipt)
        )
        blocked_release = tx.FenceReleaseRecord.recorded(
            no_effect_release_intent
        ).block(tx.BridgeBlockReason.EXPLICIT_ABORT)
        refreshed_observation = observation(
            operation.intent,
            operation.receipt,
            observed_at=NOW + timedelta(seconds=10),
        )
        refreshed_verification = tx.BridgeOperationVerification.create(
            operation.intent,
            operation.receipt,
            refreshed_observation,
            verified_at=NOW + timedelta(seconds=10),
        )
        refreshed_operation = operation.refresh_verification(refreshed_verification)
        blocked_operation = operation.block(tx.BridgeBlockReason.VERIFIED_DRIFT)
        return (
            (
                attempt.expected_writes[0],
                tx.encode_bridge_expected_write,
                tx.decode_bridge_expected_write,
            ),
            (
                acquisition.intent,
                tx.encode_fence_acquisition_intent,
                tx.decode_fence_acquisition_intent,
            ),
            (
                acquisition.receipt,
                tx.encode_fence_acquisition_receipt,
                tx.decode_fence_acquisition_receipt,
            ),
            (
                no_effect_acquisition_receipt,
                tx.encode_fence_acquisition_no_effect_receipt,
                tx.decode_fence_acquisition_no_effect_receipt,
            ),
            (
                acquisition,
                tx.encode_fence_acquisition_record,
                tx.decode_fence_acquisition_record,
            ),
            (
                no_effect_acquisition,
                tx.encode_fence_acquisition_record,
                tx.decode_fence_acquisition_record,
            ),
            (
                blocked_acquisition,
                tx.encode_fence_acquisition_record,
                tx.decode_fence_acquisition_record,
            ),
            (
                acquisition.receipt.binding,
                tx.encode_fence_binding,
                tx.decode_fence_binding,
            ),
            (
                operation.intent,
                tx.encode_bridge_operation_intent,
                tx.decode_bridge_operation_intent,
            ),
            (
                operation.receipt,
                tx.encode_bridge_operation_receipt,
                tx.decode_bridge_operation_receipt,
            ),
            (
                operation.authorization,
                tx.encode_bridge_dispatch_authorization,
                tx.decode_bridge_dispatch_authorization,
            ),
            (
                tx.BridgeObjectObservation(
                    provider=operation.intent.provider,
                    object_key=operation.intent.object_key,
                    revision=operation.verification.revision,
                    fingerprint=operation.verification.fingerprint,
                    observed_at=operation.verification.observed_at,
                ),
                tx.encode_bridge_object_observation,
                tx.decode_bridge_object_observation,
            ),
            (
                operation.verification,
                tx.encode_bridge_operation_verification,
                tx.decode_bridge_operation_verification,
            ),
            (
                operation,
                tx.encode_bridge_operation_record,
                tx.decode_bridge_operation_record,
            ),
            (
                refreshed_operation,
                tx.encode_bridge_operation_record,
                tx.decode_bridge_operation_record,
            ),
            (
                blocked_operation,
                tx.encode_bridge_operation_record,
                tx.decode_bridge_operation_record,
            ),
            (
                release.intent,
                tx.encode_fence_release_intent,
                tx.decode_fence_release_intent,
            ),
            (
                release.receipt,
                tx.encode_fence_release_receipt,
                tx.decode_fence_release_receipt,
            ),
            (
                no_effect_release_receipt,
                tx.encode_fence_release_no_effect_receipt,
                tx.decode_fence_release_no_effect_receipt,
            ),
            (
                release,
                tx.encode_fence_release_record,
                tx.decode_fence_release_record,
            ),
            (
                no_effect_release,
                tx.encode_fence_release_record,
                tx.decode_fence_release_record,
            ),
            (
                blocked_release,
                tx.encode_fence_release_record,
                tx.decode_fence_release_record,
            ),
            (
                attempt,
                tx.encode_bridge_operation_attempt,
                tx.decode_bridge_operation_attempt,
            ),
        )

    def test_every_persisted_dataclass_round_trips_canonically(self) -> None:
        for expected, encoder, decoder in self.codec_cases():
            with self.subTest(dataclass=type(expected).__name__):
                encoded = encoder(expected)
                json.dumps(encoded, allow_nan=False, sort_keys=True)
                self.assertEqual(decoder(deepcopy(encoded)), expected)
                self.assertEqual(encoder(decoder(deepcopy(encoded))), encoded)

    def test_every_decoder_rejects_unknown_fields(self) -> None:
        for expected, encoder, decoder in self.codec_cases():
            with self.subTest(dataclass=type(expected).__name__):
                encoded = encoder(expected)
                encoded["unexpected"] = "blocked"
                with self.assertRaises(tx.BridgeTransactionCodecError):
                    decoder(encoded)

    def test_receipt_integrity_covers_timing_evidence_and_fence_fields(self) -> None:
        operation = committed_attempt().operations[0]
        encoded = tx.encode_bridge_operation_receipt(operation.receipt)
        mutations = {
            "receipt_id": "tf-receipt-ffffffffffffffffffffffff",
            "fence_epoch": encoded["fence_epoch"] + 1,
            "fence_acquisition_receipt_digest": digest("tampered-acquisition"),
            "authorization_digest": digest("tampered-authorization"),
            "authorization_observed_at": "2026-07-29T12:00:03Z",
            "authorized_at": "2026-07-29T12:00:05Z",
            "previous_revision": {"type": "string", "value": "1"},
            "result_revision": {"type": "integer", "value": 3},
            "outcome": tx.BridgeReceiptOutcome.NO_EFFECT.value,
            "evidence": tx.BridgeReceiptEvidence.OPERATION_LEDGER.value,
            "effect_at": None,
            "acknowledged_at": "2026-07-29T12:01:10Z",
            "durable_at": "2026-07-29T12:01:11Z",
            "durable": False,
            "receipt_digest": digest("forged-receipt"),
        }
        for field_name, changed in mutations.items():
            with self.subTest(field=field_name):
                tampered = deepcopy(encoded)
                tampered[field_name] = changed
                with self.assertRaises(tx.BridgeTransactionCodecError):
                    tx.decode_bridge_operation_receipt(tampered)

    def test_standalone_receipts_reject_impossible_timestamp_order(self) -> None:
        attempt = committed_attempt()
        acquisition = deepcopy(
            tx.encode_fence_acquisition_receipt(
                attempt.acquisitions[0].receipt
            )
        )
        acquisition["durable_at"] = "2026-07-29T12:00:01Z"
        with self.assertRaises(tx.BridgeTransactionCodecError):
            tx.decode_fence_acquisition_receipt(acquisition)

        release = deepcopy(
            tx.encode_fence_release_receipt(attempt.releases[0].receipt)
        )
        release["durable_at"] = "2026-07-29T12:00:10Z"
        with self.assertRaises(tx.BridgeTransactionCodecError):
            tx.decode_fence_release_receipt(release)

    def test_codecs_reject_bool_negative_revision_and_noncanonical_time(self) -> None:
        expected = tx.encode_bridge_expected_write(spec())
        for malformed in (
            {"type": "integer", "value": True},
            {"type": "integer", "value": -1},
            {"type": "string", "value": "rev 1"},
            {"type": "string", "value": "x" * 257},
        ):
            with self.subTest(revision=malformed):
                changed = deepcopy(expected)
                changed["expected_revision"] = malformed
                with self.assertRaises(tx.BridgeTransactionCodecError):
                    tx.decode_bridge_expected_write(changed)

        encoded = tx.encode_fence_acquisition_intent(acquisition_intent())
        encoded["requested_at"] = "2026-07-29T12:00:00+00:00"
        with self.assertRaises(tx.BridgeTransactionCodecError):
            tx.decode_fence_acquisition_intent(encoded)

        attempt = tx.encode_bridge_operation_attempt(committed_attempt())
        attempt["operations"] = tuple(attempt["operations"])
        with self.assertRaises(tx.BridgeTransactionCodecError):
            tx.decode_bridge_operation_attempt(attempt)

    def test_expected_write_coverage_digest_is_canonical_but_not_plan_attestation(
        self,
    ) -> None:
        attempt = committed_attempt()
        expected_digest = tx.bridge_expected_write_coverage_digest(
            attempt.expected_writes
        )
        self.assertEqual(attempt.expected_write_coverage_digest, expected_digest)
        self.assertNotEqual(expected_digest, attempt.plan_digest)
        encoded = tx.encode_bridge_operation_attempt(attempt)
        self.assertEqual(encoded["expected_write_coverage_digest"], expected_digest)
        self.assertEqual(
            tx.decode_bridge_operation_attempt(deepcopy(encoded)),
            attempt,
        )

        changed_expected = (
            replace(
                attempt.expected_writes[0],
                post_fingerprint=digest("different-postimage"),
            ),
        )
        self.assertNotEqual(
            tx.bridge_expected_write_coverage_digest(changed_expected),
            expected_digest,
        )
        tampered = deepcopy(encoded)
        tampered["expected_write_coverage_digest"] = digest("forged-coverage")
        with self.assertRaises(tx.BridgeTransactionCodecError):
            tx.decode_bridge_operation_attempt(tampered)

    def test_fence_token_digest_is_domain_branded_and_never_persists_raw_secret(
        self,
    ) -> None:
        raw_secret = "ab" * 32
        branded = tx.derive_fence_token_digest(raw_secret)
        self.assertTrue(str(branded).startswith("tf-fence-token-sha256-v1:"))
        self.assertNotIn(raw_secret, repr(branded))
        with self.assertRaises(TypeError):
            tx.FenceTokenDigest(raw_secret)

        intent = acquisition_intent()
        with self.assertRaises(ValueError):
            tx.FenceAcquisitionReceipt.create(
                intent,
                acquired_inventory_revision="inventory-1",
                fence_revision="fence-1",
                token_digest=raw_secret,
                acquired_at=NOW + timedelta(seconds=1),
                acknowledged_at=NOW + timedelta(seconds=2),
                durable_at=NOW + timedelta(seconds=3),
            )
        receipt = tx.FenceAcquisitionReceipt.create(
            intent,
            acquired_inventory_revision="inventory-1",
            fence_revision="fence-1",
            token_digest=branded,
            acquired_at=NOW + timedelta(seconds=1),
            acknowledged_at=NOW + timedelta(seconds=2),
            durable_at=NOW + timedelta(seconds=3),
        )
        encoded = tx.encode_fence_acquisition_receipt(receipt)
        acquisition = tx.FenceAcquisitionRecord.recorded(intent).arm().acknowledge(
            receipt
        )
        expected = spec()
        operation = object_intent(expected, acquisition)
        operation_receipt = applied_receipt(operation)
        write = verified_record(operation, operation_receipt)
        release = release_record(
            acquisition,
            requested_at=NOW + timedelta(seconds=10),
        )
        attempt = tx.BridgeOperationAttempt(
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
            attempt=1,
            state=tx.BridgeAttemptState.COMMITTED,
            max_observation_age_seconds=10,
            expected_writes=(expected,),
            acquisitions=(acquisition,),
            operations=(write,),
            releases=(release,),
            release_phase_sequence=1,
            terminal_at=NOW + timedelta(seconds=14),
        )
        for persisted in (
            receipt,
            receipt.binding,
            acquisition,
            operation,
            operation_receipt,
            write,
            release.intent,
            release.receipt,
            release,
            attempt,
        ):
            self.assertNotIn(raw_secret, repr(persisted))
        self.assertNotIn(raw_secret, json.dumps(encoded, sort_keys=True))
        self.assertNotIn(
            raw_secret,
            json.dumps(tx.encode_bridge_operation_attempt(attempt), sort_keys=True),
        )
        malformed = deepcopy(encoded)
        malformed["token_digest"] = raw_secret
        with self.assertRaises(tx.BridgeTransactionCodecError):
            tx.decode_fence_acquisition_receipt(malformed)

    def test_no_sensitive_payload_or_raw_token_is_persisted(self) -> None:
        persisted = (
            tx.BridgeExpectedWrite,
            tx.FenceAcquisitionIntent,
            tx.FenceAcquisitionReceipt,
            tx.FenceAcquisitionNoEffectReceipt,
            tx.FenceAcquisitionRecord,
            tx.FenceBinding,
            tx.FenceReleaseIntent,
            tx.FenceReleaseReceipt,
            tx.FenceReleaseNoEffectReceipt,
            tx.FenceReleaseRecord,
            tx.BridgeOperationIntent,
            tx.BridgeOperationReceipt,
            tx.BridgeObjectObservation,
            tx.BridgeOperationVerification,
            tx.BridgeOperationRecord,
            tx.BridgeOperationAttempt,
        )
        forbidden = {"payload", "exception", "error_text", "reason_text", "token"}
        for dataclass_type in persisted:
            self.assertTrue(
                forbidden.isdisjoint(item.name for item in fields(dataclass_type))
            )
        for expected, encoder, _decoder in self.codec_cases():
            rendered = json.dumps(encoder(expected), sort_keys=True)
            self.assertNotIn('"payload"', rendered)
            self.assertNotIn('"token"', rendered)


if __name__ == "__main__":
    unittest.main()
