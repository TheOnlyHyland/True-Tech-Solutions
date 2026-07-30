"""Pure fail-closed transaction records for reference-provider bridges."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import json
import re
from typing import Any, Protocol

from .reference_migration import Revision, TRUE_FAMILY_PROVIDER_MANIFEST


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FENCE_TOKEN_DIGEST_PATTERN = re.compile(
    r"^tf-fence-token-sha256-v1:[0-9a-f]{64}$"
)
_OBJECT_OPERATION_ID_PATTERN = re.compile(r"^tf-bridge-[0-9a-f]{24}$")
_ACQUIRE_OPERATION_ID_PATTERN = re.compile(r"^tf-fence-acquire-[0-9a-f]{24}$")
_RELEASE_OPERATION_ID_PATTERN = re.compile(r"^tf-fence-release-[0-9a-f]{24}$")
_RECEIPT_ID_PATTERN = re.compile(r"^tf-receipt-[0-9a-f]{24}$")
_MAX_REVISION_LENGTH = 256
_MAX_FRESHNESS_SECONDS = 86_400
_FENCE_TOKEN_DIGEST_DOMAIN = b"true-family/reference-bridge/fence-token/v1\0"
_FENCE_TOKEN_DIGEST_BRAND = object()


class BridgeOperationKind(StrEnum):
    """Kind of one conditional provider mutation."""

    WRITE = "write"
    ROLLBACK = "rollback"


class BridgeOperationState(StrEnum):
    """Durable state of one object operation."""

    INTENT_RECORDED = "intent_recorded"
    DISPATCH_ARMED = "dispatch_armed"
    ACKNOWLEDGED = "acknowledged"
    VERIFIED = "verified"
    BLOCKED = "blocked"


class FenceLifecycleState(StrEnum):
    """Durable state of a fence acquisition or release."""

    INTENT_RECORDED = "intent_recorded"
    DISPATCH_ARMED = "dispatch_armed"
    ACKNOWLEDGED = "acknowledged"
    NO_EFFECT = "no_effect"
    BLOCKED = "blocked"


class BridgeAttemptState(StrEnum):
    """State of one complete write and compensation attempt."""

    OPEN = "open"
    COMMITTED = "committed"
    RESTORED = "restored"
    BLOCKED = "blocked"


class BridgeReceiptOutcome(StrEnum):
    """Durable outcome reported by an authoritative operation ledger."""

    APPLIED = "applied"
    NO_EFFECT = "no_effect"


class BridgeReceiptEvidence(StrEnum):
    """Authority that established an object-operation outcome."""

    DISPATCH_ACK = "dispatch_ack"
    OPERATION_LEDGER = "operation_ledger"


class BridgeReconciliationAction(StrEnum):
    """Only actions a caller may take while reconciling durable state."""

    DISPATCH = "dispatch"
    QUERY_RECEIPT = "query_receipt"
    VERIFY_RECEIPT = "verify_receipt"
    REFRESH_OBSERVATION = "refresh_observation"
    COMPLETE = "complete"
    BLOCK = "block"


class BridgeBlockReason(StrEnum):
    """Fixed non-sensitive reasons that may be persisted."""

    STALE_FENCE = "stale_fence"
    EXPIRED_FENCE = "expired_fence"
    STALE_OBSERVATION = "stale_observation"
    OBSERVATION_MISMATCH = "observation_mismatch"
    RECEIPT_MISMATCH = "receipt_mismatch"
    VERIFIED_DRIFT = "verified_drift"
    LIFECYCLE_MISMATCH = "lifecycle_mismatch"
    INCOMPLETE_COVERAGE = "incomplete_coverage"
    EXPLICIT_ABORT = "explicit_abort"


class BridgeTransactionError(RuntimeError):
    """Base error for a blocked bridge transaction."""


class BridgeJournalConflict(BridgeTransactionError):
    """Raised when append-only data conflicts with durable data."""


class BridgeOperationTransitionError(BridgeTransactionError):
    """Raised for a transition outside an exact state matrix."""


class BridgeTransactionBlocked(BridgeTransactionError):
    """Raised when a fixed fail-closed condition blocks progress."""

    def __init__(self, reason_code: BridgeBlockReason) -> None:
        if not isinstance(reason_code, BridgeBlockReason):
            raise TypeError("A fixed bridge block reason is required.")
        self.reason_code = reason_code
        super().__init__(f"Bridge transaction blocked: {reason_code.value}.")


class BridgeTransactionCodecError(ValueError):
    """Raised when persisted bridge metadata is not exact and canonical."""


@dataclass(frozen=True, slots=True)
class FenceTokenDigest:
    """Runtime-branded, domain-separated digest of a raw fence capability."""

    value: str
    _brand: InitVar[object] = None

    def __post_init__(self, _brand: object) -> None:
        if _brand is not _FENCE_TOKEN_DIGEST_BRAND:
            raise TypeError("Use derive_fence_token_digest() for raw capabilities.")
        if not _FENCE_TOKEN_DIGEST_PATTERN.fullmatch(self.value):
            raise ValueError("Fence token digest is not canonically branded.")

    def __str__(self) -> str:
        return self.value


def _restore_fence_token_digest(value: str) -> FenceTokenDigest:
    return FenceTokenDigest(value, _brand=_FENCE_TOKEN_DIGEST_BRAND)


def derive_fence_token_digest(raw_capability: str) -> FenceTokenDigest:
    """Hash a raw capability with the fixed fence-token domain separator."""

    if type(raw_capability) is not str or not raw_capability:
        raise ValueError("Raw fence capability must be non-empty text.")
    encoded = raw_capability.encode("utf-8")
    digest = hashlib.sha256(
        _FENCE_TOKEN_DIGEST_DOMAIN
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()
    return _restore_fence_token_digest(f"tf-fence-token-sha256-v1:{digest}")


@dataclass(frozen=True, slots=True)
class BridgeExpectedWrite:
    """One exact object mutation required by a transaction attempt."""

    provider: str
    object_key: str
    expected_revision: Revision
    pre_fingerprint: str
    post_fingerprint: str

    def __post_init__(self) -> None:
        _validate_provider(self.provider, "Expected write provider")
        _validate_string(self.object_key, "Expected write object key")
        _validate_revision(self.expected_revision, "Expected write revision")
        _validate_digest(self.pre_fingerprint, "Expected write preimage")
        _validate_digest(self.post_fingerprint, "Expected write postimage")
        if self.pre_fingerprint == self.post_fingerprint:
            raise ValueError("Expected write preimage and postimage must differ.")

    @property
    def key(self) -> tuple[str, str]:
        """Return the unique manifest key for this expected write."""

        return self.provider, self.object_key


@dataclass(frozen=True, slots=True)
class FenceAcquisitionIntent:
    """Deterministic journal-before-host-acquisition fence intent."""

    operation_id: str
    intent_digest: str
    plan_id: str
    plan_digest: str
    manifest_digest: str
    attempt: int
    provider: str
    writer_id: str
    expected_inventory_revision: Revision
    scope_digest: str
    epoch: int
    requested_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_acquire_operation_id(self.operation_id, "Acquisition operation ID")
        _validate_digest(self.intent_digest, "Acquisition intent digest")
        _validate_plan_binding(self.plan_id, self.plan_digest)
        _validate_digest(self.manifest_digest, "Acquisition manifest digest")
        _validate_positive_integer(self.attempt, "Acquisition attempt")
        _validate_provider(self.provider, "Acquisition provider")
        _validate_string(self.writer_id, "Acquisition writer ID")
        _validate_revision(
            self.expected_inventory_revision,
            "Acquisition expected inventory revision",
        )
        _validate_digest(self.scope_digest, "Acquisition scope digest")
        _validate_nonnegative_integer(self.epoch, "Acquisition epoch")
        _validate_utc(self.requested_at, "Acquisition request time")
        _validate_utc(self.expires_at, "Acquisition expiry")
        if self.expires_at <= self.requested_at:
            raise ValueError("Acquisition expiry must follow its request.")
        digest = _digest_json(_acquisition_intent_data(self))
        if self.intent_digest != digest:
            raise ValueError("Acquisition intent digest is not canonical.")
        if self.operation_id != f"tf-fence-acquire-{digest[:24]}":
            raise ValueError("Acquisition operation ID is not canonical.")

    @classmethod
    def create(
        cls,
        *,
        plan_id: str,
        plan_digest: str,
        manifest_digest: str,
        attempt: int,
        provider: str,
        writer_id: str,
        expected_inventory_revision: Revision,
        scope_digest: str,
        epoch: int,
        requested_at: datetime,
        expires_at: datetime,
    ) -> FenceAcquisitionIntent:
        """Build a deterministic host-ledger acquisition identity."""

        values = {
            "plan_id": plan_id,
            "plan_digest": plan_digest,
            "manifest_digest": manifest_digest,
            "attempt": attempt,
            "provider": provider,
            "writer_id": writer_id,
            "expected_inventory_revision": expected_inventory_revision,
            "scope_digest": scope_digest,
            "epoch": epoch,
            "requested_at": requested_at,
            "expires_at": expires_at,
        }
        digest = _digest_json(_acquisition_intent_data_from_fields(**values))
        return cls(
            operation_id=f"tf-fence-acquire-{digest[:24]}",
            intent_digest=digest,
            **values,
        )


@dataclass(frozen=True, slots=True)
class FenceBinding:
    """Acquired writer lease bound to its durable acquisition receipt."""

    provider: str
    writer_id: str
    token_digest: FenceTokenDigest
    epoch: int
    fence_revision: Revision
    base_revision: Revision
    scope_digest: str
    acquired_at: datetime
    acquisition_durable_at: datetime
    expires_at: datetime
    acquisition_operation_id: str
    acquisition_receipt_id: str
    acquisition_receipt_digest: str

    def __post_init__(self) -> None:
        _validate_provider(self.provider, "Fence provider")
        _validate_string(self.writer_id, "Fence writer ID")
        _validate_fence_token_digest(self.token_digest, "Fence token digest")
        _validate_nonnegative_integer(self.epoch, "Fence epoch")
        _validate_revision(self.fence_revision, "Fence revision")
        _validate_revision(self.base_revision, "Fence base revision")
        _validate_digest(self.scope_digest, "Fence scope digest")
        _validate_utc(self.acquired_at, "Fence acquisition")
        _validate_utc(self.acquisition_durable_at, "Fence acquisition durability")
        _validate_utc(self.expires_at, "Fence expiry")
        if not self.acquired_at <= self.acquisition_durable_at:
            raise ValueError("Fence durability cannot predate acquisition.")
        if self.expires_at <= self.acquired_at:
            raise ValueError("Fence expiry must follow acquisition.")
        _validate_acquire_operation_id(
            self.acquisition_operation_id,
            "Fence acquisition operation ID",
        )
        _validate_receipt_id(self.acquisition_receipt_id, "Fence receipt ID")
        _validate_digest(
            self.acquisition_receipt_digest,
            "Fence acquisition receipt digest",
        )


@dataclass(frozen=True, slots=True)
class FenceAcquisitionReceipt:
    """Durable host acknowledgement of one exact fence acquisition."""

    operation_id: str
    intent_digest: str
    receipt_id: str
    provider: str
    writer_id: str
    expected_inventory_revision: Revision
    acquired_inventory_revision: Revision
    fence_revision: Revision
    scope_digest: str
    epoch: int
    token_digest: FenceTokenDigest
    acquired_at: datetime
    expires_at: datetime
    acknowledged_at: datetime
    durable_at: datetime
    receipt_digest: str

    def __post_init__(self) -> None:
        _validate_acquire_operation_id(self.operation_id, "Acquisition receipt operation")
        _validate_digest(self.intent_digest, "Acquisition receipt intent digest")
        _validate_receipt_id(self.receipt_id, "Acquisition receipt ID")
        _validate_provider(self.provider, "Acquisition receipt provider")
        _validate_string(self.writer_id, "Acquisition receipt writer")
        _validate_revision(
            self.expected_inventory_revision,
            "Acquisition receipt expected inventory revision",
        )
        _validate_revision(
            self.acquired_inventory_revision,
            "Acquisition receipt acquired inventory revision",
        )
        _validate_revision(self.fence_revision, "Acquisition fence revision")
        _validate_digest(self.scope_digest, "Acquisition receipt scope")
        _validate_nonnegative_integer(self.epoch, "Acquisition receipt epoch")
        _validate_fence_token_digest(self.token_digest, "Acquisition token digest")
        for value, label in (
            (self.acquired_at, "Acquisition effect time"),
            (self.expires_at, "Acquisition receipt expiry"),
            (self.acknowledged_at, "Acquisition acknowledgement"),
            (self.durable_at, "Acquisition durability time"),
        ):
            _validate_utc(value, label)
        _validate_digest(self.receipt_digest, "Acquisition receipt digest")
        if not _same_revision(
            self.expected_inventory_revision,
            self.acquired_inventory_revision,
        ):
            raise ValueError("Fence acquisition changed the inventory revision.")
        if not (
            self.acquired_at
            <= self.acknowledged_at
            < self.expires_at
            and self.durable_at >= self.acknowledged_at
        ):
            raise ValueError("Acquisition receipt timestamps are inconsistent.")
        expected_id, expected_digest = _receipt_identity(
            "fence-acquisition",
            _acquisition_receipt_data(self, include_receipt_id=False),
        )
        if self.receipt_id != expected_id or self.receipt_digest != expected_digest:
            raise ValueError("Acquisition receipt identity is not canonical.")

    @property
    def binding(self) -> FenceBinding:
        """Return the exact object-operation fence established by this receipt."""

        return FenceBinding(
            provider=self.provider,
            writer_id=self.writer_id,
            token_digest=self.token_digest,
            epoch=self.epoch,
            fence_revision=self.fence_revision,
            base_revision=self.acquired_inventory_revision,
            scope_digest=self.scope_digest,
            acquired_at=self.acquired_at,
            acquisition_durable_at=self.durable_at,
            expires_at=self.expires_at,
            acquisition_operation_id=self.operation_id,
            acquisition_receipt_id=self.receipt_id,
            acquisition_receipt_digest=self.receipt_digest,
        )

    @property
    def outcome(self) -> BridgeReceiptOutcome:
        return BridgeReceiptOutcome.APPLIED

    def validate_for(self, intent: FenceAcquisitionIntent) -> None:
        """Require exact intent fields and valid in-lease acquisition evidence."""

        _validate_acquisition_receipt_binding(self, intent)

    @classmethod
    def create(
        cls,
        intent: FenceAcquisitionIntent,
        *,
        acquired_inventory_revision: Revision,
        fence_revision: Revision,
        token_digest: FenceTokenDigest,
        acquired_at: datetime,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceAcquisitionReceipt:
        """Build a deterministic durable acquisition receipt."""

        _require_acquisition_intent(intent)
        _validate_fence_token_digest(token_digest, "Acquisition token digest")
        values = {
            "operation_id": intent.operation_id,
            "intent_digest": intent.intent_digest,
            "provider": intent.provider,
            "writer_id": intent.writer_id,
            "expected_inventory_revision": intent.expected_inventory_revision,
            "acquired_inventory_revision": acquired_inventory_revision,
            "fence_revision": fence_revision,
            "scope_digest": intent.scope_digest,
            "epoch": intent.epoch,
            "token_digest": token_digest,
            "acquired_at": acquired_at,
            "expires_at": intent.expires_at,
            "acknowledged_at": acknowledged_at,
            "durable_at": durable_at,
        }
        receipt_id, receipt_digest = _receipt_identity(
            "fence-acquisition",
            _acquisition_receipt_data_from_fields(**values),
        )
        receipt = cls(
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            **values,
        )
        receipt.validate_for(intent)
        return receipt


@dataclass(frozen=True, slots=True)
class FenceAcquisitionNoEffectReceipt:
    """Authoritative durable tombstone for an unreceived acquisition dispatch."""

    operation_id: str
    intent_digest: str
    receipt_id: str
    provider: str
    writer_id: str
    expected_inventory_revision: Revision
    scope_digest: str
    epoch: int
    outcome: BridgeReceiptOutcome
    evidence: BridgeReceiptEvidence
    acknowledged_at: datetime
    durable_at: datetime
    durable: bool
    receipt_digest: str

    def __post_init__(self) -> None:
        _validate_acquire_operation_id(
            self.operation_id,
            "Acquisition tombstone operation",
        )
        _validate_digest(self.intent_digest, "Acquisition tombstone intent digest")
        _validate_receipt_id(self.receipt_id, "Acquisition tombstone receipt ID")
        _validate_provider(self.provider, "Acquisition tombstone provider")
        _validate_string(self.writer_id, "Acquisition tombstone writer")
        _validate_revision(
            self.expected_inventory_revision,
            "Acquisition tombstone expected inventory revision",
        )
        _validate_digest(self.scope_digest, "Acquisition tombstone scope")
        _validate_nonnegative_integer(self.epoch, "Acquisition tombstone epoch")
        if self.outcome is not BridgeReceiptOutcome.NO_EFFECT:
            raise ValueError("Acquisition tombstone outcome must be no-effect.")
        if self.evidence is not BridgeReceiptEvidence.OPERATION_LEDGER:
            raise ValueError("Acquisition tombstone requires operation-ledger evidence.")
        _validate_utc(self.acknowledged_at, "Acquisition tombstone acknowledgement")
        _validate_utc(self.durable_at, "Acquisition tombstone durability")
        if type(self.durable) is not bool or not self.durable:
            raise ValueError("Acquisition tombstone must be durably persisted.")
        if self.durable_at < self.acknowledged_at:
            raise ValueError("Acquisition tombstone durability predates acknowledgement.")
        _validate_digest(self.receipt_digest, "Acquisition tombstone digest")
        expected_id, expected_digest = _receipt_identity(
            "fence-acquisition-no-effect",
            _acquisition_no_effect_data(self, include_receipt_id=False),
        )
        if self.receipt_id != expected_id or self.receipt_digest != expected_digest:
            raise ValueError("Acquisition tombstone identity is not canonical.")

    def validate_for(self, intent: FenceAcquisitionIntent) -> None:
        _validate_acquisition_no_effect_binding(self, intent)

    @classmethod
    def create(
        cls,
        intent: FenceAcquisitionIntent,
        *,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceAcquisitionNoEffectReceipt:
        """Build a deterministic authoritative no-effect acquisition receipt."""

        _require_acquisition_intent(intent)
        values = {
            "operation_id": intent.operation_id,
            "intent_digest": intent.intent_digest,
            "provider": intent.provider,
            "writer_id": intent.writer_id,
            "expected_inventory_revision": intent.expected_inventory_revision,
            "scope_digest": intent.scope_digest,
            "epoch": intent.epoch,
            "outcome": BridgeReceiptOutcome.NO_EFFECT,
            "evidence": BridgeReceiptEvidence.OPERATION_LEDGER,
            "acknowledged_at": acknowledged_at,
            "durable_at": durable_at,
            "durable": True,
        }
        receipt_id, receipt_digest = _receipt_identity(
            "fence-acquisition-no-effect",
            _acquisition_no_effect_data_from_fields(**values),
        )
        receipt = cls(
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            **values,
        )
        receipt.validate_for(intent)
        return receipt


@dataclass(frozen=True, slots=True)
class FenceAcquisitionRecord:
    """Current durable projection of one acquisition operation."""

    intent: FenceAcquisitionIntent
    state: FenceLifecycleState
    receipt: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt | None = None
    reason_code: BridgeBlockReason | None = None
    blocked_from: FenceLifecycleState | None = None

    def __post_init__(self) -> None:
        _validate_acquisition_record(self)

    @classmethod
    def recorded(cls, intent: FenceAcquisitionIntent) -> FenceAcquisitionRecord:
        return cls(intent, FenceLifecycleState.INTENT_RECORDED)

    def arm(self) -> FenceAcquisitionRecord:
        if self.state is not FenceLifecycleState.INTENT_RECORDED:
            raise BridgeOperationTransitionError("Acquisition cannot be armed.")
        return replace(self, state=FenceLifecycleState.DISPATCH_ARMED)

    def acknowledge(
        self,
        receipt: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt,
    ) -> FenceAcquisitionRecord:
        if self.state is not FenceLifecycleState.DISPATCH_ARMED:
            raise BridgeOperationTransitionError("Acquisition cannot be acknowledged.")
        if isinstance(receipt, FenceAcquisitionReceipt):
            state = FenceLifecycleState.ACKNOWLEDGED
        elif isinstance(receipt, FenceAcquisitionNoEffectReceipt):
            state = FenceLifecycleState.NO_EFFECT
        else:
            raise TypeError("A typed acquisition lifecycle receipt is required.")
        return replace(
            self,
            state=state,
            receipt=receipt,
        )

    def block(self, reason_code: BridgeBlockReason) -> FenceAcquisitionRecord:
        if self.state not in {
            FenceLifecycleState.INTENT_RECORDED,
            FenceLifecycleState.DISPATCH_ARMED,
        }:
            raise BridgeOperationTransitionError("Acquisition cannot be blocked.")
        return replace(
            self,
            state=FenceLifecycleState.BLOCKED,
            reason_code=reason_code,
            blocked_from=self.state,
        )


@dataclass(frozen=True, slots=True)
class FenceReleaseIntent:
    """Deterministic journal-before-host-release fence intent."""

    operation_id: str
    intent_digest: str
    plan_id: str
    plan_digest: str
    manifest_digest: str
    attempt: int
    release_attempt: int
    provider: str
    writer_id: str
    acquisition_operation_id: str
    acquisition_receipt_id: str
    acquisition_receipt_digest: str
    token_digest: FenceTokenDigest
    scope_digest: str
    epoch: int
    expected_inventory_revision: Revision
    requested_at: datetime

    def __post_init__(self) -> None:
        _validate_release_operation_id(self.operation_id, "Release operation ID")
        _validate_digest(self.intent_digest, "Release intent digest")
        _validate_plan_binding(self.plan_id, self.plan_digest)
        _validate_digest(self.manifest_digest, "Release manifest digest")
        _validate_positive_integer(self.attempt, "Release attempt")
        _validate_positive_integer(self.release_attempt, "Release dispatch attempt")
        _validate_provider(self.provider, "Release provider")
        _validate_string(self.writer_id, "Release writer ID")
        _validate_acquire_operation_id(
            self.acquisition_operation_id,
            "Release acquisition operation ID",
        )
        _validate_receipt_id(
            self.acquisition_receipt_id,
            "Release acquisition receipt ID",
        )
        _validate_digest(
            self.acquisition_receipt_digest,
            "Release acquisition receipt digest",
        )
        _validate_fence_token_digest(self.token_digest, "Release token digest")
        _validate_digest(self.scope_digest, "Release scope digest")
        _validate_nonnegative_integer(self.epoch, "Release epoch")
        _validate_revision(
            self.expected_inventory_revision,
            "Release expected inventory revision",
        )
        _validate_utc(self.requested_at, "Release request time")
        digest = _digest_json(_release_intent_data(self))
        if self.intent_digest != digest:
            raise ValueError("Release intent digest is not canonical.")
        if self.operation_id != f"tf-fence-release-{digest[:24]}":
            raise ValueError("Release operation ID is not canonical.")

    @classmethod
    def create(
        cls,
        acquisition: FenceAcquisitionRecord,
        *,
        expected_inventory_revision: Revision,
        requested_at: datetime,
        release_attempt: int = 1,
    ) -> FenceReleaseIntent:
        """Build a deterministic release bound to an acquired fence receipt."""

        _require_acquisition_record(acquisition)
        if (
            acquisition.state is not FenceLifecycleState.ACKNOWLEDGED
            or not isinstance(acquisition.receipt, FenceAcquisitionReceipt)
        ):
            raise ValueError("Release requires an acknowledged acquisition.")
        source = acquisition.intent
        receipt = acquisition.receipt
        _validate_utc(requested_at, "Release request time")
        if requested_at < receipt.durable_at:
            raise ValueError("Release request cannot predate acquisition durability.")
        values = {
            "plan_id": source.plan_id,
            "plan_digest": source.plan_digest,
            "manifest_digest": source.manifest_digest,
            "attempt": source.attempt,
            "release_attempt": release_attempt,
            "provider": receipt.provider,
            "writer_id": receipt.writer_id,
            "acquisition_operation_id": receipt.operation_id,
            "acquisition_receipt_id": receipt.receipt_id,
            "acquisition_receipt_digest": receipt.receipt_digest,
            "token_digest": receipt.token_digest,
            "scope_digest": receipt.scope_digest,
            "epoch": receipt.epoch,
            "expected_inventory_revision": expected_inventory_revision,
            "requested_at": requested_at,
        }
        digest = _digest_json(_release_intent_data_from_fields(**values))
        return cls(
            operation_id=f"tf-fence-release-{digest[:24]}",
            intent_digest=digest,
            **values,
        )


@dataclass(frozen=True, slots=True)
class FenceReleaseReceipt:
    """Durable host acknowledgement that one exact fence was released."""

    operation_id: str
    intent_digest: str
    receipt_id: str
    release_attempt: int
    provider: str
    writer_id: str
    acquisition_operation_id: str
    acquisition_receipt_id: str
    acquisition_receipt_digest: str
    token_digest: FenceTokenDigest
    scope_digest: str
    epoch: int
    expected_inventory_revision: Revision
    final_inventory_revision: Revision
    released_at: datetime
    acknowledged_at: datetime
    durable_at: datetime
    receipt_digest: str

    def __post_init__(self) -> None:
        _validate_release_operation_id(self.operation_id, "Release receipt operation")
        _validate_digest(self.intent_digest, "Release receipt intent digest")
        _validate_receipt_id(self.receipt_id, "Release receipt ID")
        _validate_positive_integer(
            self.release_attempt,
            "Release receipt dispatch attempt",
        )
        _validate_provider(self.provider, "Release receipt provider")
        _validate_string(self.writer_id, "Release receipt writer")
        _validate_acquire_operation_id(
            self.acquisition_operation_id,
            "Release receipt acquisition operation",
        )
        _validate_receipt_id(
            self.acquisition_receipt_id,
            "Release receipt acquisition receipt",
        )
        _validate_digest(
            self.acquisition_receipt_digest,
            "Release receipt acquisition digest",
        )
        _validate_fence_token_digest(
            self.token_digest,
            "Release receipt token digest",
        )
        _validate_digest(self.scope_digest, "Release receipt scope")
        _validate_nonnegative_integer(self.epoch, "Release receipt epoch")
        _validate_revision(
            self.expected_inventory_revision,
            "Release receipt expected revision",
        )
        _validate_revision(
            self.final_inventory_revision,
            "Release receipt final revision",
        )
        for value, label in (
            (self.released_at, "Release effect time"),
            (self.acknowledged_at, "Release acknowledgement"),
            (self.durable_at, "Release durability time"),
        ):
            _validate_utc(value, label)
        _validate_digest(self.receipt_digest, "Release receipt digest")
        if not _same_revision(
            self.expected_inventory_revision,
            self.final_inventory_revision,
        ):
            raise ValueError("Fence release changed the inventory revision.")
        if not (
            self.released_at <= self.acknowledged_at <= self.durable_at
        ):
            raise ValueError("Release receipt timestamps are inconsistent.")
        expected_id, expected_digest = _receipt_identity(
            "fence-release",
            _release_receipt_data(self, include_receipt_id=False),
        )
        if self.receipt_id != expected_id or self.receipt_digest != expected_digest:
            raise ValueError("Release receipt identity is not canonical.")

    def validate_for(self, intent: FenceReleaseIntent) -> None:
        """Require exact release-intent and durable timing binding."""

        _validate_release_receipt_binding(self, intent)

    @property
    def outcome(self) -> BridgeReceiptOutcome:
        return BridgeReceiptOutcome.APPLIED

    @classmethod
    def create(
        cls,
        intent: FenceReleaseIntent,
        *,
        final_inventory_revision: Revision,
        released_at: datetime,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceReleaseReceipt:
        """Build a deterministic durable release receipt."""

        _require_release_intent(intent)
        values = {
            "operation_id": intent.operation_id,
            "intent_digest": intent.intent_digest,
            "release_attempt": intent.release_attempt,
            "provider": intent.provider,
            "writer_id": intent.writer_id,
            "acquisition_operation_id": intent.acquisition_operation_id,
            "acquisition_receipt_id": intent.acquisition_receipt_id,
            "acquisition_receipt_digest": intent.acquisition_receipt_digest,
            "token_digest": intent.token_digest,
            "scope_digest": intent.scope_digest,
            "epoch": intent.epoch,
            "expected_inventory_revision": intent.expected_inventory_revision,
            "final_inventory_revision": final_inventory_revision,
            "released_at": released_at,
            "acknowledged_at": acknowledged_at,
            "durable_at": durable_at,
        }
        receipt_id, receipt_digest = _receipt_identity(
            "fence-release",
            _release_receipt_data_from_fields(**values),
        )
        receipt = cls(
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            **values,
        )
        receipt.validate_for(intent)
        return receipt


@dataclass(frozen=True, slots=True)
class FenceReleaseNoEffectReceipt:
    """Authoritative durable tombstone for an unreceived release dispatch."""

    operation_id: str
    intent_digest: str
    receipt_id: str
    release_attempt: int
    provider: str
    writer_id: str
    acquisition_operation_id: str
    acquisition_receipt_id: str
    acquisition_receipt_digest: str
    token_digest: FenceTokenDigest
    scope_digest: str
    epoch: int
    expected_inventory_revision: Revision
    outcome: BridgeReceiptOutcome
    evidence: BridgeReceiptEvidence
    acknowledged_at: datetime
    durable_at: datetime
    durable: bool
    receipt_digest: str

    def __post_init__(self) -> None:
        _validate_release_operation_id(self.operation_id, "Release tombstone operation")
        _validate_digest(self.intent_digest, "Release tombstone intent digest")
        _validate_receipt_id(self.receipt_id, "Release tombstone receipt ID")
        _validate_positive_integer(
            self.release_attempt,
            "Release tombstone dispatch attempt",
        )
        _validate_provider(self.provider, "Release tombstone provider")
        _validate_string(self.writer_id, "Release tombstone writer")
        _validate_acquire_operation_id(
            self.acquisition_operation_id,
            "Release tombstone acquisition operation",
        )
        _validate_receipt_id(
            self.acquisition_receipt_id,
            "Release tombstone acquisition receipt",
        )
        _validate_digest(
            self.acquisition_receipt_digest,
            "Release tombstone acquisition digest",
        )
        _validate_fence_token_digest(
            self.token_digest,
            "Release tombstone token digest",
        )
        _validate_digest(self.scope_digest, "Release tombstone scope")
        _validate_nonnegative_integer(self.epoch, "Release tombstone epoch")
        _validate_revision(
            self.expected_inventory_revision,
            "Release tombstone expected inventory revision",
        )
        if self.outcome is not BridgeReceiptOutcome.NO_EFFECT:
            raise ValueError("Release tombstone outcome must be no-effect.")
        if self.evidence is not BridgeReceiptEvidence.OPERATION_LEDGER:
            raise ValueError("Release tombstone requires operation-ledger evidence.")
        _validate_utc(self.acknowledged_at, "Release tombstone acknowledgement")
        _validate_utc(self.durable_at, "Release tombstone durability")
        if type(self.durable) is not bool or not self.durable:
            raise ValueError("Release tombstone must be durably persisted.")
        if self.durable_at < self.acknowledged_at:
            raise ValueError("Release tombstone durability predates acknowledgement.")
        _validate_digest(self.receipt_digest, "Release tombstone digest")
        expected_id, expected_digest = _receipt_identity(
            "fence-release-no-effect",
            _release_no_effect_data(self, include_receipt_id=False),
        )
        if self.receipt_id != expected_id or self.receipt_digest != expected_digest:
            raise ValueError("Release tombstone identity is not canonical.")

    def validate_for(self, intent: FenceReleaseIntent) -> None:
        _validate_release_no_effect_binding(self, intent)

    @classmethod
    def create(
        cls,
        intent: FenceReleaseIntent,
        *,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceReleaseNoEffectReceipt:
        """Build a deterministic authoritative no-effect release receipt."""

        _require_release_intent(intent)
        values = {
            "operation_id": intent.operation_id,
            "intent_digest": intent.intent_digest,
            "release_attempt": intent.release_attempt,
            "provider": intent.provider,
            "writer_id": intent.writer_id,
            "acquisition_operation_id": intent.acquisition_operation_id,
            "acquisition_receipt_id": intent.acquisition_receipt_id,
            "acquisition_receipt_digest": intent.acquisition_receipt_digest,
            "token_digest": intent.token_digest,
            "scope_digest": intent.scope_digest,
            "epoch": intent.epoch,
            "expected_inventory_revision": intent.expected_inventory_revision,
            "outcome": BridgeReceiptOutcome.NO_EFFECT,
            "evidence": BridgeReceiptEvidence.OPERATION_LEDGER,
            "acknowledged_at": acknowledged_at,
            "durable_at": durable_at,
            "durable": True,
        }
        receipt_id, receipt_digest = _receipt_identity(
            "fence-release-no-effect",
            _release_no_effect_data_from_fields(**values),
        )
        receipt = cls(
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            **values,
        )
        receipt.validate_for(intent)
        return receipt


@dataclass(frozen=True, slots=True)
class FenceReleaseRecord:
    """Current durable projection of one release operation."""

    intent: FenceReleaseIntent
    state: FenceLifecycleState
    receipt: FenceReleaseReceipt | FenceReleaseNoEffectReceipt | None = None
    reason_code: BridgeBlockReason | None = None
    blocked_from: FenceLifecycleState | None = None

    def __post_init__(self) -> None:
        _validate_release_record(self)

    @classmethod
    def recorded(cls, intent: FenceReleaseIntent) -> FenceReleaseRecord:
        return cls(intent, FenceLifecycleState.INTENT_RECORDED)

    def arm(self) -> FenceReleaseRecord:
        if self.state is not FenceLifecycleState.INTENT_RECORDED:
            raise BridgeOperationTransitionError("Release cannot be armed.")
        return replace(self, state=FenceLifecycleState.DISPATCH_ARMED)

    def acknowledge(
        self,
        receipt: FenceReleaseReceipt | FenceReleaseNoEffectReceipt,
    ) -> FenceReleaseRecord:
        if self.state is not FenceLifecycleState.DISPATCH_ARMED:
            raise BridgeOperationTransitionError("Release cannot be acknowledged.")
        if isinstance(receipt, FenceReleaseReceipt):
            state = FenceLifecycleState.ACKNOWLEDGED
        elif isinstance(receipt, FenceReleaseNoEffectReceipt):
            state = FenceLifecycleState.NO_EFFECT
        else:
            raise TypeError("A typed release lifecycle receipt is required.")
        return replace(
            self,
            state=state,
            receipt=receipt,
        )

    def block(self, reason_code: BridgeBlockReason) -> FenceReleaseRecord:
        if self.state not in {
            FenceLifecycleState.INTENT_RECORDED,
            FenceLifecycleState.DISPATCH_ARMED,
        }:
            raise BridgeOperationTransitionError("Release cannot be blocked.")
        return replace(
            self,
            state=FenceLifecycleState.BLOCKED,
            reason_code=reason_code,
            blocked_from=self.state,
        )


@dataclass(frozen=True, slots=True)
class BridgeOperationIntent:
    """Canonical journal-before-dispatch intent for one provider object."""

    operation_id: str
    intent_digest: str
    plan_id: str
    plan_digest: str
    manifest_digest: str
    attempt: int
    sequence: int
    kind: BridgeOperationKind
    provider: str
    object_key: str
    expected_revision: Revision
    pre_fingerprint: str
    post_fingerprint: str
    fence: FenceBinding
    parent_operation_id: str | None = None

    def __post_init__(self) -> None:
        _validate_object_operation_id(self.operation_id, "Object operation ID")
        _validate_digest(self.intent_digest, "Object intent digest")
        _validate_object_intent_fields(self)
        digest = _digest_json(_object_intent_data(self))
        if self.intent_digest != digest or self.operation_id != f"tf-bridge-{digest[:24]}":
            raise ValueError("Object operation identity is not canonical.")

    @classmethod
    def create(
        cls,
        *,
        plan_id: str,
        plan_digest: str,
        manifest_digest: str,
        attempt: int,
        sequence: int,
        kind: BridgeOperationKind,
        provider: str,
        object_key: str,
        expected_revision: Revision,
        pre_fingerprint: str,
        post_fingerprint: str,
        fence: FenceBinding,
        parent_operation_id: str | None = None,
    ) -> BridgeOperationIntent:
        """Build the deterministic digest and object operation ID."""

        values = {
            "plan_id": plan_id,
            "plan_digest": plan_digest,
            "manifest_digest": manifest_digest,
            "attempt": attempt,
            "sequence": sequence,
            "kind": kind,
            "provider": provider,
            "object_key": object_key,
            "expected_revision": expected_revision,
            "pre_fingerprint": pre_fingerprint,
            "post_fingerprint": post_fingerprint,
            "fence": fence,
            "parent_operation_id": parent_operation_id,
        }
        digest = _digest_json(_object_intent_data_from_fields(**values))
        return cls(
            operation_id=f"tf-bridge-{digest[:24]}",
            intent_digest=digest,
            **values,
        )


@dataclass(frozen=True, slots=True)
class BridgeOperationReceipt:
    """Durable operation-ledger outcome bound to one object intent."""

    operation_id: str
    intent_digest: str
    receipt_id: str
    kind: BridgeOperationKind
    provider: str
    object_key: str
    fence_token_digest: FenceTokenDigest
    fence_epoch: int
    fence_scope_digest: str
    fence_writer_id: str
    fence_acquisition_operation_id: str
    fence_acquisition_receipt_id: str
    fence_acquisition_receipt_digest: str
    authorization_digest: str
    authorization_observed_at: datetime
    authorized_at: datetime
    previous_revision: Revision
    result_revision: Revision
    pre_fingerprint: str
    post_fingerprint: str
    outcome: BridgeReceiptOutcome
    evidence: BridgeReceiptEvidence
    effect_at: datetime | None
    acknowledged_at: datetime
    durable_at: datetime
    durable: bool
    receipt_digest: str

    def __post_init__(self) -> None:
        _validate_object_operation_id(self.operation_id, "Receipt operation ID")
        _validate_digest(self.intent_digest, "Receipt intent digest")
        _validate_receipt_id(self.receipt_id, "Object receipt ID")
        if not isinstance(self.kind, BridgeOperationKind):
            raise TypeError("Receipt kind must be a BridgeOperationKind.")
        _validate_provider(self.provider, "Receipt provider")
        _validate_string(self.object_key, "Receipt object key")
        _validate_fence_token_digest(
            self.fence_token_digest,
            "Receipt fence token digest",
        )
        _validate_nonnegative_integer(self.fence_epoch, "Receipt fence epoch")
        _validate_digest(self.fence_scope_digest, "Receipt fence scope")
        _validate_string(self.fence_writer_id, "Receipt fence writer")
        _validate_acquire_operation_id(
            self.fence_acquisition_operation_id,
            "Receipt fence acquisition operation",
        )
        _validate_receipt_id(
            self.fence_acquisition_receipt_id,
            "Receipt fence acquisition receipt",
        )
        _validate_digest(
            self.fence_acquisition_receipt_digest,
            "Receipt fence acquisition digest",
        )
        _validate_digest(self.authorization_digest, "Receipt authorization digest")
        _validate_utc(
            self.authorization_observed_at,
            "Receipt authorization observation time",
        )
        _validate_utc(self.authorized_at, "Receipt authorization time")
        if self.authorized_at < self.authorization_observed_at:
            raise ValueError("Receipt authorization predates its observation.")
        _validate_revision(self.previous_revision, "Receipt previous revision")
        _validate_revision(self.result_revision, "Receipt result revision")
        _validate_digest(self.pre_fingerprint, "Receipt preimage")
        _validate_digest(self.post_fingerprint, "Receipt postimage")
        if self.pre_fingerprint == self.post_fingerprint:
            raise ValueError("Receipt preimage and postimage must differ.")
        expected_authorization_digest = _digest_json(
            _authorization_data_from_fields(
                operation_id=self.operation_id,
                intent_digest=self.intent_digest,
                provider=self.provider,
                object_key=self.object_key,
                fence_acquisition_operation_id=(
                    self.fence_acquisition_operation_id
                ),
                fence_acquisition_receipt_id=self.fence_acquisition_receipt_id,
                fence_acquisition_receipt_digest=(
                    self.fence_acquisition_receipt_digest
                ),
                revision=self.previous_revision,
                fingerprint=self.pre_fingerprint,
                observed_at=self.authorization_observed_at,
                authorized_at=self.authorized_at,
            )
        )
        if self.authorization_digest != expected_authorization_digest:
            raise ValueError("Receipt authorization digest is not canonical.")
        if not isinstance(self.outcome, BridgeReceiptOutcome):
            raise TypeError("Receipt outcome must be a BridgeReceiptOutcome.")
        if not isinstance(self.evidence, BridgeReceiptEvidence):
            raise TypeError("Receipt evidence must be a BridgeReceiptEvidence.")
        if self.effect_at is not None:
            _validate_utc(self.effect_at, "Receipt effect time")
        _validate_utc(self.acknowledged_at, "Receipt acknowledgement")
        _validate_utc(self.durable_at, "Receipt durability time")
        if type(self.durable) is not bool or not self.durable:
            raise ValueError("Operation receipt must be durably persisted.")
        if self.durable_at < self.acknowledged_at:
            raise ValueError("Object receipt durability predates acknowledgement.")
        _validate_digest(self.receipt_digest, "Object receipt digest")
        if self.outcome is BridgeReceiptOutcome.APPLIED:
            if self.evidence is not BridgeReceiptEvidence.DISPATCH_ACK:
                raise ValueError("Applied outcome requires dispatch acknowledgement.")
            if self.effect_at is None:
                raise ValueError("Applied outcome requires an effect time.")
            if self.effect_at < max(
                self.authorization_observed_at,
                self.authorized_at,
            ):
                raise ValueError("Applied effect predates dispatch authorization.")
            if _same_revision(self.previous_revision, self.result_revision):
                raise ValueError("Applied outcome must change the typed revision.")
        else:
            if self.evidence is not BridgeReceiptEvidence.OPERATION_LEDGER:
                raise ValueError("No-effect outcome requires operation-ledger evidence.")
            if self.effect_at is not None:
                raise ValueError("No-effect outcome cannot claim an effect time.")
            if not _same_revision(self.previous_revision, self.result_revision):
                raise ValueError("No-effect outcome must preserve the exact revision.")
        expected_id, expected_digest = _receipt_identity(
            "object-operation",
            _object_receipt_data(self, include_receipt_id=False),
        )
        if self.receipt_id != expected_id or self.receipt_digest != expected_digest:
            raise ValueError("Object receipt identity is not canonical.")

    @property
    def result_fingerprint(self) -> str:
        if self.outcome is BridgeReceiptOutcome.APPLIED:
            return self.post_fingerprint
        return self.pre_fingerprint

    def validate_for(self, intent: BridgeOperationIntent) -> None:
        """Require exact intent, acquired fence, outcome, and timing binding."""

        _validate_object_receipt_binding(self, intent)

    def validate_authorization(
        self,
        authorization: BridgeDispatchAuthorization,
    ) -> None:
        _validate_receipt_authorization_binding(self, authorization)

    @classmethod
    def create(
        cls,
        intent: BridgeOperationIntent,
        authorization: BridgeDispatchAuthorization,
        *,
        previous_revision: Revision,
        result_revision: Revision,
        outcome: BridgeReceiptOutcome,
        evidence: BridgeReceiptEvidence,
        effect_at: datetime | None,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> BridgeOperationReceipt:
        """Build a deterministic durable object-operation outcome."""

        _require_object_intent(intent)
        _require_authorization(authorization)
        authorization.validate_for(intent)
        values = {
            "operation_id": intent.operation_id,
            "intent_digest": intent.intent_digest,
            "kind": intent.kind,
            "provider": intent.provider,
            "object_key": intent.object_key,
            "fence_token_digest": intent.fence.token_digest,
            "fence_epoch": intent.fence.epoch,
            "fence_scope_digest": intent.fence.scope_digest,
            "fence_writer_id": intent.fence.writer_id,
            "fence_acquisition_operation_id": intent.fence.acquisition_operation_id,
            "fence_acquisition_receipt_id": intent.fence.acquisition_receipt_id,
            "fence_acquisition_receipt_digest": intent.fence.acquisition_receipt_digest,
            "authorization_digest": authorization.authorization_digest,
            "authorization_observed_at": authorization.observed_at,
            "authorized_at": authorization.authorized_at,
            "previous_revision": previous_revision,
            "result_revision": result_revision,
            "pre_fingerprint": intent.pre_fingerprint,
            "post_fingerprint": intent.post_fingerprint,
            "outcome": outcome,
            "evidence": evidence,
            "effect_at": effect_at,
            "acknowledged_at": acknowledged_at,
            "durable_at": durable_at,
            "durable": True,
        }
        receipt_id, receipt_digest = _receipt_identity(
            "object-operation",
            _object_receipt_data_from_fields(**values),
        )
        receipt = cls(
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            **values,
        )
        receipt.validate_for(intent)
        receipt.validate_authorization(authorization)
        return receipt


@dataclass(frozen=True, slots=True)
class BridgeObjectObservation:
    """Payload-free read-back of one provider object."""

    provider: str
    object_key: str
    revision: Revision
    fingerprint: str
    observed_at: datetime

    def __post_init__(self) -> None:
        _validate_provider(self.provider, "Observation provider")
        _validate_string(self.object_key, "Observation object key")
        _validate_revision(self.revision, "Observation revision")
        _validate_digest(self.fingerprint, "Observation fingerprint")
        _validate_utc(self.observed_at, "Observation time")


@dataclass(frozen=True, slots=True)
class BridgeDispatchAuthorization:
    """Exact fresh preimage evidence durably authorizing one host dispatch."""

    operation_id: str
    intent_digest: str
    provider: str
    object_key: str
    fence_acquisition_operation_id: str
    fence_acquisition_receipt_id: str
    fence_acquisition_receipt_digest: str
    revision: Revision
    fingerprint: str
    observed_at: datetime
    authorized_at: datetime
    authorization_digest: str

    def __post_init__(self) -> None:
        _validate_object_operation_id(
            self.operation_id,
            "Dispatch authorization operation ID",
        )
        _validate_digest(
            self.intent_digest,
            "Dispatch authorization intent digest",
        )
        _validate_provider(self.provider, "Dispatch authorization provider")
        _validate_string(self.object_key, "Dispatch authorization object key")
        _validate_acquire_operation_id(
            self.fence_acquisition_operation_id,
            "Dispatch authorization acquisition operation",
        )
        _validate_receipt_id(
            self.fence_acquisition_receipt_id,
            "Dispatch authorization acquisition receipt",
        )
        _validate_digest(
            self.fence_acquisition_receipt_digest,
            "Dispatch authorization acquisition digest",
        )
        _validate_revision(self.revision, "Dispatch authorization revision")
        _validate_digest(self.fingerprint, "Dispatch authorization fingerprint")
        _validate_utc(self.observed_at, "Dispatch authorization observation time")
        _validate_utc(self.authorized_at, "Dispatch authorization time")
        if self.authorized_at < self.observed_at:
            raise ValueError("Dispatch authorization cannot predate its observation.")
        _validate_digest(
            self.authorization_digest,
            "Dispatch authorization digest",
        )
        if self.authorization_digest != _digest_json(_authorization_data(self)):
            raise ValueError("Dispatch authorization digest is not canonical.")

    def validate_for(self, intent: BridgeOperationIntent) -> None:
        _validate_authorization_binding(self, intent)

    @classmethod
    def create(
        cls,
        intent: BridgeOperationIntent,
        observation: BridgeObjectObservation,
        *,
        authorized_at: datetime,
    ) -> BridgeDispatchAuthorization:
        """Create exact payload-free authorization from a fresh preimage read."""

        _require_object_intent(intent)
        _require_observation(observation)
        values = {
            "operation_id": intent.operation_id,
            "intent_digest": intent.intent_digest,
            "provider": intent.provider,
            "object_key": intent.object_key,
            "fence_acquisition_operation_id": (
                intent.fence.acquisition_operation_id
            ),
            "fence_acquisition_receipt_id": intent.fence.acquisition_receipt_id,
            "fence_acquisition_receipt_digest": (
                intent.fence.acquisition_receipt_digest
            ),
            "revision": observation.revision,
            "fingerprint": observation.fingerprint,
            "observed_at": observation.observed_at,
            "authorized_at": authorized_at,
        }
        authorization = cls(
            authorization_digest=_digest_json(
                _authorization_data_from_fields(**values)
            ),
            **values,
        )
        authorization.validate_for(intent)
        return authorization


@dataclass(frozen=True, slots=True)
class BridgeOperationVerification:
    """Exact receipt and fresh read-back evidence for one operation."""

    operation_id: str
    intent_digest: str
    receipt_id: str
    receipt_digest: str
    provider: str
    object_key: str
    revision: Revision
    fingerprint: str
    observed_at: datetime
    verified_at: datetime

    def __post_init__(self) -> None:
        _validate_object_operation_id(self.operation_id, "Verification operation ID")
        _validate_digest(self.intent_digest, "Verification intent digest")
        _validate_receipt_id(self.receipt_id, "Verification receipt ID")
        _validate_digest(self.receipt_digest, "Verification receipt digest")
        _validate_provider(self.provider, "Verification provider")
        _validate_string(self.object_key, "Verification object key")
        _validate_revision(self.revision, "Verification revision")
        _validate_digest(self.fingerprint, "Verification fingerprint")
        _validate_utc(self.observed_at, "Verification observation time")
        _validate_utc(self.verified_at, "Verification time")
        if self.verified_at < self.observed_at:
            raise ValueError("Verification cannot precede its observation.")

    def validate_for(
        self,
        intent: BridgeOperationIntent,
        receipt: BridgeOperationReceipt,
    ) -> None:
        _validate_verification_binding(self, intent, receipt)

    @classmethod
    def create(
        cls,
        intent: BridgeOperationIntent,
        receipt: BridgeOperationReceipt,
        observation: BridgeObjectObservation,
        *,
        verified_at: datetime,
    ) -> BridgeOperationVerification:
        """Build exact read-back verification at a trusted recorder time."""

        receipt.validate_for(intent)
        _require_observation(observation)
        verification = cls(
            operation_id=intent.operation_id,
            intent_digest=intent.intent_digest,
            receipt_id=receipt.receipt_id,
            receipt_digest=receipt.receipt_digest,
            provider=intent.provider,
            object_key=intent.object_key,
            revision=observation.revision,
            fingerprint=observation.fingerprint,
            observed_at=observation.observed_at,
            verified_at=verified_at,
        )
        verification.validate_for(intent, receipt)
        return verification


_OBJECT_TRANSITIONS = {
    BridgeOperationState.INTENT_RECORDED: frozenset(
        {BridgeOperationState.DISPATCH_ARMED, BridgeOperationState.BLOCKED}
    ),
    BridgeOperationState.DISPATCH_ARMED: frozenset(
        {BridgeOperationState.ACKNOWLEDGED, BridgeOperationState.BLOCKED}
    ),
    BridgeOperationState.ACKNOWLEDGED: frozenset(
        {BridgeOperationState.VERIFIED, BridgeOperationState.BLOCKED}
    ),
    BridgeOperationState.VERIFIED: frozenset({BridgeOperationState.BLOCKED}),
    BridgeOperationState.BLOCKED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class BridgeOperationRecord:
    """Current append-only projection of one object operation."""

    intent: BridgeOperationIntent
    state: BridgeOperationState
    authorization: BridgeDispatchAuthorization | None = None
    receipt: BridgeOperationReceipt | None = None
    verifications: tuple[BridgeOperationVerification, ...] = ()
    reason_code: BridgeBlockReason | None = None
    blocked_from: BridgeOperationState | None = None

    def __post_init__(self) -> None:
        _validate_object_record(self)

    @classmethod
    def recorded(cls, intent: BridgeOperationIntent) -> BridgeOperationRecord:
        return cls(intent, BridgeOperationState.INTENT_RECORDED)

    @property
    def verification(self) -> BridgeOperationVerification | None:
        """Return the newest append-only verification evidence."""

        return self.verifications[-1] if self.verifications else None

    def transition(
        self,
        state: BridgeOperationState,
        *,
        authorization: BridgeDispatchAuthorization | None = None,
        receipt: BridgeOperationReceipt | None = None,
        verification: BridgeOperationVerification | None = None,
        reason_code: BridgeBlockReason | None = None,
    ) -> BridgeOperationRecord:
        if not isinstance(state, BridgeOperationState):
            raise TypeError("A BridgeOperationState is required.")
        if state not in _OBJECT_TRANSITIONS[self.state]:
            raise BridgeOperationTransitionError(
                f"Transition {self.state.value} -> {state.value} is not allowed."
            )
        if state is BridgeOperationState.DISPATCH_ARMED:
            if (
                authorization is None
                or any(
                    value is not None
                    for value in (receipt, verification, reason_code)
                )
            ):
                raise BridgeOperationTransitionError(
                    "Arming requires exactly one dispatch authorization."
                )
            return replace(self, state=state, authorization=authorization)
        if state is BridgeOperationState.ACKNOWLEDGED:
            if (
                authorization is not None
                or receipt is None
                or verification is not None
                or reason_code is not None
            ):
                raise BridgeOperationTransitionError(
                    "Acknowledgement requires exactly one receipt."
                )
            return replace(self, state=state, receipt=receipt)
        if state is BridgeOperationState.VERIFIED:
            if (
                authorization is not None
                or receipt is not None
                or verification is None
                or reason_code is not None
            ):
                raise BridgeOperationTransitionError(
                    "Verification requires exactly one verification record."
                )
            return replace(self, state=state, verifications=(verification,))
        if (
            reason_code is None
            or authorization is not None
            or receipt is not None
            or verification is not None
        ):
            raise BridgeOperationTransitionError(
                "Blocking requires exactly one fixed reason code."
            )
        return replace(
            self,
            state=state,
            reason_code=reason_code,
            blocked_from=self.state,
        )

    def arm(
        self,
        authorization: BridgeDispatchAuthorization,
    ) -> BridgeOperationRecord:
        return self.transition(
            BridgeOperationState.DISPATCH_ARMED,
            authorization=authorization,
        )

    def acknowledge(self, receipt: BridgeOperationReceipt) -> BridgeOperationRecord:
        return self.transition(BridgeOperationState.ACKNOWLEDGED, receipt=receipt)

    def verify(
        self,
        verification: BridgeOperationVerification,
    ) -> BridgeOperationRecord:
        return self.transition(
            BridgeOperationState.VERIFIED,
            verification=verification,
        )

    def refresh_verification(
        self,
        verification: BridgeOperationVerification,
    ) -> BridgeOperationRecord:
        if self.state is not BridgeOperationState.VERIFIED or not self.verifications:
            raise BridgeOperationTransitionError(
                "Only a verified operation may append refreshed evidence."
            )
        latest = self.verifications[-1]
        if (
            verification.observed_at <= latest.observed_at
            or verification.verified_at < latest.verified_at
        ):
            raise BridgeOperationTransitionError(
                "Refreshed verification must be causally newer."
            )
        return replace(self, verifications=self.verifications + (verification,))

    def block(self, reason_code: BridgeBlockReason) -> BridgeOperationRecord:
        return self.transition(
            BridgeOperationState.BLOCKED,
            reason_code=reason_code,
        )


@dataclass(frozen=True, slots=True)
class BridgeOperationAttempt:
    """One exact transaction attempt, including all safety-lock lifecycle."""

    plan_id: str
    plan_digest: str
    manifest_digest: str
    attempt: int
    state: BridgeAttemptState
    max_observation_age_seconds: int
    expected_writes: tuple[BridgeExpectedWrite, ...]
    acquisitions: tuple[FenceAcquisitionRecord, ...] = ()
    operations: tuple[BridgeOperationRecord, ...] = ()
    releases: tuple[FenceReleaseRecord, ...] = ()
    release_phase_sequence: int | None = None
    reason_code: BridgeBlockReason | None = None
    terminal_at: datetime | None = None

    def __post_init__(self) -> None:
        _validate_attempt(self)

    @property
    def expected_write_coverage_digest(self) -> str:
        """Return the canonical Store-binding digest for exact write coverage."""

        return bridge_expected_write_coverage_digest(self.expected_writes)

    @classmethod
    def open(
        cls,
        *,
        plan_id: str,
        plan_digest: str,
        manifest_digest: str,
        attempt: int,
        max_observation_age_seconds: int,
        expected_writes: tuple[BridgeExpectedWrite, ...],
    ) -> BridgeOperationAttempt:
        """Create an empty attempt with immutable exact write coverage."""

        return cls(
            plan_id=plan_id,
            plan_digest=plan_digest,
            manifest_digest=manifest_digest,
            attempt=attempt,
            state=BridgeAttemptState.OPEN,
            max_observation_age_seconds=max_observation_age_seconds,
            expected_writes=expected_writes,
        )


class BridgeOperationJournal(Protocol):
    """Durable journal contract used by the transaction recorder."""

    def append_attempt(self, attempt: BridgeOperationAttempt) -> BridgeOperationAttempt: ...
    def attempts_for(self, plan_id: str) -> tuple[BridgeOperationAttempt, ...]: ...
    def provider_epoch_high_water(self, provider: str) -> int | None: ...
    def get_attempt(self, plan_id: str, attempt: int) -> BridgeOperationAttempt: ...
    def get_operation(self, operation_id: str) -> BridgeOperationRecord: ...
    def get_acquisition(self, operation_id: str) -> FenceAcquisitionRecord: ...
    def get_release(self, operation_id: str) -> FenceReleaseRecord: ...
    def record_acquisition_intent(
        self, intent: FenceAcquisitionIntent
    ) -> FenceAcquisitionRecord: ...
    def arm_acquisition(self, operation_id: str) -> FenceAcquisitionRecord: ...
    def block_acquisition(
        self, operation_id: str, reason_code: BridgeBlockReason
    ) -> FenceAcquisitionRecord: ...
    def record_acquisition_receipt(
        self,
        receipt: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt,
    ) -> FenceAcquisitionRecord: ...
    def record_release_intent(self, intent: FenceReleaseIntent) -> FenceReleaseRecord: ...
    def arm_release(self, operation_id: str) -> FenceReleaseRecord: ...
    def record_release_receipt(
        self,
        receipt: FenceReleaseReceipt | FenceReleaseNoEffectReceipt,
    ) -> FenceReleaseRecord: ...
    def record_intent(self, intent: BridgeOperationIntent) -> BridgeOperationRecord: ...
    def arm_operation(
        self,
        operation_id: str,
        authorization: BridgeDispatchAuthorization,
    ) -> BridgeOperationRecord: ...
    def record_receipt(self, receipt: BridgeOperationReceipt) -> BridgeOperationRecord: ...
    def record_verification(
        self, verification: BridgeOperationVerification
    ) -> BridgeOperationRecord: ...
    def block_operation(
        self, operation_id: str, reason_code: BridgeBlockReason
    ) -> BridgeOperationRecord: ...
    def set_attempt_state(
        self,
        plan_id: str,
        attempt: int,
        state: BridgeAttemptState,
        *,
        reason_code: BridgeBlockReason | None = None,
        terminal_at: datetime | None = None,
    ) -> BridgeOperationAttempt: ...


class FenceAuthority(Protocol):
    """Current fence and durable host-ledger lookup contract."""

    def current_binding(self, provider: str) -> FenceBinding | None: ...
    def acquisition_receipt(
        self, operation_id: str
    ) -> FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt | None: ...
    def release_receipt(
        self, operation_id: str
    ) -> FenceReleaseReceipt | FenceReleaseNoEffectReceipt | None: ...


class InMemoryBridgeOperationJournal:
    """Strict append-only attempt journal for deterministic offline tests."""

    def __init__(self) -> None:
        self._attempts: dict[str, list[BridgeOperationAttempt]] = {}
        self._object_index: dict[str, tuple[str, int, int]] = {}
        self._acquisition_index: dict[str, tuple[str, int, int]] = {}
        self._release_index: dict[str, tuple[str, int, int]] = {}
        self._identity_index: dict[str, str] = {}
        self._receipt_index: dict[str, str] = {}

    def append_attempt(
        self,
        attempt: BridgeOperationAttempt,
    ) -> BridgeOperationAttempt:
        _require_attempt(attempt)
        attempts = self._attempts.setdefault(attempt.plan_id, [])
        if attempt.attempt <= len(attempts):
            existing = attempts[attempt.attempt - 1]
            if existing == attempt:
                return existing
            raise BridgeJournalConflict("An existing attempt has conflicting data.")
        if attempt.attempt != len(attempts) + 1:
            raise BridgeJournalConflict("Attempts must be appended contiguously.")
        if attempts:
            previous = attempts[-1]
            if previous.state is not BridgeAttemptState.RESTORED:
                raise BridgeJournalConflict(
                    "A retry is allowed only after a restored attempt."
                )
            if (
                previous.plan_digest != attempt.plan_digest
                or previous.manifest_digest != attempt.manifest_digest
                or _retry_expected_writes(previous) != attempt.expected_writes
                or previous.max_observation_age_seconds
                != attempt.max_observation_age_seconds
            ):
                raise BridgeJournalConflict("A retry changed immutable attempt scope.")
            self._assert_prepopulated_retry_epochs(attempt, attempts)
        elif attempt.attempt != 1:
            raise BridgeJournalConflict("The first attempt must be attempt one.")
        self._assert_unclaimed_attempt(attempt)
        self._assert_global_epoch_history(attempt)
        attempts.append(attempt)
        self._index_attempt(attempt)
        return attempt

    def attempts_for(self, plan_id: str) -> tuple[BridgeOperationAttempt, ...]:
        _validate_string(plan_id, "Journal plan ID")
        return tuple(self._attempts.get(plan_id, ()))

    def provider_epoch_high_water(self, provider: str) -> int | None:
        """Reconstruct the globally allocated provider epoch high-water mark."""

        _validate_provider(provider, "Journal epoch provider")
        epochs = [
            acquisition.intent.epoch
            for attempts in self._attempts.values()
            for attempt in attempts
            for acquisition in attempt.acquisitions
            if acquisition.intent.provider == provider
        ]
        return max(epochs) if epochs else None

    def get_attempt(self, plan_id: str, attempt: int) -> BridgeOperationAttempt:
        _validate_string(plan_id, "Journal plan ID")
        _validate_positive_integer(attempt, "Journal attempt")
        try:
            return self._attempts[plan_id][attempt - 1]
        except (KeyError, IndexError) as err:
            raise KeyError("Unknown bridge operation attempt.") from err

    def get_operation(self, operation_id: str) -> BridgeOperationRecord:
        plan_id, attempt, index = self._object_location(operation_id)
        return self._attempts[plan_id][attempt - 1].operations[index]

    def get_acquisition(self, operation_id: str) -> FenceAcquisitionRecord:
        plan_id, attempt, index = self._acquisition_location(operation_id)
        return self._attempts[plan_id][attempt - 1].acquisitions[index]

    def get_release(self, operation_id: str) -> FenceReleaseRecord:
        plan_id, attempt, index = self._release_location(operation_id)
        return self._attempts[plan_id][attempt - 1].releases[index]

    def record_acquisition_intent(
        self,
        intent: FenceAcquisitionIntent,
    ) -> FenceAcquisitionRecord:
        _require_acquisition_intent(intent)
        existing_kind = self._identity_index.get(intent.operation_id)
        if existing_kind is not None:
            if existing_kind == "acquisition":
                existing = self.get_acquisition(intent.operation_id)
                if existing.intent == intent:
                    return existing
            raise BridgeJournalConflict("Acquisition operation ID is not immutable.")
        attempt = self.get_attempt(intent.plan_id, intent.attempt)
        if attempt.state is BridgeAttemptState.BLOCKED:
            if not _provider_needs_compensation(attempt, intent.provider):
                raise BridgeJournalConflict(
                    "Blocked attempts may acquire only for required compensation."
                )
        elif attempt.state is not BridgeAttemptState.OPEN:
            raise BridgeJournalConflict("A terminal attempt cannot acquire a fence.")
        self._assert_new_epoch(
            intent.provider,
            intent.epoch,
            intent.requested_at,
        )
        record = FenceAcquisitionRecord.recorded(intent)
        acquisitions = tuple(
            sorted(
                attempt.acquisitions + (record,),
                key=_acquisition_sort_key,
            )
        )
        updated = replace(attempt, acquisitions=acquisitions)
        self._store_attempt(updated)
        index = acquisitions.index(record)
        self._claim_identity(intent.operation_id, "acquisition")
        self._acquisition_index[intent.operation_id] = (
            intent.plan_id,
            intent.attempt,
            index,
        )
        self._reindex_acquisitions(updated)
        return record

    def arm_acquisition(self, operation_id: str) -> FenceAcquisitionRecord:
        record = self.get_acquisition(operation_id)
        if record.state is FenceLifecycleState.DISPATCH_ARMED:
            return record
        updated = record.arm()
        self._replace_acquisition(updated)
        return updated

    def record_acquisition_receipt(
        self,
        receipt: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt,
    ) -> FenceAcquisitionRecord:
        _require_acquisition_lifecycle_receipt(receipt)
        record = self.get_acquisition(receipt.operation_id)
        if record.receipt is not None:
            if record.receipt == receipt:
                return record
            raise BridgeJournalConflict("Acquisition has a conflicting receipt.")
        self._assert_receipt_unclaimed(receipt.receipt_id, receipt.operation_id)
        try:
            receipt.validate_for(record.intent)
        except (TypeError, ValueError) as err:
            raise BridgeJournalConflict("Acquisition receipt does not match.") from err
        try:
            updated = record.acknowledge(receipt)
        except BridgeOperationTransitionError as err:
            raise BridgeJournalConflict(
                "Acquisition receipt arrived in an invalid state."
            ) from err
        self._replace_acquisition(updated)
        self._receipt_index[receipt.receipt_id] = receipt.operation_id
        return updated

    def block_acquisition(
        self,
        operation_id: str,
        reason_code: BridgeBlockReason,
    ) -> FenceAcquisitionRecord:
        if not isinstance(reason_code, BridgeBlockReason):
            raise TypeError("A fixed bridge block reason is required.")
        record = self.get_acquisition(operation_id)
        if record.state is FenceLifecycleState.BLOCKED:
            if record.reason_code is reason_code:
                return record
            raise BridgeJournalConflict("Blocked acquisition reason is immutable.")
        plan_id, attempt_number, index = self._acquisition_location(operation_id)
        attempt = self.get_attempt(plan_id, attempt_number)
        blocked = record.block(reason_code)
        acquisitions = list(attempt.acquisitions)
        acquisitions[index] = blocked
        updated = replace(
            attempt,
            state=BridgeAttemptState.BLOCKED,
            acquisitions=tuple(acquisitions),
            reason_code=attempt.reason_code or reason_code,
            terminal_at=None,
        )
        self._store_attempt(updated)
        return blocked

    def record_release_intent(
        self,
        intent: FenceReleaseIntent,
    ) -> FenceReleaseRecord:
        _require_release_intent(intent)
        existing_kind = self._identity_index.get(intent.operation_id)
        if existing_kind is not None:
            if existing_kind == "release":
                existing = self.get_release(intent.operation_id)
                if existing.intent == intent:
                    return existing
            raise BridgeJournalConflict("Release operation ID is not immutable.")
        attempt = self.get_attempt(intent.plan_id, intent.attempt)
        if attempt.state not in {BridgeAttemptState.OPEN, BridgeAttemptState.BLOCKED}:
            raise BridgeJournalConflict("A terminal attempt cannot release a fence.")
        acquisition = _acquisition_for_id(
            attempt,
            intent.acquisition_operation_id,
        )
        if acquisition is None:
            raise BridgeJournalConflict("Release acquisition is not journaled.")
        _validate_release_intent_acquisition(intent, acquisition)
        release_phase_sequence = attempt.release_phase_sequence
        if not attempt.releases:
            if release_phase_sequence is not None:
                raise BridgeJournalConflict("Release phase boundary is inconsistent.")
            if any(
                not _operation_effect_resolved(item)
                for item in attempt.operations
            ):
                raise BridgeJournalConflict(
                    "Release phase requires every recorded operation to resolve."
                )
            release_phase_sequence = len(attempt.operations)
        elif release_phase_sequence is None:
            raise BridgeJournalConflict("Release phase lacks its durable boundary.")
        unresolved = [
            item
            for item in attempt.operations
            if item.intent.fence.acquisition_operation_id
            == intent.acquisition_operation_id
            and not _operation_effect_resolved(item)
        ]
        if unresolved:
            raise BridgeJournalConflict(
                "A fence cannot be released with unresolved object operations."
            )
        prior_releases = sorted(
            (
                item
                for item in attempt.releases
                if item.intent.acquisition_operation_id
                == intent.acquisition_operation_id
            ),
            key=lambda item: item.intent.release_attempt,
        )
        expected_release_attempt = len(prior_releases) + 1
        if intent.release_attempt != expected_release_attempt:
            raise BridgeJournalConflict("Release attempts must be contiguous.")
        if prior_releases:
            previous = prior_releases[-1]
            if (
                previous.state is not FenceLifecycleState.NO_EFFECT
                or not isinstance(previous.receipt, FenceReleaseNoEffectReceipt)
                or intent.requested_at < previous.receipt.durable_at
                or not _same_revision(
                    intent.expected_inventory_revision,
                    previous.intent.expected_inventory_revision,
                )
            ):
                raise BridgeJournalConflict(
                    "A release retry requires a durable prior no-effect tombstone."
                )
        record = FenceReleaseRecord.recorded(intent)
        releases = tuple(
            sorted(attempt.releases + (record,), key=_release_sort_key)
        )
        updated = replace(
            attempt,
            releases=releases,
            release_phase_sequence=release_phase_sequence,
        )
        self._store_attempt(updated)
        self._claim_identity(intent.operation_id, "release")
        self._release_index[intent.operation_id] = (
            intent.plan_id,
            intent.attempt,
            releases.index(record),
        )
        self._reindex_releases(updated)
        return record

    def arm_release(self, operation_id: str) -> FenceReleaseRecord:
        record = self.get_release(operation_id)
        if record.state is FenceLifecycleState.DISPATCH_ARMED:
            return record
        updated = record.arm()
        self._replace_release(updated)
        return updated

    def record_release_receipt(
        self,
        receipt: FenceReleaseReceipt | FenceReleaseNoEffectReceipt,
    ) -> FenceReleaseRecord:
        _require_release_lifecycle_receipt(receipt)
        record = self.get_release(receipt.operation_id)
        if record.receipt is not None:
            if record.receipt == receipt:
                return record
            raise BridgeJournalConflict("Release has a conflicting receipt.")
        self._assert_receipt_unclaimed(receipt.receipt_id, receipt.operation_id)
        try:
            receipt.validate_for(record.intent)
        except (TypeError, ValueError) as err:
            raise BridgeJournalConflict("Release receipt does not match.") from err
        try:
            updated = record.acknowledge(receipt)
        except BridgeOperationTransitionError as err:
            raise BridgeJournalConflict(
                "Release receipt arrived in an invalid state."
            ) from err
        self._replace_release(updated)
        self._receipt_index[receipt.receipt_id] = receipt.operation_id
        return updated

    def record_intent(
        self,
        intent: BridgeOperationIntent,
    ) -> BridgeOperationRecord:
        _require_object_intent(intent)
        existing_kind = self._identity_index.get(intent.operation_id)
        if existing_kind is not None:
            if existing_kind == "object":
                existing = self.get_operation(intent.operation_id)
                if existing.intent == intent:
                    return existing
            raise BridgeJournalConflict("Object operation ID is not immutable.")
        attempt = self.get_attempt(intent.plan_id, intent.attempt)
        if attempt.state is BridgeAttemptState.BLOCKED:
            if intent.kind is not BridgeOperationKind.ROLLBACK:
                raise BridgeJournalConflict(
                    "Blocked attempts permit only compensating rollback intents."
                )
        elif attempt.state is not BridgeAttemptState.OPEN:
            raise BridgeJournalConflict("A terminal attempt cannot add operations.")
        acquisition = _acquisition_for_id(
            attempt,
            intent.fence.acquisition_operation_id,
        )
        if (
            acquisition is None
            or acquisition.state is not FenceLifecycleState.ACKNOWLEDGED
            or not isinstance(acquisition.receipt, FenceAcquisitionReceipt)
            or acquisition.receipt.binding != intent.fence
        ):
            raise BridgeJournalConflict(
                "Object operations require a journaled acknowledged acquisition."
            )
        if any(
            item.intent.acquisition_operation_id
            == intent.fence.acquisition_operation_id
            for item in attempt.releases
        ):
            raise BridgeJournalConflict("A released fence cannot accept operations.")
        if (
            intent.kind is BridgeOperationKind.WRITE
            and attempt.release_phase_sequence is not None
        ):
            raise BridgeJournalConflict(
                "Normal writes cannot begin after the release phase."
            )
        prior_epochs = [
            item.intent.epoch
            for prior_attempt in self._attempts.get(intent.plan_id, ())
            if prior_attempt.attempt < intent.attempt
            for item in prior_attempt.acquisitions
            if item.intent.provider == intent.provider
        ]
        if prior_epochs and intent.fence.epoch <= max(prior_epochs):
            raise BridgeJournalConflict(
                "Object intent regressed the provider epoch high-water mark."
            )
        if intent.sequence != len(attempt.operations) + 1:
            raise BridgeJournalConflict("Object operation sequences must be contiguous.")
        record = BridgeOperationRecord.recorded(intent)
        updated = replace(attempt, operations=attempt.operations + (record,))
        self._store_attempt(updated)
        self._claim_identity(intent.operation_id, "object")
        self._object_index[intent.operation_id] = (
            intent.plan_id,
            intent.attempt,
            intent.sequence - 1,
        )
        return record

    def arm_operation(
        self,
        operation_id: str,
        authorization: BridgeDispatchAuthorization,
    ) -> BridgeOperationRecord:
        _require_authorization(authorization)
        record = self.get_operation(operation_id)
        if record.state is BridgeOperationState.DISPATCH_ARMED:
            if record.authorization == authorization:
                return record
            raise BridgeJournalConflict(
                "Armed object operation authorization is immutable."
            )
        try:
            authorization.validate_for(record.intent)
        except (TypeError, ValueError) as err:
            raise BridgeJournalConflict(
                "Dispatch authorization does not match object intent."
            ) from err
        plan_id, attempt_number, _index = self._object_location(operation_id)
        attempt = self.get_attempt(plan_id, attempt_number)
        if not _observation_fresh(
            authorization.observed_at,
            authorization.authorized_at,
            attempt,
        ):
            raise BridgeJournalConflict(
                "Dispatch authorization observation is stale."
            )
        if (
            attempt.release_phase_sequence is not None
            and record.intent.sequence <= attempt.release_phase_sequence
        ):
            raise BridgeJournalConflict(
                "A release-closed operation cannot later be armed."
            )
        if (
            attempt.state is BridgeAttemptState.BLOCKED
            and record.intent.kind is not BridgeOperationKind.ROLLBACK
        ):
            raise BridgeJournalConflict(
                "Blocked attempts cannot arm non-rollback operations."
            )
        acquisition = _acquisition_for_id(
            attempt,
            record.intent.fence.acquisition_operation_id,
        )
        if (
            acquisition is None
            or acquisition.state is not FenceLifecycleState.ACKNOWLEDGED
            or not isinstance(acquisition.receipt, FenceAcquisitionReceipt)
        ):
            raise BridgeJournalConflict(
                "Object dispatch requires an acknowledged acquisition."
            )
        if any(
            item.intent.acquisition_operation_id
            == record.intent.fence.acquisition_operation_id
            for item in attempt.releases
        ):
            raise BridgeJournalConflict("Object dispatch cannot follow fence release.")
        updated = record.arm(authorization)
        self._replace_object(updated, allow_recovery=False)
        return updated

    def record_receipt(
        self,
        receipt: BridgeOperationReceipt,
    ) -> BridgeOperationRecord:
        _require_object_receipt(receipt)
        record = self.get_operation(receipt.operation_id)
        if record.receipt is not None:
            if record.receipt == receipt:
                return record
            raise BridgeJournalConflict("Object operation has a conflicting receipt.")
        self._assert_receipt_unclaimed(receipt.receipt_id, receipt.operation_id)
        try:
            receipt.validate_for(record.intent)
            if record.authorization is None:
                raise ValueError("Object receipt lacks dispatch authorization.")
            receipt.validate_authorization(record.authorization)
        except (TypeError, ValueError) as err:
            raise BridgeJournalConflict("Object receipt does not match intent.") from err
        try:
            updated = record.acknowledge(receipt)
        except BridgeOperationTransitionError as err:
            raise BridgeJournalConflict(
                "Object receipt arrived in an invalid state."
            ) from err
        self._replace_object(updated, allow_recovery=True)
        self._receipt_index[receipt.receipt_id] = receipt.operation_id
        return updated

    def record_verification(
        self,
        verification: BridgeOperationVerification,
    ) -> BridgeOperationRecord:
        _require_verification(verification)
        record = self.get_operation(verification.operation_id)
        if verification in record.verifications:
            return record
        attempt = self.get_attempt(record.intent.plan_id, record.intent.attempt)
        if attempt.state in {
            BridgeAttemptState.COMMITTED,
            BridgeAttemptState.RESTORED,
        }:
            raise BridgeJournalConflict(
                "Terminal attempt verification history is immutable."
            )
        if record.receipt is None:
            raise BridgeJournalConflict("Verification requires a durable receipt.")
        try:
            verification.validate_for(record.intent, record.receipt)
        except (TypeError, ValueError) as err:
            raise BridgeJournalConflict("Verification does not match receipt.") from err
        try:
            if record.state is BridgeOperationState.ACKNOWLEDGED:
                updated = record.verify(verification)
            elif record.state is BridgeOperationState.VERIFIED:
                updated = record.refresh_verification(verification)
            else:
                raise BridgeOperationTransitionError(
                    "Verification arrived outside an appendable state."
                )
        except BridgeOperationTransitionError as err:
            raise BridgeJournalConflict(
                "Object verification arrived in an invalid state."
            ) from err
        self._replace_object(updated, allow_recovery=True)
        return updated

    def block_operation(
        self,
        operation_id: str,
        reason_code: BridgeBlockReason,
    ) -> BridgeOperationRecord:
        if not isinstance(reason_code, BridgeBlockReason):
            raise TypeError("A fixed bridge block reason is required.")
        record = self.get_operation(operation_id)
        if record.state is BridgeOperationState.BLOCKED:
            if record.reason_code is reason_code:
                return record
            raise BridgeJournalConflict("Blocked operation reason is immutable.")
        plan_id, attempt_number, index = self._object_location(operation_id)
        attempt = self.get_attempt(plan_id, attempt_number)
        if attempt.state not in {BridgeAttemptState.OPEN, BridgeAttemptState.BLOCKED}:
            raise BridgeJournalConflict("Terminal attempt cannot be blocked again.")
        blocked = record.block(reason_code)
        operations = list(attempt.operations)
        operations[index] = blocked
        updated_attempt = replace(
            attempt,
            state=BridgeAttemptState.BLOCKED,
            operations=tuple(operations),
            reason_code=attempt.reason_code or reason_code,
            terminal_at=None,
        )
        self._store_attempt(updated_attempt)
        return blocked

    def set_attempt_state(
        self,
        plan_id: str,
        attempt: int,
        state: BridgeAttemptState,
        *,
        reason_code: BridgeBlockReason | None = None,
        terminal_at: datetime | None = None,
    ) -> BridgeOperationAttempt:
        if not isinstance(state, BridgeAttemptState):
            raise TypeError("A BridgeAttemptState is required.")
        current = self.get_attempt(plan_id, attempt)
        if (
            current.state is state
            and current.terminal_at == terminal_at
            and (
                current.reason_code is reason_code
                or (
                    state is BridgeAttemptState.RESTORED
                    and reason_code is None
                    and current.reason_code is not None
                )
            )
        ):
            return current
        if current.state is BridgeAttemptState.BLOCKED:
            if state is not BridgeAttemptState.RESTORED:
                raise BridgeJournalConflict(
                    "A blocked attempt may only become exactly restored."
                )
            reason_code = current.reason_code
        elif current.state is not BridgeAttemptState.OPEN:
            raise BridgeJournalConflict("A terminal attempt cannot change state.")
        if state is BridgeAttemptState.OPEN:
            raise BridgeJournalConflict("An open attempt cannot transition to open.")
        updated = replace(
            current,
            state=state,
            reason_code=reason_code,
            terminal_at=terminal_at,
        )
        self._store_attempt(updated)
        return updated

    def _assert_new_epoch(
        self,
        provider: str,
        epoch: int,
        requested_at: datetime,
    ) -> None:
        high_water = self.provider_epoch_high_water(provider)
        if high_water is not None and epoch <= high_water:
            raise BridgeJournalConflict(
                "Provider acquisition epoch regressed the global high-water mark."
            )
        prior_requests = [
            acquisition.intent.requested_at
            for attempts in self._attempts.values()
            for old_attempt in attempts
            for acquisition in old_attempt.acquisitions
            if acquisition.intent.provider == provider
        ]
        if prior_requests and requested_at < max(prior_requests):
            raise BridgeJournalConflict(
                "Provider acquisition request predates the global epoch history."
            )

    def _assert_global_epoch_history(
        self,
        candidate: BridgeOperationAttempt,
    ) -> None:
        histories: dict[str, list[FenceAcquisitionIntent]] = {}
        for attempts in self._attempts.values():
            for attempt in attempts:
                for acquisition in attempt.acquisitions:
                    histories.setdefault(acquisition.intent.provider, []).append(
                        acquisition.intent
                    )
        for acquisition in candidate.acquisitions:
            histories.setdefault(acquisition.intent.provider, []).append(
                acquisition.intent
            )
        for provider, intents in histories.items():
            ordered = sorted(
                intents,
                key=lambda item: (item.requested_at, item.epoch, item.operation_id),
            )
            epochs = [item.epoch for item in ordered]
            if any(current <= previous for previous, current in zip(epochs, epochs[1:])):
                raise BridgeJournalConflict(
                    f"Provider {provider} has non-monotonic cross-plan epochs."
                )

    def _assert_prepopulated_retry_epochs(
        self,
        attempt: BridgeOperationAttempt,
        previous_attempts: list[BridgeOperationAttempt],
    ) -> None:
        for provider in TRUE_FAMILY_PROVIDER_MANIFEST:
            prior = [
                item.intent.epoch
                for old_attempt in previous_attempts
                for item in old_attempt.acquisitions
                if item.intent.provider == provider
            ]
            current = [
                item.intent.epoch
                for item in attempt.acquisitions
                if item.intent.provider == provider
            ]
            if prior and current and min(current) <= max(prior):
                raise BridgeJournalConflict(
                    "Pre-populated retry contains a regressed provider epoch."
                )

    def _assert_unclaimed_attempt(self, attempt: BridgeOperationAttempt) -> None:
        local_ids: set[str] = set()
        local_receipts: set[str] = set()
        for operation_id, kind, receipt_id in _attempt_identity_rows(attempt):
            if operation_id in local_ids or operation_id in self._identity_index:
                raise BridgeJournalConflict("Operation ID is globally immutable.")
            local_ids.add(operation_id)
            if receipt_id is not None:
                if receipt_id in local_receipts or receipt_id in self._receipt_index:
                    raise BridgeJournalConflict("Receipt ID is globally immutable.")
                local_receipts.add(receipt_id)

    def _index_attempt(self, attempt: BridgeOperationAttempt) -> None:
        for index, item in enumerate(attempt.acquisitions):
            operation_id = item.intent.operation_id
            self._claim_identity(operation_id, "acquisition")
            self._acquisition_index[operation_id] = (
                attempt.plan_id,
                attempt.attempt,
                index,
            )
            if item.receipt is not None:
                self._receipt_index[item.receipt.receipt_id] = operation_id
        for index, item in enumerate(attempt.operations):
            operation_id = item.intent.operation_id
            self._claim_identity(operation_id, "object")
            self._object_index[operation_id] = (
                attempt.plan_id,
                attempt.attempt,
                index,
            )
            if item.receipt is not None:
                self._receipt_index[item.receipt.receipt_id] = operation_id
        for index, item in enumerate(attempt.releases):
            operation_id = item.intent.operation_id
            self._claim_identity(operation_id, "release")
            self._release_index[operation_id] = (
                attempt.plan_id,
                attempt.attempt,
                index,
            )
            if item.receipt is not None:
                self._receipt_index[item.receipt.receipt_id] = operation_id

    def _claim_identity(self, operation_id: str, kind: str) -> None:
        existing = self._identity_index.get(operation_id)
        if existing is not None and existing != kind:
            raise BridgeJournalConflict("Operation ID changed operation kind.")
        self._identity_index[operation_id] = kind

    def _assert_receipt_unclaimed(self, receipt_id: str, operation_id: str) -> None:
        existing = self._receipt_index.get(receipt_id)
        if existing is not None and existing != operation_id:
            raise BridgeJournalConflict("Receipt ID is bound to another operation.")

    def _store_attempt(self, attempt: BridgeOperationAttempt) -> None:
        _require_attempt(attempt)
        self._attempts[attempt.plan_id][attempt.attempt - 1] = attempt

    def _replace_acquisition(self, record: FenceAcquisitionRecord) -> None:
        plan_id, attempt_number, index = self._acquisition_location(
            record.intent.operation_id
        )
        attempt = self.get_attempt(plan_id, attempt_number)
        acquisitions = list(attempt.acquisitions)
        acquisitions[index] = record
        self._store_attempt(replace(attempt, acquisitions=tuple(acquisitions)))

    def _replace_release(self, record: FenceReleaseRecord) -> None:
        plan_id, attempt_number, index = self._release_location(
            record.intent.operation_id
        )
        attempt = self.get_attempt(plan_id, attempt_number)
        releases = list(attempt.releases)
        releases[index] = record
        self._store_attempt(replace(attempt, releases=tuple(releases)))

    def _replace_object(
        self,
        record: BridgeOperationRecord,
        *,
        allow_recovery: bool,
    ) -> None:
        plan_id, attempt_number, index = self._object_location(
            record.intent.operation_id
        )
        attempt = self.get_attempt(plan_id, attempt_number)
        if attempt.state is BridgeAttemptState.BLOCKED and not allow_recovery:
            if record.intent.kind is not BridgeOperationKind.ROLLBACK:
                raise BridgeJournalConflict("Blocked attempt rejects new write dispatch.")
        operations = list(attempt.operations)
        operations[index] = record
        self._store_attempt(replace(attempt, operations=tuple(operations)))

    def _reindex_acquisitions(self, attempt: BridgeOperationAttempt) -> None:
        for index, item in enumerate(attempt.acquisitions):
            self._acquisition_index[item.intent.operation_id] = (
                attempt.plan_id,
                attempt.attempt,
                index,
            )

    def _reindex_releases(self, attempt: BridgeOperationAttempt) -> None:
        for index, item in enumerate(attempt.releases):
            self._release_index[item.intent.operation_id] = (
                attempt.plan_id,
                attempt.attempt,
                index,
            )

    def _object_location(self, operation_id: str) -> tuple[str, int, int]:
        _validate_object_operation_id(operation_id, "Journal object operation ID")
        try:
            return self._object_index[operation_id]
        except KeyError as err:
            raise KeyError("Unknown object operation.") from err

    def _acquisition_location(self, operation_id: str) -> tuple[str, int, int]:
        _validate_acquire_operation_id(operation_id, "Journal acquisition ID")
        try:
            return self._acquisition_index[operation_id]
        except KeyError as err:
            raise KeyError("Unknown fence acquisition.") from err

    def _release_location(self, operation_id: str) -> tuple[str, int, int]:
        _validate_release_operation_id(operation_id, "Journal release ID")
        try:
            return self._release_index[operation_id]
        except KeyError as err:
            raise KeyError("Unknown fence release.") from err


class InMemoryFenceAuthority:
    """Exact current fence plus deterministic durable lifecycle ledgers."""

    def __init__(self, bindings: tuple[FenceBinding, ...] = ()) -> None:
        if type(bindings) is not tuple:
            raise TypeError("Fence authority bindings must be a tuple.")
        self._bindings: dict[str, FenceBinding] = {}
        self._high_water: dict[str, int] = {}
        self._acquisitions: dict[
            str,
            FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt,
        ] = {}
        self._releases: dict[
            str,
            FenceReleaseReceipt | FenceReleaseNoEffectReceipt,
        ] = {}
        self._receipt_ids: dict[str, str] = {}
        for binding in bindings:
            self.put(binding)

    def put(self, binding: FenceBinding) -> None:
        _require_fence(binding)
        current = self._bindings.get(binding.provider)
        high_water = self._high_water.get(binding.provider, -1)
        if current == binding:
            return
        if binding.epoch <= high_water:
            raise BridgeJournalConflict("Fence authority rejected epoch regression.")
        self._bindings[binding.provider] = binding
        self._high_water[binding.provider] = binding.epoch

    def current_binding(self, provider: str) -> FenceBinding | None:
        _validate_provider(provider, "Fence authority provider")
        return self._bindings.get(provider)

    def acquisition_receipt(
        self,
        operation_id: str,
    ) -> FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt | None:
        _validate_acquire_operation_id(operation_id, "Acquisition lookup ID")
        return self._acquisitions.get(operation_id)

    def release_receipt(
        self,
        operation_id: str,
    ) -> FenceReleaseReceipt | FenceReleaseNoEffectReceipt | None:
        _validate_release_operation_id(operation_id, "Release lookup ID")
        return self._releases.get(operation_id)

    def acquire(
        self,
        intent: FenceAcquisitionIntent,
        *,
        acquired_inventory_revision: Revision,
        fence_revision: Revision,
        token_digest: FenceTokenDigest,
        acquired_at: datetime,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceAcquisitionReceipt:
        """Apply or replay one deterministic host-ledger acquisition."""

        _require_acquisition_intent(intent)
        existing = self._acquisitions.get(intent.operation_id)
        if existing is not None:
            if not isinstance(existing, FenceAcquisitionReceipt):
                raise BridgeJournalConflict(
                    "A tombstoned acquisition cannot later be applied."
                )
            existing.validate_for(intent)
            return existing
        if self._bindings.get(intent.provider) is not None:
            raise BridgeJournalConflict("Provider already has an unreleased fence.")
        if intent.epoch <= self._high_water.get(intent.provider, -1):
            raise BridgeJournalConflict("Fence authority rejected epoch regression.")
        receipt = FenceAcquisitionReceipt.create(
            intent,
            acquired_inventory_revision=acquired_inventory_revision,
            fence_revision=fence_revision,
            token_digest=token_digest,
            acquired_at=acquired_at,
            acknowledged_at=acknowledged_at,
            durable_at=durable_at,
        )
        self._claim_receipt(receipt.receipt_id, intent.operation_id)
        self._acquisitions[intent.operation_id] = receipt
        self._bindings[intent.provider] = receipt.binding
        self._high_water[intent.provider] = intent.epoch
        return receipt

    def tombstone_acquisition(
        self,
        intent: FenceAcquisitionIntent,
        *,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceAcquisitionNoEffectReceipt:
        """Persist or replay an authoritative unreceived-acquisition tombstone."""

        _require_acquisition_intent(intent)
        existing = self._acquisitions.get(intent.operation_id)
        if existing is not None:
            if not isinstance(existing, FenceAcquisitionNoEffectReceipt):
                raise BridgeJournalConflict(
                    "An applied acquisition cannot later be tombstoned."
                )
            existing.validate_for(intent)
            return existing
        current = self._bindings.get(intent.provider)
        if (
            current is not None
            and current.acquisition_operation_id == intent.operation_id
        ):
            raise BridgeJournalConflict(
                "An active acquired fence cannot be tombstoned as no-effect."
            )
        receipt = FenceAcquisitionNoEffectReceipt.create(
            intent,
            acknowledged_at=acknowledged_at,
            durable_at=durable_at,
        )
        self._claim_receipt(receipt.receipt_id, intent.operation_id)
        self._acquisitions[intent.operation_id] = receipt
        self._high_water[intent.provider] = max(
            intent.epoch,
            self._high_water.get(intent.provider, -1),
        )
        return receipt

    def release(
        self,
        intent: FenceReleaseIntent,
        *,
        final_inventory_revision: Revision,
        released_at: datetime,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceReleaseReceipt:
        """Apply or replay one deterministic host-ledger release."""

        _require_release_intent(intent)
        existing = self._releases.get(intent.operation_id)
        if existing is not None:
            if not isinstance(existing, FenceReleaseReceipt):
                raise BridgeJournalConflict("A tombstoned release cannot later apply.")
            existing.validate_for(intent)
            return existing
        current = self._bindings.get(intent.provider)
        if current is None or (
            current.acquisition_operation_id != intent.acquisition_operation_id
            or current.acquisition_receipt_id != intent.acquisition_receipt_id
            or current.acquisition_receipt_digest
            != intent.acquisition_receipt_digest
            or current.token_digest != intent.token_digest
            or current.epoch != intent.epoch
        ):
            raise BridgeJournalConflict("Release does not own the current fence.")
        if intent.requested_at < current.acquired_at:
            raise BridgeJournalConflict("Release request predates fence acquisition.")
        receipt = FenceReleaseReceipt.create(
            intent,
            final_inventory_revision=final_inventory_revision,
            released_at=released_at,
            acknowledged_at=acknowledged_at,
            durable_at=durable_at,
        )
        self._claim_receipt(receipt.receipt_id, intent.operation_id)
        self._releases[intent.operation_id] = receipt
        del self._bindings[intent.provider]
        return receipt

    def tombstone_release(
        self,
        intent: FenceReleaseIntent,
        *,
        acknowledged_at: datetime,
        durable_at: datetime,
    ) -> FenceReleaseNoEffectReceipt:
        """Persist or replay an authoritative unreceived-release tombstone."""

        _require_release_intent(intent)
        existing = self._releases.get(intent.operation_id)
        if existing is not None:
            if not isinstance(existing, FenceReleaseNoEffectReceipt):
                raise BridgeJournalConflict("An applied release cannot be tombstoned.")
            existing.validate_for(intent)
            return existing
        current = self._bindings.get(intent.provider)
        if not _binding_matches_release(current, intent):
            raise BridgeJournalConflict(
                "Release tombstone requires the exact fence to remain held."
            )
        receipt = FenceReleaseNoEffectReceipt.create(
            intent,
            acknowledged_at=acknowledged_at,
            durable_at=durable_at,
        )
        self._claim_receipt(receipt.receipt_id, intent.operation_id)
        self._releases[intent.operation_id] = receipt
        return receipt

    def _claim_receipt(self, receipt_id: str, operation_id: str) -> None:
        existing = self._receipt_ids.get(receipt_id)
        if existing is not None and existing != operation_id:
            raise BridgeJournalConflict("Authority receipt ID is not immutable.")
        self._receipt_ids[receipt_id] = operation_id


class BridgeTransactionRecorder:
    """Persist, recover, and verify bridge effects without blind redispatch."""

    def __init__(
        self,
        journal: BridgeOperationJournal,
        authority: FenceAuthority,
        *,
        max_observation_age: timedelta = timedelta(seconds=5),
    ) -> None:
        methods = (
            "append_attempt",
            "attempts_for",
            "provider_epoch_high_water",
            "get_attempt",
            "get_operation",
            "get_acquisition",
            "get_release",
            "record_acquisition_intent",
            "arm_acquisition",
            "block_acquisition",
            "record_acquisition_receipt",
            "record_release_intent",
            "arm_release",
            "record_release_receipt",
            "record_intent",
            "arm_operation",
            "record_receipt",
            "record_verification",
            "block_operation",
            "set_attempt_state",
        )
        if any(not callable(getattr(journal, name, None)) for name in methods):
            raise TypeError("A complete bridge operation journal is required.")
        authority_methods = (
            "current_binding",
            "acquisition_receipt",
            "release_receipt",
        )
        if any(not callable(getattr(authority, name, None)) for name in authority_methods):
            raise TypeError("A complete bridge fence authority is required.")
        self._max_observation_age_seconds = _freshness_seconds(max_observation_age)
        self._journal = journal
        self._authority = authority

    def begin_attempt(
        self,
        *,
        plan_id: str,
        plan_digest: str,
        manifest_digest: str,
        attempt: int,
        expected_writes: tuple[BridgeExpectedWrite, ...],
    ) -> BridgeOperationAttempt:
        return self._journal.append_attempt(
            BridgeOperationAttempt.open(
                plan_id=plan_id,
                plan_digest=plan_digest,
                manifest_digest=manifest_digest,
                attempt=attempt,
                max_observation_age_seconds=self._max_observation_age_seconds,
                expected_writes=expected_writes,
            )
        )

    def prepare_acquisition(
        self,
        intent: FenceAcquisitionIntent,
    ) -> FenceAcquisitionRecord:
        return self._journal.record_acquisition_intent(intent)

    def reconcile_acquisition(
        self,
        operation_id: str,
        *,
        at: datetime,
    ) -> BridgeReconciliationAction:
        _validate_utc(at, "Acquisition reconciliation time")
        record = self._journal.get_acquisition(operation_id)
        if record.state is FenceLifecycleState.BLOCKED:
            return BridgeReconciliationAction.BLOCK
        if record.state in {
            FenceLifecycleState.ACKNOWLEDGED,
            FenceLifecycleState.NO_EFFECT,
        }:
            return BridgeReconciliationAction.COMPLETE
        if record.state is FenceLifecycleState.DISPATCH_ARMED:
            return BridgeReconciliationAction.QUERY_RECEIPT
        if at < record.intent.requested_at:
            raise BridgeTransactionBlocked(BridgeBlockReason.LIFECYCLE_MISMATCH)
        if at >= record.intent.expires_at:
            self._journal.block_acquisition(
                operation_id,
                BridgeBlockReason.EXPIRED_FENCE,
            )
            return BridgeReconciliationAction.BLOCK
        known = self._authority.acquisition_receipt(operation_id)
        current = self._authority.current_binding(record.intent.provider)
        self._journal.arm_acquisition(operation_id)
        if known is not None or current is not None:
            return BridgeReconciliationAction.QUERY_RECEIPT
        return BridgeReconciliationAction.DISPATCH

    def acknowledge_acquisition(
        self,
        receipt: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt,
    ) -> FenceAcquisitionRecord:
        return self._journal.record_acquisition_receipt(receipt)

    def prepare_release(self, intent: FenceReleaseIntent) -> FenceReleaseRecord:
        return self._journal.record_release_intent(intent)

    def reconcile_release(
        self,
        operation_id: str,
        *,
        at: datetime,
    ) -> BridgeReconciliationAction:
        _validate_utc(at, "Release reconciliation time")
        record = self._journal.get_release(operation_id)
        if record.state is FenceLifecycleState.BLOCKED:
            return BridgeReconciliationAction.BLOCK
        if record.state in {
            FenceLifecycleState.ACKNOWLEDGED,
            FenceLifecycleState.NO_EFFECT,
        }:
            return BridgeReconciliationAction.COMPLETE
        if record.state is FenceLifecycleState.DISPATCH_ARMED:
            return BridgeReconciliationAction.QUERY_RECEIPT
        if at < record.intent.requested_at:
            raise BridgeTransactionBlocked(BridgeBlockReason.LIFECYCLE_MISMATCH)
        known = self._authority.release_receipt(operation_id)
        current = self._authority.current_binding(record.intent.provider)
        self._journal.arm_release(operation_id)
        if known is not None or not _binding_matches_release(current, record.intent):
            return BridgeReconciliationAction.QUERY_RECEIPT
        return BridgeReconciliationAction.DISPATCH

    def acknowledge_release(
        self,
        receipt: FenceReleaseReceipt | FenceReleaseNoEffectReceipt,
    ) -> FenceReleaseRecord:
        return self._journal.record_release_receipt(receipt)

    def prepare(
        self,
        intent: BridgeOperationIntent,
        *,
        at: datetime,
    ) -> BridgeOperationRecord:
        _require_object_intent(intent)
        self._require_current_live_fence(intent.fence, at)
        return self._journal.record_intent(intent)

    def arm(
        self,
        operation_id: str,
        observation: BridgeObjectObservation,
        *,
        at: datetime,
    ) -> BridgeOperationRecord:
        _validate_utc(at, "Object dispatch arm time")
        _require_observation(observation)
        record = self._journal.get_operation(operation_id)
        if record.state is not BridgeOperationState.INTENT_RECORDED:
            raise BridgeOperationTransitionError(
                "Only a recorded object intent may be armed."
            )
        attempt = self._attempt_for_intent(record.intent)
        if (
            not _observation_fresh(observation.observed_at, at, attempt)
            or observation.observed_at < record.intent.fence.acquisition_durable_at
        ):
            raise BridgeTransactionBlocked(BridgeBlockReason.STALE_OBSERVATION)
        if _observation_is_postimage(observation, record.intent):
            self._journal.block_operation(
                operation_id,
                BridgeBlockReason.LIFECYCLE_MISMATCH,
            )
            raise BridgeTransactionBlocked(BridgeBlockReason.LIFECYCLE_MISMATCH)
        if not _observation_is_preimage(observation, record.intent):
            self._journal.block_operation(
                operation_id,
                BridgeBlockReason.OBSERVATION_MISMATCH,
            )
            raise BridgeTransactionBlocked(BridgeBlockReason.OBSERVATION_MISMATCH)
        try:
            self._require_current_live_fence(record.intent.fence, at)
        except BridgeTransactionBlocked as err:
            self._journal.block_operation(operation_id, err.reason_code)
            raise
        authorization = BridgeDispatchAuthorization.create(
            record.intent,
            observation,
            authorized_at=at,
        )
        return self._journal.arm_operation(operation_id, authorization)

    def acknowledge(
        self,
        receipt: BridgeOperationReceipt,
    ) -> BridgeOperationRecord:
        return self._journal.record_receipt(receipt)

    def reconcile(
        self,
        operation_id: str,
        observation: BridgeObjectObservation | None,
        *,
        at: datetime,
    ) -> BridgeReconciliationAction:
        _validate_utc(at, "Object reconciliation time")
        record = self._journal.get_operation(operation_id)
        if record.state is BridgeOperationState.BLOCKED:
            return BridgeReconciliationAction.BLOCK
        if record.state is BridgeOperationState.DISPATCH_ARMED:
            return BridgeReconciliationAction.QUERY_RECEIPT
        if observation is None:
            return BridgeReconciliationAction.REFRESH_OBSERVATION
        _require_observation(observation)
        attempt = self._attempt_for_intent(record.intent)
        if not _observation_fresh(observation.observed_at, at, attempt):
            return BridgeReconciliationAction.REFRESH_OBSERVATION
        if not _observation_identity_matches(observation, record.intent):
            reason = (
                BridgeBlockReason.VERIFIED_DRIFT
                if record.state is BridgeOperationState.VERIFIED
                else BridgeBlockReason.OBSERVATION_MISMATCH
            )
            return self._block(operation_id, reason)
        if record.state is BridgeOperationState.INTENT_RECORDED:
            if observation.observed_at < record.intent.fence.acquisition_durable_at:
                return BridgeReconciliationAction.REFRESH_OBSERVATION
            if _observation_is_postimage(observation, record.intent):
                return self._block(
                    operation_id,
                    BridgeBlockReason.LIFECYCLE_MISMATCH,
                )
            if not _observation_is_preimage(observation, record.intent):
                return self._block(
                    operation_id,
                    BridgeBlockReason.OBSERVATION_MISMATCH,
                )
            try:
                self._require_current_live_fence(record.intent.fence, at)
            except BridgeTransactionBlocked as err:
                return self._block(operation_id, err.reason_code)
            authorization = BridgeDispatchAuthorization.create(
                record.intent,
                observation,
                authorized_at=at,
            )
            self._journal.arm_operation(operation_id, authorization)
            return BridgeReconciliationAction.DISPATCH
        if record.state is BridgeOperationState.ACKNOWLEDGED:
            if record.receipt is None:
                return self._block(operation_id, BridgeBlockReason.RECEIPT_MISMATCH)
            if _observation_matches_receipt(observation, record.receipt):
                return BridgeReconciliationAction.VERIFY_RECEIPT
            return self._block(
                operation_id,
                BridgeBlockReason.OBSERVATION_MISMATCH,
            )
        verification = record.verification
        if (
            record.receipt is not None
            and verification is not None
            and _observation_matches_receipt(observation, record.receipt)
        ):
            if observation.observed_at > verification.observed_at:
                return BridgeReconciliationAction.VERIFY_RECEIPT
            if _observation_fresh(verification.observed_at, at, attempt):
                return BridgeReconciliationAction.COMPLETE
            return BridgeReconciliationAction.REFRESH_OBSERVATION
        return self._block(operation_id, BridgeBlockReason.VERIFIED_DRIFT)

    def verify_receipt(
        self,
        operation_id: str,
        observation: BridgeObjectObservation,
        *,
        at: datetime,
    ) -> BridgeOperationRecord:
        _validate_utc(at, "Receipt verification time")
        _require_observation(observation)
        record = self._journal.get_operation(operation_id)
        if record.state not in {
            BridgeOperationState.ACKNOWLEDGED,
            BridgeOperationState.VERIFIED,
        }:
            raise BridgeOperationTransitionError(
                "Only an acknowledged or verified operation may be verified."
            )
        attempt = self._attempt_for_intent(record.intent)
        if not _observation_fresh(observation.observed_at, at, attempt):
            raise BridgeTransactionBlocked(BridgeBlockReason.STALE_OBSERVATION)
        if record.receipt is None:
            self._journal.block_operation(
                operation_id,
                BridgeBlockReason.RECEIPT_MISMATCH,
            )
            raise BridgeTransactionBlocked(BridgeBlockReason.RECEIPT_MISMATCH)
        latest = record.verification
        if latest is not None and observation.observed_at <= latest.observed_at:
            if (
                observation.observed_at == latest.observed_at
                and _same_revision(observation.revision, latest.revision)
                and observation.fingerprint == latest.fingerprint
                and _observation_identity_matches(observation, record.intent)
            ):
                return record
            raise BridgeOperationTransitionError(
                "Refreshed observation must be newer than durable evidence."
            )
        try:
            verification = BridgeOperationVerification.create(
                record.intent,
                record.receipt,
                observation,
                verified_at=at,
            )
        except (TypeError, ValueError) as err:
            self._journal.block_operation(
                operation_id,
                BridgeBlockReason.OBSERVATION_MISMATCH,
            )
            raise BridgeTransactionBlocked(
                BridgeBlockReason.OBSERVATION_MISMATCH
            ) from err
        return self._journal.record_verification(verification)

    def finish_attempt(
        self,
        plan_id: str,
        attempt: int,
        state: BridgeAttemptState,
        *,
        at: datetime,
    ) -> BridgeOperationAttempt:
        _validate_utc(at, "Attempt terminal time")
        if state not in {BridgeAttemptState.COMMITTED, BridgeAttemptState.RESTORED}:
            raise ValueError("Finish accepts only committed or restored state.")
        current = self._journal.get_attempt(plan_id, attempt)
        if current.max_observation_age_seconds != self._max_observation_age_seconds:
            raise BridgeTransactionBlocked(BridgeBlockReason.LIFECYCLE_MISMATCH)
        return self._journal.set_attempt_state(
            plan_id,
            attempt,
            state,
            terminal_at=at,
        )

    def _attempt_for_intent(
        self,
        intent: BridgeOperationIntent,
    ) -> BridgeOperationAttempt:
        attempt = self._journal.get_attempt(intent.plan_id, intent.attempt)
        if attempt.max_observation_age_seconds != self._max_observation_age_seconds:
            raise BridgeTransactionBlocked(BridgeBlockReason.LIFECYCLE_MISMATCH)
        return attempt

    def _require_current_live_fence(
        self,
        fence: FenceBinding,
        at: datetime,
    ) -> None:
        _validate_utc(at, "Fence authority check time")
        if self._authority.current_binding(fence.provider) != fence:
            raise BridgeTransactionBlocked(BridgeBlockReason.STALE_FENCE)
        if not _fence_live_at(fence, at):
            raise BridgeTransactionBlocked(BridgeBlockReason.EXPIRED_FENCE)

    def _block(
        self,
        operation_id: str,
        reason_code: BridgeBlockReason,
    ) -> BridgeReconciliationAction:
        self._journal.block_operation(operation_id, reason_code)
        return BridgeReconciliationAction.BLOCK


def _validate_acquisition_receipt_binding(
    receipt: FenceAcquisitionReceipt,
    intent: FenceAcquisitionIntent,
) -> None:
    _require_acquisition_intent(intent)
    receipt.__post_init__()
    if not (
        receipt.operation_id == intent.operation_id
        and receipt.intent_digest == intent.intent_digest
        and receipt.provider == intent.provider
        and receipt.writer_id == intent.writer_id
        and _same_revision(
            receipt.expected_inventory_revision,
            intent.expected_inventory_revision,
        )
        and receipt.scope_digest == intent.scope_digest
        and receipt.epoch == intent.epoch
        and receipt.expires_at == intent.expires_at
    ):
        raise ValueError("Acquisition receipt does not match its intent.")
    if not (
        intent.requested_at
        <= receipt.acquired_at
        <= receipt.acknowledged_at
        < intent.expires_at
        and receipt.durable_at >= receipt.acknowledged_at
    ):
        raise ValueError("Acquisition receipt timing is not authoritative.")


def _validate_acquisition_no_effect_binding(
    receipt: FenceAcquisitionNoEffectReceipt,
    intent: FenceAcquisitionIntent,
) -> None:
    _require_acquisition_intent(intent)
    receipt.__post_init__()
    if not (
        receipt.operation_id == intent.operation_id
        and receipt.intent_digest == intent.intent_digest
        and receipt.provider == intent.provider
        and receipt.writer_id == intent.writer_id
        and _same_revision(
            receipt.expected_inventory_revision,
            intent.expected_inventory_revision,
        )
        and receipt.scope_digest == intent.scope_digest
        and receipt.epoch == intent.epoch
    ):
        raise ValueError("Acquisition tombstone does not match its full intent.")
    if not intent.expires_at <= receipt.acknowledged_at <= receipt.durable_at:
        raise ValueError(
            "Acquisition tombstone requires authoritative post-expiry durability."
        )


def _validate_release_receipt_binding(
    receipt: FenceReleaseReceipt,
    intent: FenceReleaseIntent,
) -> None:
    _require_release_intent(intent)
    receipt.__post_init__()
    if not (
        receipt.operation_id == intent.operation_id
        and receipt.intent_digest == intent.intent_digest
        and receipt.release_attempt == intent.release_attempt
        and receipt.provider == intent.provider
        and receipt.writer_id == intent.writer_id
        and receipt.acquisition_operation_id == intent.acquisition_operation_id
        and receipt.acquisition_receipt_id == intent.acquisition_receipt_id
        and receipt.acquisition_receipt_digest
        == intent.acquisition_receipt_digest
        and receipt.token_digest == intent.token_digest
        and receipt.scope_digest == intent.scope_digest
        and receipt.epoch == intent.epoch
        and _same_revision(
            receipt.expected_inventory_revision,
            intent.expected_inventory_revision,
        )
    ):
        raise ValueError("Release receipt does not match its intent.")
    if not (
        intent.requested_at
        <= receipt.released_at
        <= receipt.acknowledged_at
        <= receipt.durable_at
    ):
        raise ValueError("Release receipt timing is not authoritative.")


def _validate_release_no_effect_binding(
    receipt: FenceReleaseNoEffectReceipt,
    intent: FenceReleaseIntent,
) -> None:
    _require_release_intent(intent)
    receipt.__post_init__()
    if not (
        receipt.operation_id == intent.operation_id
        and receipt.intent_digest == intent.intent_digest
        and receipt.release_attempt == intent.release_attempt
        and receipt.provider == intent.provider
        and receipt.writer_id == intent.writer_id
        and receipt.acquisition_operation_id == intent.acquisition_operation_id
        and receipt.acquisition_receipt_id == intent.acquisition_receipt_id
        and receipt.acquisition_receipt_digest
        == intent.acquisition_receipt_digest
        and receipt.token_digest == intent.token_digest
        and receipt.scope_digest == intent.scope_digest
        and receipt.epoch == intent.epoch
        and _same_revision(
            receipt.expected_inventory_revision,
            intent.expected_inventory_revision,
        )
    ):
        raise ValueError("Release tombstone does not match its full intent.")
    if not intent.requested_at <= receipt.acknowledged_at <= receipt.durable_at:
        raise ValueError("Release tombstone timing is not authoritative.")


def _validate_authorization_binding(
    authorization: BridgeDispatchAuthorization,
    intent: BridgeOperationIntent,
) -> None:
    _require_object_intent(intent)
    authorization.__post_init__()
    if not (
        authorization.operation_id == intent.operation_id
        and authorization.intent_digest == intent.intent_digest
        and authorization.provider == intent.provider
        and authorization.object_key == intent.object_key
        and authorization.fence_acquisition_operation_id
        == intent.fence.acquisition_operation_id
        and authorization.fence_acquisition_receipt_id
        == intent.fence.acquisition_receipt_id
        and authorization.fence_acquisition_receipt_digest
        == intent.fence.acquisition_receipt_digest
        and _same_revision(
            authorization.revision,
            intent.expected_revision,
        )
        and authorization.fingerprint == intent.pre_fingerprint
    ):
        raise ValueError("Dispatch authorization does not match its full intent.")
    if not (
        intent.fence.acquisition_durable_at
        <= authorization.observed_at
        <= authorization.authorized_at
        < intent.fence.expires_at
    ):
        raise ValueError("Dispatch authorization timing is outside its fence.")


def _validate_receipt_authorization_binding(
    receipt: BridgeOperationReceipt,
    authorization: BridgeDispatchAuthorization,
) -> None:
    _require_authorization(authorization)
    if not (
        receipt.operation_id == authorization.operation_id
        and receipt.intent_digest == authorization.intent_digest
        and receipt.provider == authorization.provider
        and receipt.object_key == authorization.object_key
        and receipt.fence_acquisition_operation_id
        == authorization.fence_acquisition_operation_id
        and receipt.fence_acquisition_receipt_id
        == authorization.fence_acquisition_receipt_id
        and receipt.fence_acquisition_receipt_digest
        == authorization.fence_acquisition_receipt_digest
        and _same_revision(receipt.previous_revision, authorization.revision)
        and receipt.pre_fingerprint == authorization.fingerprint
        and receipt.authorization_observed_at == authorization.observed_at
        and receipt.authorized_at == authorization.authorized_at
        and receipt.authorization_digest == authorization.authorization_digest
    ):
        raise ValueError("Object receipt does not match persisted authorization.")


def _validate_object_receipt_binding(
    receipt: BridgeOperationReceipt,
    intent: BridgeOperationIntent,
) -> None:
    _require_object_intent(intent)
    receipt.__post_init__()
    if not (
        receipt.operation_id == intent.operation_id
        and receipt.intent_digest == intent.intent_digest
        and receipt.kind is intent.kind
        and receipt.provider == intent.provider
        and receipt.object_key == intent.object_key
        and receipt.fence_token_digest == intent.fence.token_digest
        and receipt.fence_epoch == intent.fence.epoch
        and receipt.fence_scope_digest == intent.fence.scope_digest
        and receipt.fence_writer_id == intent.fence.writer_id
        and receipt.fence_acquisition_operation_id
        == intent.fence.acquisition_operation_id
        and receipt.fence_acquisition_receipt_id
        == intent.fence.acquisition_receipt_id
        and receipt.fence_acquisition_receipt_digest
        == intent.fence.acquisition_receipt_digest
        and receipt.authorization_observed_at
        >= intent.fence.acquisition_durable_at
        and receipt.authorization_observed_at <= receipt.authorized_at
        and receipt.authorized_at < intent.fence.expires_at
        and _same_revision(receipt.previous_revision, intent.expected_revision)
        and receipt.pre_fingerprint == intent.pre_fingerprint
        and receipt.post_fingerprint == intent.post_fingerprint
    ):
        raise ValueError("Object receipt does not match its complete intent.")
    if receipt.durable_at < receipt.acknowledged_at:
        raise ValueError("Object receipt durability predates acknowledgement.")
    if receipt.outcome is BridgeReceiptOutcome.APPLIED:
        if receipt.effect_at is None or not (
            intent.fence.acquisition_durable_at
            <= receipt.effect_at
            and receipt.authorized_at <= receipt.effect_at
            <= receipt.acknowledged_at
            < intent.fence.expires_at
        ):
            raise ValueError("Applied receipt lacks in-lease effect evidence.")
    elif receipt.acknowledged_at < intent.fence.expires_at:
        raise ValueError("No-effect ledger outcome requires lease expiry.")


def _validate_verification_binding(
    verification: BridgeOperationVerification,
    intent: BridgeOperationIntent,
    receipt: BridgeOperationReceipt,
) -> None:
    receipt.validate_for(intent)
    verification.__post_init__()
    if not (
        verification.operation_id == intent.operation_id
        and verification.intent_digest == intent.intent_digest
        and verification.receipt_id == receipt.receipt_id
        and verification.receipt_digest == receipt.receipt_digest
        and verification.provider == intent.provider
        and verification.object_key == intent.object_key
        and _same_revision(verification.revision, receipt.result_revision)
        and verification.fingerprint == receipt.result_fingerprint
        and verification.observed_at >= receipt.durable_at
    ):
        raise ValueError("Verification does not match its intent and receipt.")


def _validate_acquisition_record(record: FenceAcquisitionRecord) -> None:
    _require_acquisition_intent(record.intent)
    if not isinstance(record.state, FenceLifecycleState):
        raise TypeError("Acquisition state must be a FenceLifecycleState.")
    if record.receipt is not None:
        _require_acquisition_lifecycle_receipt(record.receipt)
        record.receipt.validate_for(record.intent)
    _validate_optional_reason(record.reason_code, "Acquisition reason")
    _validate_optional_lifecycle_state(record.blocked_from, "Acquisition blocked source")
    if record.state in {
        FenceLifecycleState.INTENT_RECORDED,
        FenceLifecycleState.DISPATCH_ARMED,
    }:
        if (
            record.receipt is not None
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("Pre-ack acquisition contains later evidence.")
    elif record.state is FenceLifecycleState.ACKNOWLEDGED:
        if (
            not isinstance(record.receipt, FenceAcquisitionReceipt)
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("Acknowledged acquisition requires only its receipt.")
    elif record.state is FenceLifecycleState.NO_EFFECT:
        if (
            not isinstance(record.receipt, FenceAcquisitionNoEffectReceipt)
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("No-effect acquisition requires only its tombstone.")
    elif (
        record.receipt is not None
        or record.reason_code is None
        or record.blocked_from
        not in {
            FenceLifecycleState.INTENT_RECORDED,
            FenceLifecycleState.DISPATCH_ARMED,
        }
    ):
        raise ValueError("Blocked acquisition lacks exact source state.")


def _validate_release_record(record: FenceReleaseRecord) -> None:
    _require_release_intent(record.intent)
    if not isinstance(record.state, FenceLifecycleState):
        raise TypeError("Release state must be a FenceLifecycleState.")
    if record.receipt is not None:
        _require_release_lifecycle_receipt(record.receipt)
        record.receipt.validate_for(record.intent)
    _validate_optional_reason(record.reason_code, "Release reason")
    _validate_optional_lifecycle_state(record.blocked_from, "Release blocked source")
    if record.state in {
        FenceLifecycleState.INTENT_RECORDED,
        FenceLifecycleState.DISPATCH_ARMED,
    }:
        if (
            record.receipt is not None
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("Pre-ack release contains later evidence.")
    elif record.state is FenceLifecycleState.ACKNOWLEDGED:
        if (
            not isinstance(record.receipt, FenceReleaseReceipt)
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("Acknowledged release requires only its receipt.")
    elif record.state is FenceLifecycleState.NO_EFFECT:
        if (
            not isinstance(record.receipt, FenceReleaseNoEffectReceipt)
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("No-effect release requires only its tombstone.")
    elif (
        record.receipt is not None
        or record.reason_code is None
        or record.blocked_from
        not in {
            FenceLifecycleState.INTENT_RECORDED,
            FenceLifecycleState.DISPATCH_ARMED,
        }
    ):
        raise ValueError("Blocked release lacks exact source state.")


def _validate_object_intent_fields(intent: BridgeOperationIntent) -> None:
    _validate_plan_binding(intent.plan_id, intent.plan_digest)
    _validate_digest(intent.manifest_digest, "Object intent manifest digest")
    _validate_positive_integer(intent.attempt, "Object intent attempt")
    _validate_positive_integer(intent.sequence, "Object intent sequence")
    if not isinstance(intent.kind, BridgeOperationKind):
        raise TypeError("Object intent kind must be a BridgeOperationKind.")
    _validate_provider(intent.provider, "Object intent provider")
    _validate_string(intent.object_key, "Object intent key")
    _validate_revision(intent.expected_revision, "Object expected revision")
    _validate_digest(intent.pre_fingerprint, "Object preimage")
    _validate_digest(intent.post_fingerprint, "Object postimage")
    if intent.pre_fingerprint == intent.post_fingerprint:
        raise ValueError("Object preimage and postimage must differ.")
    _require_fence(intent.fence)
    if intent.fence.provider != intent.provider:
        raise ValueError("Object intent and fence providers do not match.")
    if intent.kind is BridgeOperationKind.WRITE:
        if intent.parent_operation_id is not None:
            raise ValueError("Write intent cannot have a parent operation.")
    else:
        if intent.parent_operation_id is None:
            raise ValueError("Rollback intent requires a parent write.")
        _validate_object_operation_id(
            intent.parent_operation_id,
            "Rollback parent operation ID",
        )


def _validate_object_record(record: BridgeOperationRecord) -> None:
    _require_object_intent(record.intent)
    if not isinstance(record.state, BridgeOperationState):
        raise TypeError("Object record state must be a BridgeOperationState.")
    if record.authorization is not None:
        _require_authorization(record.authorization)
        record.authorization.validate_for(record.intent)
    if record.receipt is not None:
        _require_object_receipt(record.receipt)
        record.receipt.validate_for(record.intent)
        if record.authorization is None:
            raise ValueError("Object receipt requires dispatch authorization.")
        record.receipt.validate_authorization(record.authorization)
    if type(record.verifications) is not tuple:
        raise TypeError("Object verifications must be an append-only tuple.")
    for index, verification in enumerate(record.verifications):
        if record.receipt is None:
            raise ValueError("Verification requires an object receipt.")
        _require_verification(verification)
        verification.validate_for(record.intent, record.receipt)
        if index:
            previous = record.verifications[index - 1]
            if (
                verification.observed_at <= previous.observed_at
                or verification.verified_at < previous.verified_at
            ):
                raise ValueError("Verification history is not causally append-only.")
    _validate_optional_reason(record.reason_code, "Object operation reason")
    _validate_optional_object_state(record.blocked_from, "Object blocked source")
    if record.state is BridgeOperationState.INTENT_RECORDED:
        if any(
            value is not None
            for value in (
                record.authorization,
                record.receipt,
                record.reason_code,
                record.blocked_from,
            )
        ) or record.verifications:
            raise ValueError("Recorded object intent contains later evidence.")
    elif record.state is BridgeOperationState.DISPATCH_ARMED:
        if (
            record.authorization is None
            or record.receipt is not None
            or record.reason_code is not None
            or record.blocked_from is not None
            or record.verifications
        ):
            raise ValueError("Armed operation requires only its authorization.")
    elif record.state is BridgeOperationState.ACKNOWLEDGED:
        if (
            record.authorization is None
            or record.receipt is None
            or record.verifications
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("Acknowledged operation requires only its receipt.")
    elif record.state is BridgeOperationState.VERIFIED:
        if (
            record.authorization is None
            or record.receipt is None
            or not record.verifications
            or record.reason_code is not None
            or record.blocked_from is not None
        ):
            raise ValueError("Verified operation requires receipt and verification.")
    elif record.reason_code is None or record.blocked_from is None:
        raise ValueError("Blocked operation requires a fixed reason and source.")
    elif record.blocked_from is BridgeOperationState.INTENT_RECORDED:
        if (
            record.authorization is not None
            or record.receipt is not None
            or record.verifications
        ):
            raise ValueError("Undispatched block contains effect evidence.")
    elif record.blocked_from is BridgeOperationState.DISPATCH_ARMED:
        if (
            record.authorization is None
            or record.receipt is not None
            or record.verifications
        ):
            raise ValueError("Armed block lacks immutable authorization evidence.")
    elif record.blocked_from is BridgeOperationState.ACKNOWLEDGED:
        if (
            record.authorization is None
            or record.receipt is None
            or record.verifications
        ):
            raise ValueError("Acknowledged block lacks exact receipt state.")
    elif record.blocked_from is BridgeOperationState.VERIFIED:
        if (
            record.authorization is None
            or record.receipt is None
            or not record.verifications
        ):
            raise ValueError("Verified block lacks retained verification history.")
    else:
        raise ValueError("Blocked operation source is not valid.")


def _validate_attempt(attempt: BridgeOperationAttempt) -> None:
    _validate_plan_binding(attempt.plan_id, attempt.plan_digest)
    _validate_digest(attempt.manifest_digest, "Attempt manifest digest")
    _validate_positive_integer(attempt.attempt, "Attempt number")
    if not isinstance(attempt.state, BridgeAttemptState):
        raise TypeError("Attempt state must be a BridgeAttemptState.")
    _validate_freshness_seconds(attempt.max_observation_age_seconds)
    if type(attempt.expected_writes) is not tuple or not attempt.expected_writes:
        raise ValueError("Attempt requires a non-empty expected-write tuple.")
    for item in attempt.expected_writes:
        _require_expected_write(item)
    expected_keys = tuple(item.key for item in attempt.expected_writes)
    if expected_keys != tuple(sorted(expected_keys)) or len(expected_keys) != len(
        set(expected_keys)
    ):
        raise ValueError("Expected writes must be unique and canonically sorted.")
    for values, label in (
        (attempt.acquisitions, "Attempt acquisitions"),
        (attempt.operations, "Attempt operations"),
        (attempt.releases, "Attempt releases"),
    ):
        if type(values) is not tuple:
            raise TypeError(f"{label} must be a tuple.")
    if attempt.release_phase_sequence is not None:
        _validate_nonnegative_integer(
            attempt.release_phase_sequence,
            "Attempt release phase sequence",
        )
        if attempt.release_phase_sequence > len(attempt.operations):
            raise ValueError("Release phase sequence exceeds operation history.")
    if bool(attempt.releases) != (attempt.release_phase_sequence is not None):
        raise ValueError("Release records and release phase boundary must agree.")
    _validate_optional_reason(attempt.reason_code, "Attempt reason")
    if attempt.terminal_at is not None:
        _validate_utc(attempt.terminal_at, "Attempt terminal time")

    acquisition_by_id: dict[str, FenceAcquisitionRecord] = {}
    provider_epoch: dict[str, int] = {}
    receipt_ids: set[str] = set()
    operation_ids: set[str] = set()
    if tuple(sorted(attempt.acquisitions, key=_acquisition_sort_key)) != (
        attempt.acquisitions
    ):
        raise ValueError("Acquisitions are not canonically sorted.")
    for acquisition in attempt.acquisitions:
        _require_acquisition_record(acquisition)
        source = acquisition.intent
        if (
            source.plan_id != attempt.plan_id
            or source.plan_digest != attempt.plan_digest
            or source.manifest_digest != attempt.manifest_digest
            or source.attempt != attempt.attempt
        ):
            raise ValueError("Acquisition does not match its attempt.")
        previous_epoch = provider_epoch.get(source.provider)
        if previous_epoch is not None and source.epoch <= previous_epoch:
            raise ValueError("Provider acquisition epochs must strictly increase.")
        provider_epoch[source.provider] = source.epoch
        if source.operation_id in operation_ids:
            raise ValueError("Attempt operation identities must be unique.")
        operation_ids.add(source.operation_id)
        acquisition_by_id[source.operation_id] = acquisition
        if acquisition.receipt is not None:
            _claim_local_receipt(receipt_ids, acquisition.receipt.receipt_id)

    expected_by_key = {item.key: item for item in attempt.expected_writes}
    writes_by_key: dict[tuple[str, str], BridgeOperationRecord] = {}
    writes_by_id: dict[str, BridgeOperationRecord] = {}
    rollbacks: dict[str, list[BridgeOperationRecord]] = {}
    object_epoch: dict[str, int] = {}
    for sequence, record in enumerate(attempt.operations, start=1):
        _require_object_record(record)
        intent = record.intent
        if (
            intent.plan_id != attempt.plan_id
            or intent.plan_digest != attempt.plan_digest
            or intent.manifest_digest != attempt.manifest_digest
            or intent.attempt != attempt.attempt
            or intent.sequence != sequence
        ):
            raise ValueError("Object operation does not match attempt sequence.")
        if intent.operation_id in operation_ids:
            raise ValueError("Attempt operation identities must be unique.")
        operation_ids.add(intent.operation_id)
        acquisition = acquisition_by_id.get(intent.fence.acquisition_operation_id)
        if (
            acquisition is None
            or acquisition.state is not FenceLifecycleState.ACKNOWLEDGED
            or not isinstance(acquisition.receipt, FenceAcquisitionReceipt)
            or acquisition.receipt.binding != intent.fence
        ):
            raise ValueError("Object operation lacks its acquired fence receipt.")
        previous_epoch = object_epoch.get(intent.provider)
        if previous_epoch is not None and intent.fence.epoch < previous_epoch:
            raise ValueError("Object operation fence epochs cannot regress.")
        object_epoch[intent.provider] = intent.fence.epoch
        if record.receipt is not None:
            _claim_local_receipt(receipt_ids, record.receipt.receipt_id)
        if record.authorization is not None and not _observation_fresh(
            record.authorization.observed_at,
            record.authorization.authorized_at,
            attempt,
        ):
            raise ValueError("Object dispatch authorization is stale.")
        if intent.kind is BridgeOperationKind.WRITE:
            spec = expected_by_key.get((intent.provider, intent.object_key))
            if spec is None or not _intent_matches_expected(intent, spec):
                raise ValueError("Write intent is outside exact expected coverage.")
            if spec.key in writes_by_key:
                raise ValueError("Expected write has more than one write intent.")
            writes_by_key[spec.key] = record
            writes_by_id[intent.operation_id] = record
            continue
        parent_id = intent.parent_operation_id
        parent = writes_by_id.get(parent_id or "")
        if parent is None or not _eligible_rollback_parent(parent):
            raise ValueError(
                "Rollback parent must be an earlier durable verified applied write."
            )
        rollback_chain = rollbacks.setdefault(parent.intent.operation_id, [])
        if rollback_chain:
            previous_rollback = rollback_chain[-1]
            if not _rollback_proven_no_effect(previous_rollback):
                raise ValueError(
                    "Rollback retry requires exact proven prior no-effect."
                )
            required_epoch = previous_rollback.intent.fence.epoch
        else:
            required_epoch = parent.intent.fence.epoch
        if not (
            intent.provider == parent.intent.provider
            and intent.object_key == parent.intent.object_key
            and intent.pre_fingerprint == parent.intent.post_fingerprint
            and intent.post_fingerprint == parent.intent.pre_fingerprint
            and parent.receipt is not None
            and _same_revision(
                intent.expected_revision,
                parent.receipt.result_revision,
            )
            and intent.fence.epoch > required_epoch
        ):
            raise ValueError("Rollback does not exactly and newly fence its parent.")
        rollback_chain.append(record)

    release_phase_sequence = attempt.release_phase_sequence
    if release_phase_sequence is not None:
        closed_operations = attempt.operations[:release_phase_sequence]
        later_operations = attempt.operations[release_phase_sequence:]
        if any(
            not _operation_effect_resolved(item)
            for item in closed_operations
        ):
            raise ValueError("Release phase closed an unresolved operation.")
        if any(
            item.intent.kind is not BridgeOperationKind.WRITE
            for item in closed_operations
        ):
            raise ValueError("Release phase boundary includes a rollback.")
        if any(
            item.intent.kind is BridgeOperationKind.WRITE
            for item in later_operations
        ):
            raise ValueError("Normal write appears after release phase boundary.")

    releases_by_acquisition: dict[str, list[FenceReleaseRecord]] = {}
    if tuple(sorted(attempt.releases, key=_release_sort_key)) != attempt.releases:
        raise ValueError("Releases are not canonically sorted.")
    for release in attempt.releases:
        _require_release_record(release)
        source = release.intent
        if (
            source.plan_id != attempt.plan_id
            or source.plan_digest != attempt.plan_digest
            or source.manifest_digest != attempt.manifest_digest
            or source.attempt != attempt.attempt
        ):
            raise ValueError("Release does not match its attempt.")
        if source.operation_id in operation_ids:
            raise ValueError("Attempt operation identities must be unique.")
        operation_ids.add(source.operation_id)
        acquisition = acquisition_by_id.get(source.acquisition_operation_id)
        if acquisition is None:
            raise ValueError("Release references an unknown acquisition.")
        _validate_release_intent_acquisition(source, acquisition)
        releases_by_acquisition.setdefault(
            source.acquisition_operation_id,
            [],
        ).append(release)
        if release.receipt is not None:
            _claim_local_receipt(receipt_ids, release.receipt.receipt_id)

    for acquisition_id, release_chain in releases_by_acquisition.items():
        for release_attempt, release in enumerate(release_chain, start=1):
            if release.intent.release_attempt != release_attempt:
                raise ValueError("Release attempts are not contiguous.")
            if release_attempt > 1:
                previous = release_chain[release_attempt - 2]
                if (
                    previous.state is not FenceLifecycleState.NO_EFFECT
                    or not isinstance(
                        previous.receipt,
                        FenceReleaseNoEffectReceipt,
                    )
                    or release.intent.requested_at < previous.receipt.durable_at
                    or not _same_revision(
                        release.intent.expected_inventory_revision,
                        previous.intent.expected_inventory_revision,
                    )
                ):
                    raise ValueError(
                        "Release retry lacks a durable prior no-effect tombstone."
                    )
        first_release = release_chain[0]
        fenced_operations = [
            item
            for item in attempt.operations
            if item.intent.fence.acquisition_operation_id == acquisition_id
        ]
        if any(not _operation_effect_resolved(item) for item in fenced_operations):
            raise ValueError("Fence release began with unresolved object operations.")
        for operation in fenced_operations:
            if _proven_undispatched(operation):
                continue
            if not any(
                verification.verified_at <= first_release.intent.requested_at
                for verification in operation.verifications
            ):
                raise ValueError(
                    "Fence release lacks pre-release effect verification."
                )

    acquisitions_by_provider: dict[str, list[FenceAcquisitionRecord]] = {}
    for acquisition in attempt.acquisitions:
        acquisitions_by_provider.setdefault(acquisition.intent.provider, []).append(
            acquisition
        )
    for provider_acquisitions in acquisitions_by_provider.values():
        for previous, current in zip(
            provider_acquisitions,
            provider_acquisitions[1:],
            strict=False,
        ):
            if _acquisition_proven_undispatched(previous):
                continue
            if previous.state is FenceLifecycleState.NO_EFFECT:
                if (
                    not isinstance(
                        previous.receipt,
                        FenceAcquisitionNoEffectReceipt,
                    )
                    or previous.receipt.durable_at > current.intent.requested_at
                ):
                    raise ValueError(
                        "A newer fence predates the prior acquisition tombstone."
                    )
                continue
            prior_releases = releases_by_acquisition.get(
                previous.intent.operation_id,
                [],
            )
            prior_release = prior_releases[-1] if prior_releases else None
            if (
                previous.state is not FenceLifecycleState.ACKNOWLEDGED
                or not isinstance(previous.receipt, FenceAcquisitionReceipt)
                or prior_release is None
                or prior_release.state is not FenceLifecycleState.ACKNOWLEDGED
                or not isinstance(prior_release.receipt, FenceReleaseReceipt)
                or prior_release.receipt.durable_at > current.intent.requested_at
            ):
                raise ValueError(
                    "A newer provider fence requires durable prior release."
                )

    blocked_evidence = any(
        item.state is FenceLifecycleState.BLOCKED for item in attempt.acquisitions
    ) or any(
        item.state is BridgeOperationState.BLOCKED for item in attempt.operations
    ) or any(item.state is FenceLifecycleState.BLOCKED for item in attempt.releases)
    no_effect_acquisition_evidence = any(
        item.state is FenceLifecycleState.NO_EFFECT
        for item in attempt.acquisitions
    )
    if attempt.state is BridgeAttemptState.OPEN:
        if attempt.reason_code is not None or attempt.terminal_at is not None:
            raise ValueError("Open attempt cannot have terminal metadata.")
        if blocked_evidence:
            raise ValueError("Open attempt cannot contain blocked operations.")
        return
    if attempt.state is BridgeAttemptState.BLOCKED:
        if attempt.reason_code is None or not blocked_evidence:
            raise ValueError("Blocked attempt requires fixed blocked evidence.")
        if attempt.terminal_at is not None:
            raise ValueError("Compensatable blocked attempt is not terminalized.")
        return
    if attempt.terminal_at is None:
        raise ValueError("Terminal attempt requires its terminal time.")
    if attempt.state is BridgeAttemptState.COMMITTED:
        if attempt.reason_code is not None or blocked_evidence:
            raise ValueError("Committed attempt cannot retain blocked evidence.")
    elif blocked_evidence != (attempt.reason_code is not None):
        raise ValueError("Restored blocked evidence and reason must agree.")
    if (
        attempt.state is BridgeAttemptState.COMMITTED
        and set(writes_by_key) != set(expected_by_key)
    ):
        raise ValueError("Committed attempt lacks exact expected-write coverage.")
    missing_expected = set(expected_by_key) - set(writes_by_key)
    if missing_expected:
        if attempt.state is not BridgeAttemptState.RESTORED:
            raise ValueError("Terminal attempt lacks expected-write coverage.")
        if not (blocked_evidence or no_effect_acquisition_evidence):
            raise ValueError("Missing writes require immutable abort evidence.")
    _validate_terminal_lifecycle(
        attempt,
        acquisition_by_id,
        releases_by_acquisition,
    )
    if attempt.state is BridgeAttemptState.COMMITTED:
        if any(rollbacks.values()):
            raise ValueError("Committed attempt cannot contain rollbacks.")
        for record in writes_by_key.values():
            if not _verified_outcome(record, BridgeReceiptOutcome.APPLIED):
                raise ValueError("Committed write must be verified and applied.")
            _validate_terminal_verification(record, attempt)
        return
    for record in writes_by_key.values():
        if _proven_undispatched(record):
            if rollbacks.get(record.intent.operation_id):
                raise ValueError("Undispatched write cannot have a rollback.")
            continue
        if record.receipt is None or record.verification is None:
            raise ValueError("Restored write must have a verified durable outcome.")
        rollback_chain = rollbacks.get(record.intent.operation_id, [])
        if record.receipt.outcome is BridgeReceiptOutcome.NO_EFFECT:
            if record.state is not BridgeOperationState.VERIFIED:
                raise ValueError("No-effect write has uncertain terminal state.")
            if rollback_chain:
                raise ValueError("No-effect write cannot have a rollback.")
            _validate_terminal_verification(record, attempt)
        else:
            if not _eligible_rollback_parent(record) or not rollback_chain:
                raise ValueError("Applied write lacks exact verified rollback.")
            if any(
                not _rollback_proven_no_effect(item)
                for item in rollback_chain[:-1]
            ):
                raise ValueError("Rollback retry chain contains uncertain effects.")
            final_rollback = rollback_chain[-1]
            if not _verified_outcome(
                final_rollback,
                BridgeReceiptOutcome.APPLIED,
            ):
                raise ValueError("Applied write lacks final verified compensation.")
            _validate_terminal_verification(final_rollback, attempt)


def _validate_terminal_lifecycle(
    attempt: BridgeOperationAttempt,
    acquisitions: dict[str, FenceAcquisitionRecord],
    releases: dict[str, list[FenceReleaseRecord]],
) -> None:
    terminal_at = attempt.terminal_at
    if terminal_at is None:
        raise ValueError("Terminal lifecycle requires terminal time.")
    if not acquisitions:
        raise ValueError("Terminal attempt requires acquired fences.")
    for operation_id, acquisition in acquisitions.items():
        release_chain = releases.get(operation_id, [])
        if acquisition.state is FenceLifecycleState.NO_EFFECT:
            if (
                not isinstance(
                    acquisition.receipt,
                    FenceAcquisitionNoEffectReceipt,
                )
                or acquisition.receipt.durable_at > terminal_at
                or release_chain
            ):
                raise ValueError("Terminal acquisition tombstone is incomplete.")
            continue
        if acquisition.state is FenceLifecycleState.BLOCKED:
            if not _acquisition_proven_undispatched(acquisition) or release_chain:
                raise ValueError("Blocked acquisition effect remains uncertain.")
            continue
        if (
            acquisition.state is not FenceLifecycleState.ACKNOWLEDGED
            or not isinstance(acquisition.receipt, FenceAcquisitionReceipt)
            or acquisition.receipt.durable_at > terminal_at
        ):
            raise ValueError("Terminal attempt has incomplete fence acquisition.")
        if not release_chain:
            raise ValueError("Terminal attempt lacks durable fence release.")
        for release in release_chain[:-1]:
            if (
                release.state is not FenceLifecycleState.NO_EFFECT
                or not isinstance(release.receipt, FenceReleaseNoEffectReceipt)
                or release.receipt.durable_at > terminal_at
            ):
                raise ValueError("Release retry history contains uncertain effects.")
        final_release = release_chain[-1]
        if (
            final_release.state is not FenceLifecycleState.ACKNOWLEDGED
            or not isinstance(final_release.receipt, FenceReleaseReceipt)
            or final_release.receipt.durable_at > terminal_at
        ):
            raise ValueError("Applied fence lacks a final durable release.")
    if not set(releases).issubset(acquisitions):
        raise ValueError("Terminal release references unknown acquisition.")


def _validate_terminal_verification(
    record: BridgeOperationRecord,
    attempt: BridgeOperationAttempt,
) -> None:
    if record.verification is None or attempt.terminal_at is None:
        raise ValueError("Terminal operation lacks verification evidence.")
    if not _observation_fresh(
        record.verification.observed_at,
        attempt.terminal_at,
        attempt,
    ) or record.verification.verified_at > attempt.terminal_at:
        raise ValueError("Terminal verification evidence is stale.")


def _validate_release_intent_acquisition(
    intent: FenceReleaseIntent,
    acquisition: FenceAcquisitionRecord,
) -> None:
    if (
        acquisition.state is not FenceLifecycleState.ACKNOWLEDGED
        or not isinstance(acquisition.receipt, FenceAcquisitionReceipt)
    ):
        raise ValueError("Release requires acknowledged acquisition evidence.")
    receipt = acquisition.receipt
    if not (
        intent.plan_id == acquisition.intent.plan_id
        and intent.plan_digest == acquisition.intent.plan_digest
        and intent.manifest_digest == acquisition.intent.manifest_digest
        and intent.attempt == acquisition.intent.attempt
        and intent.provider == receipt.provider
        and intent.writer_id == receipt.writer_id
        and intent.acquisition_operation_id == receipt.operation_id
        and intent.acquisition_receipt_id == receipt.receipt_id
        and intent.acquisition_receipt_digest == receipt.receipt_digest
        and intent.token_digest == receipt.token_digest
        and intent.scope_digest == receipt.scope_digest
        and intent.epoch == receipt.epoch
        and intent.requested_at >= receipt.durable_at
    ):
        raise ValueError("Release intent does not match its acquisition.")


def _intent_matches_expected(
    intent: BridgeOperationIntent,
    expected: BridgeExpectedWrite,
) -> bool:
    return (
        intent.kind is BridgeOperationKind.WRITE
        and intent.provider == expected.provider
        and intent.object_key == expected.object_key
        and _same_revision(intent.expected_revision, expected.expected_revision)
        and intent.pre_fingerprint == expected.pre_fingerprint
        and intent.post_fingerprint == expected.post_fingerprint
    )


def _eligible_rollback_parent(record: BridgeOperationRecord) -> bool:
    return (
        (
            record.state is BridgeOperationState.VERIFIED
            or (
                record.state is BridgeOperationState.BLOCKED
                and record.blocked_from is BridgeOperationState.VERIFIED
            )
        )
        and record.receipt is not None
        and record.verification is not None
        and record.receipt.outcome is BridgeReceiptOutcome.APPLIED
    )


def _verified_outcome(
    record: BridgeOperationRecord,
    outcome: BridgeReceiptOutcome,
) -> bool:
    return (
        record.state is BridgeOperationState.VERIFIED
        and record.receipt is not None
        and record.verification is not None
        and record.receipt.outcome is outcome
    )


def _proven_undispatched(record: BridgeOperationRecord) -> bool:
    return (
        record.state is BridgeOperationState.BLOCKED
        and record.blocked_from is BridgeOperationState.INTENT_RECORDED
        and record.authorization is None
        and record.receipt is None
        and not record.verifications
    )


def _rollback_proven_no_effect(record: BridgeOperationRecord) -> bool:
    return _proven_undispatched(record) or _verified_outcome(
        record,
        BridgeReceiptOutcome.NO_EFFECT,
    )


def _operation_effect_resolved(record: BridgeOperationRecord) -> bool:
    if record.state is BridgeOperationState.VERIFIED:
        return True
    if record.state is not BridgeOperationState.BLOCKED:
        return False
    if _proven_undispatched(record):
        return True
    return (
        record.blocked_from is BridgeOperationState.VERIFIED
        and record.receipt is not None
        and bool(record.verifications)
    )


def _acquisition_proven_undispatched(record: FenceAcquisitionRecord) -> bool:
    return (
        record.state is FenceLifecycleState.BLOCKED
        and record.blocked_from is FenceLifecycleState.INTENT_RECORDED
        and record.receipt is None
    )


def _provider_needs_compensation(
    attempt: BridgeOperationAttempt,
    provider: str,
) -> bool:
    rollback_chains: dict[str, list[BridgeOperationRecord]] = {}
    for item in attempt.operations:
        if item.intent.kind is BridgeOperationKind.ROLLBACK:
            rollback_chains.setdefault(item.intent.parent_operation_id or "", []).append(
                item
            )
    for item in attempt.operations:
        if (
            item.intent.provider != provider
            or item.intent.kind is not BridgeOperationKind.WRITE
            or not _eligible_rollback_parent(item)
        ):
            continue
        chain = rollback_chains.get(item.intent.operation_id, [])
        if not chain or _rollback_proven_no_effect(chain[-1]):
            return True
    return False


def _retry_expected_writes(
    attempt: BridgeOperationAttempt,
) -> tuple[BridgeExpectedWrite, ...]:
    if attempt.state is not BridgeAttemptState.RESTORED:
        raise ValueError("Retry coverage requires a restored attempt.")
    writes = {
        (item.intent.provider, item.intent.object_key): item
        for item in attempt.operations
        if item.intent.kind is BridgeOperationKind.WRITE
    }
    rollbacks: dict[str, list[BridgeOperationRecord]] = {}
    for item in attempt.operations:
        if item.intent.kind is BridgeOperationKind.ROLLBACK:
            rollbacks.setdefault(item.intent.parent_operation_id or "", []).append(item)
    result: list[BridgeExpectedWrite] = []
    for expected in attempt.expected_writes:
        write = writes.get(expected.key)
        if write is None or _proven_undispatched(write):
            revision = expected.expected_revision
        elif write.receipt is None:
            raise ValueError("Restored retry write lacks a receipt.")
        elif write.receipt.outcome is BridgeReceiptOutcome.NO_EFFECT:
            revision = write.receipt.result_revision
        else:
            rollback_chain = rollbacks.get(write.intent.operation_id, [])
            rollback = rollback_chain[-1] if rollback_chain else None
            if rollback is None or rollback.receipt is None:
                raise ValueError("Restored retry write lacks rollback receipt.")
            revision = rollback.receipt.result_revision
        result.append(
            BridgeExpectedWrite(
                provider=expected.provider,
                object_key=expected.object_key,
                expected_revision=revision,
                pre_fingerprint=expected.pre_fingerprint,
                post_fingerprint=expected.post_fingerprint,
            )
        )
    return tuple(result)


def _acquisition_for_id(
    attempt: BridgeOperationAttempt,
    operation_id: str,
) -> FenceAcquisitionRecord | None:
    return next(
        (
            item
            for item in attempt.acquisitions
            if item.intent.operation_id == operation_id
        ),
        None,
    )


def _attempt_identity_rows(
    attempt: BridgeOperationAttempt,
) -> tuple[tuple[str, str, str | None], ...]:
    rows: list[tuple[str, str, str | None]] = []
    for item in attempt.acquisitions:
        rows.append(
            (
                item.intent.operation_id,
                "acquisition",
                None if item.receipt is None else item.receipt.receipt_id,
            )
        )
    for item in attempt.operations:
        rows.append(
            (
                item.intent.operation_id,
                "object",
                None if item.receipt is None else item.receipt.receipt_id,
            )
        )
    for item in attempt.releases:
        rows.append(
            (
                item.intent.operation_id,
                "release",
                None if item.receipt is None else item.receipt.receipt_id,
            )
        )
    return tuple(rows)


def _claim_local_receipt(receipts: set[str], receipt_id: str) -> None:
    if receipt_id in receipts:
        raise ValueError("Attempt receipt identities must be unique.")
    receipts.add(receipt_id)


def _acquisition_sort_key(
    record: FenceAcquisitionRecord,
) -> tuple[str, int, str]:
    return record.intent.provider, record.intent.epoch, record.intent.operation_id


def _release_sort_key(record: FenceReleaseRecord) -> tuple[str, int, int, str]:
    return (
        record.intent.provider,
        record.intent.epoch,
        record.intent.release_attempt,
        record.intent.operation_id,
    )


def _binding_matches_release(
    binding: FenceBinding | None,
    intent: FenceReleaseIntent,
) -> bool:
    return binding is not None and (
        binding.provider == intent.provider
        and binding.writer_id == intent.writer_id
        and binding.token_digest == intent.token_digest
        and binding.epoch == intent.epoch
        and binding.scope_digest == intent.scope_digest
        and binding.acquisition_operation_id == intent.acquisition_operation_id
        and binding.acquisition_receipt_id == intent.acquisition_receipt_id
        and binding.acquisition_receipt_digest == intent.acquisition_receipt_digest
    )


def _observation_identity_matches(
    observation: BridgeObjectObservation,
    intent: BridgeOperationIntent,
) -> bool:
    return (
        observation.provider == intent.provider
        and observation.object_key == intent.object_key
    )


def _observation_is_preimage(
    observation: BridgeObjectObservation,
    intent: BridgeOperationIntent,
) -> bool:
    return (
        _observation_identity_matches(observation, intent)
        and _same_revision(observation.revision, intent.expected_revision)
        and observation.fingerprint == intent.pre_fingerprint
    )


def _observation_is_postimage(
    observation: BridgeObjectObservation,
    intent: BridgeOperationIntent,
) -> bool:
    return (
        _observation_identity_matches(observation, intent)
        and observation.fingerprint == intent.post_fingerprint
    )


def _observation_matches_receipt(
    observation: BridgeObjectObservation,
    receipt: BridgeOperationReceipt,
) -> bool:
    return (
        observation.provider == receipt.provider
        and observation.object_key == receipt.object_key
        and _same_revision(observation.revision, receipt.result_revision)
        and observation.fingerprint == receipt.result_fingerprint
        and observation.observed_at >= receipt.durable_at
    )


def _observation_fresh(
    observed_at: datetime,
    at: datetime,
    attempt: BridgeOperationAttempt,
) -> bool:
    return (
        observed_at <= at
        and at - observed_at
        <= timedelta(seconds=attempt.max_observation_age_seconds)
    )


def _fence_live_at(fence: FenceBinding, at: datetime) -> bool:
    return fence.acquired_at <= at < fence.expires_at


def _freshness_seconds(value: timedelta) -> int:
    if type(value) is not timedelta:
        raise TypeError("Maximum observation age must be a timedelta.")
    seconds = value.total_seconds()
    if not seconds.is_integer():
        raise ValueError("Maximum observation age must use whole seconds.")
    result = int(seconds)
    _validate_freshness_seconds(result)
    return result


def _validate_freshness_seconds(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_FRESHNESS_SECONDS:
        raise ValueError("Observation freshness seconds are out of range.")


def _validate_plan_binding(plan_id: str, plan_digest: str) -> None:
    _validate_string(plan_id, "Reference plan ID")
    _validate_digest(plan_digest, "Reference plan digest")
    identity = hashlib.sha256(
        f"reference-plan:{plan_digest}".encode("utf-8")
    ).hexdigest()
    if plan_id != f"tf-reference-{identity[:24]}":
        raise ValueError("Reference plan ID does not match its digest.")


def _validate_provider(value: Any, label: str) -> None:
    if type(value) is not str or value not in TRUE_FAMILY_PROVIDER_MANIFEST:
        raise ValueError(f"{label} must name one provider in the manifest.")


def _validate_string(value: Any, label: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} must be canonical non-empty text.")


def _validate_revision(value: Any, label: str) -> None:
    if type(value) is int:
        if value < 0:
            raise ValueError(f"{label} cannot be negative.")
        return
    if (
        type(value) is str
        and 0 < len(value) <= _MAX_REVISION_LENGTH
        and all(33 <= ord(character) <= 126 for character in value)
    ):
        return
    raise ValueError(f"{label} is not a canonical typed revision.")


def _validate_digest(value: Any, label: str) -> None:
    if type(value) is not str or not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest.")


def _validate_fence_token_digest(value: Any, label: str) -> None:
    if (
        type(value) is not FenceTokenDigest
        or not _FENCE_TOKEN_DIGEST_PATTERN.fullmatch(value.value)
    ):
        raise ValueError(f"{label} must be a branded fence-token digest.")


def _validate_object_operation_id(value: Any, label: str) -> None:
    if type(value) is not str or not _OBJECT_OPERATION_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not canonical.")


def _validate_acquire_operation_id(value: Any, label: str) -> None:
    if type(value) is not str or not _ACQUIRE_OPERATION_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not canonical.")


def _validate_release_operation_id(value: Any, label: str) -> None:
    if type(value) is not str or not _RELEASE_OPERATION_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not canonical.")


def _validate_receipt_id(value: Any, label: str) -> None:
    if type(value) is not str or not _RECEIPT_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not canonical.")


def _validate_positive_integer(value: Any, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive integer.")


def _validate_nonnegative_integer(value: Any, label: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer.")


def _validate_utc(value: Any, label: str) -> None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError(f"{label} must be an aware UTC datetime.")


def _validate_optional_reason(value: Any, label: str) -> None:
    if value is not None and not isinstance(value, BridgeBlockReason):
        raise TypeError(f"{label} must be a fixed BridgeBlockReason.")


def _validate_optional_lifecycle_state(value: Any, label: str) -> None:
    if value is not None and not isinstance(value, FenceLifecycleState):
        raise TypeError(f"{label} must be a FenceLifecycleState.")


def _validate_optional_object_state(value: Any, label: str) -> None:
    if value is not None and not isinstance(value, BridgeOperationState):
        raise TypeError(f"{label} must be a BridgeOperationState.")


def _same_revision(left: Revision, right: Revision) -> bool:
    return type(left) is type(right) and left == right


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as err:
        raise ValueError("Bridge metadata cannot be represented canonically.") from err


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def bridge_expected_write_coverage_digest(
    expected_writes: tuple[BridgeExpectedWrite, ...],
) -> str:
    """Digest exact canonical write coverage without asserting plan authority."""

    if type(expected_writes) is not tuple or not expected_writes:
        raise ValueError("Expected-write coverage requires a non-empty tuple.")
    for item in expected_writes:
        _require_expected_write(item)
    keys = tuple(item.key for item in expected_writes)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError("Expected-write coverage must be unique and sorted.")
    return _digest_json(
        {
            "domain": "true-family/reference-bridge/expected-write-coverage/v1",
            "expected_writes": [
                {
                    "provider": item.provider,
                    "object_key": item.object_key,
                    "expected_revision": _encode_revision(item.expected_revision),
                    "pre_fingerprint": item.pre_fingerprint,
                    "post_fingerprint": item.post_fingerprint,
                }
                for item in expected_writes
            ],
        }
    )


def _receipt_identity(domain: str, data: dict[str, Any]) -> tuple[str, str]:
    identity = _digest_json({"domain": domain, "content": data})
    receipt_id = f"tf-receipt-{identity[:24]}"
    receipt_digest = _digest_json(
        {"domain": domain, "receipt_id": receipt_id, "content": data}
    )
    return receipt_id, receipt_digest


def _encode_revision(value: Revision) -> dict[str, Any]:
    _validate_revision(value, "Revision")
    return {
        "type": "integer" if type(value) is int else "string",
        "value": value,
    }


def _encode_timestamp(value: datetime) -> str:
    _validate_utc(value, "Timestamp")
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _acquisition_intent_data(intent: FenceAcquisitionIntent) -> dict[str, Any]:
    return _acquisition_intent_data_from_fields(
        plan_id=intent.plan_id,
        plan_digest=intent.plan_digest,
        manifest_digest=intent.manifest_digest,
        attempt=intent.attempt,
        provider=intent.provider,
        writer_id=intent.writer_id,
        expected_inventory_revision=intent.expected_inventory_revision,
        scope_digest=intent.scope_digest,
        epoch=intent.epoch,
        requested_at=intent.requested_at,
        expires_at=intent.expires_at,
    )


def _acquisition_intent_data_from_fields(**values: Any) -> dict[str, Any]:
    return {
        "schema": 1,
        "plan_id": values["plan_id"],
        "plan_digest": values["plan_digest"],
        "manifest_digest": values["manifest_digest"],
        "attempt": values["attempt"],
        "provider": values["provider"],
        "writer_id": values["writer_id"],
        "expected_inventory_revision": _encode_revision(
            values["expected_inventory_revision"]
        ),
        "scope_digest": values["scope_digest"],
        "epoch": values["epoch"],
        "requested_at": _encode_timestamp(values["requested_at"]),
        "expires_at": _encode_timestamp(values["expires_at"]),
    }


def _acquisition_receipt_data(
    receipt: FenceAcquisitionReceipt,
    *,
    include_receipt_id: bool,
) -> dict[str, Any]:
    data = _acquisition_receipt_data_from_fields(
        operation_id=receipt.operation_id,
        intent_digest=receipt.intent_digest,
        provider=receipt.provider,
        writer_id=receipt.writer_id,
        expected_inventory_revision=receipt.expected_inventory_revision,
        acquired_inventory_revision=receipt.acquired_inventory_revision,
        fence_revision=receipt.fence_revision,
        scope_digest=receipt.scope_digest,
        epoch=receipt.epoch,
        token_digest=receipt.token_digest,
        acquired_at=receipt.acquired_at,
        expires_at=receipt.expires_at,
        acknowledged_at=receipt.acknowledged_at,
        durable_at=receipt.durable_at,
    )
    if include_receipt_id:
        data["receipt_id"] = receipt.receipt_id
    return data


def _acquisition_receipt_data_from_fields(**values: Any) -> dict[str, Any]:
    return {
        "schema": 1,
        "operation_id": values["operation_id"],
        "intent_digest": values["intent_digest"],
        "provider": values["provider"],
        "writer_id": values["writer_id"],
        "expected_inventory_revision": _encode_revision(
            values["expected_inventory_revision"]
        ),
        "acquired_inventory_revision": _encode_revision(
            values["acquired_inventory_revision"]
        ),
        "fence_revision": _encode_revision(values["fence_revision"]),
        "scope_digest": values["scope_digest"],
        "epoch": values["epoch"],
        "token_digest": values["token_digest"].value,
        "acquired_at": _encode_timestamp(values["acquired_at"]),
        "expires_at": _encode_timestamp(values["expires_at"]),
        "acknowledged_at": _encode_timestamp(values["acknowledged_at"]),
        "durable_at": _encode_timestamp(values["durable_at"]),
    }


def _acquisition_no_effect_data(
    receipt: FenceAcquisitionNoEffectReceipt,
    *,
    include_receipt_id: bool,
) -> dict[str, Any]:
    data = _acquisition_no_effect_data_from_fields(
        operation_id=receipt.operation_id,
        intent_digest=receipt.intent_digest,
        provider=receipt.provider,
        writer_id=receipt.writer_id,
        expected_inventory_revision=receipt.expected_inventory_revision,
        scope_digest=receipt.scope_digest,
        epoch=receipt.epoch,
        outcome=receipt.outcome,
        evidence=receipt.evidence,
        acknowledged_at=receipt.acknowledged_at,
        durable_at=receipt.durable_at,
        durable=receipt.durable,
    )
    if include_receipt_id:
        data["receipt_id"] = receipt.receipt_id
    return data


def _acquisition_no_effect_data_from_fields(**values: Any) -> dict[str, Any]:
    outcome = values["outcome"]
    evidence = values["evidence"]
    if not isinstance(outcome, BridgeReceiptOutcome):
        raise TypeError("Acquisition tombstone outcome is not typed.")
    if not isinstance(evidence, BridgeReceiptEvidence):
        raise TypeError("Acquisition tombstone evidence is not typed.")
    return {
        "schema": 1,
        "operation_id": values["operation_id"],
        "intent_digest": values["intent_digest"],
        "provider": values["provider"],
        "writer_id": values["writer_id"],
        "expected_inventory_revision": _encode_revision(
            values["expected_inventory_revision"]
        ),
        "scope_digest": values["scope_digest"],
        "epoch": values["epoch"],
        "outcome": outcome.value,
        "evidence": evidence.value,
        "acknowledged_at": _encode_timestamp(values["acknowledged_at"]),
        "durable_at": _encode_timestamp(values["durable_at"]),
        "durable": values["durable"],
    }


def _release_intent_data(intent: FenceReleaseIntent) -> dict[str, Any]:
    return _release_intent_data_from_fields(
        plan_id=intent.plan_id,
        plan_digest=intent.plan_digest,
        manifest_digest=intent.manifest_digest,
        attempt=intent.attempt,
        release_attempt=intent.release_attempt,
        provider=intent.provider,
        writer_id=intent.writer_id,
        acquisition_operation_id=intent.acquisition_operation_id,
        acquisition_receipt_id=intent.acquisition_receipt_id,
        acquisition_receipt_digest=intent.acquisition_receipt_digest,
        token_digest=intent.token_digest,
        scope_digest=intent.scope_digest,
        epoch=intent.epoch,
        expected_inventory_revision=intent.expected_inventory_revision,
        requested_at=intent.requested_at,
    )


def _release_intent_data_from_fields(**values: Any) -> dict[str, Any]:
    return {
        "schema": 1,
        "plan_id": values["plan_id"],
        "plan_digest": values["plan_digest"],
        "manifest_digest": values["manifest_digest"],
        "attempt": values["attempt"],
        "release_attempt": values["release_attempt"],
        "provider": values["provider"],
        "writer_id": values["writer_id"],
        "acquisition_operation_id": values["acquisition_operation_id"],
        "acquisition_receipt_id": values["acquisition_receipt_id"],
        "acquisition_receipt_digest": values["acquisition_receipt_digest"],
        "token_digest": values["token_digest"].value,
        "scope_digest": values["scope_digest"],
        "epoch": values["epoch"],
        "expected_inventory_revision": _encode_revision(
            values["expected_inventory_revision"]
        ),
        "requested_at": _encode_timestamp(values["requested_at"]),
    }


def _release_receipt_data(
    receipt: FenceReleaseReceipt,
    *,
    include_receipt_id: bool,
) -> dict[str, Any]:
    data = _release_receipt_data_from_fields(
        operation_id=receipt.operation_id,
        intent_digest=receipt.intent_digest,
        release_attempt=receipt.release_attempt,
        provider=receipt.provider,
        writer_id=receipt.writer_id,
        acquisition_operation_id=receipt.acquisition_operation_id,
        acquisition_receipt_id=receipt.acquisition_receipt_id,
        acquisition_receipt_digest=receipt.acquisition_receipt_digest,
        token_digest=receipt.token_digest,
        scope_digest=receipt.scope_digest,
        epoch=receipt.epoch,
        expected_inventory_revision=receipt.expected_inventory_revision,
        final_inventory_revision=receipt.final_inventory_revision,
        released_at=receipt.released_at,
        acknowledged_at=receipt.acknowledged_at,
        durable_at=receipt.durable_at,
    )
    if include_receipt_id:
        data["receipt_id"] = receipt.receipt_id
    return data


def _release_receipt_data_from_fields(**values: Any) -> dict[str, Any]:
    return {
        "schema": 1,
        "operation_id": values["operation_id"],
        "intent_digest": values["intent_digest"],
        "release_attempt": values["release_attempt"],
        "provider": values["provider"],
        "writer_id": values["writer_id"],
        "acquisition_operation_id": values["acquisition_operation_id"],
        "acquisition_receipt_id": values["acquisition_receipt_id"],
        "acquisition_receipt_digest": values["acquisition_receipt_digest"],
        "token_digest": values["token_digest"].value,
        "scope_digest": values["scope_digest"],
        "epoch": values["epoch"],
        "expected_inventory_revision": _encode_revision(
            values["expected_inventory_revision"]
        ),
        "final_inventory_revision": _encode_revision(
            values["final_inventory_revision"]
        ),
        "released_at": _encode_timestamp(values["released_at"]),
        "acknowledged_at": _encode_timestamp(values["acknowledged_at"]),
        "durable_at": _encode_timestamp(values["durable_at"]),
    }


def _release_no_effect_data(
    receipt: FenceReleaseNoEffectReceipt,
    *,
    include_receipt_id: bool,
) -> dict[str, Any]:
    data = _release_no_effect_data_from_fields(
        operation_id=receipt.operation_id,
        intent_digest=receipt.intent_digest,
        release_attempt=receipt.release_attempt,
        provider=receipt.provider,
        writer_id=receipt.writer_id,
        acquisition_operation_id=receipt.acquisition_operation_id,
        acquisition_receipt_id=receipt.acquisition_receipt_id,
        acquisition_receipt_digest=receipt.acquisition_receipt_digest,
        token_digest=receipt.token_digest,
        scope_digest=receipt.scope_digest,
        epoch=receipt.epoch,
        expected_inventory_revision=receipt.expected_inventory_revision,
        outcome=receipt.outcome,
        evidence=receipt.evidence,
        acknowledged_at=receipt.acknowledged_at,
        durable_at=receipt.durable_at,
        durable=receipt.durable,
    )
    if include_receipt_id:
        data["receipt_id"] = receipt.receipt_id
    return data


def _release_no_effect_data_from_fields(**values: Any) -> dict[str, Any]:
    outcome = values["outcome"]
    evidence = values["evidence"]
    if not isinstance(outcome, BridgeReceiptOutcome):
        raise TypeError("Release tombstone outcome is not typed.")
    if not isinstance(evidence, BridgeReceiptEvidence):
        raise TypeError("Release tombstone evidence is not typed.")
    return {
        "schema": 1,
        "operation_id": values["operation_id"],
        "intent_digest": values["intent_digest"],
        "release_attempt": values["release_attempt"],
        "provider": values["provider"],
        "writer_id": values["writer_id"],
        "acquisition_operation_id": values["acquisition_operation_id"],
        "acquisition_receipt_id": values["acquisition_receipt_id"],
        "acquisition_receipt_digest": values["acquisition_receipt_digest"],
        "token_digest": values["token_digest"].value,
        "scope_digest": values["scope_digest"],
        "epoch": values["epoch"],
        "expected_inventory_revision": _encode_revision(
            values["expected_inventory_revision"]
        ),
        "outcome": outcome.value,
        "evidence": evidence.value,
        "acknowledged_at": _encode_timestamp(values["acknowledged_at"]),
        "durable_at": _encode_timestamp(values["durable_at"]),
        "durable": values["durable"],
    }


def _fence_data(fence: FenceBinding) -> dict[str, Any]:
    return {
        "provider": fence.provider,
        "writer_id": fence.writer_id,
        "token_digest": fence.token_digest.value,
        "epoch": fence.epoch,
        "fence_revision": _encode_revision(fence.fence_revision),
        "base_revision": _encode_revision(fence.base_revision),
        "scope_digest": fence.scope_digest,
        "acquired_at": _encode_timestamp(fence.acquired_at),
        "acquisition_durable_at": _encode_timestamp(
            fence.acquisition_durable_at
        ),
        "expires_at": _encode_timestamp(fence.expires_at),
        "acquisition_operation_id": fence.acquisition_operation_id,
        "acquisition_receipt_id": fence.acquisition_receipt_id,
        "acquisition_receipt_digest": fence.acquisition_receipt_digest,
    }


def _authorization_data(
    authorization: BridgeDispatchAuthorization,
) -> dict[str, Any]:
    return _authorization_data_from_fields(
        operation_id=authorization.operation_id,
        intent_digest=authorization.intent_digest,
        provider=authorization.provider,
        object_key=authorization.object_key,
        fence_acquisition_operation_id=(
            authorization.fence_acquisition_operation_id
        ),
        fence_acquisition_receipt_id=(
            authorization.fence_acquisition_receipt_id
        ),
        fence_acquisition_receipt_digest=(
            authorization.fence_acquisition_receipt_digest
        ),
        revision=authorization.revision,
        fingerprint=authorization.fingerprint,
        observed_at=authorization.observed_at,
        authorized_at=authorization.authorized_at,
    )


def _authorization_data_from_fields(**values: Any) -> dict[str, Any]:
    return {
        "schema": 1,
        "operation_id": values["operation_id"],
        "intent_digest": values["intent_digest"],
        "provider": values["provider"],
        "object_key": values["object_key"],
        "fence_acquisition_operation_id": values[
            "fence_acquisition_operation_id"
        ],
        "fence_acquisition_receipt_id": values[
            "fence_acquisition_receipt_id"
        ],
        "fence_acquisition_receipt_digest": values[
            "fence_acquisition_receipt_digest"
        ],
        "revision": _encode_revision(values["revision"]),
        "fingerprint": values["fingerprint"],
        "observed_at": _encode_timestamp(values["observed_at"]),
        "authorized_at": _encode_timestamp(values["authorized_at"]),
    }


def _object_intent_data(intent: BridgeOperationIntent) -> dict[str, Any]:
    return _object_intent_data_from_fields(
        plan_id=intent.plan_id,
        plan_digest=intent.plan_digest,
        manifest_digest=intent.manifest_digest,
        attempt=intent.attempt,
        sequence=intent.sequence,
        kind=intent.kind,
        provider=intent.provider,
        object_key=intent.object_key,
        expected_revision=intent.expected_revision,
        pre_fingerprint=intent.pre_fingerprint,
        post_fingerprint=intent.post_fingerprint,
        fence=intent.fence,
        parent_operation_id=intent.parent_operation_id,
    )


def _object_intent_data_from_fields(**values: Any) -> dict[str, Any]:
    kind = values["kind"]
    if not isinstance(kind, BridgeOperationKind):
        raise TypeError("Object intent kind must be a BridgeOperationKind.")
    fence = values["fence"]
    _require_fence(fence)
    return {
        "schema": 1,
        "plan_id": values["plan_id"],
        "plan_digest": values["plan_digest"],
        "manifest_digest": values["manifest_digest"],
        "attempt": values["attempt"],
        "sequence": values["sequence"],
        "kind": kind.value,
        "provider": values["provider"],
        "object_key": values["object_key"],
        "expected_revision": _encode_revision(values["expected_revision"]),
        "pre_fingerprint": values["pre_fingerprint"],
        "post_fingerprint": values["post_fingerprint"],
        "fence": _fence_data(fence),
        "parent_operation_id": values["parent_operation_id"],
    }


def _object_receipt_data(
    receipt: BridgeOperationReceipt,
    *,
    include_receipt_id: bool,
) -> dict[str, Any]:
    data = _object_receipt_data_from_fields(
        operation_id=receipt.operation_id,
        intent_digest=receipt.intent_digest,
        kind=receipt.kind,
        provider=receipt.provider,
        object_key=receipt.object_key,
        fence_token_digest=receipt.fence_token_digest,
        fence_epoch=receipt.fence_epoch,
        fence_scope_digest=receipt.fence_scope_digest,
        fence_writer_id=receipt.fence_writer_id,
        fence_acquisition_operation_id=receipt.fence_acquisition_operation_id,
        fence_acquisition_receipt_id=receipt.fence_acquisition_receipt_id,
        fence_acquisition_receipt_digest=receipt.fence_acquisition_receipt_digest,
        authorization_digest=receipt.authorization_digest,
        authorization_observed_at=receipt.authorization_observed_at,
        authorized_at=receipt.authorized_at,
        previous_revision=receipt.previous_revision,
        result_revision=receipt.result_revision,
        pre_fingerprint=receipt.pre_fingerprint,
        post_fingerprint=receipt.post_fingerprint,
        outcome=receipt.outcome,
        evidence=receipt.evidence,
        effect_at=receipt.effect_at,
        acknowledged_at=receipt.acknowledged_at,
        durable_at=receipt.durable_at,
        durable=receipt.durable,
    )
    if include_receipt_id:
        data["receipt_id"] = receipt.receipt_id
    return data


def _object_receipt_data_from_fields(**values: Any) -> dict[str, Any]:
    kind = values["kind"]
    outcome = values["outcome"]
    evidence = values["evidence"]
    if not isinstance(kind, BridgeOperationKind):
        raise TypeError("Receipt kind must be a BridgeOperationKind.")
    if not isinstance(outcome, BridgeReceiptOutcome):
        raise TypeError("Receipt outcome must be a BridgeReceiptOutcome.")
    if not isinstance(evidence, BridgeReceiptEvidence):
        raise TypeError("Receipt evidence must be a BridgeReceiptEvidence.")
    effect_at = values["effect_at"]
    return {
        "schema": 1,
        "operation_id": values["operation_id"],
        "intent_digest": values["intent_digest"],
        "kind": kind.value,
        "provider": values["provider"],
        "object_key": values["object_key"],
        "fence_token_digest": values["fence_token_digest"].value,
        "fence_epoch": values["fence_epoch"],
        "fence_scope_digest": values["fence_scope_digest"],
        "fence_writer_id": values["fence_writer_id"],
        "fence_acquisition_operation_id": values[
            "fence_acquisition_operation_id"
        ],
        "fence_acquisition_receipt_id": values["fence_acquisition_receipt_id"],
        "fence_acquisition_receipt_digest": values[
            "fence_acquisition_receipt_digest"
        ],
        "authorization_digest": values["authorization_digest"],
        "authorization_observed_at": _encode_timestamp(
            values["authorization_observed_at"]
        ),
        "authorized_at": _encode_timestamp(values["authorized_at"]),
        "previous_revision": _encode_revision(values["previous_revision"]),
        "result_revision": _encode_revision(values["result_revision"]),
        "pre_fingerprint": values["pre_fingerprint"],
        "post_fingerprint": values["post_fingerprint"],
        "outcome": outcome.value,
        "evidence": evidence.value,
        "effect_at": None if effect_at is None else _encode_timestamp(effect_at),
        "acknowledged_at": _encode_timestamp(values["acknowledged_at"]),
        "durable_at": _encode_timestamp(values["durable_at"]),
        "durable": values["durable"],
    }


def _codec_error(path: str, detail: str) -> BridgeTransactionCodecError:
    return BridgeTransactionCodecError(f"{path}: {detail}.")


def _exact_dict(value: Any, path: str, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise _codec_error(path, "must be a built-in dict")
    if set(value) != keys or any(type(key) is not str for key in value):
        raise _codec_error(path, "has missing or unknown keys")
    return value


def _exact_list(value: Any, path: str) -> list[Any]:
    if type(value) is not list:
        raise _codec_error(path, "must be a built-in list")
    return value


def _decode_string(value: Any, path: str) -> str:
    try:
        _validate_string(value, path)
    except ValueError as err:
        raise _codec_error(path, "must be canonical non-empty text") from err
    return value


def _decode_digest(value: Any, path: str) -> str:
    if type(value) is not str or not _DIGEST_PATTERN.fullmatch(value):
        raise _codec_error(path, "must be a lowercase SHA-256 digest")
    return value


def _decode_fence_token_digest(value: Any, path: str) -> FenceTokenDigest:
    if type(value) is not str or not _FENCE_TOKEN_DIGEST_PATTERN.fullmatch(value):
        raise _codec_error(path, "must be a branded fence-token digest")
    return _restore_fence_token_digest(value)


def _decode_provider(value: Any, path: str) -> str:
    if type(value) is not str or value not in TRUE_FAMILY_PROVIDER_MANIFEST:
        raise _codec_error(path, "must name one provider in the manifest")
    return value


def _decode_operation_id(value: Any, pattern: re.Pattern[str], path: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise _codec_error(path, "must be a canonical operation ID")
    return value


def _decode_receipt_id(value: Any, path: str) -> str:
    if type(value) is not str or not _RECEIPT_ID_PATTERN.fullmatch(value):
        raise _codec_error(path, "must be a canonical receipt ID")
    return value


def _decode_positive_integer(value: Any, path: str) -> int:
    if type(value) is not int or value < 1:
        raise _codec_error(path, "must be a positive integer")
    return value


def _decode_nonnegative_integer(value: Any, path: str) -> int:
    if type(value) is not int or value < 0:
        raise _codec_error(path, "must be a non-negative integer")
    return value


def _decode_boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise _codec_error(path, "must be a literal boolean")
    return value


def _decode_revision(value: Any, path: str) -> Revision:
    raw = _exact_dict(value, path, {"type", "value"})
    revision_type = raw["type"]
    revision = raw["value"]
    if revision_type == "integer" and type(revision) is int:
        try:
            _validate_revision(revision, path)
        except ValueError as err:
            raise _codec_error(path, "contains an invalid integer revision") from err
        return revision
    if revision_type == "string" and type(revision) is str:
        try:
            _validate_revision(revision, path)
        except ValueError as err:
            raise _codec_error(path, "contains an invalid string revision") from err
        return revision
    raise _codec_error(path, "contains a malformed typed revision")


def _decode_timestamp(value: Any, path: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise _codec_error(path, "must be a canonical UTC timestamp")
    try:
        decoded = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as err:
        raise _codec_error(path, "must be a canonical UTC timestamp") from err
    if decoded.tzinfo is not UTC or _encode_timestamp(decoded) != value:
        raise _codec_error(path, "must be a canonical UTC timestamp")
    return decoded


def _decode_enum(value: Any, enum_type: type[StrEnum], path: str) -> Any:
    if type(value) is not str:
        raise _codec_error(path, "must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as err:
        raise _codec_error(path, "contains an unknown enum value") from err


def _decode_reason(value: Any, path: str) -> BridgeBlockReason | None:
    if value is None:
        return None
    return _decode_enum(value, BridgeBlockReason, path)


def _decode_optional_enum(
    value: Any,
    enum_type: type[StrEnum],
    path: str,
) -> Any:
    if value is None:
        return None
    return _decode_enum(value, enum_type, path)


def _construct(path: str, constructor: Any, **values: Any) -> Any:
    try:
        return constructor(**values)
    except (TypeError, ValueError) as err:
        raise _codec_error(path, str(err)) from err


def _roundtrip(raw: dict[str, Any], encoded: dict[str, Any], path: str) -> None:
    try:
        if _canonical_json(raw) != _canonical_json(encoded):
            raise _codec_error(path, "is not canonical")
    except ValueError as err:
        if isinstance(err, BridgeTransactionCodecError):
            raise
        raise _codec_error(path, "cannot be represented canonically") from err


def _require_dataclass(
    value: Any,
    expected_type: type[Any],
    label: str,
    codec_path: str | None,
) -> None:
    try:
        if not isinstance(value, expected_type):
            raise TypeError(f"A {label} is required.")
        value.__post_init__()
    except (TypeError, ValueError) as err:
        if codec_path is None:
            raise
        raise _codec_error(codec_path, str(err)) from err


def _require_expected_write(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(value, BridgeExpectedWrite, "BridgeExpectedWrite", codec_path)


def _require_acquisition_intent(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceAcquisitionIntent,
        "FenceAcquisitionIntent",
        codec_path,
    )


def _require_acquisition_receipt(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceAcquisitionReceipt,
        "FenceAcquisitionReceipt",
        codec_path,
    )


def _require_acquisition_no_effect_receipt(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceAcquisitionNoEffectReceipt,
        "FenceAcquisitionNoEffectReceipt",
        codec_path,
    )


def _require_acquisition_lifecycle_receipt(value: Any) -> None:
    if isinstance(value, FenceAcquisitionReceipt):
        _require_acquisition_receipt(value)
        return
    if isinstance(value, FenceAcquisitionNoEffectReceipt):
        _require_acquisition_no_effect_receipt(value)
        return
    raise TypeError("A typed acquisition lifecycle receipt is required.")


def _require_acquisition_record(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceAcquisitionRecord,
        "FenceAcquisitionRecord",
        codec_path,
    )


def _require_fence(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(value, FenceBinding, "FenceBinding", codec_path)


def _require_release_intent(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceReleaseIntent,
        "FenceReleaseIntent",
        codec_path,
    )


def _require_release_receipt(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceReleaseReceipt,
        "FenceReleaseReceipt",
        codec_path,
    )


def _require_release_no_effect_receipt(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceReleaseNoEffectReceipt,
        "FenceReleaseNoEffectReceipt",
        codec_path,
    )


def _require_release_lifecycle_receipt(value: Any) -> None:
    if isinstance(value, FenceReleaseReceipt):
        _require_release_receipt(value)
        return
    if isinstance(value, FenceReleaseNoEffectReceipt):
        _require_release_no_effect_receipt(value)
        return
    raise TypeError("A typed release lifecycle receipt is required.")


def _require_release_record(
    value: Any,
    *,
    codec_path: str | None = None,
) -> None:
    _require_dataclass(
        value,
        FenceReleaseRecord,
        "FenceReleaseRecord",
        codec_path,
    )


def _require_object_intent(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeOperationIntent,
        "BridgeOperationIntent",
        codec_path,
    )


def _require_object_receipt(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeOperationReceipt,
        "BridgeOperationReceipt",
        codec_path,
    )


def _require_observation(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeObjectObservation,
        "BridgeObjectObservation",
        codec_path,
    )


def _require_authorization(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeDispatchAuthorization,
        "BridgeDispatchAuthorization",
        codec_path,
    )


def _require_verification(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeOperationVerification,
        "BridgeOperationVerification",
        codec_path,
    )


def _require_object_record(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeOperationRecord,
        "BridgeOperationRecord",
        codec_path,
    )


def _require_attempt(value: Any, *, codec_path: str | None = None) -> None:
    _require_dataclass(
        value,
        BridgeOperationAttempt,
        "BridgeOperationAttempt",
        codec_path,
    )


def encode_bridge_expected_write(value: BridgeExpectedWrite) -> dict[str, Any]:
    """Encode one exact expected-write specification."""

    _require_expected_write(value, codec_path="expected_write")
    return {
        "provider": value.provider,
        "object_key": value.object_key,
        "expected_revision": _encode_revision(value.expected_revision),
        "pre_fingerprint": value.pre_fingerprint,
        "post_fingerprint": value.post_fingerprint,
    }


def decode_bridge_expected_write(value: Any) -> BridgeExpectedWrite:
    """Decode one exact expected-write specification."""

    path = "expected_write"
    raw = _exact_dict(
        value,
        path,
        {
            "provider",
            "object_key",
            "expected_revision",
            "pre_fingerprint",
            "post_fingerprint",
        },
    )
    result = _construct(
        path,
        BridgeExpectedWrite,
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        object_key=_decode_string(raw["object_key"], f"{path}.object_key"),
        expected_revision=_decode_revision(
            raw["expected_revision"],
            f"{path}.expected_revision",
        ),
        pre_fingerprint=_decode_digest(
            raw["pre_fingerprint"],
            f"{path}.pre_fingerprint",
        ),
        post_fingerprint=_decode_digest(
            raw["post_fingerprint"],
            f"{path}.post_fingerprint",
        ),
    )
    _roundtrip(raw, encode_bridge_expected_write(result), path)
    return result


def encode_fence_acquisition_intent(
    value: FenceAcquisitionIntent,
) -> dict[str, Any]:
    """Encode one deterministic fence acquisition intent."""

    _require_acquisition_intent(value, codec_path="acquisition_intent")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "plan_id": value.plan_id,
        "plan_digest": value.plan_digest,
        "manifest_digest": value.manifest_digest,
        "attempt": value.attempt,
        "provider": value.provider,
        "writer_id": value.writer_id,
        "expected_inventory_revision": _encode_revision(
            value.expected_inventory_revision
        ),
        "scope_digest": value.scope_digest,
        "epoch": value.epoch,
        "requested_at": _encode_timestamp(value.requested_at),
        "expires_at": _encode_timestamp(value.expires_at),
    }


def decode_fence_acquisition_intent(value: Any) -> FenceAcquisitionIntent:
    """Decode and recompute one acquisition operation identity."""

    path = "acquisition_intent"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "plan_id",
            "plan_digest",
            "manifest_digest",
            "attempt",
            "provider",
            "writer_id",
            "expected_inventory_revision",
            "scope_digest",
            "epoch",
            "requested_at",
            "expires_at",
        },
    )
    result = _construct(
        path,
        FenceAcquisitionIntent,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        plan_id=_decode_string(raw["plan_id"], f"{path}.plan_id"),
        plan_digest=_decode_digest(raw["plan_digest"], f"{path}.plan_digest"),
        manifest_digest=_decode_digest(
            raw["manifest_digest"],
            f"{path}.manifest_digest",
        ),
        attempt=_decode_positive_integer(raw["attempt"], f"{path}.attempt"),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        expected_inventory_revision=_decode_revision(
            raw["expected_inventory_revision"],
            f"{path}.expected_inventory_revision",
        ),
        scope_digest=_decode_digest(
            raw["scope_digest"],
            f"{path}.scope_digest",
        ),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        requested_at=_decode_timestamp(
            raw["requested_at"],
            f"{path}.requested_at",
        ),
        expires_at=_decode_timestamp(raw["expires_at"], f"{path}.expires_at"),
    )
    _roundtrip(raw, encode_fence_acquisition_intent(result), path)
    return result


def encode_fence_acquisition_receipt(
    value: FenceAcquisitionReceipt,
) -> dict[str, Any]:
    """Encode one durable acquisition receipt."""

    _require_acquisition_receipt(value, codec_path="acquisition_receipt")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "receipt_id": value.receipt_id,
        "outcome": value.outcome.value,
        "provider": value.provider,
        "writer_id": value.writer_id,
        "expected_inventory_revision": _encode_revision(
            value.expected_inventory_revision
        ),
        "acquired_inventory_revision": _encode_revision(
            value.acquired_inventory_revision
        ),
        "fence_revision": _encode_revision(value.fence_revision),
        "scope_digest": value.scope_digest,
        "epoch": value.epoch,
        "token_digest": value.token_digest.value,
        "acquired_at": _encode_timestamp(value.acquired_at),
        "expires_at": _encode_timestamp(value.expires_at),
        "acknowledged_at": _encode_timestamp(value.acknowledged_at),
        "durable_at": _encode_timestamp(value.durable_at),
        "receipt_digest": value.receipt_digest,
    }


def decode_fence_acquisition_receipt(value: Any) -> FenceAcquisitionReceipt:
    """Decode and recompute one durable acquisition receipt."""

    path = "acquisition_receipt"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "receipt_id",
            "outcome",
            "provider",
            "writer_id",
            "expected_inventory_revision",
            "acquired_inventory_revision",
            "fence_revision",
            "scope_digest",
            "epoch",
            "token_digest",
            "acquired_at",
            "expires_at",
            "acknowledged_at",
            "durable_at",
            "receipt_digest",
        },
    )
    if (
        _decode_enum(
            raw["outcome"],
            BridgeReceiptOutcome,
            f"{path}.outcome",
        )
        is not BridgeReceiptOutcome.APPLIED
    ):
        raise _codec_error(path, "applied receipt has a non-applied outcome")
    result = _construct(
        path,
        FenceAcquisitionReceipt,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        receipt_id=_decode_receipt_id(raw["receipt_id"], f"{path}.receipt_id"),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        expected_inventory_revision=_decode_revision(
            raw["expected_inventory_revision"],
            f"{path}.expected_inventory_revision",
        ),
        acquired_inventory_revision=_decode_revision(
            raw["acquired_inventory_revision"],
            f"{path}.acquired_inventory_revision",
        ),
        fence_revision=_decode_revision(
            raw["fence_revision"],
            f"{path}.fence_revision",
        ),
        scope_digest=_decode_digest(
            raw["scope_digest"],
            f"{path}.scope_digest",
        ),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        token_digest=_decode_fence_token_digest(
            raw["token_digest"],
            f"{path}.token_digest",
        ),
        acquired_at=_decode_timestamp(raw["acquired_at"], f"{path}.acquired_at"),
        expires_at=_decode_timestamp(raw["expires_at"], f"{path}.expires_at"),
        acknowledged_at=_decode_timestamp(
            raw["acknowledged_at"],
            f"{path}.acknowledged_at",
        ),
        durable_at=_decode_timestamp(raw["durable_at"], f"{path}.durable_at"),
        receipt_digest=_decode_digest(
            raw["receipt_digest"],
            f"{path}.receipt_digest",
        ),
    )
    _roundtrip(raw, encode_fence_acquisition_receipt(result), path)
    return result


def encode_fence_acquisition_no_effect_receipt(
    value: FenceAcquisitionNoEffectReceipt,
) -> dict[str, Any]:
    """Encode one authoritative acquisition no-effect tombstone."""

    _require_acquisition_no_effect_receipt(
        value,
        codec_path="acquisition_no_effect_receipt",
    )
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "receipt_id": value.receipt_id,
        "provider": value.provider,
        "writer_id": value.writer_id,
        "expected_inventory_revision": _encode_revision(
            value.expected_inventory_revision
        ),
        "scope_digest": value.scope_digest,
        "epoch": value.epoch,
        "outcome": value.outcome.value,
        "evidence": value.evidence.value,
        "acknowledged_at": _encode_timestamp(value.acknowledged_at),
        "durable_at": _encode_timestamp(value.durable_at),
        "durable": value.durable,
        "receipt_digest": value.receipt_digest,
    }


def decode_fence_acquisition_no_effect_receipt(
    value: Any,
) -> FenceAcquisitionNoEffectReceipt:
    """Decode and recompute one acquisition no-effect tombstone."""

    path = "acquisition_no_effect_receipt"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "receipt_id",
            "provider",
            "writer_id",
            "expected_inventory_revision",
            "scope_digest",
            "epoch",
            "outcome",
            "evidence",
            "acknowledged_at",
            "durable_at",
            "durable",
            "receipt_digest",
        },
    )
    result = _construct(
        path,
        FenceAcquisitionNoEffectReceipt,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(raw["intent_digest"], f"{path}.intent_digest"),
        receipt_id=_decode_receipt_id(raw["receipt_id"], f"{path}.receipt_id"),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        expected_inventory_revision=_decode_revision(
            raw["expected_inventory_revision"],
            f"{path}.expected_inventory_revision",
        ),
        scope_digest=_decode_digest(raw["scope_digest"], f"{path}.scope_digest"),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        outcome=_decode_enum(
            raw["outcome"],
            BridgeReceiptOutcome,
            f"{path}.outcome",
        ),
        evidence=_decode_enum(
            raw["evidence"],
            BridgeReceiptEvidence,
            f"{path}.evidence",
        ),
        acknowledged_at=_decode_timestamp(
            raw["acknowledged_at"],
            f"{path}.acknowledged_at",
        ),
        durable_at=_decode_timestamp(raw["durable_at"], f"{path}.durable_at"),
        durable=_decode_boolean(raw["durable"], f"{path}.durable"),
        receipt_digest=_decode_digest(
            raw["receipt_digest"],
            f"{path}.receipt_digest",
        ),
    )
    _roundtrip(raw, encode_fence_acquisition_no_effect_receipt(result), path)
    return result


def _encode_acquisition_lifecycle_receipt(
    value: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, FenceAcquisitionReceipt):
        return encode_fence_acquisition_receipt(value)
    return encode_fence_acquisition_no_effect_receipt(value)


def encode_fence_acquisition_record(
    value: FenceAcquisitionRecord,
) -> dict[str, Any]:
    """Encode one acquisition state projection."""

    _require_acquisition_record(value, codec_path="acquisition_record")
    return {
        "intent": encode_fence_acquisition_intent(value.intent),
        "state": value.state.value,
        "receipt": _encode_acquisition_lifecycle_receipt(value.receipt),
        "reason_code": None if value.reason_code is None else value.reason_code.value,
        "blocked_from": (
            None if value.blocked_from is None else value.blocked_from.value
        ),
    }


def decode_fence_acquisition_record(value: Any) -> FenceAcquisitionRecord:
    """Decode one acquisition state projection."""

    path = "acquisition_record"
    raw = _exact_dict(
        value,
        path,
        {"intent", "state", "receipt", "reason_code", "blocked_from"},
    )
    receipt = raw["receipt"]
    if receipt is not None:
        if type(receipt) is not dict:
            raise _codec_error(f"{path}.receipt", "must be a built-in dict")
        outcome = receipt.get("outcome")
        if outcome == BridgeReceiptOutcome.APPLIED.value:
            receipt = decode_fence_acquisition_receipt(receipt)
        elif outcome == BridgeReceiptOutcome.NO_EFFECT.value:
            receipt = decode_fence_acquisition_no_effect_receipt(receipt)
        else:
            raise _codec_error(f"{path}.receipt", "has an unknown outcome")
    result = _construct(
        path,
        FenceAcquisitionRecord,
        intent=decode_fence_acquisition_intent(raw["intent"]),
        state=_decode_enum(
            raw["state"],
            FenceLifecycleState,
            f"{path}.state",
        ),
        receipt=receipt,
        reason_code=_decode_reason(raw["reason_code"], f"{path}.reason_code"),
        blocked_from=_decode_optional_enum(
            raw["blocked_from"],
            FenceLifecycleState,
            f"{path}.blocked_from",
        ),
    )
    _roundtrip(raw, encode_fence_acquisition_record(result), path)
    return result


def encode_fence_binding(value: FenceBinding) -> dict[str, Any]:
    """Encode one acquired fence bound to its receipt."""

    _require_fence(value, codec_path="fence")
    return _fence_data(value)


def decode_fence_binding(value: Any) -> FenceBinding:
    """Decode one acquired fence bound to its receipt."""

    path = "fence"
    raw = _exact_dict(
        value,
        path,
        {
            "provider",
            "writer_id",
            "token_digest",
            "epoch",
            "fence_revision",
            "base_revision",
            "scope_digest",
            "acquired_at",
            "acquisition_durable_at",
            "expires_at",
            "acquisition_operation_id",
            "acquisition_receipt_id",
            "acquisition_receipt_digest",
        },
    )
    result = _construct(
        path,
        FenceBinding,
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        token_digest=_decode_fence_token_digest(
            raw["token_digest"],
            f"{path}.token_digest",
        ),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        fence_revision=_decode_revision(
            raw["fence_revision"],
            f"{path}.fence_revision",
        ),
        base_revision=_decode_revision(
            raw["base_revision"],
            f"{path}.base_revision",
        ),
        scope_digest=_decode_digest(
            raw["scope_digest"],
            f"{path}.scope_digest",
        ),
        acquired_at=_decode_timestamp(raw["acquired_at"], f"{path}.acquired_at"),
        acquisition_durable_at=_decode_timestamp(
            raw["acquisition_durable_at"],
            f"{path}.acquisition_durable_at",
        ),
        expires_at=_decode_timestamp(raw["expires_at"], f"{path}.expires_at"),
        acquisition_operation_id=_decode_operation_id(
            raw["acquisition_operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.acquisition_operation_id",
        ),
        acquisition_receipt_id=_decode_receipt_id(
            raw["acquisition_receipt_id"],
            f"{path}.acquisition_receipt_id",
        ),
        acquisition_receipt_digest=_decode_digest(
            raw["acquisition_receipt_digest"],
            f"{path}.acquisition_receipt_digest",
        ),
    )
    _roundtrip(raw, encode_fence_binding(result), path)
    return result


def encode_fence_release_intent(value: FenceReleaseIntent) -> dict[str, Any]:
    """Encode one deterministic fence release intent."""

    _require_release_intent(value, codec_path="release_intent")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "plan_id": value.plan_id,
        "plan_digest": value.plan_digest,
        "manifest_digest": value.manifest_digest,
        "attempt": value.attempt,
        "release_attempt": value.release_attempt,
        "provider": value.provider,
        "writer_id": value.writer_id,
        "acquisition_operation_id": value.acquisition_operation_id,
        "acquisition_receipt_id": value.acquisition_receipt_id,
        "acquisition_receipt_digest": value.acquisition_receipt_digest,
        "token_digest": value.token_digest.value,
        "scope_digest": value.scope_digest,
        "epoch": value.epoch,
        "expected_inventory_revision": _encode_revision(
            value.expected_inventory_revision
        ),
        "requested_at": _encode_timestamp(value.requested_at),
    }


def decode_fence_release_intent(value: Any) -> FenceReleaseIntent:
    """Decode and recompute one release operation identity."""

    path = "release_intent"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "plan_id",
            "plan_digest",
            "manifest_digest",
            "attempt",
            "release_attempt",
            "provider",
            "writer_id",
            "acquisition_operation_id",
            "acquisition_receipt_id",
            "acquisition_receipt_digest",
            "token_digest",
            "scope_digest",
            "epoch",
            "expected_inventory_revision",
            "requested_at",
        },
    )
    result = _construct(
        path,
        FenceReleaseIntent,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _RELEASE_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        plan_id=_decode_string(raw["plan_id"], f"{path}.plan_id"),
        plan_digest=_decode_digest(raw["plan_digest"], f"{path}.plan_digest"),
        manifest_digest=_decode_digest(
            raw["manifest_digest"],
            f"{path}.manifest_digest",
        ),
        attempt=_decode_positive_integer(raw["attempt"], f"{path}.attempt"),
        release_attempt=_decode_positive_integer(
            raw["release_attempt"],
            f"{path}.release_attempt",
        ),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        acquisition_operation_id=_decode_operation_id(
            raw["acquisition_operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.acquisition_operation_id",
        ),
        acquisition_receipt_id=_decode_receipt_id(
            raw["acquisition_receipt_id"],
            f"{path}.acquisition_receipt_id",
        ),
        acquisition_receipt_digest=_decode_digest(
            raw["acquisition_receipt_digest"],
            f"{path}.acquisition_receipt_digest",
        ),
        token_digest=_decode_fence_token_digest(
            raw["token_digest"],
            f"{path}.token_digest",
        ),
        scope_digest=_decode_digest(
            raw["scope_digest"],
            f"{path}.scope_digest",
        ),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        expected_inventory_revision=_decode_revision(
            raw["expected_inventory_revision"],
            f"{path}.expected_inventory_revision",
        ),
        requested_at=_decode_timestamp(
            raw["requested_at"],
            f"{path}.requested_at",
        ),
    )
    _roundtrip(raw, encode_fence_release_intent(result), path)
    return result


def encode_fence_release_receipt(value: FenceReleaseReceipt) -> dict[str, Any]:
    """Encode one durable fence release receipt."""

    _require_release_receipt(value, codec_path="release_receipt")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "receipt_id": value.receipt_id,
        "release_attempt": value.release_attempt,
        "outcome": value.outcome.value,
        "provider": value.provider,
        "writer_id": value.writer_id,
        "acquisition_operation_id": value.acquisition_operation_id,
        "acquisition_receipt_id": value.acquisition_receipt_id,
        "acquisition_receipt_digest": value.acquisition_receipt_digest,
        "token_digest": value.token_digest.value,
        "scope_digest": value.scope_digest,
        "epoch": value.epoch,
        "expected_inventory_revision": _encode_revision(
            value.expected_inventory_revision
        ),
        "final_inventory_revision": _encode_revision(
            value.final_inventory_revision
        ),
        "released_at": _encode_timestamp(value.released_at),
        "acknowledged_at": _encode_timestamp(value.acknowledged_at),
        "durable_at": _encode_timestamp(value.durable_at),
        "receipt_digest": value.receipt_digest,
    }


def decode_fence_release_receipt(value: Any) -> FenceReleaseReceipt:
    """Decode and recompute one durable release receipt."""

    path = "release_receipt"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "receipt_id",
            "release_attempt",
            "outcome",
            "provider",
            "writer_id",
            "acquisition_operation_id",
            "acquisition_receipt_id",
            "acquisition_receipt_digest",
            "token_digest",
            "scope_digest",
            "epoch",
            "expected_inventory_revision",
            "final_inventory_revision",
            "released_at",
            "acknowledged_at",
            "durable_at",
            "receipt_digest",
        },
    )
    if (
        _decode_enum(
            raw["outcome"],
            BridgeReceiptOutcome,
            f"{path}.outcome",
        )
        is not BridgeReceiptOutcome.APPLIED
    ):
        raise _codec_error(path, "applied receipt has a non-applied outcome")
    result = _construct(
        path,
        FenceReleaseReceipt,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _RELEASE_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        receipt_id=_decode_receipt_id(raw["receipt_id"], f"{path}.receipt_id"),
        release_attempt=_decode_positive_integer(
            raw["release_attempt"],
            f"{path}.release_attempt",
        ),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        acquisition_operation_id=_decode_operation_id(
            raw["acquisition_operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.acquisition_operation_id",
        ),
        acquisition_receipt_id=_decode_receipt_id(
            raw["acquisition_receipt_id"],
            f"{path}.acquisition_receipt_id",
        ),
        acquisition_receipt_digest=_decode_digest(
            raw["acquisition_receipt_digest"],
            f"{path}.acquisition_receipt_digest",
        ),
        token_digest=_decode_fence_token_digest(
            raw["token_digest"],
            f"{path}.token_digest",
        ),
        scope_digest=_decode_digest(
            raw["scope_digest"],
            f"{path}.scope_digest",
        ),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        expected_inventory_revision=_decode_revision(
            raw["expected_inventory_revision"],
            f"{path}.expected_inventory_revision",
        ),
        final_inventory_revision=_decode_revision(
            raw["final_inventory_revision"],
            f"{path}.final_inventory_revision",
        ),
        released_at=_decode_timestamp(raw["released_at"], f"{path}.released_at"),
        acknowledged_at=_decode_timestamp(
            raw["acknowledged_at"],
            f"{path}.acknowledged_at",
        ),
        durable_at=_decode_timestamp(raw["durable_at"], f"{path}.durable_at"),
        receipt_digest=_decode_digest(
            raw["receipt_digest"],
            f"{path}.receipt_digest",
        ),
    )
    _roundtrip(raw, encode_fence_release_receipt(result), path)
    return result


def encode_fence_release_no_effect_receipt(
    value: FenceReleaseNoEffectReceipt,
) -> dict[str, Any]:
    """Encode one authoritative release no-effect tombstone."""

    _require_release_no_effect_receipt(
        value,
        codec_path="release_no_effect_receipt",
    )
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "receipt_id": value.receipt_id,
        "release_attempt": value.release_attempt,
        "provider": value.provider,
        "writer_id": value.writer_id,
        "acquisition_operation_id": value.acquisition_operation_id,
        "acquisition_receipt_id": value.acquisition_receipt_id,
        "acquisition_receipt_digest": value.acquisition_receipt_digest,
        "token_digest": value.token_digest.value,
        "scope_digest": value.scope_digest,
        "epoch": value.epoch,
        "expected_inventory_revision": _encode_revision(
            value.expected_inventory_revision
        ),
        "outcome": value.outcome.value,
        "evidence": value.evidence.value,
        "acknowledged_at": _encode_timestamp(value.acknowledged_at),
        "durable_at": _encode_timestamp(value.durable_at),
        "durable": value.durable,
        "receipt_digest": value.receipt_digest,
    }


def decode_fence_release_no_effect_receipt(
    value: Any,
) -> FenceReleaseNoEffectReceipt:
    """Decode and recompute one release no-effect tombstone."""

    path = "release_no_effect_receipt"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "receipt_id",
            "release_attempt",
            "provider",
            "writer_id",
            "acquisition_operation_id",
            "acquisition_receipt_id",
            "acquisition_receipt_digest",
            "token_digest",
            "scope_digest",
            "epoch",
            "expected_inventory_revision",
            "outcome",
            "evidence",
            "acknowledged_at",
            "durable_at",
            "durable",
            "receipt_digest",
        },
    )
    result = _construct(
        path,
        FenceReleaseNoEffectReceipt,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _RELEASE_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(raw["intent_digest"], f"{path}.intent_digest"),
        receipt_id=_decode_receipt_id(raw["receipt_id"], f"{path}.receipt_id"),
        release_attempt=_decode_positive_integer(
            raw["release_attempt"],
            f"{path}.release_attempt",
        ),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        writer_id=_decode_string(raw["writer_id"], f"{path}.writer_id"),
        acquisition_operation_id=_decode_operation_id(
            raw["acquisition_operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.acquisition_operation_id",
        ),
        acquisition_receipt_id=_decode_receipt_id(
            raw["acquisition_receipt_id"],
            f"{path}.acquisition_receipt_id",
        ),
        acquisition_receipt_digest=_decode_digest(
            raw["acquisition_receipt_digest"],
            f"{path}.acquisition_receipt_digest",
        ),
        token_digest=_decode_fence_token_digest(
            raw["token_digest"],
            f"{path}.token_digest",
        ),
        scope_digest=_decode_digest(raw["scope_digest"], f"{path}.scope_digest"),
        epoch=_decode_nonnegative_integer(raw["epoch"], f"{path}.epoch"),
        expected_inventory_revision=_decode_revision(
            raw["expected_inventory_revision"],
            f"{path}.expected_inventory_revision",
        ),
        outcome=_decode_enum(
            raw["outcome"],
            BridgeReceiptOutcome,
            f"{path}.outcome",
        ),
        evidence=_decode_enum(
            raw["evidence"],
            BridgeReceiptEvidence,
            f"{path}.evidence",
        ),
        acknowledged_at=_decode_timestamp(
            raw["acknowledged_at"],
            f"{path}.acknowledged_at",
        ),
        durable_at=_decode_timestamp(raw["durable_at"], f"{path}.durable_at"),
        durable=_decode_boolean(raw["durable"], f"{path}.durable"),
        receipt_digest=_decode_digest(
            raw["receipt_digest"],
            f"{path}.receipt_digest",
        ),
    )
    _roundtrip(raw, encode_fence_release_no_effect_receipt(result), path)
    return result


def _encode_release_lifecycle_receipt(
    value: FenceReleaseReceipt | FenceReleaseNoEffectReceipt | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, FenceReleaseReceipt):
        return encode_fence_release_receipt(value)
    return encode_fence_release_no_effect_receipt(value)


def encode_fence_release_record(value: FenceReleaseRecord) -> dict[str, Any]:
    """Encode one release state projection."""

    _require_release_record(value, codec_path="release_record")
    return {
        "intent": encode_fence_release_intent(value.intent),
        "state": value.state.value,
        "receipt": _encode_release_lifecycle_receipt(value.receipt),
        "reason_code": None if value.reason_code is None else value.reason_code.value,
        "blocked_from": (
            None if value.blocked_from is None else value.blocked_from.value
        ),
    }


def decode_fence_release_record(value: Any) -> FenceReleaseRecord:
    """Decode one release state projection."""

    path = "release_record"
    raw = _exact_dict(
        value,
        path,
        {"intent", "state", "receipt", "reason_code", "blocked_from"},
    )
    receipt = raw["receipt"]
    if receipt is not None:
        if type(receipt) is not dict:
            raise _codec_error(f"{path}.receipt", "must be a built-in dict")
        outcome = receipt.get("outcome")
        if outcome == BridgeReceiptOutcome.APPLIED.value:
            receipt = decode_fence_release_receipt(receipt)
        elif outcome == BridgeReceiptOutcome.NO_EFFECT.value:
            receipt = decode_fence_release_no_effect_receipt(receipt)
        else:
            raise _codec_error(f"{path}.receipt", "has an unknown outcome")
    result = _construct(
        path,
        FenceReleaseRecord,
        intent=decode_fence_release_intent(raw["intent"]),
        state=_decode_enum(
            raw["state"],
            FenceLifecycleState,
            f"{path}.state",
        ),
        receipt=receipt,
        reason_code=_decode_reason(raw["reason_code"], f"{path}.reason_code"),
        blocked_from=_decode_optional_enum(
            raw["blocked_from"],
            FenceLifecycleState,
            f"{path}.blocked_from",
        ),
    )
    _roundtrip(raw, encode_fence_release_record(result), path)
    return result


def encode_bridge_operation_intent(
    value: BridgeOperationIntent,
) -> dict[str, Any]:
    """Encode one deterministic object operation intent."""

    _require_object_intent(value, codec_path="object_intent")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "plan_id": value.plan_id,
        "plan_digest": value.plan_digest,
        "manifest_digest": value.manifest_digest,
        "attempt": value.attempt,
        "sequence": value.sequence,
        "kind": value.kind.value,
        "provider": value.provider,
        "object_key": value.object_key,
        "expected_revision": _encode_revision(value.expected_revision),
        "pre_fingerprint": value.pre_fingerprint,
        "post_fingerprint": value.post_fingerprint,
        "fence": encode_fence_binding(value.fence),
        "parent_operation_id": value.parent_operation_id,
    }


def decode_bridge_operation_intent(value: Any) -> BridgeOperationIntent:
    """Decode and recompute one object operation identity."""

    path = "object_intent"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "plan_id",
            "plan_digest",
            "manifest_digest",
            "attempt",
            "sequence",
            "kind",
            "provider",
            "object_key",
            "expected_revision",
            "pre_fingerprint",
            "post_fingerprint",
            "fence",
            "parent_operation_id",
        },
    )
    parent = raw["parent_operation_id"]
    if parent is not None:
        parent = _decode_operation_id(
            parent,
            _OBJECT_OPERATION_ID_PATTERN,
            f"{path}.parent_operation_id",
        )
    result = _construct(
        path,
        BridgeOperationIntent,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _OBJECT_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        plan_id=_decode_string(raw["plan_id"], f"{path}.plan_id"),
        plan_digest=_decode_digest(raw["plan_digest"], f"{path}.plan_digest"),
        manifest_digest=_decode_digest(
            raw["manifest_digest"],
            f"{path}.manifest_digest",
        ),
        attempt=_decode_positive_integer(raw["attempt"], f"{path}.attempt"),
        sequence=_decode_positive_integer(raw["sequence"], f"{path}.sequence"),
        kind=_decode_enum(
            raw["kind"],
            BridgeOperationKind,
            f"{path}.kind",
        ),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        object_key=_decode_string(raw["object_key"], f"{path}.object_key"),
        expected_revision=_decode_revision(
            raw["expected_revision"],
            f"{path}.expected_revision",
        ),
        pre_fingerprint=_decode_digest(
            raw["pre_fingerprint"],
            f"{path}.pre_fingerprint",
        ),
        post_fingerprint=_decode_digest(
            raw["post_fingerprint"],
            f"{path}.post_fingerprint",
        ),
        fence=decode_fence_binding(raw["fence"]),
        parent_operation_id=parent,
    )
    _roundtrip(raw, encode_bridge_operation_intent(result), path)
    return result


def encode_bridge_operation_receipt(
    value: BridgeOperationReceipt,
) -> dict[str, Any]:
    """Encode one durable object-operation outcome."""

    _require_object_receipt(value, codec_path="object_receipt")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "receipt_id": value.receipt_id,
        "kind": value.kind.value,
        "provider": value.provider,
        "object_key": value.object_key,
        "fence_token_digest": value.fence_token_digest.value,
        "fence_epoch": value.fence_epoch,
        "fence_scope_digest": value.fence_scope_digest,
        "fence_writer_id": value.fence_writer_id,
        "fence_acquisition_operation_id": value.fence_acquisition_operation_id,
        "fence_acquisition_receipt_id": value.fence_acquisition_receipt_id,
        "fence_acquisition_receipt_digest": value.fence_acquisition_receipt_digest,
        "authorization_digest": value.authorization_digest,
        "authorization_observed_at": _encode_timestamp(
            value.authorization_observed_at
        ),
        "authorized_at": _encode_timestamp(value.authorized_at),
        "previous_revision": _encode_revision(value.previous_revision),
        "result_revision": _encode_revision(value.result_revision),
        "pre_fingerprint": value.pre_fingerprint,
        "post_fingerprint": value.post_fingerprint,
        "outcome": value.outcome.value,
        "evidence": value.evidence.value,
        "effect_at": (
            None if value.effect_at is None else _encode_timestamp(value.effect_at)
        ),
        "acknowledged_at": _encode_timestamp(value.acknowledged_at),
        "durable_at": _encode_timestamp(value.durable_at),
        "durable": value.durable,
        "receipt_digest": value.receipt_digest,
    }


def decode_bridge_operation_receipt(value: Any) -> BridgeOperationReceipt:
    """Decode and recompute one durable object-operation outcome."""

    path = "object_receipt"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "receipt_id",
            "kind",
            "provider",
            "object_key",
            "fence_token_digest",
            "fence_epoch",
            "fence_scope_digest",
            "fence_writer_id",
            "fence_acquisition_operation_id",
            "fence_acquisition_receipt_id",
            "fence_acquisition_receipt_digest",
            "authorization_digest",
            "authorization_observed_at",
            "authorized_at",
            "previous_revision",
            "result_revision",
            "pre_fingerprint",
            "post_fingerprint",
            "outcome",
            "evidence",
            "effect_at",
            "acknowledged_at",
            "durable_at",
            "durable",
            "receipt_digest",
        },
    )
    effect_at = raw["effect_at"]
    if effect_at is not None:
        effect_at = _decode_timestamp(effect_at, f"{path}.effect_at")
    result = _construct(
        path,
        BridgeOperationReceipt,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _OBJECT_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        receipt_id=_decode_receipt_id(raw["receipt_id"], f"{path}.receipt_id"),
        kind=_decode_enum(
            raw["kind"],
            BridgeOperationKind,
            f"{path}.kind",
        ),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        object_key=_decode_string(raw["object_key"], f"{path}.object_key"),
        fence_token_digest=_decode_fence_token_digest(
            raw["fence_token_digest"],
            f"{path}.fence_token_digest",
        ),
        fence_epoch=_decode_nonnegative_integer(
            raw["fence_epoch"],
            f"{path}.fence_epoch",
        ),
        fence_scope_digest=_decode_digest(
            raw["fence_scope_digest"],
            f"{path}.fence_scope_digest",
        ),
        fence_writer_id=_decode_string(
            raw["fence_writer_id"],
            f"{path}.fence_writer_id",
        ),
        fence_acquisition_operation_id=_decode_operation_id(
            raw["fence_acquisition_operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.fence_acquisition_operation_id",
        ),
        fence_acquisition_receipt_id=_decode_receipt_id(
            raw["fence_acquisition_receipt_id"],
            f"{path}.fence_acquisition_receipt_id",
        ),
        fence_acquisition_receipt_digest=_decode_digest(
            raw["fence_acquisition_receipt_digest"],
            f"{path}.fence_acquisition_receipt_digest",
        ),
        authorization_digest=_decode_digest(
            raw["authorization_digest"],
            f"{path}.authorization_digest",
        ),
        authorization_observed_at=_decode_timestamp(
            raw["authorization_observed_at"],
            f"{path}.authorization_observed_at",
        ),
        authorized_at=_decode_timestamp(
            raw["authorized_at"],
            f"{path}.authorized_at",
        ),
        previous_revision=_decode_revision(
            raw["previous_revision"],
            f"{path}.previous_revision",
        ),
        result_revision=_decode_revision(
            raw["result_revision"],
            f"{path}.result_revision",
        ),
        pre_fingerprint=_decode_digest(
            raw["pre_fingerprint"],
            f"{path}.pre_fingerprint",
        ),
        post_fingerprint=_decode_digest(
            raw["post_fingerprint"],
            f"{path}.post_fingerprint",
        ),
        outcome=_decode_enum(
            raw["outcome"],
            BridgeReceiptOutcome,
            f"{path}.outcome",
        ),
        evidence=_decode_enum(
            raw["evidence"],
            BridgeReceiptEvidence,
            f"{path}.evidence",
        ),
        effect_at=effect_at,
        acknowledged_at=_decode_timestamp(
            raw["acknowledged_at"],
            f"{path}.acknowledged_at",
        ),
        durable_at=_decode_timestamp(raw["durable_at"], f"{path}.durable_at"),
        durable=_decode_boolean(raw["durable"], f"{path}.durable"),
        receipt_digest=_decode_digest(
            raw["receipt_digest"],
            f"{path}.receipt_digest",
        ),
    )
    _roundtrip(raw, encode_bridge_operation_receipt(result), path)
    return result


def encode_bridge_object_observation(
    value: BridgeObjectObservation,
) -> dict[str, Any]:
    """Encode one payload-free object observation."""

    _require_observation(value, codec_path="observation")
    return {
        "provider": value.provider,
        "object_key": value.object_key,
        "revision": _encode_revision(value.revision),
        "fingerprint": value.fingerprint,
        "observed_at": _encode_timestamp(value.observed_at),
    }


def decode_bridge_object_observation(value: Any) -> BridgeObjectObservation:
    """Decode one payload-free object observation."""

    path = "observation"
    raw = _exact_dict(
        value,
        path,
        {"provider", "object_key", "revision", "fingerprint", "observed_at"},
    )
    result = _construct(
        path,
        BridgeObjectObservation,
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        object_key=_decode_string(raw["object_key"], f"{path}.object_key"),
        revision=_decode_revision(raw["revision"], f"{path}.revision"),
        fingerprint=_decode_digest(raw["fingerprint"], f"{path}.fingerprint"),
        observed_at=_decode_timestamp(raw["observed_at"], f"{path}.observed_at"),
    )
    _roundtrip(raw, encode_bridge_object_observation(result), path)
    return result


def encode_bridge_dispatch_authorization(
    value: BridgeDispatchAuthorization,
) -> dict[str, Any]:
    """Encode one exact payload-free pre-dispatch authorization."""

    _require_authorization(value, codec_path="dispatch_authorization")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "provider": value.provider,
        "object_key": value.object_key,
        "fence_acquisition_operation_id": value.fence_acquisition_operation_id,
        "fence_acquisition_receipt_id": value.fence_acquisition_receipt_id,
        "fence_acquisition_receipt_digest": (
            value.fence_acquisition_receipt_digest
        ),
        "revision": _encode_revision(value.revision),
        "fingerprint": value.fingerprint,
        "observed_at": _encode_timestamp(value.observed_at),
        "authorized_at": _encode_timestamp(value.authorized_at),
        "authorization_digest": value.authorization_digest,
    }


def decode_bridge_dispatch_authorization(
    value: Any,
) -> BridgeDispatchAuthorization:
    """Decode and recompute one pre-dispatch authorization."""

    path = "dispatch_authorization"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "provider",
            "object_key",
            "fence_acquisition_operation_id",
            "fence_acquisition_receipt_id",
            "fence_acquisition_receipt_digest",
            "revision",
            "fingerprint",
            "observed_at",
            "authorized_at",
            "authorization_digest",
        },
    )
    result = _construct(
        path,
        BridgeDispatchAuthorization,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _OBJECT_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(raw["intent_digest"], f"{path}.intent_digest"),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        object_key=_decode_string(raw["object_key"], f"{path}.object_key"),
        fence_acquisition_operation_id=_decode_operation_id(
            raw["fence_acquisition_operation_id"],
            _ACQUIRE_OPERATION_ID_PATTERN,
            f"{path}.fence_acquisition_operation_id",
        ),
        fence_acquisition_receipt_id=_decode_receipt_id(
            raw["fence_acquisition_receipt_id"],
            f"{path}.fence_acquisition_receipt_id",
        ),
        fence_acquisition_receipt_digest=_decode_digest(
            raw["fence_acquisition_receipt_digest"],
            f"{path}.fence_acquisition_receipt_digest",
        ),
        revision=_decode_revision(raw["revision"], f"{path}.revision"),
        fingerprint=_decode_digest(raw["fingerprint"], f"{path}.fingerprint"),
        observed_at=_decode_timestamp(raw["observed_at"], f"{path}.observed_at"),
        authorized_at=_decode_timestamp(
            raw["authorized_at"],
            f"{path}.authorized_at",
        ),
        authorization_digest=_decode_digest(
            raw["authorization_digest"],
            f"{path}.authorization_digest",
        ),
    )
    _roundtrip(raw, encode_bridge_dispatch_authorization(result), path)
    return result


def encode_bridge_operation_verification(
    value: BridgeOperationVerification,
) -> dict[str, Any]:
    """Encode one exact object-operation verification."""

    _require_verification(value, codec_path="verification")
    return {
        "operation_id": value.operation_id,
        "intent_digest": value.intent_digest,
        "receipt_id": value.receipt_id,
        "receipt_digest": value.receipt_digest,
        "provider": value.provider,
        "object_key": value.object_key,
        "revision": _encode_revision(value.revision),
        "fingerprint": value.fingerprint,
        "observed_at": _encode_timestamp(value.observed_at),
        "verified_at": _encode_timestamp(value.verified_at),
    }


def decode_bridge_operation_verification(
    value: Any,
) -> BridgeOperationVerification:
    """Decode one exact object-operation verification."""

    path = "verification"
    raw = _exact_dict(
        value,
        path,
        {
            "operation_id",
            "intent_digest",
            "receipt_id",
            "receipt_digest",
            "provider",
            "object_key",
            "revision",
            "fingerprint",
            "observed_at",
            "verified_at",
        },
    )
    result = _construct(
        path,
        BridgeOperationVerification,
        operation_id=_decode_operation_id(
            raw["operation_id"],
            _OBJECT_OPERATION_ID_PATTERN,
            f"{path}.operation_id",
        ),
        intent_digest=_decode_digest(
            raw["intent_digest"],
            f"{path}.intent_digest",
        ),
        receipt_id=_decode_receipt_id(raw["receipt_id"], f"{path}.receipt_id"),
        receipt_digest=_decode_digest(
            raw["receipt_digest"],
            f"{path}.receipt_digest",
        ),
        provider=_decode_provider(raw["provider"], f"{path}.provider"),
        object_key=_decode_string(raw["object_key"], f"{path}.object_key"),
        revision=_decode_revision(raw["revision"], f"{path}.revision"),
        fingerprint=_decode_digest(raw["fingerprint"], f"{path}.fingerprint"),
        observed_at=_decode_timestamp(raw["observed_at"], f"{path}.observed_at"),
        verified_at=_decode_timestamp(raw["verified_at"], f"{path}.verified_at"),
    )
    _roundtrip(raw, encode_bridge_operation_verification(result), path)
    return result


def encode_bridge_operation_record(value: BridgeOperationRecord) -> dict[str, Any]:
    """Encode one object-operation state projection."""

    _require_object_record(value, codec_path="object_record")
    return {
        "intent": encode_bridge_operation_intent(value.intent),
        "state": value.state.value,
        "authorization": (
            None
            if value.authorization is None
            else encode_bridge_dispatch_authorization(value.authorization)
        ),
        "receipt": (
            None
            if value.receipt is None
            else encode_bridge_operation_receipt(value.receipt)
        ),
        "verifications": [
            encode_bridge_operation_verification(item)
            for item in value.verifications
        ],
        "reason_code": None if value.reason_code is None else value.reason_code.value,
        "blocked_from": (
            None if value.blocked_from is None else value.blocked_from.value
        ),
    }


def decode_bridge_operation_record(value: Any) -> BridgeOperationRecord:
    """Decode one object-operation state projection."""

    path = "object_record"
    raw = _exact_dict(
        value,
        path,
        {
            "intent",
            "state",
            "authorization",
            "receipt",
            "verifications",
            "reason_code",
            "blocked_from",
        },
    )
    receipt = raw["receipt"]
    if receipt is not None:
        receipt = decode_bridge_operation_receipt(receipt)
    authorization = raw["authorization"]
    if authorization is not None:
        authorization = decode_bridge_dispatch_authorization(authorization)
    verifications = tuple(
        decode_bridge_operation_verification(item)
        for item in _exact_list(raw["verifications"], f"{path}.verifications")
    )
    result = _construct(
        path,
        BridgeOperationRecord,
        intent=decode_bridge_operation_intent(raw["intent"]),
        state=_decode_enum(
            raw["state"],
            BridgeOperationState,
            f"{path}.state",
        ),
        authorization=authorization,
        receipt=receipt,
        verifications=verifications,
        reason_code=_decode_reason(raw["reason_code"], f"{path}.reason_code"),
        blocked_from=_decode_optional_enum(
            raw["blocked_from"],
            BridgeOperationState,
            f"{path}.blocked_from",
        ),
    )
    _roundtrip(raw, encode_bridge_operation_record(result), path)
    return result


def encode_bridge_operation_attempt(
    value: BridgeOperationAttempt,
) -> dict[str, Any]:
    """Encode one complete transaction and fence-lifecycle attempt."""

    _require_attempt(value, codec_path="attempt")
    return {
        "plan_id": value.plan_id,
        "plan_digest": value.plan_digest,
        "manifest_digest": value.manifest_digest,
        "attempt": value.attempt,
        "state": value.state.value,
        "max_observation_age_seconds": value.max_observation_age_seconds,
        "expected_write_coverage_digest": value.expected_write_coverage_digest,
        "expected_writes": [
            encode_bridge_expected_write(item) for item in value.expected_writes
        ],
        "acquisitions": [
            encode_fence_acquisition_record(item) for item in value.acquisitions
        ],
        "operations": [
            encode_bridge_operation_record(item) for item in value.operations
        ],
        "releases": [encode_fence_release_record(item) for item in value.releases],
        "release_phase_sequence": value.release_phase_sequence,
        "reason_code": None if value.reason_code is None else value.reason_code.value,
        "terminal_at": (
            None if value.terminal_at is None else _encode_timestamp(value.terminal_at)
        ),
    }


def decode_bridge_operation_attempt(value: Any) -> BridgeOperationAttempt:
    """Decode and cross-validate one complete transaction attempt."""

    path = "attempt"
    raw = _exact_dict(
        value,
        path,
        {
            "plan_id",
            "plan_digest",
            "manifest_digest",
            "attempt",
            "state",
            "max_observation_age_seconds",
            "expected_write_coverage_digest",
            "expected_writes",
            "acquisitions",
            "operations",
            "releases",
            "release_phase_sequence",
            "reason_code",
            "terminal_at",
        },
    )
    terminal_at = raw["terminal_at"]
    if terminal_at is not None:
        terminal_at = _decode_timestamp(terminal_at, f"{path}.terminal_at")
    coverage_digest = _decode_digest(
        raw["expected_write_coverage_digest"],
        f"{path}.expected_write_coverage_digest",
    )
    release_phase_sequence = raw["release_phase_sequence"]
    if release_phase_sequence is not None:
        release_phase_sequence = _decode_nonnegative_integer(
            release_phase_sequence,
            f"{path}.release_phase_sequence",
        )
    result = _construct(
        path,
        BridgeOperationAttempt,
        plan_id=_decode_string(raw["plan_id"], f"{path}.plan_id"),
        plan_digest=_decode_digest(raw["plan_digest"], f"{path}.plan_digest"),
        manifest_digest=_decode_digest(
            raw["manifest_digest"],
            f"{path}.manifest_digest",
        ),
        attempt=_decode_positive_integer(raw["attempt"], f"{path}.attempt"),
        state=_decode_enum(
            raw["state"],
            BridgeAttemptState,
            f"{path}.state",
        ),
        max_observation_age_seconds=_decode_positive_integer(
            raw["max_observation_age_seconds"],
            f"{path}.max_observation_age_seconds",
        ),
        expected_writes=tuple(
            decode_bridge_expected_write(item)
            for item in _exact_list(
                raw["expected_writes"],
                f"{path}.expected_writes",
            )
        ),
        acquisitions=tuple(
            decode_fence_acquisition_record(item)
            for item in _exact_list(
                raw["acquisitions"],
                f"{path}.acquisitions",
            )
        ),
        operations=tuple(
            decode_bridge_operation_record(item)
            for item in _exact_list(raw["operations"], f"{path}.operations")
        ),
        releases=tuple(
            decode_fence_release_record(item)
            for item in _exact_list(raw["releases"], f"{path}.releases")
        ),
        release_phase_sequence=release_phase_sequence,
        reason_code=_decode_reason(raw["reason_code"], f"{path}.reason_code"),
        terminal_at=terminal_at,
    )
    if result.expected_write_coverage_digest != coverage_digest:
        raise _codec_error(path, "expected-write coverage digest does not match")
    _roundtrip(raw, encode_bridge_operation_attempt(result), path)
    return result


__all__ = [
    "BridgeAttemptState",
    "BridgeBlockReason",
    "BridgeDispatchAuthorization",
    "BridgeExpectedWrite",
    "BridgeJournalConflict",
    "BridgeObjectObservation",
    "BridgeOperationAttempt",
    "BridgeOperationIntent",
    "BridgeOperationJournal",
    "BridgeOperationKind",
    "BridgeOperationReceipt",
    "BridgeOperationRecord",
    "BridgeOperationState",
    "BridgeOperationTransitionError",
    "BridgeOperationVerification",
    "BridgeReceiptEvidence",
    "BridgeReceiptOutcome",
    "BridgeReconciliationAction",
    "BridgeTransactionBlocked",
    "BridgeTransactionCodecError",
    "BridgeTransactionError",
    "BridgeTransactionRecorder",
    "FenceAcquisitionIntent",
    "FenceAcquisitionNoEffectReceipt",
    "FenceAcquisitionReceipt",
    "FenceAcquisitionRecord",
    "FenceAuthority",
    "FenceBinding",
    "FenceLifecycleState",
    "FenceReleaseIntent",
    "FenceReleaseNoEffectReceipt",
    "FenceReleaseReceipt",
    "FenceReleaseRecord",
    "InMemoryBridgeOperationJournal",
    "InMemoryFenceAuthority",
    "FenceTokenDigest",
    "bridge_expected_write_coverage_digest",
    "decode_bridge_expected_write",
    "decode_bridge_dispatch_authorization",
    "decode_bridge_object_observation",
    "decode_bridge_operation_attempt",
    "decode_bridge_operation_intent",
    "decode_bridge_operation_receipt",
    "decode_bridge_operation_record",
    "decode_bridge_operation_verification",
    "decode_fence_acquisition_intent",
    "decode_fence_acquisition_no_effect_receipt",
    "decode_fence_acquisition_receipt",
    "decode_fence_acquisition_record",
    "decode_fence_binding",
    "decode_fence_release_intent",
    "decode_fence_release_no_effect_receipt",
    "decode_fence_release_receipt",
    "decode_fence_release_record",
    "encode_bridge_expected_write",
    "encode_bridge_dispatch_authorization",
    "encode_bridge_object_observation",
    "encode_bridge_operation_attempt",
    "encode_bridge_operation_intent",
    "encode_bridge_operation_receipt",
    "encode_bridge_operation_record",
    "encode_bridge_operation_verification",
    "encode_fence_acquisition_intent",
    "encode_fence_acquisition_no_effect_receipt",
    "encode_fence_acquisition_receipt",
    "encode_fence_acquisition_record",
    "encode_fence_binding",
    "encode_fence_release_intent",
    "encode_fence_release_no_effect_receipt",
    "encode_fence_release_receipt",
    "encode_fence_release_record",
    "derive_fence_token_digest",
]
