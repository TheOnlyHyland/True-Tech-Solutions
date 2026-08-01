"""Pure fail-closed contracts for the unwired physical-device probe.

Captured Moes BRT-100 physical dial DP2 frames use Tuya dataResponse, exposed by
Zigbee2MQTT as ``commandDataResponse``. The converter also accepts dataReport,
but this protocol deliberately does not accept it as possession or command
proof. Exact command-sequence echo across all pinned fingerprints is still an
unproven physical-bench gate.

This module has no Home Assistant imports and performs no I/O. Nothing in
integration setup imports or registers it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import InitVar, dataclass, replace
from enum import StrEnum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any


PROTOCOL_ID = "true-family-physical-probe"
PROTOCOL_VERSION = 2
STATE_SCHEMA = "true-family-physical-probe-state-v2"
BUILD_ID = "tfpp-v2-z2m-2.12.1-zh-10.6.1-zhc-26.76.0"
Z2M_2_12_1_VERSION_TUPLE = ("2.12.1", "10.6.1", "26.76.0")

MAX_STATE_JSON_BYTES = 16_384
MAX_MESSAGE_JSON_BYTES = 4_096
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 320
MAX_JSON_STRING_LENGTH = 512
MAX_CONSUMED_REQUEST_IDS = 32
MAX_PROOFS = 5
MAX_USED_SEQUENCES = 16
MAX_GENERATION = 64
MAX_RESTORE_ATTEMPTS = 3
MAX_UNCLAIMED_SAFETY_ATTEMPTS = 3
MAX_REQUEST_WINDOW_MS = 60_000
MAX_OPERATION_WINDOW_MS = 900_000
PHYSICAL_PROOF_WINDOW_MS = 60_000
DIRECT_PROOF_WINDOW_MS = 10_000
RESULT_RETRY_WINDOW_MS = 10_000
RESULT_SETTLING_WINDOW_MS = 2_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991

_POST_RESULT_SEQUENCE_RESERVE = MAX_UNCLAIMED_SAFETY_ATTEMPTS
_POST_CHALLENGE_SEQUENCE_RESERVE = (
    MAX_RESTORE_ATTEMPTS + MAX_UNCLAIMED_SAFETY_ATTEMPTS
)
_POST_NOOP_SEQUENCE_RESERVE = 1 + _POST_CHALLENGE_SEQUENCE_RESERVE

READY_TOPIC = "bridge/true_family/physical_probe/ready"
STATUS_TOPIC = "bridge/true_family/physical_probe/status"
REQUEST_TOPIC = "bridge/request/true_family/physical_probe"
RESPONSE_TOPIC = "bridge/response/true_family/physical_probe"
RESULT_TOPIC = "bridge/true_family/physical_probe/result"
ACK_TOPIC = "bridge/request/true_family/physical_probe/ack"
ACK_RESPONSE_TOPIC = "bridge/response/true_family/physical_probe/ack"

_IEEE_PATTERN = re.compile(r"^0x[0-9a-f]{16}$")
_FINGERPRINT_PATTERN = re.compile(r"^_TZE[0-9]{3}_[a-z0-9]{8}$")
_PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_BOOT_ID_PATTERN = re.compile(r"^tfpp-boot-[0-9a-f]{32}$")
_OPERATION_ID_PATTERN = re.compile(r"^tfpp-op-[0-9a-f]{24}$")
_REQUEST_ID_PATTERN = re.compile(r"^tfpp-req-[0-9a-f]{24}$")
_NONCE_PATTERN = re.compile(r"^tfpp-nonce-[0-9a-f]{32}$")
_RESULT_ID_PATTERN = re.compile(r"^tfpp-result-[0-9a-f]{24}$")
_BOUNDARY_WHITESPACE_PATTERN = re.compile(
    r"^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff]"
    r"|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff]$"
)


class PhysicalProbeError(ValueError):
    """Raised when physical-probe data is not exact and safe."""


class ProbePhase(StrEnum):
    """Durable physical-probe phases."""

    AWAITING_PHYSICAL_TARGET_1 = "awaiting_physical_target_1"
    AWAITING_PHYSICAL_TARGET_2 = "awaiting_physical_target_2"
    AWAITING_NOOP_RESPONSE = "awaiting_noop_response"
    AWAITING_CHALLENGE_RESPONSE = "awaiting_challenge_response"
    AWAITING_RESTORE_RESPONSE = "awaiting_restore_response"
    RESULT_PENDING_ACK = "result_pending_ack"
    QUIESCENT = "quiescent"
    REMEDIATION_REQUIRED = "remediation_required"


class ProbeFrameKind(StrEnum):
    """The only raw Tuya frame kind accepted as a BRT DP2 proof."""

    COMMAND_RESPONSE = "commandDataResponse"


class ProbePurpose(StrEnum):
    """Proof purpose within the ordered protocol."""

    PHYSICAL_TARGET_1 = "physical_target_1"
    PHYSICAL_TARGET_2 = "physical_target_2"
    NOOP = "noop"
    CHALLENGE = "challenge"
    RESTORE = "restore"


class ProbeOutcome(StrEnum):
    """Sanitized terminal outcomes."""

    VERIFIED = "verified"
    FAILED_SAFE = "failed_safe"
    FAILED_RESTORED = "failed_restored"


class ProbeAction(StrEnum):
    """Exact accepted MQTT actions."""

    ARM = "arm"
    RESUME = "resume"
    ACK = "ack"


_PURPOSE_ORDER = tuple(ProbePurpose)
_PHASE_PURPOSE = MappingProxyType(
    {
        ProbePhase.AWAITING_PHYSICAL_TARGET_1: ProbePurpose.PHYSICAL_TARGET_1,
        ProbePhase.AWAITING_PHYSICAL_TARGET_2: ProbePurpose.PHYSICAL_TARGET_2,
        ProbePhase.AWAITING_NOOP_RESPONSE: ProbePurpose.NOOP,
        ProbePhase.AWAITING_CHALLENGE_RESPONSE: ProbePurpose.CHALLENGE,
        ProbePhase.AWAITING_RESTORE_RESPONSE: ProbePurpose.RESTORE,
    }
)
_FAILURE_CODES = frozenset(
    {
        "competing_frame",
        "competing_write",
        "control_drift",
        "deadline_expired",
        "dispatch_failed",
        "dispatch_timeout",
        "identity_mismatch",
        "journal_uncertain",
        "proof_mismatch",
        "queue_overflow",
        "restart_recovery",
        "restore_exhausted",
    }
)
_REMEDIATION_AFTER_RESTORE_CODES = frozenset(
    {
        "competing_frame",
        "competing_write",
        "control_drift",
        "queue_overflow",
    }
)


@dataclass(frozen=True, slots=True)
class ResolvedIdentityAlias:
    """One exact converter-resolved identity for a manufacturer fingerprint."""

    manufacturer_fingerprint: str
    model: str
    vendor: str

    def __post_init__(self) -> None:
        _require_pattern(
            self.manufacturer_fingerprint,
            _FINGERPRINT_PATTERN,
            "manufacturer fingerprint",
        )
        _require_text(self.model, "resolved model", maximum=96)
        _require_text(self.vendor, "resolved vendor", maximum=96)


@dataclass(frozen=True, slots=True)
class PhysicalProbeProfile:
    """Immutable generic description of one physically probed datapoint."""

    profile_id: str
    profile_version: int
    zigbee_model: str
    resolved_aliases: tuple[ResolvedIdentityAlias, ...]
    endpoint_id: int
    cluster_name: str
    cluster_id: int
    datapoint: int
    datatype: int
    minimum_target: int
    maximum_target: int
    target_step: int
    challenge_delta: int
    required_runtime_versions: tuple[str, str, str]

    def __post_init__(self) -> None:
        _require_pattern(self.profile_id, _PROFILE_ID_PATTERN, "profile ID")
        _require_positive_integer(self.profile_version, "profile version")
        for value, label in (
            (self.zigbee_model, "profile Zigbee model"),
            (self.cluster_name, "profile cluster name"),
        ):
            _require_text(value, label, maximum=96)
        if type(self.resolved_aliases) is not tuple or not self.resolved_aliases:
            raise PhysicalProbeError("Profile aliases must be a non-empty tuple.")
        if not all(type(alias) is ResolvedIdentityAlias for alias in self.resolved_aliases):
            raise PhysicalProbeError("Profile aliases must be exact immutable aliases.")
        fingerprints = tuple(
            alias.manufacturer_fingerprint for alias in self.resolved_aliases
        )
        if len(set(fingerprints)) != len(fingerprints):
            raise PhysicalProbeError("Profile alias fingerprints must be unique.")
        for value, label in (
            (self.endpoint_id, "profile endpoint"),
            (self.cluster_id, "profile cluster ID"),
            (self.datapoint, "profile datapoint"),
            (self.datatype, "profile datatype"),
            (self.minimum_target, "profile minimum target"),
            (self.maximum_target, "profile maximum target"),
            (self.target_step, "profile target step"),
            (self.challenge_delta, "profile challenge delta"),
        ):
            _require_integer(value, label)
        if self.endpoint_id <= 0 or not 0 <= self.cluster_id <= 0xFFFF:
            raise PhysicalProbeError("Profile endpoint or cluster is outside its range.")
        if not 0 <= self.datapoint <= 0xFF or not 0 <= self.datatype <= 0xFF:
            raise PhysicalProbeError("Profile datapoint or datatype is outside its range.")
        if self.minimum_target >= self.maximum_target:
            raise PhysicalProbeError("Profile target range is invalid.")
        if self.target_step <= 0 or self.challenge_delta <= 0:
            raise PhysicalProbeError("Profile target increments must be positive.")
        if (
            type(self.required_runtime_versions) is not tuple
            or len(self.required_runtime_versions) != 3
        ):
            raise PhysicalProbeError("Required runtime versions must be an exact tuple.")
        for version in self.required_runtime_versions:
            if not re.fullmatch(r"^[0-9]+\.[0-9]+\.[0-9]+$", version):
                raise PhysicalProbeError("Required runtime version is malformed.")

    @property
    def manufacturer_fingerprints(self) -> tuple[str, ...]:
        """Return the exact fingerprint set in deterministic alias order."""

        return tuple(
            alias.manufacturer_fingerprint for alias in self.resolved_aliases
        )

    def resolved_alias(self, fingerprint: str) -> ResolvedIdentityAlias:
        """Return the sole model/vendor identity allowed for one fingerprint."""

        _require_pattern(fingerprint, _FINGERPRINT_PATTERN, "manufacturer fingerprint")
        for alias in self.resolved_aliases:
            if alias.manufacturer_fingerprint == fingerprint:
                return alias
        raise PhysicalProbeError("Manufacturer fingerprint is not in the probe profile.")

    def validate_target(self, target: int, label: str = "target") -> None:
        """Require one whole, in-range profile target."""

        _require_integer(target, label)
        if not self.minimum_target <= target <= self.maximum_target:
            raise PhysicalProbeError(f"{label.capitalize()} is outside the profile range.")
        if (target - self.minimum_target) % self.target_step:
            raise PhysicalProbeError(f"{label.capitalize()} is not on the profile step.")

    def challenge_target(self, intended_target: int) -> int:
        """Choose the exact one-step challenge without crossing the range."""

        self.validate_target(intended_target, "intended target")
        higher = intended_target + self.challenge_delta
        challenge = higher if higher <= self.maximum_target else intended_target - self.challenge_delta
        self.validate_target(challenge, "challenge target")
        if abs(challenge - intended_target) != self.challenge_delta:
            raise PhysicalProbeError("Challenge target is not exactly one challenge delta away.")
        return challenge


@dataclass(frozen=True, slots=True)
class NormalizedCandidateIdentity:
    """Bounded candidate projection; no raw Zigbee or MQTT data is retained."""

    ieee_address: str
    model: str
    vendor: str
    zigbee_model: str
    manufacturer_fingerprint: str
    endpoint_id: int
    cluster_name: str
    cluster_id: int

    def __post_init__(self) -> None:
        _require_pattern(self.ieee_address, _IEEE_PATTERN, "candidate IEEE address")
        for value, label in (
            (self.model, "candidate model"),
            (self.vendor, "candidate vendor"),
            (self.zigbee_model, "candidate Zigbee model"),
            (self.cluster_name, "candidate cluster name"),
        ):
            _require_text(value, label, maximum=96)
        _require_pattern(
            self.manufacturer_fingerprint,
            _FINGERPRINT_PATTERN,
            "candidate manufacturer fingerprint",
        )
        _require_positive_integer(self.endpoint_id, "candidate endpoint")
        _require_integer(self.cluster_id, "candidate cluster ID")
        if not 0 <= self.cluster_id <= 0xFFFF:
            raise PhysicalProbeError("Candidate cluster ID is outside its range.")

    @classmethod
    def from_projection(cls, data: Mapping[str, Any]) -> NormalizedCandidateIdentity:
        """Parse an exact normalized identity projection."""

        _require_exact_fields(data, _CANDIDATE_FIELDS, "candidate identity")
        return cls(**{field: data[field] for field in _CANDIDATE_FIELDS})

    def as_dict(self) -> dict[str, Any]:
        """Return the exact normalized projection."""

        return {field: getattr(self, field) for field in _CANDIDATE_FIELDS}

    @property
    def masked_identity(self) -> str:
        """Return the only IEEE representation allowed in public messages."""

        return f"...{self.ieee_address[-4:].upper()}"

    def require_profile(self, profile: PhysicalProbeProfile) -> None:
        """Require every candidate field pinned by the supplied profile."""

        alias = profile.resolved_alias(self.manufacturer_fingerprint)
        if (
            self.model != alias.model
            or self.vendor != alias.vendor
            or self.zigbee_model != profile.zigbee_model
            or self.endpoint_id != profile.endpoint_id
            or self.cluster_name != profile.cluster_name
            or self.cluster_id != profile.cluster_id
        ):
            raise PhysicalProbeError("Candidate identity does not match the probe profile.")


_CANDIDATE_FIELDS = frozenset(
    {
        "ieee_address",
        "model",
        "vendor",
        "zigbee_model",
        "manufacturer_fingerprint",
        "endpoint_id",
        "cluster_name",
        "cluster_id",
    }
)
_PROOF_FIELDS = frozenset({"purpose", "frame_kind", "sequence", "target"})


@dataclass(frozen=True, slots=True)
class ExpectedProbeProof:
    """Exact next DP2 response; only physical steps have an unknown sequence."""

    purpose: ProbePurpose
    frame_kind: ProbeFrameKind
    sequence: int | None
    target: int

    def __post_init__(self) -> None:
        _validate_proof_fields(self.purpose, self.frame_kind, self.target)
        physical = self.purpose in {
            ProbePurpose.PHYSICAL_TARGET_1,
            ProbePurpose.PHYSICAL_TARGET_2,
        }
        if physical:
            if self.sequence is not None:
                raise PhysicalProbeError("A physical response sequence cannot be predicted.")
        else:
            _require_generated_sequence(self.sequence, "expected command sequence")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExpectedProbeProof:
        """Restore one exact expected-proof projection."""

        _require_exact_fields(data, _PROOF_FIELDS, "expected proof")
        return cls(
            purpose=_parse_enum(ProbePurpose, data["purpose"], "proof purpose"),
            frame_kind=_parse_enum(
                ProbeFrameKind, data["frame_kind"], "proof frame kind"
            ),
            sequence=data["sequence"],
            target=data["target"],
        )

    def as_dict(self) -> dict[str, Any]:
        """Return exact expected-proof fields."""

        return {
            "purpose": self.purpose.value,
            "frame_kind": self.frame_kind.value,
            "sequence": self.sequence,
            "target": self.target,
        }

    def accepts(self, proof: ProbeCommandProof) -> bool:
        """Return whether an observed normalized proof is exact."""

        return (
            proof.purpose is self.purpose
            and proof.frame_kind is self.frame_kind
            and proof.target == self.target
            and (self.sequence is None or proof.sequence == self.sequence)
        )


@dataclass(frozen=True, slots=True)
class ProbeCommandProof:
    """One normalized DP2 commandDataResponse proof."""

    purpose: ProbePurpose
    frame_kind: ProbeFrameKind
    sequence: int
    target: int
    profile: InitVar[PhysicalProbeProfile | None] = None

    def __post_init__(self, profile: PhysicalProbeProfile | None) -> None:
        _validate_proof_fields(self.purpose, self.frame_kind, self.target)
        if profile is None:
            profile = BRT_PROFILE
        if not isinstance(profile, PhysicalProbeProfile):
            raise PhysicalProbeError("Proof profile is malformed.")
        profile.validate_target(self.target, "proof target")
        if self.purpose in {
            ProbePurpose.PHYSICAL_TARGET_1,
            ProbePurpose.PHYSICAL_TARGET_2,
        }:
            _require_uint16(self.sequence, "physical proof sequence")
        else:
            _require_generated_sequence(self.sequence, "command proof sequence")

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        profile: PhysicalProbeProfile | None = None,
    ) -> ProbeCommandProof:
        """Restore one exact normalized proof."""

        _require_exact_fields(data, _PROOF_FIELDS, "command proof")
        return cls(
            purpose=_parse_enum(ProbePurpose, data["purpose"], "proof purpose"),
            frame_kind=_parse_enum(
                ProbeFrameKind, data["frame_kind"], "proof frame kind"
            ),
            sequence=data["sequence"],
            target=data["target"],
            profile=profile,
        )

    def as_dict(self) -> dict[str, Any]:
        """Return exact normalized proof fields."""

        return {
            "purpose": self.purpose.value,
            "frame_kind": self.frame_kind.value,
            "sequence": self.sequence,
            "target": self.target,
        }


_RECOVERY_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "protocol_version",
        "build_id",
        "profile_id",
        "profile_version",
        "candidate_ieee",
        "candidate_set_topic",
        "operation_id",
        "bound_boot_id",
        "phase",
        "generation",
        "operation_deadline_ms",
        "last_request_deadline_ms",
        "expected_proof_deadline_ms",
        "intended_target",
        "challenge_target",
        "physical_targets",
        "restore_required",
        "remediation_after_restore",
        "restore_attempts",
        "consumed_request_ids",
        "used_sequences",
        "proofs",
        "expected_proof",
        "outcome",
        "failure_code",
        "result_id",
        "result_not_before_ms",
        "cleanup_allowed",
    }
)


@dataclass(frozen=True, slots=True)
class ProbeRecoveryRecord:
    """Exact bounded durable state; it contains no raw frames or credentials."""

    schema: str
    protocol_id: str
    protocol_version: int
    build_id: str
    profile_id: str
    profile_version: int
    candidate_ieee: str
    candidate_set_topic: str
    operation_id: str
    bound_boot_id: str
    phase: ProbePhase
    generation: int
    operation_deadline_ms: int
    last_request_deadline_ms: int
    expected_proof_deadline_ms: int
    intended_target: int
    challenge_target: int
    physical_targets: tuple[int, int]
    restore_required: bool
    remediation_after_restore: bool
    restore_attempts: int
    consumed_request_ids: tuple[str, ...]
    used_sequences: tuple[int, ...]
    proofs: tuple[ProbeCommandProof, ...]
    expected_proof: ExpectedProbeProof | None
    outcome: ProbeOutcome | None
    failure_code: str | None
    result_id: str | None
    result_not_before_ms: int
    cleanup_allowed: bool

    def __post_init__(self) -> None:
        profile = _validate_recovery_scalars(self)
        _validate_recovery_collections(self, profile)
        _validate_recovery_phase(self)
        _validate_recovery_sequence_capacity(self)
        if len(self.canonical_json().encode("utf-8")) > MAX_STATE_JSON_BYTES:
            raise PhysicalProbeError("Recovery record exceeds its byte limit.")

    @classmethod
    def arm(
        cls,
        *,
        profile: PhysicalProbeProfile,
        candidate: NormalizedCandidateIdentity,
        candidate_set_topic: str,
        operation_id: str,
        boot_id: str,
        request_id: str,
        request_deadline_ms: int,
        operation_deadline_ms: int,
        intended_target: int,
        physical_targets: tuple[int, int],
        now_ms: int,
    ) -> ProbeRecoveryRecord:
        """Create the first durable state without dispatching a command."""

        candidate.require_profile(profile)
        _require_set_topic(candidate_set_topic)
        _require_pattern(operation_id, _OPERATION_ID_PATTERN, "operation ID")
        _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
        _require_pattern(request_id, _REQUEST_ID_PATTERN, "request ID")
        _validate_fresh_deadline(
            request_deadline_ms,
            now_ms,
            MAX_REQUEST_WINDOW_MS,
            "request deadline",
        )
        _validate_fresh_deadline(
            operation_deadline_ms,
            now_ms,
            MAX_OPERATION_WINDOW_MS,
            "operation deadline",
        )
        if request_deadline_ms >= operation_deadline_ms:
            raise PhysicalProbeError("Operation deadline must follow the request deadline.")
        profile.validate_target(intended_target, "intended target")
        _validate_physical_targets(physical_targets, intended_target, profile)
        expected_deadline = _bounded_phase_deadline(
            now_ms,
            operation_deadline_ms,
            PHYSICAL_PROOF_WINDOW_MS,
        )
        return cls(
            schema=STATE_SCHEMA,
            protocol_id=PROTOCOL_ID,
            protocol_version=PROTOCOL_VERSION,
            build_id=BUILD_ID,
            profile_id=profile.profile_id,
            profile_version=profile.profile_version,
            candidate_ieee=candidate.ieee_address,
            candidate_set_topic=candidate_set_topic,
            operation_id=operation_id,
            bound_boot_id=boot_id,
            phase=ProbePhase.AWAITING_PHYSICAL_TARGET_1,
            generation=1,
            operation_deadline_ms=operation_deadline_ms,
            last_request_deadline_ms=request_deadline_ms,
            expected_proof_deadline_ms=expected_deadline,
            intended_target=intended_target,
            challenge_target=profile.challenge_target(intended_target),
            physical_targets=physical_targets,
            restore_required=False,
            remediation_after_restore=False,
            restore_attempts=0,
            consumed_request_ids=(request_id,),
            used_sequences=(),
            proofs=(),
            expected_proof=ExpectedProbeProof(
                ProbePurpose.PHYSICAL_TARGET_1,
                ProbeFrameKind.COMMAND_RESPONSE,
                None,
                physical_targets[0],
            ),
            outcome=None,
            failure_code=None,
            result_id=None,
            result_not_before_ms=0,
            cleanup_allowed=False,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProbeRecoveryRecord:
        """Load and revalidate every field of a durable record."""

        _require_exact_fields(data, _RECOVERY_FIELDS, "probe recovery record")
        physical_targets = data["physical_targets"]
        consumed = data["consumed_request_ids"]
        sequences = data["used_sequences"]
        proofs = data["proofs"]
        if type(physical_targets) is not list or len(physical_targets) != 2:
            raise PhysicalProbeError("Stored physical targets must be a two-item list.")
        for value, label in (
            (consumed, "consumed request IDs"),
            (sequences, "used sequences"),
            (proofs, "proofs"),
        ):
            if type(value) is not list:
                raise PhysicalProbeError(f"Stored {label} must be a list.")
        expected = data["expected_proof"]
        outcome = data["outcome"]
        return cls(
            schema=data["schema"],
            protocol_id=data["protocol_id"],
            protocol_version=data["protocol_version"],
            build_id=data["build_id"],
            profile_id=data["profile_id"],
            profile_version=data["profile_version"],
            candidate_ieee=data["candidate_ieee"],
            candidate_set_topic=data["candidate_set_topic"],
            operation_id=data["operation_id"],
            bound_boot_id=data["bound_boot_id"],
            phase=_parse_enum(ProbePhase, data["phase"], "probe phase"),
            generation=data["generation"],
            operation_deadline_ms=data["operation_deadline_ms"],
            last_request_deadline_ms=data["last_request_deadline_ms"],
            expected_proof_deadline_ms=data["expected_proof_deadline_ms"],
            intended_target=data["intended_target"],
            challenge_target=data["challenge_target"],
            physical_targets=(physical_targets[0], physical_targets[1]),
            restore_required=data["restore_required"],
            remediation_after_restore=data["remediation_after_restore"],
            restore_attempts=data["restore_attempts"],
            consumed_request_ids=tuple(consumed),
            used_sequences=tuple(sequences),
            proofs=tuple(ProbeCommandProof.from_dict(item) for item in proofs),
            expected_proof=(
                ExpectedProbeProof.from_dict(expected) if expected is not None else None
            ),
            outcome=(
                _parse_enum(ProbeOutcome, outcome, "probe outcome")
                if outcome is not None
                else None
            ),
            failure_code=data["failure_code"],
            result_id=data["result_id"],
            result_not_before_ms=data["result_not_before_ms"],
            cleanup_allowed=data["cleanup_allowed"],
        )

    def as_dict(self) -> dict[str, Any]:
        """Return the one exact durable JSON object."""

        return {
            "schema": self.schema,
            "protocol_id": self.protocol_id,
            "protocol_version": self.protocol_version,
            "build_id": self.build_id,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "candidate_ieee": self.candidate_ieee,
            "candidate_set_topic": self.candidate_set_topic,
            "operation_id": self.operation_id,
            "bound_boot_id": self.bound_boot_id,
            "phase": self.phase.value,
            "generation": self.generation,
            "operation_deadline_ms": self.operation_deadline_ms,
            "last_request_deadline_ms": self.last_request_deadline_ms,
            "expected_proof_deadline_ms": self.expected_proof_deadline_ms,
            "intended_target": self.intended_target,
            "challenge_target": self.challenge_target,
            "physical_targets": list(self.physical_targets),
            "restore_required": self.restore_required,
            "remediation_after_restore": self.remediation_after_restore,
            "restore_attempts": self.restore_attempts,
            "consumed_request_ids": list(self.consumed_request_ids),
            "used_sequences": list(self.used_sequences),
            "proofs": [proof.as_dict() for proof in self.proofs],
            "expected_proof": (
                self.expected_proof.as_dict() if self.expected_proof else None
            ),
            "outcome": self.outcome.value if self.outcome else None,
            "failure_code": self.failure_code,
            "result_id": self.result_id,
            "result_not_before_ms": self.result_not_before_ms,
            "cleanup_allowed": self.cleanup_allowed,
        }

    def canonical_json(self) -> str:
        """Return deterministic bounded UTF-8 persistence text."""

        return canonical_json(self.as_dict(), maximum_bytes=MAX_STATE_JSON_BYTES)

    def accept_proof(
        self,
        proof: ProbeCommandProof,
        *,
        now_ms: int,
        next_sequence: int | None = None,
    ) -> ProbeRecoveryRecord:
        """Advance one exact timely proof, persisting before caller dispatch."""

        if self.expected_proof is None or not self.expected_proof.accepts(proof):
            raise PhysicalProbeError("Observed proof does not match the expected proof.")
        _require_safe_milliseconds(now_ms, "proof time")
        if now_ms >= self.expected_proof_deadline_ms:
            raise PhysicalProbeError("Observed proof arrived after its deadline.")
        physical = proof.purpose in {
            ProbePurpose.PHYSICAL_TARGET_1,
            ProbePurpose.PHYSICAL_TARGET_2,
        }
        if physical:
            if proof.sequence in self.used_sequences:
                raise PhysicalProbeError("Physical proof sequence is not fresh.")
            used_sequences = (*self.used_sequences, proof.sequence)
        else:
            if proof.sequence not in self.used_sequences:
                raise PhysicalProbeError("Command response sequence was never dispatched.")
            used_sequences = self.used_sequences
        proofs = (*self.proofs, proof)

        if self.phase is ProbePhase.AWAITING_PHYSICAL_TARGET_1:
            return self._transition(
                phase=ProbePhase.AWAITING_PHYSICAL_TARGET_2,
                proofs=proofs,
                used_sequences=used_sequences,
                expected_proof=ExpectedProbeProof(
                    ProbePurpose.PHYSICAL_TARGET_2,
                    ProbeFrameKind.COMMAND_RESPONSE,
                    None,
                    self.physical_targets[1],
                ),
                expected_proof_deadline_ms=_bounded_phase_deadline(
                    now_ms,
                    self.operation_deadline_ms,
                    PHYSICAL_PROOF_WINDOW_MS,
                ),
            )
        if self.phase is ProbePhase.AWAITING_PHYSICAL_TARGET_2:
            sequence = _require_new_sequence(
                next_sequence,
                used_sequences,
                reserve_after=_POST_NOOP_SEQUENCE_RESERVE,
            )
            return self._transition(
                phase=ProbePhase.AWAITING_NOOP_RESPONSE,
                proofs=proofs,
                used_sequences=(*used_sequences, sequence),
                expected_proof=ExpectedProbeProof(
                    ProbePurpose.NOOP,
                    ProbeFrameKind.COMMAND_RESPONSE,
                    sequence,
                    self.intended_target,
                ),
                expected_proof_deadline_ms=_bounded_phase_deadline(
                    now_ms,
                    self.operation_deadline_ms,
                    DIRECT_PROOF_WINDOW_MS,
                ),
            )
        if self.phase is ProbePhase.AWAITING_NOOP_RESPONSE:
            sequence = _require_new_sequence(
                next_sequence,
                used_sequences,
                reserve_after=_POST_CHALLENGE_SEQUENCE_RESERVE,
            )
            return self._transition(
                phase=ProbePhase.AWAITING_CHALLENGE_RESPONSE,
                proofs=proofs,
                used_sequences=(*used_sequences, sequence),
                expected_proof=ExpectedProbeProof(
                    ProbePurpose.CHALLENGE,
                    ProbeFrameKind.COMMAND_RESPONSE,
                    sequence,
                    self.challenge_target,
                ),
                expected_proof_deadline_ms=_bounded_phase_deadline(
                    now_ms,
                    self.operation_deadline_ms,
                    DIRECT_PROOF_WINDOW_MS,
                ),
                restore_required=True,
            )
        if self.phase is ProbePhase.AWAITING_CHALLENGE_RESPONSE:
            return self.begin_restore(
                sequence=next_sequence,
                failure_code=self.failure_code,
                now_ms=now_ms,
                proofs=proofs,
                used_sequences=used_sequences,
            )
        if self.phase is ProbePhase.AWAITING_RESTORE_RESPONSE:
            if self.remediation_after_restore:
                return self.to_remediation(
                    failure_code=self.failure_code or "restart_recovery",
                    restore_required=False,
                )
            outcome = (
                ProbeOutcome.FAILED_RESTORED
                if self.failure_code is not None
                else ProbeOutcome.VERIFIED
            )
            return self._terminal(
                outcome,
                proofs=proofs,
                used_sequences=used_sequences,
                now_ms=now_ms,
            )
        raise PhysicalProbeError("No proof is accepted in the current phase.")

    def begin_restore(
        self,
        *,
        sequence: int | None,
        failure_code: str | None,
        now_ms: int,
        proofs: tuple[ProbeCommandProof, ...] | None = None,
        used_sequences: tuple[int, ...] | None = None,
        remediation_after_restore: bool | None = None,
    ) -> ProbeRecoveryRecord:
        """Create one fresh bounded restore attempt."""

        if self.phase not in {
            ProbePhase.AWAITING_CHALLENGE_RESPONSE,
            ProbePhase.AWAITING_RESTORE_RESPONSE,
            ProbePhase.RESULT_PENDING_ACK,
            ProbePhase.REMEDIATION_REQUIRED,
        }:
            raise PhysicalProbeError("Restore is not available in this phase.")
        if failure_code is not None:
            _validate_failure_code(failure_code)
        if remediation_after_restore is None:
            remediation_after_restore = (
                self.remediation_after_restore
                or self.phase is ProbePhase.REMEDIATION_REQUIRED
                or failure_code in _REMEDIATION_AFTER_RESTORE_CODES
            )
        if type(remediation_after_restore) is not bool:
            raise PhysicalProbeError("Restore remediation intent must be boolean.")
        attempts = self.restore_attempts + 1
        if attempts > MAX_RESTORE_ATTEMPTS:
            raise PhysicalProbeError("Restore attempt limit is exhausted.")
        base_used = self.used_sequences if used_sequences is None else used_sequences
        sequence = _require_new_sequence(
            sequence,
            base_used,
            reserve_after=(
                MAX_RESTORE_ATTEMPTS
                - attempts
                + MAX_UNCLAIMED_SAFETY_ATTEMPTS
            ),
        )
        return self._transition(
            phase=ProbePhase.AWAITING_RESTORE_RESPONSE,
            expected_proof_deadline_ms=_full_phase_deadline(
                now_ms,
                self.operation_deadline_ms,
                DIRECT_PROOF_WINDOW_MS,
            ),
            used_sequences=(*base_used, sequence),
            proofs=self.proofs if proofs is None else proofs,
            expected_proof=ExpectedProbeProof(
                ProbePurpose.RESTORE,
                ProbeFrameKind.COMMAND_RESPONSE,
                sequence,
                self.intended_target,
            ),
            restore_required=True,
            remediation_after_restore=remediation_after_restore,
            restore_attempts=attempts,
            failure_code=failure_code,
            outcome=None,
            result_id=None,
            result_not_before_ms=0,
            cleanup_allowed=False,
        )

    def reuse_restore(self, *, boot_id: str, now_ms: int) -> ProbeRecoveryRecord:
        """Re-arm the same persisted restore sequence after restart."""

        if (
            self.phase is not ProbePhase.AWAITING_RESTORE_RESPONSE
            or self.expected_proof is None
            or self.restore_attempts < 1
        ):
            raise PhysicalProbeError("No persisted restore can be reused.")
        _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
        return self._transition(
            bound_boot_id=boot_id,
            expected_proof_deadline_ms=_full_phase_deadline(
                now_ms,
                self.operation_deadline_ms,
                DIRECT_PROOF_WINDOW_MS,
            ),
            failure_code=self.failure_code or "restart_recovery",
        )

    def fail_safe(
        self,
        failure_code: str,
        *,
        now_ms: int,
        boot_id: str,
    ) -> ProbeRecoveryRecord:
        """Finish before a challenge when no restore can be required."""

        if self.restore_required or self.phase in {
            ProbePhase.RESULT_PENDING_ACK,
            ProbePhase.QUIESCENT,
            ProbePhase.REMEDIATION_REQUIRED,
        }:
            raise PhysicalProbeError("A safe failure is not available in this phase.")
        _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
        if boot_id != self.bound_boot_id:
            raise PhysicalProbeError("Safe terminalization requires the bound boot.")
        _validate_failure_code(failure_code)
        return self._terminal(
            ProbeOutcome.FAILED_SAFE,
            proofs=self.proofs,
            used_sequences=self.used_sequences,
            failure_code=failure_code,
            now_ms=now_ms,
        )

    def to_remediation(
        self,
        *,
        failure_code: str,
        restore_required: bool,
    ) -> ProbeRecoveryRecord:
        """Latch a durable no-cleanup state without claiming success."""

        _validate_failure_code(failure_code)
        if type(restore_required) is not bool:
            raise PhysicalProbeError("Remediation restore flag must be boolean.")
        changes = {
            "phase": ProbePhase.REMEDIATION_REQUIRED,
            "expected_proof": None,
            "expected_proof_deadline_ms": 0,
            "restore_required": restore_required,
            "remediation_after_restore": False,
            "outcome": None,
            "failure_code": failure_code,
            "result_id": None,
            "result_not_before_ms": 0,
            "cleanup_allowed": False,
        }
        if self.generation < MAX_GENERATION:
            return self._transition(**changes)
        return replace(self, **changes)

    def resume(
        self,
        *,
        boot_id: str,
        request_id: str,
        request_deadline_ms: int,
        now_ms: int,
        next_sequence: int | None = None,
    ) -> ProbeRecoveryRecord:
        """Bind unfinished safe work to a fresh boot; only a no-op may dispatch."""

        if self.restore_required or self.phase in {
            ProbePhase.RESULT_PENDING_ACK,
            ProbePhase.QUIESCENT,
            ProbePhase.REMEDIATION_REQUIRED,
        }:
            raise PhysicalProbeError("This recovery phase cannot be resumed.")
        if now_ms >= self.operation_deadline_ms:
            raise PhysicalProbeError("The operation deadline has expired.")
        _validate_request_binding(
            self,
            boot_id=boot_id,
            request_id=request_id,
            request_deadline_ms=request_deadline_ms,
            now_ms=now_ms,
        )
        expected = self.expected_proof
        used = self.used_sequences
        proof_deadline = _bounded_phase_deadline(
            now_ms,
            self.operation_deadline_ms,
            (
                DIRECT_PROOF_WINDOW_MS
                if self.phase is ProbePhase.AWAITING_NOOP_RESPONSE
                else PHYSICAL_PROOF_WINDOW_MS
            ),
        )
        if self.phase is ProbePhase.AWAITING_NOOP_RESPONSE:
            sequence = _require_new_sequence(
                next_sequence,
                used,
                reserve_after=_POST_NOOP_SEQUENCE_RESERVE,
            )
            used = (*used, sequence)
            expected = ExpectedProbeProof(
                ProbePurpose.NOOP,
                ProbeFrameKind.COMMAND_RESPONSE,
                sequence,
                self.intended_target,
            )
        return self._transition(
            bound_boot_id=boot_id,
            consumed_request_ids=_next_consumed_ids(self, boot_id, request_id),
            last_request_deadline_ms=request_deadline_ms,
            used_sequences=used,
            expected_proof=expected,
            expected_proof_deadline_ms=proof_deadline,
        )

    def acknowledge(
        self,
        *,
        boot_id: str,
        request_id: str,
        request_deadline_ms: int,
        result_id: str,
        now_ms: int,
    ) -> ProbeRecoveryRecord:
        """Durably enter quiescence; this is the only cleanup-allowed state."""

        if self.phase is not ProbePhase.RESULT_PENDING_ACK or result_id != self.result_id:
            raise PhysicalProbeError("Acknowledgement does not match a pending result.")
        _require_safe_milliseconds(now_ms, "acknowledgement time")
        if boot_id != self.bound_boot_id:
            raise PhysicalProbeError("Result acknowledgement must use the bound boot.")
        if now_ms >= self.operation_deadline_ms:
            raise PhysicalProbeError("The operation deadline has expired.")
        if now_ms < self.result_not_before_ms:
            raise PhysicalProbeError("Result acknowledgement is still settling.")
        _validate_request_binding(
            self,
            boot_id=boot_id,
            request_id=request_id,
            request_deadline_ms=request_deadline_ms,
            now_ms=now_ms,
        )
        return self._transition(
            phase=ProbePhase.QUIESCENT,
            bound_boot_id=boot_id,
            consumed_request_ids=_next_consumed_ids(self, boot_id, request_id),
            last_request_deadline_ms=request_deadline_ms,
            expected_proof_deadline_ms=0,
            cleanup_allowed=True,
        )

    def _terminal(
        self,
        outcome: ProbeOutcome,
        *,
        proofs: tuple[ProbeCommandProof, ...],
        used_sequences: tuple[int, ...],
        failure_code: str | None = None,
        now_ms: int,
    ) -> ProbeRecoveryRecord:
        failure = self.failure_code if failure_code is None else failure_code
        result_not_before_ms = _checked_add(
            now_ms,
            RESULT_SETTLING_WINDOW_MS,
            "result settling time",
        )
        if result_not_before_ms >= self.operation_deadline_ms:
            raise PhysicalProbeError(
                "Result settling cannot complete within operation authority."
            )
        values = {
            **self.as_dict(),
            "phase": ProbePhase.RESULT_PENDING_ACK.value,
            "generation": self.generation + 1,
            "operation_deadline_ms": self.operation_deadline_ms,
            "expected_proof_deadline_ms": 0,
            "restore_required": False,
            "remediation_after_restore": False,
            "used_sequences": list(used_sequences),
            "proofs": [proof.as_dict() for proof in proofs],
            "expected_proof": None,
            "outcome": outcome.value,
            "failure_code": failure,
            "result_id": None,
            "result_not_before_ms": result_not_before_ms,
            "cleanup_allowed": False,
        }
        values["result_id"] = calculate_result_id(values)
        return ProbeRecoveryRecord.from_dict(values)

    def _transition(self, **changes: Any) -> ProbeRecoveryRecord:
        if self.generation >= MAX_GENERATION:
            raise PhysicalProbeError("Probe generation limit is exhausted.")
        if (
            "operation_deadline_ms" in changes
            and changes["operation_deadline_ms"] != self.operation_deadline_ms
        ):
            raise PhysicalProbeError("Operation authority is immutable.")
        return replace(self, generation=self.generation + 1, **changes)


_COMMON_REQUEST_FIELDS = frozenset(
    {
        "action",
        "protocol_id",
        "protocol_version",
        "build_id",
        "profile_id",
        "profile_version",
        "boot_id",
        "request_id",
        "operation_id",
        "nonce",
        "phase",
        "generation",
        "request_deadline_ms",
    }
)
_ARM_REQUEST_FIELDS = _COMMON_REQUEST_FIELDS | {
    "candidate",
    "intended_target",
    "physical_targets",
    "operation_deadline_ms",
}
_ACK_REQUEST_FIELDS = _COMMON_REQUEST_FIELDS | {"result_id"}


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """Exact canonical arm, resume, or result-acknowledgement message."""

    action: ProbeAction
    profile_id: str
    profile_version: int
    boot_id: str
    request_id: str
    operation_id: str
    nonce: str
    phase: ProbePhase
    generation: int
    request_deadline_ms: int
    candidate: NormalizedCandidateIdentity | None = None
    intended_target: int | None = None
    physical_targets: tuple[int, int] | None = None
    operation_deadline_ms: int | None = None
    result_id: str | None = None

    def __post_init__(self) -> None:
        profile = _profile(self.profile_id, self.profile_version)
        _require_pattern(self.boot_id, _BOOT_ID_PATTERN, "request boot ID")
        _require_pattern(self.request_id, _REQUEST_ID_PATTERN, "request ID")
        _require_pattern(self.operation_id, _OPERATION_ID_PATTERN, "operation ID")
        _require_pattern(self.nonce, _NONCE_PATTERN, "request nonce")
        _require_nonnegative_integer(self.generation, "request generation")
        if self.generation > MAX_GENERATION:
            raise PhysicalProbeError("Request generation exceeds its bound.")
        _require_safe_milliseconds(self.request_deadline_ms, "request deadline")
        if self.action is ProbeAction.ARM:
            if self.phase is not ProbePhase.QUIESCENT or self.candidate is None:
                raise PhysicalProbeError("Arm request must target quiescence with a candidate.")
            self.candidate.require_profile(profile)
            if self.intended_target is None or self.physical_targets is None:
                raise PhysicalProbeError("Arm request requires exact target fields.")
            profile.validate_target(self.intended_target, "intended target")
            _validate_physical_targets(
                self.physical_targets, self.intended_target, profile
            )
            _require_safe_milliseconds(
                self.operation_deadline_ms, "operation deadline"
            )
            if self.result_id is not None:
                raise PhysicalProbeError("Arm request cannot contain a result ID.")
        elif self.action is ProbeAction.ACK:
            if self.phase is not ProbePhase.RESULT_PENDING_ACK:
                raise PhysicalProbeError("Ack request must target a pending result.")
            _require_pattern(self.result_id, _RESULT_ID_PATTERN, "result ID")
            if any(
                value is not None
                for value in (
                    self.candidate,
                    self.intended_target,
                    self.physical_targets,
                    self.operation_deadline_ms,
                )
            ):
                raise PhysicalProbeError("Ack request has unexpected arm fields.")
        else:
            if self.phase in {
                ProbePhase.RESULT_PENDING_ACK,
                ProbePhase.QUIESCENT,
                ProbePhase.REMEDIATION_REQUIRED,
            } or any(
                value is not None
                for value in (
                    self.candidate,
                    self.intended_target,
                    self.physical_targets,
                    self.operation_deadline_ms,
                    self.result_id,
                )
            ):
                raise PhysicalProbeError("Resume request has unexpected fields or phase.")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProbeRequest:
        """Parse one strict request variant without coercion."""

        if type(data) is not dict:
            raise PhysicalProbeError("Probe request must be a plain object.")
        action = _parse_enum(ProbeAction, data.get("action"), "probe action")
        expected_fields = (
            _ARM_REQUEST_FIELDS
            if action is ProbeAction.ARM
            else _ACK_REQUEST_FIELDS
            if action is ProbeAction.ACK
            else _COMMON_REQUEST_FIELDS
        )
        _require_exact_fields(data, expected_fields, "probe request")
        if data["protocol_id"] != PROTOCOL_ID or data["protocol_version"] != PROTOCOL_VERSION:
            raise PhysicalProbeError("Probe request protocol identity is incompatible.")
        if data["build_id"] != BUILD_ID:
            raise PhysicalProbeError("Probe request build identity is incompatible.")
        targets = data.get("physical_targets")
        if targets is not None and (type(targets) is not list or len(targets) != 2):
            raise PhysicalProbeError("Request physical targets must be a two-item list.")
        candidate = data.get("candidate")
        return cls(
            action=action,
            profile_id=data["profile_id"],
            profile_version=data["profile_version"],
            boot_id=data["boot_id"],
            request_id=data["request_id"],
            operation_id=data["operation_id"],
            nonce=data["nonce"],
            phase=_parse_enum(ProbePhase, data["phase"], "request phase"),
            generation=data["generation"],
            request_deadline_ms=data["request_deadline_ms"],
            candidate=(
                NormalizedCandidateIdentity.from_projection(candidate)
                if candidate is not None
                else None
            ),
            intended_target=data.get("intended_target"),
            physical_targets=(
                (targets[0], targets[1]) if targets is not None else None
            ),
            operation_deadline_ms=data.get("operation_deadline_ms"),
            result_id=data.get("result_id"),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return the exact request variant."""

        data: dict[str, Any] = {
            "action": self.action.value,
            "protocol_id": PROTOCOL_ID,
            "protocol_version": PROTOCOL_VERSION,
            "build_id": BUILD_ID,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "boot_id": self.boot_id,
            "request_id": self.request_id,
            "operation_id": self.operation_id,
            "nonce": self.nonce,
            "phase": self.phase.value,
            "generation": self.generation,
            "request_deadline_ms": self.request_deadline_ms,
        }
        if self.action is ProbeAction.ARM:
            data.update(
                {
                    "candidate": self.candidate.as_dict() if self.candidate else None,
                    "intended_target": self.intended_target,
                    "physical_targets": (
                        list(self.physical_targets) if self.physical_targets else None
                    ),
                    "operation_deadline_ms": self.operation_deadline_ms,
                }
            )
        elif self.action is ProbeAction.ACK:
            data["result_id"] = self.result_id
        return data


def canonical_json(value: Any, *, maximum_bytes: int = MAX_MESSAGE_JSON_BYTES) -> str:
    """Serialize bounded JSON exactly as UTF-8 JavaScript JSON.stringify order."""

    _require_positive_integer(maximum_bytes, "JSON byte limit")
    _validate_json_tree(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as err:
        raise PhysicalProbeError("Value is not canonical JSON data.") from err
    if len(encoded.encode("utf-8")) > maximum_bytes:
        raise PhysicalProbeError("Canonical JSON exceeds its byte limit.")
    return encoded


def parse_canonical_json(
    text: str, *, maximum_bytes: int = MAX_MESSAGE_JSON_BYTES
) -> dict[str, Any]:
    """Parse one bounded canonical plain JSON object and reject duplicates."""

    if type(text) is not str:
        raise PhysicalProbeError("Canonical JSON input must be text.")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as err:
        raise PhysicalProbeError("Canonical JSON input is not valid UTF-8 text.") from err
    if not encoded or len(encoded) > maximum_bytes:
        raise PhysicalProbeError("Canonical JSON input is empty or oversized.")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PhysicalProbeError("Canonical JSON contains a duplicate key.")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, PhysicalProbeError, RecursionError) as err:
        raise PhysicalProbeError("Canonical JSON input is malformed.") from err
    if type(value) is not dict:
        raise PhysicalProbeError("Canonical JSON root must be a plain object.")
    if canonical_json(value, maximum_bytes=maximum_bytes) != text:
        raise PhysicalProbeError("JSON input is not in canonical form.")
    return value


def canonical_digest(value: Any, *, domain: str = PROTOCOL_ID) -> str:
    """Return a UTF-8 domain-separated digest of bounded canonical JSON."""

    _require_text(domain, "digest domain", maximum=96)
    body = canonical_json(value, maximum_bytes=MAX_STATE_JSON_BYTES).encode("utf-8")
    domain_bytes = domain.encode("utf-8")
    return hashlib.sha256(
        len(domain_bytes).to_bytes(2, "big")
        + domain_bytes
        + len(body).to_bytes(4, "big")
        + body
    ).hexdigest()


def calculate_result_id(record_data: Mapping[str, Any]) -> str:
    """Calculate the stable correlated result ID without exposing the IEEE."""

    required = {
        "operation_id",
        "profile_id",
        "profile_version",
        "intended_target",
        "challenge_target",
        "proofs",
        "outcome",
        "failure_code",
    }
    if not isinstance(record_data, Mapping) or not required <= set(record_data):
        raise PhysicalProbeError("Result identity input is incomplete.")
    digest = canonical_digest(
        {field: record_data[field] for field in sorted(required)},
        domain="true-family-physical-probe/result/v2",
    )
    return f"tfpp-result-{digest[:24]}"


def ready_message(boot_id: str) -> dict[str, Any]:
    """Return the exact non-retained ready projection."""

    _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
    return {
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "build_id": BUILD_ID,
        "profile_id": BRT_PROFILE.profile_id,
        "profile_version": BRT_PROFILE.profile_version,
        "boot_id": boot_id,
        "phase": "ready",
        "required_runtime_versions": {
            "zigbee2mqtt": Z2M_2_12_1_VERSION_TUPLE[0],
            "zigbee_herdsman": Z2M_2_12_1_VERSION_TUPLE[1],
            "zigbee_herdsman_converters": Z2M_2_12_1_VERSION_TUPLE[2],
        },
        "request_topic": REQUEST_TOPIC,
        "ack_topic": ACK_TOPIC,
    }


def status_message(
    boot_id: str,
    record: ProbeRecoveryRecord | None,
    *,
    remediation_required: bool = False,
) -> dict[str, Any]:
    """Return status with only a masked IEEE and fixed failure state."""

    _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
    if type(remediation_required) is not bool:
        raise PhysicalProbeError("Remediation state must be boolean.")
    remediation = remediation_required or record is not None and record.phase is ProbePhase.REMEDIATION_REQUIRED
    if (
        record is not None
        and record.phase in {ProbePhase.RESULT_PENDING_ACK, ProbePhase.QUIESCENT}
        and record.bound_boot_id != boot_id
        and not remediation
    ):
        raise PhysicalProbeError("Status cannot advertise an old-boot result.")
    return {
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "build_id": BUILD_ID,
        "profile_id": BRT_PROFILE.profile_id,
        "profile_version": BRT_PROFILE.profile_version,
        "boot_id": boot_id,
        "phase": (
            "remediation_required"
            if remediation
            else record.phase.value
            if record
            else "idle"
        ),
        "generation": record.generation if record else 0,
        "operation_id": record.operation_id if record else None,
        "result_id": record.result_id if record and not remediation else None,
        "result_not_before_ms": (
            record.result_not_before_ms if record and not remediation else 0
        ),
        "identity": mask_ieee(record.candidate_ieee) if record else None,
        "restore_required": record.restore_required if record else False,
        "restore_attempts": record.restore_attempts if record else 0,
        "cleanup_allowed": record.cleanup_allowed if record and not remediation else False,
    }


def result_message(boot_id: str, record: ProbeRecoveryRecord) -> dict[str, Any]:
    """Return one exact terminal result projection."""

    _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
    if record.phase not in {ProbePhase.RESULT_PENDING_ACK, ProbePhase.QUIESCENT}:
        raise PhysicalProbeError("A result message requires a terminal record.")
    if record.bound_boot_id != boot_id:
        raise PhysicalProbeError("Result publication requires its bound boot.")
    return {
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "build_id": BUILD_ID,
        "profile_id": record.profile_id,
        "profile_version": record.profile_version,
        "boot_id": boot_id,
        "operation_id": record.operation_id,
        "result_id": record.result_id,
        "result_not_before_ms": record.result_not_before_ms,
        "phase": record.phase.value,
        "generation": record.generation,
        "identity": mask_ieee(record.candidate_ieee),
        "outcome": record.outcome.value if record.outcome else None,
        "failure_code": record.failure_code,
        "cleanup_allowed": record.cleanup_allowed,
    }


def response_message(
    boot_id: str,
    *,
    request_id: str | None,
    operation_id: str | None,
    action: str,
    accepted: bool,
    phase: str,
    generation: int,
    error_code: str | None,
) -> dict[str, Any]:
    """Return a bounded correlated response without echoing request payload."""

    _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
    if request_id is not None:
        _require_pattern(request_id, _REQUEST_ID_PATTERN, "request ID")
    if operation_id is not None:
        _require_pattern(operation_id, _OPERATION_ID_PATTERN, "operation ID")
    _require_text(action, "response action", maximum=16)
    if type(accepted) is not bool:
        raise PhysicalProbeError("Response acceptance must be boolean.")
    _require_text(phase, "response phase", maximum=48)
    _require_nonnegative_integer(generation, "response generation")
    if generation > MAX_GENERATION:
        raise PhysicalProbeError("Response generation exceeds its bound.")
    if error_code is not None:
        _require_text(error_code, "response error code", maximum=48)
    return {
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "build_id": BUILD_ID,
        "boot_id": boot_id,
        "request_id": request_id,
        "operation_id": operation_id,
        "action": action,
        "accepted": accepted,
        "phase": phase,
        "generation": generation,
        "error_code": error_code,
    }


def mask_ieee(ieee_address: str) -> str:
    """Mask a normalized IEEE address for public output."""

    _require_pattern(ieee_address, _IEEE_PATTERN, "IEEE address")
    return f"...{ieee_address[-4:].upper()}"


def _validate_recovery_scalars(record: ProbeRecoveryRecord) -> PhysicalProbeProfile:
    if record.schema != STATE_SCHEMA or record.protocol_id != PROTOCOL_ID:
        raise PhysicalProbeError("Recovery record schema or protocol is incompatible.")
    if record.protocol_version != PROTOCOL_VERSION or record.build_id != BUILD_ID:
        raise PhysicalProbeError("Recovery record build identity is incompatible.")
    profile = _profile(record.profile_id, record.profile_version)
    _require_pattern(record.candidate_ieee, _IEEE_PATTERN, "candidate IEEE address")
    _require_set_topic(record.candidate_set_topic)
    _require_pattern(record.operation_id, _OPERATION_ID_PATTERN, "operation ID")
    _require_pattern(record.bound_boot_id, _BOOT_ID_PATTERN, "bound boot ID")
    _require_nonnegative_integer(record.generation, "record generation")
    if not 1 <= record.generation <= MAX_GENERATION:
        raise PhysicalProbeError("Record generation is outside its bound.")
    for value, label in (
        (record.operation_deadline_ms, "operation deadline"),
        (record.last_request_deadline_ms, "last request deadline"),
        (record.expected_proof_deadline_ms, "expected proof deadline"),
        (record.result_not_before_ms, "result not-before time"),
    ):
        _require_safe_milliseconds(value, label)
    profile.validate_target(record.intended_target, "intended target")
    profile.validate_target(record.challenge_target, "challenge target")
    if record.challenge_target != profile.challenge_target(record.intended_target):
        raise PhysicalProbeError("Stored challenge target is not canonical.")
    if (
        type(record.restore_required) is not bool
        or type(record.remediation_after_restore) is not bool
        or type(record.cleanup_allowed) is not bool
    ):
        raise PhysicalProbeError("Recovery flags must be strict booleans.")
    _require_nonnegative_integer(record.restore_attempts, "restore attempts")
    if record.restore_attempts > MAX_RESTORE_ATTEMPTS:
        raise PhysicalProbeError("Restore attempts exceed their bound.")
    if record.failure_code is not None:
        _validate_failure_code(record.failure_code)
    return profile


def _validate_recovery_collections(
    record: ProbeRecoveryRecord, profile: PhysicalProbeProfile
) -> None:
    _validate_physical_targets(record.physical_targets, record.intended_target, profile)
    if type(record.consumed_request_ids) is not tuple or not 1 <= len(
        record.consumed_request_ids
    ) <= MAX_CONSUMED_REQUEST_IDS:
        raise PhysicalProbeError("Consumed request IDs are outside their bound.")
    for request_id in record.consumed_request_ids:
        _require_pattern(request_id, _REQUEST_ID_PATTERN, "consumed request ID")
    if len(set(record.consumed_request_ids)) != len(record.consumed_request_ids):
        raise PhysicalProbeError("Consumed request IDs must be unique.")
    if type(record.used_sequences) is not tuple or len(record.used_sequences) > MAX_USED_SEQUENCES:
        raise PhysicalProbeError("Used sequences are outside their bound.")
    for sequence in record.used_sequences:
        _require_uint16(sequence, "used sequence")
    if len(set(record.used_sequences)) != len(record.used_sequences):
        raise PhysicalProbeError("Used sequences must be unique.")
    if type(record.proofs) is not tuple or len(record.proofs) > MAX_PROOFS:
        raise PhysicalProbeError("Proofs are outside their bound.")
    last_index = -1
    proof_targets = {
        ProbePurpose.PHYSICAL_TARGET_1: record.physical_targets[0],
        ProbePurpose.PHYSICAL_TARGET_2: record.physical_targets[1],
        ProbePurpose.NOOP: record.intended_target,
        ProbePurpose.CHALLENGE: record.challenge_target,
        ProbePurpose.RESTORE: record.intended_target,
    }
    for proof in record.proofs:
        if not isinstance(proof, ProbeCommandProof):
            raise PhysicalProbeError("Stored proof has the wrong type.")
        profile.validate_target(proof.target, "proof target")
        index = _PURPOSE_ORDER.index(proof.purpose)
        if index <= last_index:
            raise PhysicalProbeError("Stored proofs are duplicated or out of order.")
        if proof.sequence not in record.used_sequences:
            raise PhysicalProbeError("Stored proof sequence is not in the used set.")
        if proof.target != proof_targets[proof.purpose]:
            raise PhysicalProbeError("Stored proof target is not canonical.")
        last_index = index
    if record.expected_proof is not None:
        profile.validate_target(record.expected_proof.target, "expected target")
        if (
            record.expected_proof.sequence is not None
            and record.expected_proof.sequence not in record.used_sequences
        ):
            raise PhysicalProbeError("Expected command sequence is not in the used set.")


def _validate_recovery_phase(record: ProbeRecoveryRecord) -> None:
    purposes = tuple(proof.purpose for proof in record.proofs)
    p1 = ProbePurpose.PHYSICAL_TARGET_1
    p2 = ProbePurpose.PHYSICAL_TARGET_2
    noop = ProbePurpose.NOOP
    challenge = ProbePurpose.CHALLENGE
    restore = ProbePurpose.RESTORE

    if record.phase in {
        ProbePhase.RESULT_PENDING_ACK,
        ProbePhase.QUIESCENT,
        ProbePhase.REMEDIATION_REQUIRED,
    }:
        if record.expected_proof is not None or record.expected_proof_deadline_ms != 0:
            raise PhysicalProbeError("Terminal state cannot expect another proof.")
        if record.phase is ProbePhase.REMEDIATION_REQUIRED:
            if (
                record.outcome is not None
                or record.result_id is not None
                or record.result_not_before_ms != 0
                or record.remediation_after_restore
                or record.cleanup_allowed
            ):
                raise PhysicalProbeError("Remediation state cannot claim a result or cleanup.")
            if record.failure_code is None:
                raise PhysicalProbeError("Remediation state requires a fixed failure code.")
            return
        if record.restore_required:
            raise PhysicalProbeError("Result state cannot require restore.")
        if record.outcome is None or record.result_id is None:
            raise PhysicalProbeError("Result state requires an outcome and result ID.")
        if record.result_not_before_ms <= 0 or record.remediation_after_restore:
            raise PhysicalProbeError("Result state has invalid settling or remediation metadata.")
        if record.result_not_before_ms >= record.operation_deadline_ms:
            raise PhysicalProbeError("Result settling exceeds operation authority.")
        if record.result_not_before_ms > _checked_add(
            record.operation_deadline_ms,
            RESULT_SETTLING_WINDOW_MS,
            "result settling bound",
        ):
            raise PhysicalProbeError("Result settling time exceeds its durable bound.")
        _require_pattern(record.result_id, _RESULT_ID_PATTERN, "result ID")
        if calculate_result_id(record.as_dict()) != record.result_id:
            raise PhysicalProbeError("Stored result ID is not canonical.")
        if record.outcome is ProbeOutcome.VERIFIED and record.failure_code is not None:
            raise PhysicalProbeError("Verified result cannot contain a failure code.")
        if record.outcome is not ProbeOutcome.VERIFIED and record.failure_code is None:
            raise PhysicalProbeError("Failed result requires a fixed failure code.")
        if record.cleanup_allowed is not (record.phase is ProbePhase.QUIESCENT):
            raise PhysicalProbeError("Cleanup is allowed only after result acknowledgement.")
        if record.outcome is ProbeOutcome.VERIFIED and purposes != (
            p1,
            p2,
            noop,
            challenge,
            restore,
        ):
            raise PhysicalProbeError("Verified result requires every ordered proof.")
        if record.outcome is ProbeOutcome.FAILED_RESTORED and purposes not in {
            (p1, p2, noop, restore),
            (p1, p2, noop, challenge, restore),
        }:
            raise PhysicalProbeError("Failed restored result has incomplete proof history.")
        if record.outcome is ProbeOutcome.FAILED_SAFE and purposes not in {
            (),
            (p1,),
            (p1, p2),
        }:
            raise PhysicalProbeError("Safe failure has impossible proof history.")
        if (
            record.outcome is ProbeOutcome.FAILED_SAFE
            and record.restore_attempts != 0
        ) or (
            record.outcome is not ProbeOutcome.FAILED_SAFE
            and record.restore_attempts < 1
        ):
            raise PhysicalProbeError("Result restore-attempt count is inconsistent.")
        return

    if record.outcome is not None or record.result_id is not None or record.cleanup_allowed:
        raise PhysicalProbeError("Active record contains terminal fields.")
    if record.result_not_before_ms != 0:
        raise PhysicalProbeError("Active record cannot carry result settling time.")
    if (
        record.phase is not ProbePhase.AWAITING_RESTORE_RESPONSE
        and record.remediation_after_restore
    ):
        raise PhysicalProbeError("Remediation intent is valid only during restore.")
    expected_purpose = _PHASE_PURPOSE[record.phase]
    if record.expected_proof is None or record.expected_proof.purpose is not expected_purpose:
        raise PhysicalProbeError("Active phase and expected proof do not match.")
    if not 0 < record.expected_proof_deadline_ms <= record.operation_deadline_ms:
        raise PhysicalProbeError("Active proof deadline is invalid.")
    expected_target = {
        p1: record.physical_targets[0],
        p2: record.physical_targets[1],
        noop: record.intended_target,
        challenge: record.challenge_target,
        restore: record.intended_target,
    }[expected_purpose]
    if record.expected_proof.target != expected_target:
        raise PhysicalProbeError("Expected proof target is not canonical.")
    must_restore = record.phase in {
        ProbePhase.AWAITING_CHALLENGE_RESPONSE,
        ProbePhase.AWAITING_RESTORE_RESPONSE,
    }
    if record.restore_required is not must_restore:
        raise PhysicalProbeError("Restore-required flag does not match the phase.")
    valid_histories = {
        ProbePhase.AWAITING_PHYSICAL_TARGET_1: {()},
        ProbePhase.AWAITING_PHYSICAL_TARGET_2: {(p1,)},
        ProbePhase.AWAITING_NOOP_RESPONSE: {(p1, p2)},
        ProbePhase.AWAITING_CHALLENGE_RESPONSE: {(p1, p2, noop)},
        ProbePhase.AWAITING_RESTORE_RESPONSE: {
            (p1, p2, noop),
            (p1, p2, noop, challenge),
            (p1, p2, noop, challenge, restore),
        },
    }[record.phase]
    if purposes not in valid_histories:
        raise PhysicalProbeError("Active phase has incomplete proof history.")
    if record.phase is ProbePhase.AWAITING_RESTORE_RESPONSE:
        if not 1 <= record.restore_attempts <= MAX_RESTORE_ATTEMPTS:
            raise PhysicalProbeError("Restore phase requires a bounded attempt count.")
        if (
            record.failure_code in _REMEDIATION_AFTER_RESTORE_CODES
            and not record.remediation_after_restore
        ):
            raise PhysicalProbeError("Safety restore must retain remediation intent.")
        if purposes != (p1, p2, noop, challenge) and record.failure_code is None:
            raise PhysicalProbeError("Fallback restore requires a failure code.")
    elif record.restore_attempts != 0:
        raise PhysicalProbeError("Restore attempts are nonzero before restore phase.")
    if record.failure_code is not None and record.phase is not ProbePhase.AWAITING_RESTORE_RESPONSE:
        raise PhysicalProbeError("Active failure code is allowed only during restore.")


def _validate_recovery_sequence_capacity(record: ProbeRecoveryRecord) -> None:
    if record.phase is ProbePhase.AWAITING_PHYSICAL_TARGET_1:
        required = 3 + _POST_NOOP_SEQUENCE_RESERVE
    elif record.phase is ProbePhase.AWAITING_PHYSICAL_TARGET_2:
        required = 2 + _POST_NOOP_SEQUENCE_RESERVE
    elif record.phase is ProbePhase.AWAITING_NOOP_RESPONSE:
        required = _POST_NOOP_SEQUENCE_RESERVE
    elif record.phase is ProbePhase.AWAITING_CHALLENGE_RESPONSE:
        required = _POST_CHALLENGE_SEQUENCE_RESERVE
    elif record.phase is ProbePhase.AWAITING_RESTORE_RESPONSE:
        required = (
            MAX_RESTORE_ATTEMPTS
            - record.restore_attempts
            + MAX_UNCLAIMED_SAFETY_ATTEMPTS
        )
    else:
        required = _POST_RESULT_SEQUENCE_RESERVE
    if len(record.used_sequences) + required > MAX_USED_SEQUENCES:
        raise PhysicalProbeError(
            "Recovery record consumed reserved restoration sequence capacity."
        )


def _validate_proof_fields(
    purpose: ProbePurpose, frame_kind: ProbeFrameKind, target: int
) -> None:
    if not isinstance(purpose, ProbePurpose) or frame_kind is not ProbeFrameKind.COMMAND_RESPONSE:
        raise PhysicalProbeError("Every BRT DP2 proof must be commandDataResponse.")
    _require_integer(target, "proof target")


def _validate_physical_targets(
    targets: tuple[int, int], intended_target: int, profile: PhysicalProbeProfile
) -> None:
    if type(targets) is not tuple or len(targets) != 2:
        raise PhysicalProbeError("Physical targets must be an immutable ordered pair.")
    for target in targets:
        profile.validate_target(target, "physical target")
    if targets[0] == targets[1] or targets[1] != intended_target:
        raise PhysicalProbeError(
            "Physical targets must be distinct and end at the intended target."
        )


def _validate_request_binding(
    record: ProbeRecoveryRecord,
    *,
    boot_id: str,
    request_id: str,
    request_deadline_ms: int,
    now_ms: int,
) -> None:
    _require_pattern(boot_id, _BOOT_ID_PATTERN, "boot ID")
    _require_pattern(request_id, _REQUEST_ID_PATTERN, "request ID")
    _validate_fresh_deadline(
        request_deadline_ms,
        now_ms,
        MAX_REQUEST_WINDOW_MS,
        "request deadline",
    )
    if request_deadline_ms <= record.last_request_deadline_ms:
        raise PhysicalProbeError("Request deadline must advance monotonically.")
    if boot_id == record.bound_boot_id and request_id in record.consumed_request_ids:
        raise PhysicalProbeError("Request ID has already been consumed.")
    if boot_id == record.bound_boot_id and len(record.consumed_request_ids) >= MAX_CONSUMED_REQUEST_IDS:
        raise PhysicalProbeError("Consumed request ID capacity is exhausted for this boot.")


def _next_consumed_ids(
    record: ProbeRecoveryRecord, boot_id: str, request_id: str
) -> tuple[str, ...]:
    if boot_id == record.bound_boot_id:
        return (*record.consumed_request_ids, request_id)
    return (request_id,)


def _require_new_sequence(
    sequence: int | None,
    used: tuple[int, ...],
    *,
    reserve_after: int = 0,
) -> int:
    _require_generated_sequence(sequence, "next command sequence")
    assert type(sequence) is int
    if sequence in used:
        raise PhysicalProbeError("Command sequence must be distinct.")
    _require_nonnegative_integer(reserve_after, "reserved sequence capacity")
    if len(used) + 1 + reserve_after > MAX_USED_SEQUENCES:
        raise PhysicalProbeError(
            "Command would consume reserved restoration sequence capacity."
        )
    return sequence


def _validate_failure_code(value: str) -> None:
    if type(value) is not str or value not in _FAILURE_CODES:
        raise PhysicalProbeError("Failure code is not an allowlisted fixed value.")


def _profile(profile_id: str, profile_version: int) -> PhysicalProbeProfile:
    _require_pattern(profile_id, _PROFILE_ID_PATTERN, "profile ID")
    _require_positive_integer(profile_version, "profile version")
    try:
        return PROFILES[(profile_id, profile_version)]
    except KeyError as err:
        raise PhysicalProbeError("Probe profile identity is unsupported.") from err


def _bounded_phase_deadline(now_ms: int, operation_deadline_ms: int, window_ms: int) -> int:
    _require_safe_milliseconds(now_ms, "current time")
    _require_safe_milliseconds(operation_deadline_ms, "operation deadline")
    _require_positive_integer(window_ms, "phase window")
    deadline = min(
        _checked_add(now_ms, window_ms, "phase deadline"),
        operation_deadline_ms,
    )
    if deadline <= now_ms:
        raise PhysicalProbeError("No time remains for the next proof phase.")
    return deadline


def _full_phase_deadline(now_ms: int, operation_deadline_ms: int, window_ms: int) -> int:
    _require_safe_milliseconds(now_ms, "current time")
    _require_safe_milliseconds(operation_deadline_ms, "operation deadline")
    _require_positive_integer(window_ms, "phase window")
    deadline = _checked_add(now_ms, window_ms, "full phase deadline")
    if deadline > operation_deadline_ms:
        raise PhysicalProbeError(
            "A full proof window does not remain within operation authority."
        )
    return deadline


def _checked_add(value: int, increment: int, label: str) -> int:
    _require_safe_milliseconds(value, label)
    _require_positive_integer(increment, f"{label} increment")
    result = value + increment
    if result > MAX_SAFE_INTEGER:
        raise PhysicalProbeError(f"{label.capitalize()} exceeds safe milliseconds.")
    return result


def _validate_fresh_deadline(
    deadline_ms: int, now_ms: int, maximum_window_ms: int, label: str
) -> None:
    _require_safe_milliseconds(deadline_ms, label)
    _require_safe_milliseconds(now_ms, "current time")
    if not now_ms < deadline_ms <= now_ms + maximum_window_ms:
        raise PhysicalProbeError(f"{label.capitalize()} is stale or too far ahead.")


def _validate_json_tree(value: Any) -> None:
    nodes = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise PhysicalProbeError("JSON value exceeds its structural bound.")
        if item is None or type(item) in {bool, int, str}:
            if type(item) is int and not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                raise PhysicalProbeError("JSON integer exceeds the safe range.")
            if type(item) is str:
                if len(item) > MAX_JSON_STRING_LENGTH:
                    raise PhysicalProbeError("JSON string exceeds its length bound.")
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError as err:
                    raise PhysicalProbeError("JSON string is not valid UTF-8 text.") from err
            return
        if type(item) is list:
            for child in item:
                walk(child, depth + 1)
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or len(key) > 96:
                    raise PhysicalProbeError("JSON object key is not bounded text.")
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError as err:
                    raise PhysicalProbeError("JSON object key is not valid UTF-8 text.") from err
                walk(child, depth + 1)
            return
        raise PhysicalProbeError("JSON value contains an unsupported type.")

    walk(value, 0)


def _require_exact_fields(
    data: Mapping[str, Any], expected: frozenset[str] | set[str], label: str
) -> None:
    if type(data) is not dict or set(data) != set(expected):
        raise PhysicalProbeError(f"{label.capitalize()} has missing or unexpected fields.")


def _require_text(value: Any, label: str, *, maximum: int) -> None:
    if (
        type(value) is not str
        or not value
        or _BOUNDARY_WHITESPACE_PATTERN.search(value) is not None
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise PhysicalProbeError(f"{label.capitalize()} must be canonical bounded text.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as err:
        raise PhysicalProbeError(
            f"{label.capitalize()} must be canonical bounded text."
        ) from err


def _require_set_topic(value: Any) -> None:
    _require_text(value, "candidate set topic", maximum=160)
    if (
        not value.endswith("/set")
        or value.startswith("/")
        or "//" in value
        or "+" in value
        or "#" in value
    ):
        raise PhysicalProbeError("Candidate set topic is not exact.")


def _require_pattern(value: Any, pattern: re.Pattern[str], label: str) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise PhysicalProbeError(f"{label.capitalize()} is malformed.")


def _require_integer(value: Any, label: str) -> None:
    if type(value) is not int:
        raise PhysicalProbeError(f"{label.capitalize()} must be a strict integer.")


def _require_nonnegative_integer(value: Any, label: str) -> None:
    _require_integer(value, label)
    if value < 0:
        raise PhysicalProbeError(f"{label.capitalize()} cannot be negative.")


def _require_positive_integer(value: Any, label: str) -> None:
    _require_integer(value, label)
    if value <= 0:
        raise PhysicalProbeError(f"{label.capitalize()} must be positive.")


def _require_uint16(value: Any, label: str) -> None:
    _require_integer(value, label)
    if not 0 <= value <= 0xFFFF:
        raise PhysicalProbeError(f"{label.capitalize()} is outside uint16.")


def _require_generated_sequence(value: Any, label: str) -> None:
    _require_integer(value, label)
    if not 0 <= value <= 0xFFFE:
        raise PhysicalProbeError(
            f"{label.capitalize()} is outside the generated sequence range."
        )


def _require_safe_milliseconds(value: Any, label: str) -> None:
    _require_integer(value, label)
    if not 0 <= value <= MAX_SAFE_INTEGER:
        raise PhysicalProbeError(f"{label.capitalize()} is outside safe milliseconds.")


def _parse_enum[T: StrEnum](enum_type: type[T], value: Any, label: str) -> T:
    if type(value) is not str:
        raise PhysicalProbeError(f"{label.capitalize()} must be text.")
    try:
        return enum_type(value)
    except ValueError as err:
        raise PhysicalProbeError(f"{label.capitalize()} is unsupported.") from err


BRT_PROFILE = PhysicalProbeProfile(
    profile_id="moes-brt-100-trv",
    profile_version=2,
    zigbee_model="TS0601",
    resolved_aliases=(
        ResolvedIdentityAlias(
            manufacturer_fingerprint="_TZE200_b6wax7g0",
            model="BRT-100-TRV",
            vendor="Moes",
        ),
        ResolvedIdentityAlias(
            manufacturer_fingerprint="_TZE200_qsoecqlk",
            model="Powerswitch-ZK(W)",
            vendor="Sibling",
        ),
        ResolvedIdentityAlias(
            manufacturer_fingerprint="_TZE200_6y7kyjga",
            model="BRT-100-TRV",
            vendor="Moes",
        ),
    ),
    endpoint_id=1,
    cluster_name="manuSpecificTuya",
    cluster_id=0xEF00,
    datapoint=2,
    datatype=2,
    minimum_target=0,
    maximum_target=35,
    target_step=1,
    challenge_delta=1,
    required_runtime_versions=Z2M_2_12_1_VERSION_TUPLE,
)

PROFILES = MappingProxyType(
    {(BRT_PROFILE.profile_id, BRT_PROFILE.profile_version): BRT_PROFILE}
)
