"""Pure raw-evidence preflight reports for the unwired physical probe.

This standalone module performs no collection, deployment, MQTT, filesystem,
process, network, subprocess, or Home Assistant work. Reports and permit
candidates are data projections, never authority tokens. Every permit candidate
and verification revalidates the complete caller-supplied raw evidence chain.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import StrEnum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, NoReturn


MANIFEST_SCHEMA = "true-family-brt-probe-manifest-v1"
MANIFEST_VERSION = 1
ACL_PLAN_SCHEMA = "true-family-physical-probe-acl-plan-v1"
DEPLOYMENT_SNAPSHOT_SCHEMA = "true-family-probe-deployment-snapshot-v1"
DEPLOYMENT_ATTESTATION_SCHEMA = "true-family-probe-deployment-attestation-v1"
PREARM_SNAPSHOT_SCHEMA = "true-family-probe-prearm-snapshot-v1"
PREARM_ATTESTATION_SCHEMA = "true-family-probe-prearm-attestation-v1"
ARM_PERMIT_SCHEMA = "true-family-probe-arm-permit-v1"
SANITIZED_STATUS_SCHEMA = "true-family-probe-preflight-status-v1"

PROTOCOL_ID = "true-family-physical-probe"
PROTOCOL_VERSION = 2
STATE_SCHEMA = "true-family-physical-probe-state-v2"
BUILD_ID = "tfpp-v2-z2m-2.12.1-zh-10.6.1-zhc-26.76.0"
PROFILE_ID = "moes-brt-100-trv"
PROFILE_VERSION = 2

_PROBE_ARTIFACT_STEM = "true_family_brt_" + "probe"
ARTIFACT_SOURCE = f"custom_components/true_family/probe/{_PROBE_ARTIFACT_STEM}.mjs"
DEPLOYED_FILENAME = f"{_PROBE_ARTIFACT_STEM}.mjs"
EXTENSION_CLASS = "TrueFamilyBrtProbeExtension"
ARTIFACT_BYTE_LENGTH = 164_691
ARTIFACT_SHA256 = (
    "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1"
)
EXTENSION_DEPLOYMENT_PATH = f"external_extensions/{_PROBE_ARTIFACT_STEM}.mjs"
JOURNAL_PATH = f"{_PROBE_ARTIFACT_STEM}.state.json"

NODE_VERSION = "20.19.2"
ZIGBEE2MQTT_VERSION = "2.12.1"
ZIGBEE2MQTT_COMMIT = "aa909a8a62f76e2dd98ace3a172bca88ee56f5fe"
ZIGBEE2MQTT_TREE = "fd134890cc89e628caa48f6f235862b0bfe40c45"
ZIGBEE2MQTT_NPM_INTEGRITY = (
    "sha512-OucrVP2raFmMEKK+4r7qHOSamAmaM4WI0WYLbLRhZ1s73frVDcppzD/"
    "6BHGPWFIalJrxGrdKHYSbRmpQqLUt5w=="
)
HERDSMAN_VERSION = "10.6.1"
HERDSMAN_COMMIT = "b9f67e9bc2ba90f93be28fd4c21aa487f941f9a1"
CONVERTERS_VERSION = "26.76.0"
CONVERTERS_COMMIT = "1d15c0ca29d2ec80c9bc67f9186e072e15129487"

_TOPIC_ROOT = "bridge/true_family/physical_" + "probe"
READY_TOPIC = f"{_TOPIC_ROOT}/ready"
STATUS_TOPIC = f"{_TOPIC_ROOT}/status"
REQUEST_TOPIC = "bridge/request/true_family/physical_" + "probe"
RESPONSE_TOPIC = "bridge/response/true_family/physical_" + "probe"
RESULT_TOPIC = f"{_TOPIC_ROOT}/result"
ACK_TOPIC = f"{REQUEST_TOPIC}/ack"
ACK_RESPONSE_TOPIC = f"{RESPONSE_TOPIC}/ack"

MAX_SNAPSHOT_JSON_BYTES = 65_536
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 1_024
MAX_JSON_STRING_LENGTH = 512
MAX_JSON_LIST_LENGTH = 64
MAX_JSON_MAPPING_FIELDS = 64
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_DEPLOYMENT_WINDOW_MS = 60_000
MAX_PREARM_WINDOW_MS = 5_000
MAX_REQUEST_WINDOW_MS = 60_000
MAX_OPERATION_WINDOW_MS = 900_000

_PROFILE_MINIMUM_TARGET = 0
_PROFILE_MAXIMUM_TARGET = 35
_PROFILE_TARGET_STEP = 1
_PROFILE_ENDPOINT_ID = 1
_PROFILE_ZIGBEE_MODEL = "TS0601"
_PROFILE_CLUSTER_NAME = "manuSpecificTuya"
_PROFILE_CLUSTER_ID = 0xEF00
_PROFILE_DATAPOINT = 2
_PROFILE_DATATYPE = 2
_PROFILE_CHALLENGE_DELTA = 1
_PROFILE_ALIASES = MappingProxyType(
    {
        "_TZE200_b6wax7g0": ("BRT-100-TRV", "Moes"),
        "_TZE200_qsoecqlk": ("Powerswitch-ZK(W)", "Sibling"),
        "_TZE200_6y7kyjga": ("BRT-100-TRV", "Moes"),
    }
)

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IEEE_PATTERN = re.compile(r"^0x[0-9a-f]{16}$")
_FINGERPRINT_PATTERN = re.compile(r"^_TZE[0-9]{3}_[a-z0-9]{8}$")
_BOOT_PATTERN = re.compile(r"^tfpp-boot-[0-9a-f]{32}$")
_REQUEST_PATTERN = re.compile(r"^tfpp-req-[0-9a-f]{24}$")
_OPERATION_PATTERN = re.compile(r"^tfpp-op-[0-9a-f]{24}$")
_NONCE_PATTERN = re.compile(r"^tfpp-nonce-[0-9a-f]{32}$")
_BOUNDARY_WHITESPACE_PATTERN = re.compile(
    r"^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff]"
    r"|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff]$"
)

_MANIFEST_DIGEST_DOMAIN = "true-family-physical-probe/manifest/v1"
_ACL_DIGEST_DOMAIN = "true-family-physical-probe/acl/v1"
_SCOPE_DIGEST_DOMAIN = "true-family-physical-probe/scope/v1"
_ARTIFACT_DIGEST_DOMAIN = "true-family-physical-probe/artifact/v1"
_EXTENSION_PATH_DIGEST_DOMAIN = "true-family-physical-probe/extension-path/v1"
_JOURNAL_PATH_DIGEST_DOMAIN = "true-family-physical-probe/journal-path/v1"
_OWNER_DIGEST_DOMAIN = "true-family-physical-probe/owner/v1"
_FENCE_DIGEST_DOMAIN = "true-family-physical-probe/fence/v1"
_DEPLOYMENT_DIGEST_DOMAIN = "true-family-physical-probe/deployment/v1"
_PREARM_DIGEST_DOMAIN = "true-family-physical-probe/prearm/v1"
_CANDIDATE_IDENTITY_DIGEST_DOMAIN = (
    "true-family-physical-probe/candidate-identity/v1"
)
_CANDIDATE_SCOPE_DIGEST_DOMAIN = "true-family-physical-probe/candidate-scope/v1"
_ARM_REQUEST_DIGEST_DOMAIN = "true-family-physical-probe/arm-request/v1"
_ARM_WIRE_DIGEST_DOMAIN = "true-family-physical-probe/arm-wire/v1"
_REQUEST_TOPIC_DIGEST_DOMAIN = "true-family-physical-probe/request-topic/v1"
_ARM_PERMIT_DIGEST_DOMAIN = "true-family-physical-probe/arm-permit/v1"


class PreflightErrorCode(StrEnum):
    """Fixed rejection classes containing no caller-controlled detail."""

    INVALID_INPUT = "invalid_input"
    ACL_REJECTED = "acl_rejected"
    DEPLOYMENT_REJECTED = "deployment_rejected"
    PREARM_REJECTED = "prearm_rejected"
    ARM_REJECTED = "arm_rejected"
    INTERNAL_REJECTED = "internal_rejected"


class PreflightPublicState(StrEnum):
    """Sanitized public report state."""

    REJECTED = "rejected"


class AclAction(StrEnum):
    """Broker ACL operations represented by this contract."""

    PUBLISH = "publish"
    SUBSCRIBE = "subscribe"


class PrincipalRole(StrEnum):
    """Explicit broker principal roles; unknown values also deny."""

    ORCHESTRATOR = "orchestrator"
    ZIGBEE2MQTT = "zigbee2mqtt"
    ADMIN_RECOVERY = "admin_recovery"
    OTHER = "other"
    ANONYMOUS = "anonymous"


class ProbePermitAction(StrEnum):
    """The sole publication action represented by a permit candidate."""

    ARM = "arm"


_PRINCIPAL_ROLES_BY_VALUE = MappingProxyType(
    {role.value: role for role in PrincipalRole}
)
_ACL_ACTIONS_BY_VALUE = MappingProxyType(
    {action.value: action for action in AclAction}
)


_ERROR_MESSAGES = MappingProxyType(
    {
        PreflightErrorCode.INVALID_INPUT: "Preflight input was rejected.",
        PreflightErrorCode.ACL_REJECTED: "Probe ACL preflight was rejected.",
        PreflightErrorCode.DEPLOYMENT_REJECTED: (
            "Probe deployment preflight was rejected."
        ),
        PreflightErrorCode.PREARM_REJECTED: "Probe pre-arm check was rejected.",
        PreflightErrorCode.ARM_REJECTED: "Probe ARM candidate was rejected.",
        PreflightErrorCode.INTERNAL_REJECTED: "Preflight failed closed.",
    }
)


class PhysicalProbePreflightError(ValueError):
    """A fixed rejection with a read-only sanitized code."""

    __slots__ = ("_code",)

    def __init__(self, code: PreflightErrorCode) -> None:
        safe_code = (
            code
            if type(code) is PreflightErrorCode
            else PreflightErrorCode.INTERNAL_REJECTED
        )
        object.__setattr__(self, "_code", safe_code)
        super().__init__(
            _ERROR_MESSAGES.get(
                safe_code,
                _ERROR_MESSAGES[PreflightErrorCode.INTERNAL_REJECTED],
            )
        )

    @property
    def code(self) -> PreflightErrorCode:
        """Return the immutable sanitized rejection code."""

        return self._code

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"code", "_code"} and hasattr(self, "_code"):
            raise AttributeError("Preflight rejection code is read-only.")
        object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class SanitizedPreflightStatus:
    """Safe public projection of any rejection."""

    schema: str
    state: PreflightPublicState
    code: PreflightErrorCode
    message: str

    def __post_init__(self) -> None:
        if (
            self.schema != SANITIZED_STATUS_SCHEMA
            or type(self.state) is not PreflightPublicState
            or self.state is not PreflightPublicState.REJECTED
            or type(self.code) is not PreflightErrorCode
            or self.message
            != _ERROR_MESSAGES.get(
                self.code,
                _ERROR_MESSAGES[PreflightErrorCode.INTERNAL_REJECTED],
            )
        ):
            _fail(PreflightErrorCode.INTERNAL_REJECTED)


@dataclass(frozen=True, slots=True)
class _ProbeScope:
    base_topic: str = field(repr=False)
    friendly_name: str = field(repr=False)
    candidate_ieee: str = field(repr=False)
    set_topic: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProbeAclPlan:
    """Digest-safe ACL plan with private effective policy hidden from repr."""

    schema: str
    scope_digest: str
    policy_digest: str
    effective_policy: Mapping[str, Any] = field(repr=False)
    _scope: _ProbeScope = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != ACL_PLAN_SCHEMA:
            _fail(PreflightErrorCode.ACL_REJECTED)
        _require_digest(self.scope_digest, PreflightErrorCode.ACL_REJECTED)
        _require_digest(self.policy_digest, PreflightErrorCode.ACL_REJECTED)
        if type(self.effective_policy) is not MappingProxyType:
            _fail(PreflightErrorCode.ACL_REJECTED)
        if type(self._scope) is not _ProbeScope:
            _fail(PreflightErrorCode.ACL_REJECTED)


@dataclass(frozen=True, slots=True)
class DeploymentAttestation:
    """Safe deployment report; never sufficient authorization input."""

    schema: str
    snapshot_digest: str
    manifest_digest: str
    artifact_digest: str
    acl_digest: str
    observed_at_ms: int
    expires_at_ms: int
    collection_epoch_digest: str
    process_instance_digest: str
    expected_owner_digest: str
    candidate_identity_digest: str
    candidate_scope_digest: str
    configuration_generation: int
    configuration_digest: str
    acl_generation: int
    fence_digest: str

    def __post_init__(self) -> None:
        _validate_deployment_report(self)


@dataclass(frozen=True, slots=True)
class PreArmAttestation:
    """Safe pre-arm report; never sufficient authorization input."""

    schema: str
    deployment_snapshot_digest: str
    snapshot_digest: str
    manifest_digest: str
    acl_digest: str
    observed_at_ms: int
    expires_at_ms: int
    collection_epoch_digest: str
    process_instance_digest: str
    expected_owner_digest: str
    candidate_identity_digest: str
    candidate_scope_digest: str
    configuration_generation: int
    configuration_digest: str
    acl_generation: int
    fence_digest: str
    boot_id: str
    arm_request_digest: str

    def __post_init__(self) -> None:
        _validate_prearm_report(self)


@dataclass(frozen=True, slots=True)
class ProbeArmPermit:
    """Deterministic permit candidate; external atomic consumption is required."""

    schema: str
    permit_digest: str
    deployment_snapshot_digest: str
    prearm_snapshot_digest: str
    request_digest: str
    canonical_payload_digest: str
    request_topic_digest: str
    collection_epoch_digest: str
    expected_owner_digest: str
    fence_digest: str
    allowed_action: ProbePermitAction
    qos: int
    retain: bool
    one_shot_required: bool
    consumption_enforced: bool
    commands_authorized: bool
    expires_at_ms: int

    def __post_init__(self) -> None:
        _validate_permit_report(self)


_ACL_SCOPE_FIELDS = (
    "base_topic",
    "friendly_name",
    "candidate_ieee",
    "set_topic",
)
_PROTOCOL_FIELDS = (
    "protocol_id",
    "protocol_version",
    "state_schema",
    "build_id",
    "profile_id",
    "profile_version",
)
_IDENTITY_FIELDS = (
    "ieee_address",
    "model",
    "vendor",
    "zigbee_model",
    "manufacturer_fingerprint",
    "endpoint_id",
    "cluster_name",
    "cluster_id",
)
_CANDIDATE_SCOPE_FIELDS = (
    "base_topic",
    "friendly_name",
    "set_topic",
    "identity",
    "groups",
)
_DEPLOYMENT_FIELDS = (
    "schema",
    "manifest_schema",
    "manifest_version",
    "manifest_digest",
    "protocol",
    "observed_at_ms",
    "expires_at_ms",
    "runtime",
    "artifact",
    "deployment",
    "controls",
    "writer_inventory",
    "lifecycle",
    "fence",
    "candidate_scope",
    "effective_acl",
)
_ARTIFACT_FIELDS = (
    "source",
    "deployed_filename",
    "extension_class",
    "byte_length",
    "sha256",
    "matching_files",
    "external_converters",
    "unreviewed_command_extensions",
)
_DEPLOYMENT_STATE_FIELDS = (
    "extension_path",
    "extension_path_digest",
    "journal_path",
    "journal_path_digest",
    "journal_main_present",
    "matching_journal_temps",
    "matching_journal_aliases",
    "recovery_evidence_present",
    "journal_write_in_flight",
    "loader_count",
    "journal_owner_count",
    "dynamic_mqtt_extension_save_allowed",
    "dynamic_mqtt_extension_remove_allowed",
    "dynamic_mqtt_converter_save_allowed",
    "dynamic_mqtt_converter_remove_allowed",
)
_CONTROL_FIELDS = (
    "advanced_enable_external_js",
    "frontend_enabled",
    "payload_debug_enabled",
    "debug_to_frontend_enabled",
)
_WRITER_FIELDS = (
    "home_assistant_candidate_writer",
    "automation",
    "script",
    "scheduler",
    "frontend",
    "other_mqtt_clients",
    "unreviewed_in_process_extensions",
)
_LIFECYCLE_FIELDS = (
    "collection_epoch_digest",
    "process_instance_digest",
    "expected_owner_digest",
)
_DEPLOYMENT_FENCE_FIELDS = (
    "configuration_generation",
    "configuration_digest",
    "acl_generation",
    "acl_digest",
)
_PREARM_FIELDS = (
    "schema",
    "deployment_snapshot_digest",
    "manifest_digest",
    "protocol",
    "observed_at_ms",
    "expires_at_ms",
    "boot",
    "lifecycle",
    "fence",
    "source_inventory",
    "loaders",
    "journal_owners",
    "journal_observation",
    "candidate",
    "pending_work",
    "probe_state",
    "expected_arm_request_digest",
)
_BOOT_FIELDS = (
    "boot_id_before",
    "boot_id_after",
    "generation_before",
    "generation_after",
)
_PREARM_FENCE_FIELDS = (
    "configuration_generation_before",
    "configuration_generation_after",
    "configuration_digest_before",
    "configuration_digest_after",
    "acl_generation_before",
    "acl_generation_after",
    "acl_digest_before",
    "acl_digest_after",
)
_SOURCE_INVENTORY_FIELDS = (
    "installed_sha256",
    "loaded_sha256",
    "retained_inventory_sha256",
    "inventory_entries",
    "raw_source_exposed_to_orchestrator",
)
_OWNER_FIELDS = (
    "owner_digest",
    "collection_epoch_digest",
    "process_instance_digest",
    "extension_class",
    "artifact_digest",
    "path_digest",
    "previous_owner_drained",
    "late_completions",
)
_JOURNAL_OBSERVATION_FIELDS = (
    "observed_at_ms",
    "journal_path",
    "journal_path_digest",
    "main_present",
    "matching_temps",
    "matching_aliases",
    "recovery_evidence_present",
    "write_in_flight",
)
_PREARM_CANDIDATE_FIELDS = (
    "base_topic",
    "friendly_name",
    "set_topic",
    "identity",
    "identity_digest_before",
    "identity_digest_after",
    "scope_digest_before",
    "scope_digest_after",
    "selected_endpoint_id",
    "endpoint_inventory_complete",
    "endpoints",
    "groups",
    "rename_events",
    "group_events",
)
_ENDPOINT_FIELDS = ("endpoint_id", "has_pending_requests_api", "pending")
_PENDING_FIELDS = (
    "probe_fifo",
    "dispatch",
    "journal_write",
    "publication_retry",
    "orchestrator_outbound",
    "broker_queued_request",
    "retained_request",
)
_PROBE_STATE_FIELDS = (
    "ready",
    "phase",
    "generation",
    "record_present",
    "remediation_required",
    "arm_accepted_count",
    "endpoint_commands_since_loader_start",
)
_ARM_REQUEST_FIELDS = (
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
    "candidate",
    "intended_target",
    "physical_targets",
    "operation_deadline_ms",
)


def parse_canonical_mapping(
    text: str, *, maximum_bytes: int = MAX_SNAPSHOT_JSON_BYTES
) -> dict[str, Any]:
    """Parse bounded canonical JSON while rejecting duplicate object keys."""

    if (
        type(maximum_bytes) is not int
        or not 1 <= maximum_bytes <= MAX_SNAPSHOT_JSON_BYTES
        or type(text) is not str
    ):
        _fail(PreflightErrorCode.INVALID_INPUT)
    if not text or len(text) > maximum_bytes:
        _fail(PreflightErrorCode.INVALID_INPUT)
    encoded = _encode_utf8(text, PreflightErrorCode.INVALID_INPUT)
    if len(encoded) > maximum_bytes:
        _fail(PreflightErrorCode.INVALID_INPUT)

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(PreflightErrorCode.INVALID_INPUT)
            result[key] = value
        return result

    def reject_constant(_value: str) -> NoReturn:
        _fail(PreflightErrorCode.INVALID_INPUT)

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except Exception:
        _fail(PreflightErrorCode.INVALID_INPUT)
    if type(value) is not dict:
        _fail(PreflightErrorCode.INVALID_INPUT)
    canonical = _canonical_json(
        value,
        maximum_bytes=maximum_bytes,
        code=PreflightErrorCode.INVALID_INPUT,
    )
    if canonical != text:
        _fail(PreflightErrorCode.INVALID_INPUT)
    return value


def canonical_digest(value: Any, *, domain: str) -> str:
    """Return a bounded UTF-8 domain-separated SHA-256 digest."""

    _require_canonical_text(
        domain, maximum=96, code=PreflightErrorCode.INVALID_INPUT
    )
    return _digest(value, domain, PreflightErrorCode.INVALID_INPUT)


def derive_expected_owner_digest(
    collection_epoch_digest: str, process_instance_digest: str
) -> str:
    """Derive the only owner identity accepted for one observed process epoch."""

    code = PreflightErrorCode.DEPLOYMENT_REJECTED
    _require_digest(collection_epoch_digest, code)
    _require_digest(process_instance_digest, code)
    return _digest(
        {
            "collection_epoch_digest": collection_epoch_digest,
            "process_instance_digest": process_instance_digest,
            "artifact_digest": ARTIFACT_DIGEST,
            "extension_path_digest": EXTENSION_PATH_DIGEST,
            "journal_path_digest": JOURNAL_PATH_DIGEST,
        },
        _OWNER_DIGEST_DOMAIN,
        code,
    )


def build_acl_plan(scope: dict[str, Any]) -> ProbeAclPlan:
    """Build the sole normalized ACL policy accepted by deployment reports."""

    code = PreflightErrorCode.ACL_REJECTED
    _validate_json_tree(scope, code)
    data = _require_mapping(scope, _ACL_SCOPE_FIELDS, code)
    base_topic = _require_base_topic(data["base_topic"], code)
    friendly_name = _require_friendly_name(data["friendly_name"], code)
    candidate_ieee = data["candidate_ieee"]
    if type(candidate_ieee) is not str or _IEEE_PATTERN.fullmatch(candidate_ieee) is None:
        _fail(code)
    if friendly_name.split("/", 1)[0] == candidate_ieee:
        _fail(code)
    set_topic = _require_set_topic(data["set_topic"], friendly_name, code)
    if _contains_bridge_request(base_topic):
        _fail(code)

    private_scope = _ProbeScope(
        base_topic=base_topic,
        friendly_name=friendly_name,
        candidate_ieee=candidate_ieee,
        set_topic=set_topic,
    )
    publish_topics = (
        _prefixed(base_topic, REQUEST_TOPIC),
        _prefixed(base_topic, ACK_TOPIC),
    )
    subscribe_topics = tuple(
        _prefixed(base_topic, topic)
        for topic in (
            READY_TOPIC,
            STATUS_TOPIC,
            RESULT_TOPIC,
            RESPONSE_TOPIC,
            ACK_RESPONSE_TOPIC,
        )
    )
    candidate_roots = (
        _prefixed(base_topic, friendly_name),
        _prefixed(base_topic, candidate_ieee),
    )
    candidate_set_topic = _prefixed(base_topic, set_topic)
    for topic in (
        *publish_topics,
        *subscribe_topics,
        *candidate_roots,
        candidate_set_topic,
    ):
        if not _topic_is_valid(topic):
            _fail(code)
    if any(
        _contains_bridge_request(topic)
        for topic in (*candidate_roots, candidate_set_topic)
    ):
        _fail(code)

    policy = {
        "schema": ACL_PLAN_SCHEMA,
        "enforcement": {
            "anonymous_access": "disabled",
            "superuser_bypass": "disabled",
            "dedicated_listener": True,
            "effective_readback_complete": True,
        },
        "scope": {
            "base_topic": base_topic,
            "candidate_publish_roots": list(candidate_roots),
            "candidate_set_topic": candidate_set_topic,
        },
        "principals": {
            "orchestrator": {
                "publish_default": "deny",
                "publish_allow": [
                    {"topic": topic, "qos": 1, "retain": False}
                    for topic in publish_topics
                ],
                "subscribe_default": "deny",
                "subscribe_allow": list(subscribe_topics),
            },
            "zigbee2mqtt": {
                "publish_default": "allow",
                "subscribe_default": "allow",
                "subscribe_filters": [f"{base_topic}/#"],
                "bridge_request_publish": "deny",
            },
            "admin_recovery": {"publish_default": "deny", "subscribe_default": "deny"},
            "other": {"publish_default": "deny", "subscribe_default": "deny"},
            "anonymous": {"publish_default": "deny", "subscribe_default": "deny"},
        },
        "global_denies": {
            "unknown_principals": True,
            "non_zigbee2mqtt_candidate_publish_subtrees": True,
            "bridge_request_publish_slash_containment": True,
            "bridge_request_publish_exceptions": list(publish_topics),
        },
    }
    scope_projection = {
        "base_topic": base_topic,
        "friendly_name": friendly_name,
        "candidate_ieee": candidate_ieee,
        "set_topic": set_topic,
    }
    return ProbeAclPlan(
        schema=ACL_PLAN_SCHEMA,
        scope_digest=_digest(scope_projection, _SCOPE_DIGEST_DOMAIN, code),
        policy_digest=_digest(policy, _ACL_DIGEST_DOMAIN, code),
        effective_policy=_freeze(policy),
        _scope=private_scope,
    )


def acl_allows(
    scope: dict[str, Any],
    principal_role: PrincipalRole | str,
    action: AclAction | str,
    topic: str,
    *,
    qos: int | None = None,
    retain: bool | None = None,
) -> bool:
    """Rebuild and evaluate the raw-scope ACL; malformed values deny."""

    try:
        plan = build_acl_plan(scope)
    except PhysicalProbePreflightError:
        return False
    if type(principal_role) is PrincipalRole:
        role = principal_role
    elif type(principal_role) is str:
        role = _PRINCIPAL_ROLES_BY_VALUE.get(principal_role)
    else:
        return False
    if type(action) is AclAction:
        operation = action
    elif type(action) is str:
        operation = _ACL_ACTIONS_BY_VALUE.get(action)
    else:
        return False
    if role is None or operation is None or type(topic) is not str:
        return False

    private_scope = plan._scope
    exact_requests = {
        _prefixed(private_scope.base_topic, REQUEST_TOPIC),
        _prefixed(private_scope.base_topic, ACK_TOPIC),
    }
    candidate_roots = (
        _prefixed(private_scope.base_topic, private_scope.friendly_name),
        _prefixed(private_scope.base_topic, private_scope.candidate_ieee),
    )

    if operation is AclAction.SUBSCRIBE:
        if role is PrincipalRole.ZIGBEE2MQTT:
            if topic == f"{private_scope.base_topic}/#":
                return True
            if "+" in topic or "#" in topic:
                return False
            if not _topic_is_valid(topic):
                return False
            return True
        if "+" in topic or "#" in topic or not _topic_is_valid(topic):
            return False
        if role is PrincipalRole.ORCHESTRATOR:
            return topic in {
                _prefixed(private_scope.base_topic, READY_TOPIC),
                _prefixed(private_scope.base_topic, STATUS_TOPIC),
                _prefixed(private_scope.base_topic, RESULT_TOPIC),
                _prefixed(private_scope.base_topic, RESPONSE_TOPIC),
                _prefixed(private_scope.base_topic, ACK_RESPONSE_TOPIC),
            }
        return False

    if (
        not _topic_is_valid(topic)
        or type(qos) is not int
        or not 0 <= qos <= 2
        or type(retain) is not bool
    ):
        return False
    if any(_is_topic_subtree(topic, root) for root in candidate_roots):
        if role is not PrincipalRole.ZIGBEE2MQTT:
            return False
    if _contains_bridge_request(topic):
        return (
            role is PrincipalRole.ORCHESTRATOR
            and topic in exact_requests
            and qos == 1
            and retain is False
        )
    if role is PrincipalRole.ZIGBEE2MQTT:
        return True
    return False


def attest_deployment(
    snapshot: dict[str, Any], now_ms: int
) -> DeploymentAttestation:
    """Validate one raw deployment snapshot and return a non-authoritative report."""

    code = PreflightErrorCode.DEPLOYMENT_REJECTED
    _require_safe_integer(now_ms, code)
    _validate_json_tree(snapshot, code)
    data = _require_mapping(snapshot, _DEPLOYMENT_FIELDS, code)
    if data["schema"] != DEPLOYMENT_SNAPSHOT_SCHEMA:
        _fail(code)
    _require_manifest_binding(data, code)
    _require_protocol(data["protocol"], code)
    _require_fresh_window(
        data["observed_at_ms"],
        data["expires_at_ms"],
        now_ms,
        MAX_DEPLOYMENT_WINDOW_MS,
        code,
    )
    _require_runtime(data["runtime"], code)
    _require_artifact(data["artifact"], code)
    _require_deployment_state(data["deployment"], code)
    _require_controls(data["controls"], code)
    _require_writers(data["writer_inventory"], code)

    candidate, identity_digest, candidate_scope_digest = _normalize_candidate_scope(
        data["candidate_scope"], code
    )
    plan = build_acl_plan(
        {
            "base_topic": candidate["base_topic"],
            "friendly_name": candidate["friendly_name"],
            "candidate_ieee": candidate["identity"]["ieee_address"],
            "set_topic": candidate["set_topic"],
        }
    )
    if not _strict_json_equal(data["effective_acl"], _thaw(plan.effective_policy)):
        _fail(code)

    lifecycle = _require_mapping(data["lifecycle"], _LIFECYCLE_FIELDS, code)
    collection_epoch_digest = _require_digest(
        lifecycle["collection_epoch_digest"], code
    )
    process_instance_digest = _require_digest(
        lifecycle["process_instance_digest"], code
    )
    expected_owner_digest = derive_expected_owner_digest(
        collection_epoch_digest, process_instance_digest
    )
    if lifecycle["expected_owner_digest"] != expected_owner_digest:
        _fail(code)

    fence = _require_mapping(data["fence"], _DEPLOYMENT_FENCE_FIELDS, code)
    configuration_generation = _require_positive_integer(
        fence["configuration_generation"], code
    )
    configuration_digest = _require_digest(fence["configuration_digest"], code)
    acl_generation = _require_positive_integer(fence["acl_generation"], code)
    if fence["acl_digest"] != plan.policy_digest:
        _fail(code)
    fence_projection = {
        "collection_epoch_digest": collection_epoch_digest,
        "process_instance_digest": process_instance_digest,
        "expected_owner_digest": expected_owner_digest,
        "configuration_generation": configuration_generation,
        "configuration_digest": configuration_digest,
        "acl_generation": acl_generation,
        "acl_digest": plan.policy_digest,
        "candidate_scope_digest": candidate_scope_digest,
    }
    fence_digest = _digest(fence_projection, _FENCE_DIGEST_DOMAIN, code)
    snapshot_digest = _digest(data, _DEPLOYMENT_DIGEST_DOMAIN, code)
    return DeploymentAttestation(
        schema=DEPLOYMENT_ATTESTATION_SCHEMA,
        snapshot_digest=snapshot_digest,
        manifest_digest=MANIFEST_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
        acl_digest=plan.policy_digest,
        observed_at_ms=data["observed_at_ms"],
        expires_at_ms=data["expires_at_ms"],
        collection_epoch_digest=collection_epoch_digest,
        process_instance_digest=process_instance_digest,
        expected_owner_digest=expected_owner_digest,
        candidate_identity_digest=identity_digest,
        candidate_scope_digest=candidate_scope_digest,
        configuration_generation=configuration_generation,
        configuration_digest=configuration_digest,
        acl_generation=acl_generation,
        fence_digest=fence_digest,
    )


def validate_prearm(
    prearm_snapshot: dict[str, Any],
    deployment_snapshot: dict[str, Any],
    now_ms: int,
) -> PreArmAttestation:
    """Revalidate raw deployment evidence, then validate raw pre-arm evidence."""

    deployment = attest_deployment(deployment_snapshot, now_ms)
    code = PreflightErrorCode.PREARM_REJECTED
    _require_safe_integer(now_ms, code)
    _validate_json_tree(prearm_snapshot, code)
    data = _require_mapping(prearm_snapshot, _PREARM_FIELDS, code)
    if data["schema"] != PREARM_SNAPSHOT_SCHEMA:
        _fail(code)
    if data["deployment_snapshot_digest"] != deployment.snapshot_digest:
        _fail(code)
    if data["manifest_digest"] != deployment.manifest_digest:
        _fail(code)
    _require_protocol(data["protocol"], code)
    _require_fresh_window(
        data["observed_at_ms"],
        data["expires_at_ms"],
        now_ms,
        MAX_PREARM_WINDOW_MS,
        code,
    )
    if not (
        deployment.observed_at_ms
        < data["observed_at_ms"]
        < now_ms
        < data["expires_at_ms"]
        <= deployment.expires_at_ms
    ):
        _fail(code)

    lifecycle = _require_mapping(data["lifecycle"], _LIFECYCLE_FIELDS, code)
    if not _has_exact_values(
        lifecycle,
        {
            "collection_epoch_digest": deployment.collection_epoch_digest,
            "process_instance_digest": deployment.process_instance_digest,
            "expected_owner_digest": deployment.expected_owner_digest,
        },
    ):
        _fail(code)
    derived_owner = derive_expected_owner_digest(
        lifecycle["collection_epoch_digest"], lifecycle["process_instance_digest"]
    )
    if derived_owner != lifecycle["expected_owner_digest"]:
        _fail(code)

    fence = _require_mapping(data["fence"], _PREARM_FENCE_FIELDS, code)
    _require_prearm_fence(fence, deployment, code)
    boot_id = _require_stable_boot(data["boot"], code)
    _require_source_inventory(data["source_inventory"], code)
    _require_single_owner(
        data["loaders"], deployment, EXTENSION_PATH_DIGEST, code
    )
    _require_single_owner(
        data["journal_owners"], deployment, JOURNAL_PATH_DIGEST, code
    )
    _require_journal_observation(
        data["journal_observation"], data["observed_at_ms"], code
    )

    identity_digest, candidate_scope_digest, candidate_plan = _require_prearm_candidate(
        data["candidate"], code
    )
    if (
        identity_digest != deployment.candidate_identity_digest
        or candidate_scope_digest != deployment.candidate_scope_digest
        or candidate_plan.policy_digest != deployment.acl_digest
    ):
        _fail(code)
    _require_all_zero(data["pending_work"], _PENDING_FIELDS, code)
    _require_probe_idle(data["probe_state"], code)
    arm_request_digest = _require_digest(data["expected_arm_request_digest"], code)
    snapshot_digest = _digest(data, _PREARM_DIGEST_DOMAIN, code)
    return PreArmAttestation(
        schema=PREARM_ATTESTATION_SCHEMA,
        deployment_snapshot_digest=deployment.snapshot_digest,
        snapshot_digest=snapshot_digest,
        manifest_digest=deployment.manifest_digest,
        acl_digest=deployment.acl_digest,
        observed_at_ms=data["observed_at_ms"],
        expires_at_ms=data["expires_at_ms"],
        collection_epoch_digest=deployment.collection_epoch_digest,
        process_instance_digest=deployment.process_instance_digest,
        expected_owner_digest=deployment.expected_owner_digest,
        candidate_identity_digest=identity_digest,
        candidate_scope_digest=candidate_scope_digest,
        configuration_generation=deployment.configuration_generation,
        configuration_digest=deployment.configuration_digest,
        acl_generation=deployment.acl_generation,
        fence_digest=deployment.fence_digest,
        boot_id=boot_id,
        arm_request_digest=arm_request_digest,
    )


def authorize_arm(
    deployment_snapshot: dict[str, Any],
    prearm_snapshot: dict[str, Any],
    arm_request_json: str,
    now_ms: int,
) -> ProbeArmPermit:
    """Revalidate raw evidence and exact canonical ARM publication bytes."""

    prearm = validate_prearm(prearm_snapshot, deployment_snapshot, now_ms)
    code = PreflightErrorCode.ARM_REJECTED
    try:
        parsed_request = parse_canonical_mapping(
            arm_request_json, maximum_bytes=MAX_SNAPSHOT_JSON_BYTES
        )
    except PhysicalProbePreflightError:
        _fail(code)
    request = _normalize_arm_request(parsed_request, prearm, now_ms)
    request_digest = _digest(request, _ARM_REQUEST_DIGEST_DOMAIN, code)
    if request_digest != prearm.arm_request_digest:
        _fail(code)
    identity_digest = _digest(
        request["candidate"], _CANDIDATE_IDENTITY_DIGEST_DOMAIN, code
    )
    if identity_digest != prearm.candidate_identity_digest:
        _fail(code)
    canonical_payload_digest = _wire_digest(
        arm_request_json, _ARM_WIRE_DIGEST_DOMAIN, code
    )
    prearm_data = _require_mapping(
        prearm_snapshot, _PREARM_FIELDS, code
    )
    candidate_data = _require_mapping(
        prearm_data["candidate"], _PREARM_CANDIDATE_FIELDS, code
    )
    base_topic = _require_base_topic(candidate_data["base_topic"], code)
    request_topic = _prefixed(base_topic, REQUEST_TOPIC)
    candidate_identity = _require_mapping(
        candidate_data["identity"], _IDENTITY_FIELDS, code
    )
    if not acl_allows(
        {
            "base_topic": base_topic,
            "friendly_name": candidate_data["friendly_name"],
            "candidate_ieee": candidate_identity["ieee_address"],
            "set_topic": candidate_data["set_topic"],
        },
        PrincipalRole.ORCHESTRATOR,
        AclAction.PUBLISH,
        request_topic,
        qos=1,
        retain=False,
    ):
        _fail(code)
    request_topic_digest = _wire_digest(
        request_topic, _REQUEST_TOPIC_DIGEST_DOMAIN, code
    )

    expires_at_ms = request["request_deadline_ms"]
    permit_projection = {
        "schema": ARM_PERMIT_SCHEMA,
        "deployment_snapshot_digest": prearm.deployment_snapshot_digest,
        "prearm_snapshot_digest": prearm.snapshot_digest,
        "request_digest": request_digest,
        "canonical_payload_digest": canonical_payload_digest,
        "request_topic_digest": request_topic_digest,
        "collection_epoch_digest": prearm.collection_epoch_digest,
        "expected_owner_digest": prearm.expected_owner_digest,
        "fence_digest": prearm.fence_digest,
        "allowed_action": ProbePermitAction.ARM.value,
        "qos": 1,
        "retain": False,
        "one_shot_required": True,
        "consumption_enforced": False,
        "commands_authorized": False,
        "expires_at_ms": expires_at_ms,
    }
    return ProbeArmPermit(
        schema=ARM_PERMIT_SCHEMA,
        permit_digest=_digest(
            permit_projection, _ARM_PERMIT_DIGEST_DOMAIN, code
        ),
        deployment_snapshot_digest=prearm.deployment_snapshot_digest,
        prearm_snapshot_digest=prearm.snapshot_digest,
        request_digest=request_digest,
        canonical_payload_digest=canonical_payload_digest,
        request_topic_digest=request_topic_digest,
        collection_epoch_digest=prearm.collection_epoch_digest,
        expected_owner_digest=prearm.expected_owner_digest,
        fence_digest=prearm.fence_digest,
        allowed_action=ProbePermitAction.ARM,
        qos=1,
        retain=False,
        one_shot_required=True,
        consumption_enforced=False,
        commands_authorized=False,
        expires_at_ms=expires_at_ms,
    )


def verify_arm_permit(
    permit: ProbeArmPermit,
    deployment_snapshot: dict[str, Any],
    prearm_snapshot: dict[str, Any],
    arm_request_json: str,
    now_ms: int,
) -> bool:
    """Recompute consistency and exact-compare; this does not prove authenticity."""

    expected = authorize_arm(
        deployment_snapshot,
        prearm_snapshot,
        arm_request_json,
        now_ms,
    )
    if type(permit) is not ProbeArmPermit or not _strict_dataclass_equal(
        permit, expected
    ):
        _fail(PreflightErrorCode.ARM_REJECTED)
    return True


def public_rejection(error: BaseException) -> SanitizedPreflightStatus:
    """Project any exception to one fixed, non-sensitive rejection."""

    candidate = (
        error.code
        if type(error) is PhysicalProbePreflightError
        else PreflightErrorCode.INTERNAL_REJECTED
    )
    code = (
        candidate
        if type(candidate) is PreflightErrorCode
        else PreflightErrorCode.INTERNAL_REJECTED
    )
    message = _ERROR_MESSAGES.get(
        code, _ERROR_MESSAGES[PreflightErrorCode.INTERNAL_REJECTED]
    )
    return SanitizedPreflightStatus(
        schema=SANITIZED_STATUS_SCHEMA,
        state=PreflightPublicState.REJECTED,
        code=code,
        message=message,
    )


def _require_manifest_binding(
    data: Mapping[str, Any], code: PreflightErrorCode
) -> None:
    if (
        type(data["manifest_schema"]) is not str
        or data["manifest_schema"] != MANIFEST_SCHEMA
        or type(data["manifest_version"]) is not int
        or data["manifest_version"] != MANIFEST_VERSION
        or type(data["manifest_digest"]) is not str
        or data["manifest_digest"] != MANIFEST_DIGEST
    ):
        _fail(code)


def _require_protocol(value: Any, code: PreflightErrorCode) -> None:
    protocol = _require_mapping(value, _PROTOCOL_FIELDS, code)
    if not _has_exact_values(
        protocol,
        {
            "protocol_id": PROTOCOL_ID,
            "protocol_version": PROTOCOL_VERSION,
            "state_schema": STATE_SCHEMA,
            "build_id": BUILD_ID,
            "profile_id": PROFILE_ID,
            "profile_version": PROFILE_VERSION,
        },
    ):
        _fail(code)


def _require_runtime(value: Any, code: PreflightErrorCode) -> None:
    runtime = _require_mapping(
        value,
        ("node", "zigbee2mqtt", "zigbee_herdsman", "zigbee_herdsman_converters"),
        code,
    )
    expected = {
        "node": {"version": NODE_VERSION},
        "zigbee2mqtt": {
            "version": ZIGBEE2MQTT_VERSION,
            "commit": ZIGBEE2MQTT_COMMIT,
            "tree": ZIGBEE2MQTT_TREE,
            "npm_integrity": ZIGBEE2MQTT_NPM_INTEGRITY,
        },
        "zigbee_herdsman": {
            "version": HERDSMAN_VERSION,
            "commit": HERDSMAN_COMMIT,
        },
        "zigbee_herdsman_converters": {
            "version": CONVERTERS_VERSION,
            "commit": CONVERTERS_COMMIT,
        },
    }
    for name, expected_fields in expected.items():
        item = _require_mapping(runtime[name], tuple(expected_fields), code)
        if not _has_exact_values(item, expected_fields):
            _fail(code)


def _require_artifact(value: Any, code: PreflightErrorCode) -> None:
    artifact = _require_mapping(value, _ARTIFACT_FIELDS, code)
    expected = {
        "source": ARTIFACT_SOURCE,
        "deployed_filename": DEPLOYED_FILENAME,
        "extension_class": EXTENSION_CLASS,
        "byte_length": ARTIFACT_BYTE_LENGTH,
        "sha256": ARTIFACT_SHA256,
        "matching_files": 1,
    }
    if not _has_exact_values(
        {field_name: artifact[field_name] for field_name in expected}, expected
    ):
        _fail(code)
    if type(artifact["external_converters"]) is not list or artifact[
        "external_converters"
    ]:
        _fail(code)
    if (
        type(artifact["unreviewed_command_extensions"]) is not list
        or artifact["unreviewed_command_extensions"]
    ):
        _fail(code)


def _require_deployment_state(value: Any, code: PreflightErrorCode) -> None:
    state = _require_mapping(value, _DEPLOYMENT_STATE_FIELDS, code)
    expected = {
        "extension_path": EXTENSION_DEPLOYMENT_PATH,
        "extension_path_digest": EXTENSION_PATH_DIGEST,
        "journal_path": JOURNAL_PATH,
        "journal_path_digest": JOURNAL_PATH_DIGEST,
        "journal_main_present": False,
        "matching_journal_temps": 0,
        "matching_journal_aliases": 0,
        "recovery_evidence_present": False,
        "journal_write_in_flight": False,
        "loader_count": 1,
        "journal_owner_count": 1,
        "dynamic_mqtt_extension_save_allowed": False,
        "dynamic_mqtt_extension_remove_allowed": False,
        "dynamic_mqtt_converter_save_allowed": False,
        "dynamic_mqtt_converter_remove_allowed": False,
    }
    if not _has_exact_values(state, expected):
        _fail(code)


def _require_controls(value: Any, code: PreflightErrorCode) -> None:
    controls = _require_mapping(value, _CONTROL_FIELDS, code)
    if not _has_exact_values(
        controls,
        {
            "advanced_enable_external_js": True,
            "frontend_enabled": False,
            "payload_debug_enabled": False,
            "debug_to_frontend_enabled": False,
        },
    ):
        _fail(code)


def _require_writers(value: Any, code: PreflightErrorCode) -> None:
    writers = _require_mapping(value, _WRITER_FIELDS, code)
    if any(
        type(writers[field_name]) is not bool or writers[field_name]
        for field_name in _WRITER_FIELDS
    ):
        _fail(code)


def _normalize_identity(value: Any, code: PreflightErrorCode) -> dict[str, Any]:
    identity = _require_mapping(value, _IDENTITY_FIELDS, code)
    ieee = identity["ieee_address"]
    fingerprint = identity["manufacturer_fingerprint"]
    if type(ieee) is not str or _IEEE_PATTERN.fullmatch(ieee) is None:
        _fail(code)
    if type(fingerprint) is not str or _FINGERPRINT_PATTERN.fullmatch(fingerprint) is None:
        _fail(code)
    for field_name in ("model", "vendor", "zigbee_model", "cluster_name"):
        _require_canonical_text(identity[field_name], maximum=96, code=code)
    _require_positive_integer(identity["endpoint_id"], code)
    _require_integer_range(identity["cluster_id"], 0, 0xFFFF, code)
    alias = _PROFILE_ALIASES.get(fingerprint)
    if (
        alias is None
        or identity["model"] != alias[0]
        or identity["vendor"] != alias[1]
        or identity["zigbee_model"] != _PROFILE_ZIGBEE_MODEL
        or identity["endpoint_id"] != _PROFILE_ENDPOINT_ID
        or identity["cluster_name"] != _PROFILE_CLUSTER_NAME
        or identity["cluster_id"] != _PROFILE_CLUSTER_ID
    ):
        _fail(code)
    return {field_name: identity[field_name] for field_name in _IDENTITY_FIELDS}


def _normalize_candidate_scope(
    value: Any, code: PreflightErrorCode
) -> tuple[dict[str, Any], str, str]:
    candidate = _require_mapping(value, _CANDIDATE_SCOPE_FIELDS, code)
    base_topic = _require_base_topic(candidate["base_topic"], code)
    friendly_name = _require_friendly_name(candidate["friendly_name"], code)
    set_topic = _require_set_topic(candidate["set_topic"], friendly_name, code)
    identity = _normalize_identity(candidate["identity"], code)
    if type(candidate["groups"]) is not list or candidate["groups"]:
        _fail(code)
    normalized = {
        "base_topic": base_topic,
        "friendly_name": friendly_name,
        "set_topic": set_topic,
        "identity": identity,
        "groups": [],
    }
    identity_digest = _digest(
        identity, _CANDIDATE_IDENTITY_DIGEST_DOMAIN, code
    )
    scope_digest = _digest(normalized, _CANDIDATE_SCOPE_DIGEST_DOMAIN, code)
    return normalized, identity_digest, scope_digest


def _require_prearm_candidate(
    value: Any, code: PreflightErrorCode
) -> tuple[str, str, ProbeAclPlan]:
    candidate = _require_mapping(value, _PREARM_CANDIDATE_FIELDS, code)
    normalized, identity_digest, scope_digest = _normalize_candidate_scope(
        {
            "base_topic": candidate["base_topic"],
            "friendly_name": candidate["friendly_name"],
            "set_topic": candidate["set_topic"],
            "identity": candidate["identity"],
            "groups": candidate["groups"],
        },
        code,
    )
    if (
        candidate["identity_digest_before"] != identity_digest
        or candidate["identity_digest_after"] != identity_digest
        or candidate["scope_digest_before"] != scope_digest
        or candidate["scope_digest_after"] != scope_digest
    ):
        _fail(code)
    if (
        type(candidate["selected_endpoint_id"]) is not int
        or candidate["selected_endpoint_id"] != _PROFILE_ENDPOINT_ID
        or type(candidate["endpoint_inventory_complete"]) is not bool
        or candidate["endpoint_inventory_complete"] is not True
    ):
        _fail(code)
    endpoints = candidate["endpoints"]
    if type(endpoints) is not list or not endpoints:
        _fail(code)
    endpoint_ids: list[int] = []
    for endpoint_value in endpoints:
        endpoint = _require_mapping(endpoint_value, _ENDPOINT_FIELDS, code)
        endpoint_id = _require_integer_range(endpoint["endpoint_id"], 1, 240, code)
        if (
            type(endpoint["has_pending_requests_api"]) is not bool
            or endpoint["has_pending_requests_api"] is not True
            or type(endpoint["pending"]) is not bool
            or endpoint["pending"] is not False
        ):
            _fail(code)
        endpoint_ids.append(endpoint_id)
    if (
        endpoint_ids != sorted(endpoint_ids)
        or len(endpoint_ids) != len(set(endpoint_ids))
        or _PROFILE_ENDPOINT_ID not in endpoint_ids
        or normalized["identity"]["endpoint_id"] != candidate["selected_endpoint_id"]
    ):
        _fail(code)
    for event_field in ("rename_events", "group_events"):
        if type(candidate[event_field]) is not int or candidate[event_field] != 0:
            _fail(code)
    plan = build_acl_plan(
        {
            "base_topic": normalized["base_topic"],
            "friendly_name": normalized["friendly_name"],
            "candidate_ieee": normalized["identity"]["ieee_address"],
            "set_topic": normalized["set_topic"],
        }
    )
    return identity_digest, scope_digest, plan


def _require_prearm_fence(
    fence: Mapping[str, Any],
    deployment: DeploymentAttestation,
    code: PreflightErrorCode,
) -> None:
    expected = {
        "configuration_generation_before": deployment.configuration_generation,
        "configuration_generation_after": deployment.configuration_generation,
        "configuration_digest_before": deployment.configuration_digest,
        "configuration_digest_after": deployment.configuration_digest,
        "acl_generation_before": deployment.acl_generation,
        "acl_generation_after": deployment.acl_generation,
        "acl_digest_before": deployment.acl_digest,
        "acl_digest_after": deployment.acl_digest,
    }
    if not _has_exact_values(fence, expected):
        _fail(code)


def _require_stable_boot(value: Any, code: PreflightErrorCode) -> str:
    boot = _require_mapping(value, _BOOT_FIELDS, code)
    before = boot["boot_id_before"]
    after = boot["boot_id_after"]
    if (
        type(before) is not str
        or type(after) is not str
        or _BOOT_PATTERN.fullmatch(before) is None
        or after != before
    ):
        _fail(code)
    generation = _require_positive_integer(boot["generation_before"], code)
    if (
        type(boot["generation_after"]) is not int
        or boot["generation_after"] != generation
    ):
        _fail(code)
    return after


def _require_source_inventory(value: Any, code: PreflightErrorCode) -> None:
    inventory = _require_mapping(value, _SOURCE_INVENTORY_FIELDS, code)
    if not _has_exact_values(
        inventory,
        {
            "installed_sha256": ARTIFACT_SHA256,
            "loaded_sha256": ARTIFACT_SHA256,
            "retained_inventory_sha256": ARTIFACT_SHA256,
            "inventory_entries": 1,
            "raw_source_exposed_to_orchestrator": False,
        },
    ):
        _fail(code)


def _require_single_owner(
    value: Any,
    deployment: DeploymentAttestation,
    expected_path_digest: str,
    code: PreflightErrorCode,
) -> None:
    if type(value) is not list or len(value) != 1:
        _fail(code)
    owner = _require_mapping(value[0], _OWNER_FIELDS, code)
    expected = {
        "owner_digest": deployment.expected_owner_digest,
        "collection_epoch_digest": deployment.collection_epoch_digest,
        "process_instance_digest": deployment.process_instance_digest,
        "extension_class": EXTENSION_CLASS,
        "artifact_digest": ARTIFACT_DIGEST,
        "path_digest": expected_path_digest,
        "previous_owner_drained": True,
        "late_completions": 0,
    }
    if not _has_exact_values(owner, expected):
        _fail(code)


def _require_journal_observation(
    value: Any, observed_at_ms: int, code: PreflightErrorCode
) -> None:
    journal = _require_mapping(value, _JOURNAL_OBSERVATION_FIELDS, code)
    expected = {
        "observed_at_ms": observed_at_ms,
        "journal_path": JOURNAL_PATH,
        "journal_path_digest": JOURNAL_PATH_DIGEST,
        "main_present": False,
        "matching_temps": 0,
        "matching_aliases": 0,
        "recovery_evidence_present": False,
        "write_in_flight": False,
    }
    if not _has_exact_values(journal, expected):
        _fail(code)


def _require_all_zero(
    value: Any, expected_fields: tuple[str, ...], code: PreflightErrorCode
) -> None:
    counters = _require_mapping(value, expected_fields, code)
    if any(
        type(counters[field_name]) is not int or counters[field_name] != 0
        for field_name in expected_fields
    ):
        _fail(code)


def _require_probe_idle(value: Any, code: PreflightErrorCode) -> None:
    state = _require_mapping(value, _PROBE_STATE_FIELDS, code)
    if not _has_exact_values(
        state,
        {
            "ready": True,
            "phase": "idle",
            "generation": 0,
            "record_present": False,
            "remediation_required": False,
            "arm_accepted_count": 0,
            "endpoint_commands_since_loader_start": 0,
        },
    ):
        _fail(code)


def _normalize_arm_request(
    value: Mapping[str, Any], prearm: PreArmAttestation, now_ms: int
) -> dict[str, Any]:
    code = PreflightErrorCode.ARM_REJECTED
    _validate_json_tree(value, code)
    request = _require_mapping(value, _ARM_REQUEST_FIELDS, code)
    if not _has_exact_values(
        {
            "action": request["action"],
            "protocol_id": request["protocol_id"],
            "protocol_version": request["protocol_version"],
            "build_id": request["build_id"],
            "profile_id": request["profile_id"],
            "profile_version": request["profile_version"],
            "phase": request["phase"],
            "generation": request["generation"],
        },
        {
            "action": "arm",
            "protocol_id": PROTOCOL_ID,
            "protocol_version": PROTOCOL_VERSION,
            "build_id": BUILD_ID,
            "profile_id": PROFILE_ID,
            "profile_version": PROFILE_VERSION,
            "phase": "quiescent",
            "generation": 0,
        },
    ):
        _fail(code)
    for field_name, pattern in (
        ("boot_id", _BOOT_PATTERN),
        ("request_id", _REQUEST_PATTERN),
        ("operation_id", _OPERATION_PATTERN),
        ("nonce", _NONCE_PATTERN),
    ):
        candidate = request[field_name]
        if type(candidate) is not str or pattern.fullmatch(candidate) is None:
            _fail(code)
    if request["boot_id"] != prearm.boot_id:
        _fail(code)
    identity = _normalize_identity(request["candidate"], code)
    intended_target = _require_target(request["intended_target"], code)
    physical_targets = request["physical_targets"]
    if type(physical_targets) is not list or len(physical_targets) != 2:
        _fail(code)
    first_target = _require_target(physical_targets[0], code)
    second_target = _require_target(physical_targets[1], code)
    if first_target == second_target or second_target != intended_target:
        _fail(code)
    request_deadline = _require_future_deadline(
        request["request_deadline_ms"], now_ms, MAX_REQUEST_WINDOW_MS, code
    )
    if request_deadline > prearm.expires_at_ms:
        _fail(code)
    operation_deadline = _require_future_deadline(
        request["operation_deadline_ms"], now_ms, MAX_OPERATION_WINDOW_MS, code
    )
    if operation_deadline <= request_deadline:
        _fail(code)
    return {
        "action": "arm",
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "build_id": BUILD_ID,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "boot_id": request["boot_id"],
        "request_id": request["request_id"],
        "operation_id": request["operation_id"],
        "nonce": request["nonce"],
        "phase": "quiescent",
        "generation": 0,
        "request_deadline_ms": request_deadline,
        "candidate": identity,
        "intended_target": intended_target,
        "physical_targets": [first_target, second_target],
        "operation_deadline_ms": operation_deadline,
    }


def _require_target(value: Any, code: PreflightErrorCode) -> int:
    target = _require_integer_range(
        value, _PROFILE_MINIMUM_TARGET, _PROFILE_MAXIMUM_TARGET, code
    )
    if (target - _PROFILE_MINIMUM_TARGET) % _PROFILE_TARGET_STEP:
        _fail(code)
    return target


def _validate_deployment_report(report: DeploymentAttestation) -> None:
    code = PreflightErrorCode.DEPLOYMENT_REJECTED
    if report.schema != DEPLOYMENT_ATTESTATION_SCHEMA:
        _fail(code)
    for digest in (
        report.snapshot_digest,
        report.manifest_digest,
        report.artifact_digest,
        report.acl_digest,
        report.collection_epoch_digest,
        report.process_instance_digest,
        report.expected_owner_digest,
        report.candidate_identity_digest,
        report.candidate_scope_digest,
        report.configuration_digest,
        report.fence_digest,
    ):
        _require_digest(digest, code)
    _require_safe_integer(report.observed_at_ms, code)
    _require_safe_integer(report.expires_at_ms, code)
    _require_positive_integer(report.configuration_generation, code)
    _require_positive_integer(report.acl_generation, code)


def _validate_prearm_report(report: PreArmAttestation) -> None:
    code = PreflightErrorCode.PREARM_REJECTED
    if report.schema != PREARM_ATTESTATION_SCHEMA:
        _fail(code)
    for digest in (
        report.deployment_snapshot_digest,
        report.snapshot_digest,
        report.manifest_digest,
        report.acl_digest,
        report.collection_epoch_digest,
        report.process_instance_digest,
        report.expected_owner_digest,
        report.candidate_identity_digest,
        report.candidate_scope_digest,
        report.configuration_digest,
        report.fence_digest,
        report.arm_request_digest,
    ):
        _require_digest(digest, code)
    _require_safe_integer(report.observed_at_ms, code)
    _require_safe_integer(report.expires_at_ms, code)
    _require_positive_integer(report.configuration_generation, code)
    _require_positive_integer(report.acl_generation, code)
    if type(report.boot_id) is not str or _BOOT_PATTERN.fullmatch(report.boot_id) is None:
        _fail(code)


def _validate_permit_report(report: ProbeArmPermit) -> None:
    code = PreflightErrorCode.ARM_REJECTED
    if report.schema != ARM_PERMIT_SCHEMA:
        _fail(code)
    for digest in (
        report.permit_digest,
        report.deployment_snapshot_digest,
        report.prearm_snapshot_digest,
        report.request_digest,
        report.canonical_payload_digest,
        report.request_topic_digest,
        report.collection_epoch_digest,
        report.expected_owner_digest,
        report.fence_digest,
    ):
        _require_digest(digest, code)
    if (
        type(report.allowed_action) is not ProbePermitAction
        or report.allowed_action is not ProbePermitAction.ARM
        or type(report.qos) is not int
        or report.qos != 1
        or type(report.retain) is not bool
        or report.retain is not False
        or type(report.one_shot_required) is not bool
        or report.one_shot_required is not True
        or type(report.consumption_enforced) is not bool
        or report.consumption_enforced is not False
        or type(report.commands_authorized) is not bool
        or report.commands_authorized is not False
    ):
        _fail(code)
    _require_safe_integer(report.expires_at_ms, code)


def _require_fresh_window(
    observed_at_ms: Any,
    expires_at_ms: Any,
    now_ms: int,
    maximum_window_ms: int,
    code: PreflightErrorCode,
) -> None:
    observed = _require_safe_integer(observed_at_ms, code)
    expires = _require_safe_integer(expires_at_ms, code)
    if not observed <= now_ms < expires:
        _fail(code)
    if expires - observed > maximum_window_ms:
        _fail(code)
    if now_ms - observed >= maximum_window_ms:
        _fail(code)


def _require_future_deadline(
    value: Any, now_ms: int, maximum_window_ms: int, code: PreflightErrorCode
) -> int:
    deadline = _require_safe_integer(value, code)
    if not now_ms < deadline <= now_ms + maximum_window_ms:
        _fail(code)
    return deadline


def _require_base_topic(value: Any, code: PreflightErrorCode) -> str:
    topic = _require_canonical_text(value, maximum=128, code=code)
    if (
        topic.startswith("/")
        or topic.endswith("/")
        or "+" in topic
        or "#" in topic
    ):
        _fail(code)
    return topic


def _require_friendly_name(value: Any, code: PreflightErrorCode) -> str:
    name = _require_canonical_text(value, maximum=150, code=code)
    if (
        any(character in name for character in ("+", "#"))
        or name.split("/", 1)[0] == "bridge"
    ):
        _fail(code)
    return name


def _require_set_topic(
    value: Any, friendly_name: str, code: PreflightErrorCode
) -> str:
    topic = _require_canonical_text(value, maximum=160, code=code)
    if (
        topic != f"{friendly_name}/set"
        or topic.startswith("/")
        or "//" in topic
        or "+" in topic
        or "#" in topic
    ):
        _fail(code)
    return topic


def _require_canonical_text(
    value: Any, *, maximum: int, code: PreflightErrorCode
) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        _fail(code)
    try:
        value.encode("utf-8")
    except Exception:
        _fail(code)
    if _BOUNDARY_WHITESPACE_PATTERN.search(value) or any(
        ord(character) <= 0x1F for character in value
    ):
        _fail(code)
    return value


def _topic_is_valid(value: Any) -> bool:
    if type(value) is not str or not value or len(value) > 256:
        return False
    try:
        value.encode("utf-8")
    except Exception:
        return False
    if (
        value.startswith("/")
        or value.endswith("/")
        or "+" in value
        or "#" in value
        or _BOUNDARY_WHITESPACE_PATTERN.search(value)
        or any(ord(character) <= 0x1F for character in value)
    ):
        return False
    return True


def _contains_bridge_request(topic: str) -> bool:
    segments = topic.split("/")
    return any(
        left == "bridge" and right == "request"
        for left, right in zip(segments, segments[1:], strict=False)
    )


def _is_topic_subtree(topic: str, root: str) -> bool:
    return topic == root or topic.startswith(f"{root}/")


def _prefixed(base_topic: str, relative_topic: str) -> str:
    return f"{base_topic}/{relative_topic}"


def _require_mapping(
    value: Any, expected_fields: tuple[str, ...], code: PreflightErrorCode
) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(code)
    if set(value) != set(expected_fields):
        _fail(code)
    return dict(value)


def _require_digest(value: Any, code: PreflightErrorCode) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        _fail(code)
    return value


def _require_safe_integer(value: Any, code: PreflightErrorCode) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        _fail(code)
    return value


def _require_positive_integer(value: Any, code: PreflightErrorCode) -> int:
    number = _require_safe_integer(value, code)
    if number <= 0:
        _fail(code)
    return number


def _require_integer_range(
    value: Any, minimum: int, maximum: int, code: PreflightErrorCode
) -> int:
    number = _require_safe_integer(value, code)
    if not minimum <= number <= maximum:
        _fail(code)
    return number


def _has_exact_values(
    actual: Mapping[str, Any], expected: Mapping[str, Any]
) -> bool:
    return set(actual) == set(expected) and all(
        type(actual[field_name]) is type(expected[field_name])
        and actual[field_name] == expected[field_name]
        for field_name in expected
    )


def _strict_json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _strict_json_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _strict_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _strict_dataclass_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    return all(
        type(getattr(left, item.name)) is type(getattr(right, item.name))
        and getattr(left, item.name) == getattr(right, item.name)
        for item in fields(right)
    )


def _validate_json_tree(value: Any, code: PreflightErrorCode) -> None:
    seen: set[int] = set()
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            _fail(code)
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            _require_safe_integer(item, code)
            return
        if type(item) is str:
            if not item or len(item) > MAX_JSON_STRING_LENGTH:
                _fail(code)
            try:
                item.encode("utf-8")
            except Exception:
                _fail(code)
            return
        if type(item) is list:
            if len(item) > MAX_JSON_LIST_LENGTH or id(item) in seen:
                _fail(code)
            seen.add(id(item))
            for child in item:
                visit(child, depth + 1)
            return
        if type(item) is dict:
            if len(item) > MAX_JSON_MAPPING_FIELDS or id(item) in seen:
                _fail(code)
            seen.add(id(item))
            for key, child in item.items():
                if type(key) is not str or not key or len(key) > MAX_JSON_STRING_LENGTH:
                    _fail(code)
                try:
                    key.encode("utf-8")
                except Exception:
                    _fail(code)
                visit(child, depth + 1)
            return
        _fail(code)

    visit(value, 1)


def _canonical_json(
    value: Any,
    *,
    maximum_bytes: int,
    code: PreflightErrorCode,
) -> str:
    _validate_json_tree(value, code)
    plain = _thaw(value)
    try:
        encoded = json.dumps(
            plain,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        body = encoded.encode("utf-8")
    except Exception:
        _fail(code)
    if len(body) > maximum_bytes:
        _fail(code)
    return encoded


def _digest(value: Any, domain: str, code: PreflightErrorCode) -> str:
    try:
        body = _canonical_json(
            value,
            maximum_bytes=MAX_SNAPSHOT_JSON_BYTES,
            code=code,
        ).encode("utf-8")
        domain_bytes = domain.encode("utf-8")
    except PhysicalProbePreflightError:
        raise
    except Exception:
        _fail(code)
    return hashlib.sha256(
        len(domain_bytes).to_bytes(2, "big")
        + domain_bytes
        + len(body).to_bytes(4, "big")
        + body
    ).hexdigest()


def _wire_digest(value: str, domain: str, code: PreflightErrorCode) -> str:
    if type(value) is not str:
        _fail(code)
    try:
        body = value.encode("utf-8")
        domain_bytes = domain.encode("utf-8")
    except Exception:
        _fail(code)
    return hashlib.sha256(
        len(domain_bytes).to_bytes(2, "big")
        + domain_bytes
        + len(body).to_bytes(4, "big")
        + body
    ).hexdigest()


def _encode_utf8(value: str, code: PreflightErrorCode) -> bytes:
    try:
        return value.encode("utf-8")
    except Exception:
        _fail(code)


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType(
            {key: _freeze(item) for key, item in value.items()}
        )
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if type(value) in (dict, MappingProxyType):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_thaw(item) for item in value]
    return value


def _fail(code: PreflightErrorCode) -> NoReturn:
    raise PhysicalProbePreflightError(code) from None


_EXPECTED_MANIFEST_DATA = {
    "schema": MANIFEST_SCHEMA,
    "manifest_version": MANIFEST_VERSION,
    "artifact": {
        "source": ARTIFACT_SOURCE,
        "deployed_filename": DEPLOYED_FILENAME,
        "extension_class": EXTENSION_CLASS,
        "byte_length": ARTIFACT_BYTE_LENGTH,
        "sha256": ARTIFACT_SHA256,
    },
    "protocol": {
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "state_schema": STATE_SCHEMA,
        "build_id": BUILD_ID,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
    },
    "runtime": {
        "node": {"version": NODE_VERSION},
        "zigbee2mqtt": {
            "version": ZIGBEE2MQTT_VERSION,
            "commit": ZIGBEE2MQTT_COMMIT,
            "tree": ZIGBEE2MQTT_TREE,
            "npm_integrity": ZIGBEE2MQTT_NPM_INTEGRITY,
        },
        "zigbee_herdsman": {
            "version": HERDSMAN_VERSION,
            "commit": HERDSMAN_COMMIT,
        },
        "zigbee_herdsman_converters": {
            "version": CONVERTERS_VERSION,
            "commit": CONVERTERS_COMMIT,
        },
    },
    "topics": {
        "ready": READY_TOPIC,
        "status": STATUS_TOPIC,
        "request": REQUEST_TOPIC,
        "response": RESPONSE_TOPIC,
        "result": RESULT_TOPIC,
        "ack": ACK_TOPIC,
        "ack_response": ACK_RESPONSE_TOPIC,
    },
    "deployment": {
        "extension_path": EXTENSION_DEPLOYMENT_PATH,
        "journal_path": JOURNAL_PATH,
        "fresh_deployment_only": True,
        "dynamic_mqtt_extension_save_forbidden": True,
        "dynamic_mqtt_extension_remove_forbidden": True,
        "dynamic_mqtt_converter_save_forbidden": True,
        "dynamic_mqtt_converter_remove_forbidden": True,
        "required_loader_count": 1,
        "required_journal_owner_count": 1,
        "existing_journal_forbidden": True,
        "existing_temp_forbidden": True,
        "existing_alias_forbidden": True,
    },
}
EXPECTED_MANIFEST = _freeze(_EXPECTED_MANIFEST_DATA)
MANIFEST_DIGEST = _digest(
    _EXPECTED_MANIFEST_DATA,
    _MANIFEST_DIGEST_DOMAIN,
    PreflightErrorCode.INTERNAL_REJECTED,
)
ARTIFACT_DIGEST = _digest(
    _EXPECTED_MANIFEST_DATA["artifact"],
    _ARTIFACT_DIGEST_DOMAIN,
    PreflightErrorCode.INTERNAL_REJECTED,
)
EXTENSION_PATH_DIGEST = _digest(
    {"relative_path": EXTENSION_DEPLOYMENT_PATH},
    _EXTENSION_PATH_DIGEST_DOMAIN,
    PreflightErrorCode.INTERNAL_REJECTED,
)
JOURNAL_PATH_DIGEST = _digest(
    {"relative_path": JOURNAL_PATH},
    _JOURNAL_PATH_DIGEST_DOMAIN,
    PreflightErrorCode.INTERNAL_REJECTED,
)
