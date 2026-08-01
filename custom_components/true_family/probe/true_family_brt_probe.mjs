/**
 * Unwired True Family physical probe for Zigbee2MQTT 2.12.1.
 *
 * Captured Moes BRT-100 physical dial DP2 frames use Tuya dataResponse, exposed
 * here as commandDataResponse. The upstream converter also accepts dataReport,
 * but DP2 dataReport is deliberately competing traffic in this protocol. Exact
 * sequence echo for direct commands is not yet proven on all three fingerprints;
 * an actual-spare no-op bench gate remains mandatory.
 *
 * MANDATORY RESIDUAL WRITER FENCE: a future preflight must give Zigbee2MQTT a
 * dedicated broker principal and deny every other client all friendly-name,
 * IEEE, endpoint, and attribute write aliases for the candidate. It must
 * give the orchestrator deny-by-default publish/subscribe ACLs, deny all bridge
 * control request aliases, and freeze candidate name and group membership. It must
 * disable the Zigbee2MQTT frontend, disable every automation/script/scheduler
 * writer for that valve, allowlist only this exact external extension, exclude
 * unreviewed in-process endpoint writers, keep payload-debug logging disabled,
 * and verify this exact build. Extension and
 * converter save/remove requests must be denied, and loader publication of
 * extension source on bridge/extensions is part of the deployment privacy gate.
 * This extension cannot enforce broker ACLs or prove retain metadata because
 * eventBus does not expose it. Physical provenance is operational isolation,
 * not an origin bit; raw DP2 and write-topic monitoring is defense in depth,
 * not the writer fence. Control, rename, and group callbacks may observe a
 * built-in action only after it has happened and therefore cannot prevent it.
 * Zigbee2MQTT Mqtt.publish can also swallow broker-delivery failure; periodic
 * status/result attempts mitigate loss but prove invocation, not delivery.
 * A future lifecycle/collision preflight must enforce one loader and one journal
 * owner; this slice does not add an unsafe process-local lock for cross-instance
 * late journal completion. Immediate send and empty request queues still require
 * pinned-adapter/radio and actual-spare proof of final physical ordering.
 *
 * Filename/class collisions and extension deployment, save, removal, and
 * upgrade remain outside this source-only slice. No request payload, full IEEE,
 * nonce, or raw frame is logged or persisted as evidence. The full IEEE is
 * durable recovery identity but is masked from every public probe message.
 */

import {createHash, randomBytes, randomInt} from "node:crypto";
import {
    chmod,
    lstat,
    open,
    readFile,
    readdir,
    rename,
    unlink,
} from "node:fs/promises";
import path from "node:path";
import {fileURLToPath} from "node:url";

export const PROTOCOL_ID = "true-family-physical-probe";
export const PROTOCOL_VERSION = 2;
export const STATE_SCHEMA = "true-family-physical-probe-state-v2";
export const BUILD_ID = "tfpp-v2-z2m-2.12.1-zh-10.6.1-zhc-26.76.0";
export const ENDPOINT_COMMAND_TIMEOUT_MS = 5_000;
export const REQUIRED_RUNTIME_VERSIONS = deepFreeze({
    zigbee2mqtt: "2.12.1",
    zigbee_herdsman: "10.6.1",
    zigbee_herdsman_converters: "26.76.0",
});

export const TOPICS = deepFreeze({
    ready: "bridge/true_family/physical_probe/ready",
    status: "bridge/true_family/physical_probe/status",
    request: "bridge/request/true_family/physical_probe",
    response: "bridge/response/true_family/physical_probe",
    result: "bridge/true_family/physical_probe/result",
    ack: "bridge/request/true_family/physical_probe/ack",
    ackResponse: "bridge/response/true_family/physical_probe/ack",
});

export const EXTENSION_IDENTITY = deepFreeze({
    filename: "true_family_brt_probe.mjs",
    class_name: "TrueFamilyBrtProbeExtension",
    protocol_id: PROTOCOL_ID,
    protocol_version: PROTOCOL_VERSION,
    build_id: BUILD_ID,
    required_runtime_versions: REQUIRED_RUNTIME_VERSIONS,
});

export const RESIDUAL_DEPLOYMENT_CONTRACT = deepFreeze({
    all_candidate_write_aliases_exclusive_acl_required: true,
    all_bridge_control_requests_must_be_denied: true,
    candidate_name_and_group_membership_must_be_frozen: true,
    dedicated_topic_acl_required: true,
    frontend_must_be_disabled: true,
    automation_script_scheduler_writers_must_be_disabled: true,
    payload_debug_logging_must_be_disabled: true,
    lifecycle_preflight_required: true,
    dynamic_extension_converter_mutation_must_be_denied: true,
    single_loader_journal_ownership_required: true,
    extension_source_attestation_required: true,
    bridge_extensions_privacy_preflight_required: true,
    exact_external_extension_allowlist_required: true,
    orchestrator_publish_deny_by_default_required: true,
    orchestrator_subscription_allowlist_required: true,
    unreviewed_in_process_endpoint_writers_forbidden: true,
    physical_provenance_is_operational_isolation: true,
    event_bus_retain_metadata_available: false,
    source_enforces_broker_fence: false,
});

export const BRT_PROFILE = deepFreeze({
    profile_id: "moes-brt-100-trv",
    profile_version: 2,
    zigbee_model: "TS0601",
    resolved_aliases: [
        {manufacturer_fingerprint: "_TZE200_b6wax7g0", model: "BRT-100-TRV", vendor: "Moes"},
        {manufacturer_fingerprint: "_TZE200_qsoecqlk", model: "Powerswitch-ZK(W)", vendor: "Sibling"},
        {manufacturer_fingerprint: "_TZE200_6y7kyjga", model: "BRT-100-TRV", vendor: "Moes"},
    ],
    endpoint_id: 1,
    cluster_name: "manuSpecificTuya",
    cluster_id: 0xef00,
    datapoint: 2,
    datatype: 2,
    minimum_target: 0,
    maximum_target: 35,
    target_step: 1,
    challenge_delta: 1,
    required_runtime_versions: REQUIRED_RUNTIME_VERSIONS,
});

export const PHASES = deepFreeze({
    physical1: "awaiting_physical_target_1",
    physical2: "awaiting_physical_target_2",
    noop: "awaiting_noop_response",
    challenge: "awaiting_challenge_response",
    restore: "awaiting_restore_response",
    result: "result_pending_ack",
    quiescent: "quiescent",
    remediation: "remediation_required",
});

export const FRAME_KINDS = deepFreeze({
    report: "commandDataReport",
    response: "commandDataResponse",
});

export const PURPOSES = deepFreeze({
    physical1: "physical_target_1",
    physical2: "physical_target_2",
    noop: "noop",
    challenge: "challenge",
    restore: "restore",
});

export const OUTCOMES = deepFreeze({
    verified: "verified",
    failedSafe: "failed_safe",
    failedRestored: "failed_restored",
});

export const JOURNAL_BOUNDARIES = deepFreeze({
    tempOpen: "temp_open",
    tempWrite: "temp_write",
    tempFsync: "temp_fsync",
    tempClose: "temp_close",
    rename: "rename",
    chmod: "chmod",
    directoryOpen: "directory_open",
    directoryFsync: "directory_fsync",
    directoryClose: "directory_close",
    postRename: "post_rename",
    cleanupPreUnlinkDirectoryFsync: "cleanup_pre_unlink_directory_fsync",
    cleanupUnlink: "cleanup_unlink",
    cleanupPostUnlinkDirectoryFsync: "cleanup_post_unlink_directory_fsync",
});

export const LIMITS = deepFreeze({
    stateJsonBytes: 16_384,
    messageJsonBytes: 4_096,
    consumedRequestIds: 32,
    usedSequences: 16,
    generation: 64,
    restoreAttempts: 3,
    unclaimedSafetyAttempts: 3,
    pendingWork: 32,
    orphanTemps: 8,
    physicalProofMs: 60_000,
    directProofMs: 10_000,
    resultRetryMs: 10_000,
    resultSettleMs: 2_000,
    candidateResolutionMs: 4_000,
    dispatchMs: 10_000,
    journalMs: 5_000,
    publicationMs: 2_000,
    stopDrainMs: 10_000,
    safetyRestoreMs: 10_000,
});

const POST_RESULT_SEQUENCE_RESERVE = LIMITS.unclaimedSafetyAttempts;
const POST_CHALLENGE_SEQUENCE_RESERVE = (
    LIMITS.restoreAttempts + LIMITS.unclaimedSafetyAttempts
);
const POST_NOOP_SEQUENCE_RESERVE = 1 + POST_CHALLENGE_SEQUENCE_RESERVE;

const MAX_JSON_DEPTH = 12;
const MAX_JSON_NODES = 320;
const MAX_JSON_STRING_LENGTH = 512;
const MAX_REQUEST_WINDOW_MS = 60_000;
const MAX_OPERATION_WINDOW_MS = 900_000;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const DISPATCH_RESULT_BRAND = Symbol("true-family-dispatch-result");
const DISPATCH_INVOKED = Object.freeze({[DISPATCH_RESULT_BRAND]: "endpoint-invoked"});
const DISPATCH_NOT_INVOKED = Object.freeze({[DISPATCH_RESULT_BRAND]: "not-invoked"});

const IEEE_PATTERN = /^0x[0-9a-f]{16}$/;
const FINGERPRINT_PATTERN = /^_TZE[0-9]{3}_[a-z0-9]{8}$/;
const BOOT_ID_PATTERN = /^tfpp-boot-[0-9a-f]{32}$/;
const OPERATION_ID_PATTERN = /^tfpp-op-[0-9a-f]{24}$/;
const REQUEST_ID_PATTERN = /^tfpp-req-[0-9a-f]{24}$/;
const NONCE_PATTERN = /^tfpp-nonce-[0-9a-f]{32}$/;
const RESULT_ID_PATTERN = /^tfpp-result-[0-9a-f]{24}$/;
const TEMP_FILE_PATTERN = /^\.true_family_brt_probe\.[0-9]+\.[0-9a-f]{24}\.tmp$/;
const BOUNDARY_WHITESPACE_PATTERN = /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]$/u;

const CANDIDATE_FIELDS = Object.freeze([
    "cluster_id",
    "cluster_name",
    "endpoint_id",
    "ieee_address",
    "manufacturer_fingerprint",
    "model",
    "vendor",
    "zigbee_model",
]);
const PROOF_FIELDS = Object.freeze(["frame_kind", "purpose", "sequence", "target"]);
const RECORD_FIELDS = Object.freeze([
    "bound_boot_id",
    "build_id",
    "candidate_ieee",
    "candidate_set_topic",
    "challenge_target",
    "cleanup_allowed",
    "consumed_request_ids",
    "expected_proof",
    "expected_proof_deadline_ms",
    "failure_code",
    "generation",
    "intended_target",
    "last_request_deadline_ms",
    "operation_deadline_ms",
    "operation_id",
    "outcome",
    "phase",
    "physical_targets",
    "profile_id",
    "profile_version",
    "proofs",
    "protocol_id",
    "protocol_version",
    "remediation_after_restore",
    "restore_attempts",
    "restore_required",
    "result_id",
    "result_not_before_ms",
    "schema",
    "used_sequences",
]);
const COMMON_REQUEST_FIELDS = Object.freeze([
    "action",
    "boot_id",
    "build_id",
    "generation",
    "nonce",
    "operation_id",
    "phase",
    "profile_id",
    "profile_version",
    "protocol_id",
    "protocol_version",
    "request_deadline_ms",
    "request_id",
]);
const ARM_REQUEST_FIELDS = Object.freeze([
    ...COMMON_REQUEST_FIELDS,
    "candidate",
    "intended_target",
    "operation_deadline_ms",
    "physical_targets",
].sort());
const ACK_REQUEST_FIELDS = Object.freeze([...COMMON_REQUEST_FIELDS, "result_id"].sort());
const PURPOSE_ORDER = Object.freeze([
    PURPOSES.physical1,
    PURPOSES.physical2,
    PURPOSES.noop,
    PURPOSES.challenge,
    PURPOSES.restore,
]);
const PHASE_PURPOSE = Object.freeze({
    [PHASES.physical1]: PURPOSES.physical1,
    [PHASES.physical2]: PURPOSES.physical2,
    [PHASES.noop]: PURPOSES.noop,
    [PHASES.challenge]: PURPOSES.challenge,
    [PHASES.restore]: PURPOSES.restore,
});
const ACTIVE_PHASES = new Set(Object.keys(PHASE_PURPOSE));
const RESULT_PHASES = new Set([PHASES.result, PHASES.quiescent]);
const TERMINAL_PHASES = new Set([PHASES.result, PHASES.quiescent, PHASES.remediation]);
const ALLOWED_FAILURE_CODES = new Set([
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
]);
const REMEDIATION_AFTER_RESTORE_CODES = new Set([
    "competing_frame",
    "competing_write",
    "control_drift",
    "queue_overflow",
]);

export class ProbeValidationError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "ProbeValidationError";
        this.code = code;
    }
}

export class ProbeJournalError extends Error {
    constructor(
        message,
        {cause = undefined, recoveryRecord = null, manualRemediation = false} = {},
    ) {
        super(message, cause === undefined ? undefined : {cause});
        this.name = "ProbeJournalError";
        this.mayHaveCommitted = false;
        this.recoveryRecord = recoveryRecord;
        this.manualRemediation = manualRemediation === true;
    }
}

export class ProbeJournalUncertainError extends ProbeJournalError {
    constructor(message, options = undefined) {
        super(message, options);
        this.name = "ProbeJournalUncertainError";
        this.mayHaveCommitted = true;
    }
}

export function deepFreeze(value) {
    if (value && typeof value === "object" && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (const child of Object.values(value)) deepFreeze(child);
    }
    return value;
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected, label) {
    if (!isPlainObject(value)) {
        throw new ProbeValidationError("malformed_object", `${label} must be a plain object.`);
    }
    const actual = Object.keys(value).sort();
    const canonical = [...expected].sort();
    if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
        throw new ProbeValidationError("unexpected_fields", `${label} has missing or unexpected fields.`);
    }
}

function canonicalize(value) {
    if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
            throw new ProbeValidationError("unsafe_integer", "Canonical JSON contains an unsafe integer.");
        }
        return String(value);
    }
    if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value)
            .sort(compareCodePoints)
            .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
            .join(",")}}`;
    }
    throw new ProbeValidationError("unsupported_json_type", "Canonical JSON contains an unsupported type.");
}

function compareCodePoints(left, right) {
    const leftPoints = Array.from(left, (character) => character.codePointAt(0));
    const rightPoints = Array.from(right, (character) => character.codePointAt(0));
    const length = Math.min(leftPoints.length, rightPoints.length);
    for (let index = 0; index < length; index += 1) {
        if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
    }
    return leftPoints.length - rightPoints.length;
}

function validateJsonTree(value) {
    let nodes = 0;
    const walk = (item, depth) => {
        nodes += 1;
        if (nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
            throw new ProbeValidationError("json_resource_bound", "JSON exceeds its structural bound.");
        }
        if (item === null || typeof item === "boolean") return;
        if (typeof item === "number") {
            requireSafeInteger(item, "JSON integer");
            return;
        }
        if (typeof item === "string") {
            if (scalarLength(item) > MAX_JSON_STRING_LENGTH || !isWellFormedUnicode(item)) {
                throw new ProbeValidationError("json_string_bound", "JSON string exceeds its length bound.");
            }
            return;
        }
        if (Array.isArray(item)) {
            for (const child of item) walk(child, depth + 1);
            return;
        }
        if (isPlainObject(item)) {
            for (const [key, child] of Object.entries(item)) {
                if (scalarLength(key) > 96 || !isWellFormedUnicode(key)) {
                    throw new ProbeValidationError("json_key_bound", "JSON key exceeds its length bound.");
                }
                walk(child, depth + 1);
            }
            return;
        }
        throw new ProbeValidationError("unsupported_json_type", "JSON contains an unsupported type.");
    };
    walk(value, 0);
}

function isWellFormedUnicode(value) {
    for (let index = 0; index < value.length; index += 1) {
        const unit = value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
            index += 1;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            return false;
        }
    }
    return true;
}

function scalarLength(value) {
    return Array.from(value).length;
}

export function canonicalJson(value, maximumBytes = LIMITS.messageJsonBytes) {
    requirePositiveInteger(maximumBytes, "JSON byte limit");
    validateJsonTree(value);
    const text = canonicalize(value);
    if (Buffer.byteLength(text, "utf8") > maximumBytes) {
        throw new ProbeValidationError("json_byte_bound", "Canonical JSON exceeds its byte limit.");
    }
    return text;
}

export function parseCanonicalObject(text, maximumBytes = LIMITS.messageJsonBytes) {
    if (typeof text !== "string" || text.length === 0 || Buffer.byteLength(text, "utf8") > maximumBytes) {
        throw new ProbeValidationError("json_byte_bound", "Canonical JSON input is empty or oversized.");
    }
    let value;
    try {
        value = JSON.parse(text);
    } catch {
        throw new ProbeValidationError("malformed_json", "Canonical JSON input is malformed.");
    }
    if (!isPlainObject(value) || canonicalJson(value, maximumBytes) !== text) {
        throw new ProbeValidationError("noncanonical_json", "JSON input is not a canonical plain object.");
    }
    return value;
}

export function canonicalDigest(value, domain = PROTOCOL_ID) {
    requireText(domain, "digest domain", 96);
    const domainBytes = Buffer.from(domain, "utf8");
    const body = Buffer.from(canonicalJson(value, LIMITS.stateJsonBytes), "utf8");
    const domainLength = Buffer.alloc(2);
    const bodyLength = Buffer.alloc(4);
    domainLength.writeUInt16BE(domainBytes.length, 0);
    bodyLength.writeUInt32BE(body.length, 0);
    return createHash("sha256")
        .update(domainLength)
        .update(domainBytes)
        .update(bodyLength)
        .update(body)
        .digest("hex");
}

export function maskIeee(ieeeAddress) {
    requirePattern(ieeeAddress, IEEE_PATTERN, "IEEE address");
    return `...${ieeeAddress.slice(-4).toUpperCase()}`;
}

export function createBootId(random = randomBytes) {
    const bytes = random(16);
    if (!Buffer.isBuffer(bytes) || bytes.length !== 16) {
        throw new ProbeValidationError("random_source", "Boot random source did not return 16 bytes.");
    }
    return `tfpp-boot-${bytes.toString("hex")}`;
}

export function randomDistinctSequence(usedSequences, source = randomInt) {
    if (!Array.isArray(usedSequences) || usedSequences.length >= LIMITS.usedSequences) {
        throw new ProbeValidationError("sequence_bound", "Used sequence set is exhausted or invalid.");
    }
    const used = new Set(usedSequences);
    for (const sequence of used) requireUint16(sequence, "used sequence");
    if (used.size !== usedSequences.length) {
        throw new ProbeValidationError("duplicate_sequence", "Used sequence set contains duplicates.");
    }
    for (let attempt = 0; attempt < 128; attempt += 1) {
        const sequence = source(0, 0xffff);
        requireGeneratedSequence(sequence, "random sequence");
        if (!used.has(sequence)) return sequence;
    }
    throw new ProbeValidationError("random_source", "Unable to allocate a distinct random sequence.");
}

function requireSequenceSlots(usedSequences, requiredSlots, label) {
    requireIntegerRange(requiredSlots, 0, LIMITS.usedSequences, `${label} required slots`);
    if (
        !Array.isArray(usedSequences) ||
        usedSequences.length + requiredSlots > LIMITS.usedSequences
    ) {
        throw new ProbeValidationError(
            "sequence_bound",
            `${label} would consume reserved restoration sequence capacity.`,
        );
    }
}

function claimedRestoreReserveAfterNext(record) {
    return (
        LIMITS.restoreAttempts - record.restore_attempts - 1 +
        LIMITS.unclaimedSafetyAttempts
    );
}

function durableSequenceReserve(record) {
    if (record.phase === PHASES.physical1) {
        return 3 + POST_NOOP_SEQUENCE_RESERVE;
    }
    if (record.phase === PHASES.physical2) {
        return 2 + POST_NOOP_SEQUENCE_RESERVE;
    }
    if (record.phase === PHASES.noop) return POST_NOOP_SEQUENCE_RESERVE;
    if (record.phase === PHASES.challenge) return POST_CHALLENGE_SEQUENCE_RESERVE;
    if (record.phase === PHASES.restore) {
        return (
            LIMITS.restoreAttempts - record.restore_attempts +
            LIMITS.unclaimedSafetyAttempts
        );
    }
    return POST_RESULT_SEQUENCE_RESERVE;
}

export function challengeTarget(intendedTarget, profile = BRT_PROFILE) {
    validateTarget(intendedTarget, profile, "intended target");
    const higher = intendedTarget + profile.challenge_delta;
    const challenge = higher <= profile.maximum_target ? higher : intendedTarget - profile.challenge_delta;
    validateTarget(challenge, profile, "challenge target");
    if (Math.abs(challenge - intendedTarget) !== profile.challenge_delta) {
        throw new ProbeValidationError("challenge_target", "Challenge target is not exactly one delta away.");
    }
    return challenge;
}

export function normalizeCandidateIdentity(value, profile = BRT_PROFILE) {
    exactKeys(value, CANDIDATE_FIELDS, "candidate identity");
    requirePattern(value.ieee_address, IEEE_PATTERN, "candidate IEEE address");
    requireText(value.model, "candidate model", 96);
    requireText(value.vendor, "candidate vendor", 96);
    requireText(value.zigbee_model, "candidate Zigbee model", 96);
    requirePattern(value.manufacturer_fingerprint, FINGERPRINT_PATTERN, "candidate manufacturer fingerprint");
    requirePositiveInteger(value.endpoint_id, "candidate endpoint");
    requireText(value.cluster_name, "candidate cluster name", 96);
    requireIntegerRange(value.cluster_id, 0, 0xffff, "candidate cluster ID");
    const alias = profile.resolved_aliases.find(
        (item) => item.manufacturer_fingerprint === value.manufacturer_fingerprint,
    );
    if (
        !alias ||
        value.model !== alias.model ||
        value.vendor !== alias.vendor ||
        value.zigbee_model !== profile.zigbee_model ||
        value.endpoint_id !== profile.endpoint_id ||
        value.cluster_name !== profile.cluster_name ||
        value.cluster_id !== profile.cluster_id
    ) {
        throw new ProbeValidationError("identity_mismatch", "Candidate identity does not match the profile.");
    }
    return deepFreeze({
        ieee_address: value.ieee_address,
        model: value.model,
        vendor: value.vendor,
        zigbee_model: value.zigbee_model,
        manufacturer_fingerprint: value.manufacturer_fingerprint,
        endpoint_id: value.endpoint_id,
        cluster_name: value.cluster_name,
        cluster_id: value.cluster_id,
    });
}

function endpointSupportsProfile(endpoint, profile) {
    if (typeof endpoint.supportsInputCluster === "function") {
        try {
            return endpoint.supportsInputCluster(profile.cluster_name) && endpoint.supportsInputCluster(profile.cluster_id);
        } catch {
            return false;
        }
    }
    return Array.isArray(endpoint.inputClusters) && endpoint.inputClusters.includes(profile.cluster_id);
}

function normalizeSetTopic(name) {
    requireText(name, "candidate device name", 150);
    const topic = `${name}/set`;
    if (topic.startsWith("/") || topic.includes("//") || topic.includes("+") || topic.includes("#")) {
        throw new ProbeValidationError("identity_mismatch", "Candidate set topic is not exact.");
    }
    return topic;
}

export function parseCandidateWriteTopic(relativeTopic, candidateSetTopic, candidateIeee) {
    requireSetTopic(candidateSetTopic);
    requirePattern(candidateIeee, IEEE_PATTERN, "candidate IEEE address");
    if (
        typeof relativeTopic !== "string" ||
        relativeTopic.length === 0 ||
        !isWellFormedUnicode(relativeTopic) ||
        Buffer.byteLength(relativeTopic, "utf8") > 65_535 ||
        relativeTopic.includes("+") ||
        relativeTopic.includes("#") ||
        relativeTopic.includes("\u0000")
    ) return null;
    const roots = [
        {kind: "friendly", value: candidateSetTopic.slice(0, -4)},
        {kind: "ieee", value: candidateIeee},
    ];
    for (const root of roots) {
        if (!relativeTopic.startsWith(`${root.value}/`)) continue;
        const suffix = relativeTopic.slice(root.value.length + 1);
        let endpoint = null;
        let attribute = null;
        if (suffix === "set" || suffix.startsWith("set/")) {
            attribute = suffix === "set" ? null : suffix.slice(4);
        } else {
            const marker = suffix.indexOf("/set");
            if (marker < 0) return null;
            const setSuffix = suffix.slice(marker + 1);
            if (setSuffix !== "set" && !setSuffix.startsWith("set/")) return null;
            endpoint = suffix.slice(0, marker);
            attribute = setSuffix === "set" ? null : setSuffix.slice(4);
        }
        return deepFreeze({root_kind: root.kind, endpoint, attribute});
    }
    return null;
}

export function isCandidateWriteTopic(relativeTopic, candidateSetTopic, candidateIeee) {
    try {
        return parseCandidateWriteTopic(relativeTopic, candidateSetTopic, candidateIeee) !== null;
    } catch {
        return false;
    }
}

/** Match the pinned unanchored bridge request surface without exempting aliases. */
export function isDangerousControlTopic(relativeTopic) {
    if (typeof relativeTopic !== "string" || relativeTopic.length === 0) return false;
    if (relativeTopic === TOPICS.request || relativeTopic === TOPICS.ack) return false;
    return /(?:^|\/)bridge\/request\//u.test(relativeTopic);
}

function requireEmptyEndpointQueue(endpoint) {
    if (!endpoint || typeof endpoint.hasPendingRequests !== "function") {
        throw new ProbeValidationError("pending_requests", "Candidate endpoint pending-request API is unavailable.");
    }
    let pending;
    try {
        pending = endpoint.hasPendingRequests();
    } catch {
        throw new ProbeValidationError("pending_requests", "Candidate endpoint pending-request state is unreadable.");
    }
    if (pending !== false) {
        throw new ProbeValidationError("pending_requests", "Candidate device has pending endpoint requests.");
    }
}

/** Resolve the live Z2M definition and endpoint; ordinary device JSON is never proof. */
export function inspectCandidate(zigbee, candidateOrIeee, profile = BRT_PROFILE) {
    if (!zigbee || typeof zigbee.resolveEntity !== "function") {
        throw new ProbeValidationError("identity_mismatch", "Zigbee resolver is unavailable.");
    }
    const supplied = typeof candidateOrIeee === "string" ? null : normalizeCandidateIdentity(candidateOrIeee, profile);
    const ieeeAddress = supplied ? supplied.ieee_address : candidateOrIeee;
    requirePattern(ieeeAddress, IEEE_PATTERN, "candidate IEEE address");
    const device = zigbee.resolveEntity(ieeeAddress);
    if (!device || typeof device.isDevice !== "function" || device.isDevice() !== true) {
        throw new ProbeValidationError("identity_mismatch", "Candidate does not resolve to a device.");
    }
    if (device.ieeeAddr !== ieeeAddress || device.ID !== ieeeAddress) {
        throw new ProbeValidationError("identity_mismatch", "Resolved device IEEE identity differs.");
    }
    const definition = device.definition;
    const zh = device.zh;
    if (!isPlainObject(definition) || !zh || typeof zh !== "object") {
        throw new ProbeValidationError("identity_mismatch", "Resolved device definition is unavailable.");
    }
    const live = normalizeCandidateIdentity(
        {
            ieee_address: ieeeAddress,
            model: definition.model,
            vendor: definition.vendor,
            zigbee_model: zh.modelID,
            manufacturer_fingerprint: zh.manufacturerName,
            endpoint_id: profile.endpoint_id,
            cluster_name: profile.cluster_name,
            cluster_id: profile.cluster_id,
        },
        profile,
    );
    if (supplied && canonicalJson(supplied) !== canonicalJson(live)) {
        throw new ProbeValidationError("identity_mismatch", "Supplied and live candidate identities differ.");
    }
    const endpoint = typeof device.endpoint === "function" ? device.endpoint(profile.endpoint_id) : zh.getEndpoint?.(profile.endpoint_id);
    if (
        !endpoint ||
        endpoint.ID !== profile.endpoint_id ||
        endpoint.deviceIeeeAddress !== ieeeAddress ||
        typeof endpoint.command !== "function" ||
        !endpointSupportsProfile(endpoint, profile)
    ) {
        throw new ProbeValidationError("identity_mismatch", "Exact candidate endpoint or Tuya cluster is unavailable.");
    }
    requireEmptyEndpointQueue(endpoint);
    if (Array.isArray(zh.endpoints)) {
        for (const liveEndpoint of zh.endpoints) requireEmptyEndpointQueue(liveEndpoint);
    }
    return Object.freeze({candidate: live, endpoint, set_topic: normalizeSetTopic(device.name)});
}

export function encodeTargetValue(target, profile = BRT_PROFILE) {
    validateTarget(target, profile, "command target");
    const data = Buffer.alloc(4);
    data.writeUInt32BE(target, 0);
    return data;
}

export function buildTuyaCommand(sequence, target, profile = BRT_PROFILE) {
    requireGeneratedSequence(sequence, "command sequence");
    return {
        cluster: profile.cluster_name,
        command: "dataRequest",
        payload: {
            seq: sequence,
            dpValues: [{dp: profile.datapoint, datatype: profile.datatype, data: encodeTargetValue(target, profile)}],
        },
        options: {
            disableDefaultResponse: true,
            sendPolicy: "immediate",
            disableRecovery: true,
            timeout: ENDPOINT_COMMAND_TIMEOUT_MS,
        },
    };
}

/** Return null for unrelated traffic, otherwise one raw-data-free DP2 response. */
export function parseProbeFrame(event, candidateIeee, profile = BRT_PROFILE) {
    requirePattern(candidateIeee, IEEE_PATTERN, "candidate IEEE address");
    if (!event || typeof event !== "object" || event.device?.ieeeAddr !== candidateIeee) return null;
    const clusterMatches = event.cluster === profile.cluster_name || event.cluster === profile.cluster_id;
    if (event.endpoint?.ID !== profile.endpoint_id || !clusterMatches) return null;
    if (event.endpoint.deviceIeeeAddress !== undefined && event.endpoint.deviceIeeeAddress !== candidateIeee) {
        throw new ProbeValidationError("malformed_frame", "Frame endpoint identity differs.");
    }
    if (!isPlainObject(event.data) || !Array.isArray(event.data.dpValues) || event.data.dpValues.length > 16) {
        throw new ProbeValidationError("malformed_frame", "Tuya frame data is malformed or oversized.");
    }
    const dp2Values = event.data.dpValues.filter((item) => isPlainObject(item) && item.dp === profile.datapoint);
    if (dp2Values.length === 0) return null;
    if (event.groupID !== undefined && event.groupID !== 0) {
        throw new ProbeValidationError("competing_frame", "Grouped DP2 cannot prove direct possession.");
    }
    if (event.type !== FRAME_KINDS.response) {
        throw new ProbeValidationError("competing_frame", "BRT DP2 proof must be commandDataResponse.");
    }
    exactKeys(event.data, ["dpValues", "seq"], "Tuya frame data");
    requireUint16(event.data.seq, "Tuya inner sequence");
    if (event.data.dpValues.length !== 1 || dp2Values.length !== 1) {
        throw new ProbeValidationError("competing_frame", "DP2 proof must be the only datapoint.");
    }
    const datapoint = dp2Values[0];
    exactKeys(datapoint, ["data", "datatype", "dp"], "Tuya datapoint");
    if (datapoint.datatype !== profile.datatype) {
        throw new ProbeValidationError("competing_frame", "DP2 datatype differs.");
    }
    if (!Buffer.isBuffer(datapoint.data) || datapoint.data.length !== 4) {
        throw new ProbeValidationError("malformed_frame", "DP2 value must be an exact four-byte Buffer.");
    }
    const target = datapoint.data.readUInt32BE(0);
    validateTarget(target, profile, "frame target");
    if (!datapoint.data.equals(encodeTargetValue(target, profile))) {
        throw new ProbeValidationError("malformed_frame", "DP2 value is not canonical big-endian data.");
    }
    return deepFreeze({frame_kind: FRAME_KINDS.response, sequence: event.data.seq, target});
}

function normalizeProof(value, {expected = false, profile = BRT_PROFILE} = {}) {
    exactKeys(value, PROOF_FIELDS, expected ? "expected proof" : "proof");
    if (!PURPOSE_ORDER.includes(value.purpose) || value.frame_kind !== FRAME_KINDS.response) {
        throw new ProbeValidationError("proof_mismatch", "Every BRT DP2 proof must be commandDataResponse.");
    }
    validateTarget(value.target, profile, "proof target");
    const physical = value.purpose === PURPOSES.physical1 || value.purpose === PURPOSES.physical2;
    if (expected && physical) {
        if (value.sequence !== null) {
            throw new ProbeValidationError("proof_mismatch", "Physical response sequence cannot be predicted.");
        }
    } else if (physical) {
        requireUint16(value.sequence, "physical proof sequence");
    } else {
        requireGeneratedSequence(value.sequence, "command proof sequence");
    }
    return deepFreeze({
        purpose: value.purpose,
        frame_kind: FRAME_KINDS.response,
        sequence: value.sequence,
        target: value.target,
    });
}

export function normalizeCommandProof(value, profile = BRT_PROFILE) {
    return normalizeProof(value, {profile});
}

function expectedProof(purpose, sequence, target, profile = BRT_PROFILE) {
    return normalizeProof({purpose, frame_kind: FRAME_KINDS.response, sequence, target}, {expected: true, profile});
}

function observedProof(expected, frame) {
    if (
        frame.frame_kind !== expected.frame_kind ||
        frame.target !== expected.target ||
        (expected.sequence !== null && frame.sequence !== expected.sequence)
    ) {
        throw new ProbeValidationError("proof_mismatch", "Observed frame does not match the expected proof.");
    }
    return normalizeProof({
        purpose: expected.purpose,
        frame_kind: frame.frame_kind,
        sequence: frame.sequence,
        target: frame.target,
    });
}

function validatePhysicalTargets(targets, intendedTarget, profile = BRT_PROFILE) {
    if (!Array.isArray(targets) || targets.length !== 2) {
        throw new ProbeValidationError("physical_targets", "Physical targets must be an ordered pair.");
    }
    validateTarget(targets[0], profile, "first physical target");
    validateTarget(targets[1], profile, "second physical target");
    if (targets[0] === targets[1] || targets[1] !== intendedTarget) {
        throw new ProbeValidationError("physical_targets", "Physical targets must be distinct and end at the intended target.");
    }
}

function validateFailureCode(value) {
    if (typeof value !== "string" || !ALLOWED_FAILURE_CODES.has(value)) {
        throw new ProbeValidationError("failure_code", "Failure code is not allowlisted.");
    }
}

export function calculateResultId(record) {
    const body = {
        challenge_target: record.challenge_target,
        failure_code: record.failure_code,
        intended_target: record.intended_target,
        operation_id: record.operation_id,
        outcome: record.outcome,
        profile_id: record.profile_id,
        profile_version: record.profile_version,
        proofs: record.proofs,
    };
    return `tfpp-result-${canonicalDigest(body, "true-family-physical-probe/result/v2").slice(0, 24)}`;
}

export function validateRecoveryRecord(value, profile = BRT_PROFILE) {
    exactKeys(value, RECORD_FIELDS, "probe recovery record");
    if (
        value.schema !== STATE_SCHEMA ||
        value.protocol_id !== PROTOCOL_ID ||
        value.protocol_version !== PROTOCOL_VERSION ||
        value.build_id !== BUILD_ID ||
        value.profile_id !== profile.profile_id ||
        value.profile_version !== profile.profile_version
    ) {
        throw new ProbeValidationError("incompatible_state", "Recovery identity is incompatible.");
    }
    requirePattern(value.candidate_ieee, IEEE_PATTERN, "candidate IEEE address");
    requireSetTopic(value.candidate_set_topic);
    requirePattern(value.operation_id, OPERATION_ID_PATTERN, "operation ID");
    requirePattern(value.bound_boot_id, BOOT_ID_PATTERN, "bound boot ID");
    requireIntegerRange(value.generation, 1, LIMITS.generation, "record generation");
    requireSafeMilliseconds(value.operation_deadline_ms, "operation deadline");
    requireSafeMilliseconds(value.last_request_deadline_ms, "last request deadline");
    requireSafeMilliseconds(value.expected_proof_deadline_ms, "expected proof deadline");
    requireSafeMilliseconds(value.result_not_before_ms, "result not-before time");
    validateTarget(value.intended_target, profile, "intended target");
    validateTarget(value.challenge_target, profile, "challenge target");
    if (value.challenge_target !== challengeTarget(value.intended_target, profile)) {
        throw new ProbeValidationError("challenge_target", "Stored challenge target is not canonical.");
    }
    validatePhysicalTargets(value.physical_targets, value.intended_target, profile);
    requireBoolean(value.restore_required, "restore-required flag");
    requireBoolean(value.remediation_after_restore, "remediation-after-restore flag");
    requireBoolean(value.cleanup_allowed, "cleanup-allowed flag");
    requireIntegerRange(value.restore_attempts, 0, LIMITS.restoreAttempts, "restore attempts");

    if (
        !Array.isArray(value.consumed_request_ids) ||
        value.consumed_request_ids.length < 1 ||
        value.consumed_request_ids.length > LIMITS.consumedRequestIds
    ) {
        throw new ProbeValidationError("request_id_bound", "Consumed request IDs are outside their bound.");
    }
    for (const requestId of value.consumed_request_ids) requirePattern(requestId, REQUEST_ID_PATTERN, "consumed request ID");
    if (new Set(value.consumed_request_ids).size !== value.consumed_request_ids.length) {
        throw new ProbeValidationError("request_replay", "Consumed request IDs contain duplicates.");
    }
    if (!Array.isArray(value.used_sequences) || value.used_sequences.length > LIMITS.usedSequences) {
        throw new ProbeValidationError("sequence_bound", "Used sequences are outside their bound.");
    }
    for (const sequence of value.used_sequences) requireUint16(sequence, "used sequence");
    if (new Set(value.used_sequences).size !== value.used_sequences.length) {
        throw new ProbeValidationError("duplicate_sequence", "Used sequences contain duplicates.");
    }
    if (!Array.isArray(value.proofs) || value.proofs.length > 5) {
        throw new ProbeValidationError("proof_bound", "Proofs are outside their bound.");
    }
    const proofs = value.proofs.map((proof) => normalizeProof(proof, {profile}));
    const proofTargets = {
        [PURPOSES.physical1]: value.physical_targets[0],
        [PURPOSES.physical2]: value.physical_targets[1],
        [PURPOSES.noop]: value.intended_target,
        [PURPOSES.challenge]: value.challenge_target,
        [PURPOSES.restore]: value.intended_target,
    };
    let lastPurpose = -1;
    for (const proof of proofs) {
        const index = PURPOSE_ORDER.indexOf(proof.purpose);
        if (
            index <= lastPurpose ||
            !value.used_sequences.includes(proof.sequence) ||
            proof.target !== proofTargets[proof.purpose]
        ) {
            throw new ProbeValidationError("proof_mismatch", "Proof history is not canonical.");
        }
        lastPurpose = index;
    }
    const expected = value.expected_proof === null ? null : normalizeProof(value.expected_proof, {expected: true, profile});
    if (expected?.sequence !== null && expected && !value.used_sequences.includes(expected.sequence)) {
        throw new ProbeValidationError("proof_mismatch", "Expected command sequence is not reserved.");
    }
    if (value.failure_code !== null) validateFailureCode(value.failure_code);

    const purposes = proofs.map((proof) => proof.purpose);
    if (TERMINAL_PHASES.has(value.phase)) {
        if (expected !== null || value.expected_proof_deadline_ms !== 0) {
            throw new ProbeValidationError("terminal_state", "Terminal state cannot expect another proof.");
        }
        if (value.phase === PHASES.remediation) {
            if (
                value.outcome !== null ||
                value.result_id !== null ||
                value.result_not_before_ms !== 0 ||
                value.remediation_after_restore ||
                value.cleanup_allowed ||
                value.failure_code === null
            ) {
                throw new ProbeValidationError("terminal_state", "Remediation state claims an invalid result.");
            }
        } else {
            if (
                value.restore_required ||
                !Object.values(OUTCOMES).includes(value.outcome) ||
                typeof value.result_id !== "string" ||
                !RESULT_ID_PATTERN.test(value.result_id) ||
                value.result_not_before_ms <= 0 ||
                value.result_not_before_ms >= value.operation_deadline_ms ||
                value.result_not_before_ms > checkedAdd(
                    value.operation_deadline_ms,
                    LIMITS.resultSettleMs,
                    "result settling bound",
                ) ||
                value.remediation_after_restore
            ) {
                throw new ProbeValidationError("terminal_state", "Result state is incomplete or unsafe.");
            }
            if (value.cleanup_allowed !== (value.phase === PHASES.quiescent)) {
                throw new ProbeValidationError("cleanup_state", "Cleanup is allowed only after acknowledgement.");
            }
            if (value.outcome === OUTCOMES.verified && value.failure_code !== null) {
                throw new ProbeValidationError("terminal_state", "Verified result cannot have a failure code.");
            }
            if (value.outcome !== OUTCOMES.verified && value.failure_code === null) {
                throw new ProbeValidationError("terminal_state", "Failed result requires a fixed failure code.");
            }
            const validTerminal = {
                [OUTCOMES.verified]: [[PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop, PURPOSES.challenge, PURPOSES.restore]],
                [OUTCOMES.failedRestored]: [
                    [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop, PURPOSES.restore],
                    [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop, PURPOSES.challenge, PURPOSES.restore],
                ],
                [OUTCOMES.failedSafe]: [[], [PURPOSES.physical1], [PURPOSES.physical1, PURPOSES.physical2]],
            }[value.outcome];
            if (!arrayVariantMatches(validTerminal, purposes)) {
                throw new ProbeValidationError("terminal_state", "Terminal proof history is incomplete.");
            }
            if (value.outcome === OUTCOMES.failedSafe && value.restore_attempts !== 0) {
                throw new ProbeValidationError("terminal_state", "Safe failure cannot contain restore attempts.");
            }
            if (value.outcome !== OUTCOMES.failedSafe && value.restore_attempts < 1) {
                throw new ProbeValidationError("terminal_state", "Restored result requires a restore attempt.");
            }
        }
    } else {
        if (!ACTIVE_PHASES.has(value.phase) || expected?.purpose !== PHASE_PURPOSE[value.phase]) {
            throw new ProbeValidationError("phase_mismatch", "Active phase and expected proof differ.");
        }
        if (!(value.expected_proof_deadline_ms > 0 && value.expected_proof_deadline_ms <= value.operation_deadline_ms)) {
            throw new ProbeValidationError("phase_mismatch", "Active proof deadline is invalid.");
        }
        const expectedTargets = {
            [PURPOSES.physical1]: value.physical_targets[0],
            [PURPOSES.physical2]: value.physical_targets[1],
            [PURPOSES.noop]: value.intended_target,
            [PURPOSES.challenge]: value.challenge_target,
            [PURPOSES.restore]: value.intended_target,
        };
        if (expected.target !== expectedTargets[expected.purpose]) {
            throw new ProbeValidationError("proof_mismatch", "Expected proof target is not canonical.");
        }
        const mustRestore = value.phase === PHASES.challenge || value.phase === PHASES.restore;
        if (value.restore_required !== mustRestore || value.outcome !== null || value.result_id !== null || value.cleanup_allowed) {
            throw new ProbeValidationError("phase_mismatch", "Active state contains incompatible terminal fields.");
        }
        if (value.result_not_before_ms !== 0) {
            throw new ProbeValidationError("phase_mismatch", "Active state cannot carry result settling time.");
        }
        if (value.phase !== PHASES.restore && value.remediation_after_restore) {
            throw new ProbeValidationError("phase_mismatch", "Remediation intent is valid only during restore.");
        }
        const validActive = {
            [PHASES.physical1]: [[]],
            [PHASES.physical2]: [[PURPOSES.physical1]],
            [PHASES.noop]: [[PURPOSES.physical1, PURPOSES.physical2]],
            [PHASES.challenge]: [[PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop]],
            [PHASES.restore]: [
                [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop],
                [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop, PURPOSES.challenge],
                [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop, PURPOSES.challenge, PURPOSES.restore],
            ],
        }[value.phase];
        if (!arrayVariantMatches(validActive, purposes)) {
            throw new ProbeValidationError("phase_mismatch", "Active proof history is incomplete.");
        }
        if (value.phase === PHASES.restore) {
            if (value.restore_attempts < 1) {
                throw new ProbeValidationError("phase_mismatch", "Restore phase requires an attempt.");
            }
            if (
                REMEDIATION_AFTER_RESTORE_CODES.has(value.failure_code) &&
                !value.remediation_after_restore
            ) {
                throw new ProbeValidationError("phase_mismatch", "Safety restore must retain remediation intent.");
            }
            if (purposes.length !== 4 && value.failure_code === null) {
                throw new ProbeValidationError("phase_mismatch", "Fallback restore requires a failure code.");
            }
        } else if (value.restore_attempts !== 0 || (value.failure_code !== null && value.phase !== PHASES.restore)) {
            throw new ProbeValidationError("phase_mismatch", "Restore metadata appears before restore phase.");
        }
    }
    requireSequenceSlots(
        value.used_sequences,
        durableSequenceReserve(value),
        "Durable record",
    );

    const normalized = {
        schema: value.schema,
        protocol_id: value.protocol_id,
        protocol_version: value.protocol_version,
        build_id: value.build_id,
        profile_id: value.profile_id,
        profile_version: value.profile_version,
        candidate_ieee: value.candidate_ieee,
        candidate_set_topic: value.candidate_set_topic,
        operation_id: value.operation_id,
        bound_boot_id: value.bound_boot_id,
        phase: value.phase,
        generation: value.generation,
        operation_deadline_ms: value.operation_deadline_ms,
        last_request_deadline_ms: value.last_request_deadline_ms,
        expected_proof_deadline_ms: value.expected_proof_deadline_ms,
        intended_target: value.intended_target,
        challenge_target: value.challenge_target,
        physical_targets: [...value.physical_targets],
        restore_required: value.restore_required,
        restore_attempts: value.restore_attempts,
        consumed_request_ids: [...value.consumed_request_ids],
        used_sequences: [...value.used_sequences],
        proofs,
        expected_proof: expected,
        outcome: value.outcome,
        failure_code: value.failure_code,
        remediation_after_restore: value.remediation_after_restore,
        result_id: value.result_id,
        result_not_before_ms: value.result_not_before_ms,
        cleanup_allowed: value.cleanup_allowed,
    };
    if (RESULT_PHASES.has(normalized.phase) && calculateResultId(normalized) !== normalized.result_id) {
        throw new ProbeValidationError("result_id", "Stored result ID is not canonical.");
    }
    canonicalJson(normalized, LIMITS.stateJsonBytes);
    return deepFreeze(normalized);
}

export function normalizeRequest(value, profile = BRT_PROFILE) {
    if (!isPlainObject(value) || !["arm", "resume", "ack"].includes(value.action)) {
        throw new ProbeValidationError("malformed_request", "Probe request action is invalid.");
    }
    const fields = value.action === "arm" ? ARM_REQUEST_FIELDS : value.action === "ack" ? ACK_REQUEST_FIELDS : COMMON_REQUEST_FIELDS;
    exactKeys(value, fields, "probe request");
    if (
        value.protocol_id !== PROTOCOL_ID ||
        value.protocol_version !== PROTOCOL_VERSION ||
        value.build_id !== BUILD_ID ||
        value.profile_id !== profile.profile_id ||
        value.profile_version !== profile.profile_version
    ) {
        throw new ProbeValidationError("incompatible_request", "Probe request identity is incompatible.");
    }
    requirePattern(value.boot_id, BOOT_ID_PATTERN, "request boot ID");
    requirePattern(value.request_id, REQUEST_ID_PATTERN, "request ID");
    requirePattern(value.operation_id, OPERATION_ID_PATTERN, "operation ID");
    requirePattern(value.nonce, NONCE_PATTERN, "request nonce");
    if (!Object.values(PHASES).includes(value.phase)) {
        throw new ProbeValidationError("phase_mismatch", "Request phase is unsupported.");
    }
    requireIntegerRange(value.generation, 0, LIMITS.generation, "request generation");
    requireSafeMilliseconds(value.request_deadline_ms, "request deadline");
    const normalized = {
        action: value.action,
        protocol_id: value.protocol_id,
        protocol_version: value.protocol_version,
        build_id: value.build_id,
        profile_id: value.profile_id,
        profile_version: value.profile_version,
        boot_id: value.boot_id,
        request_id: value.request_id,
        operation_id: value.operation_id,
        nonce: value.nonce,
        phase: value.phase,
        generation: value.generation,
        request_deadline_ms: value.request_deadline_ms,
    };
    if (value.action === "arm") {
        if (value.phase !== PHASES.quiescent) {
            throw new ProbeValidationError("phase_mismatch", "Arm request must target quiescence.");
        }
        normalized.candidate = normalizeCandidateIdentity(value.candidate, profile);
        validateTarget(value.intended_target, profile, "intended target");
        validatePhysicalTargets(value.physical_targets, value.intended_target, profile);
        requireSafeMilliseconds(value.operation_deadline_ms, "operation deadline");
        normalized.intended_target = value.intended_target;
        normalized.physical_targets = [...value.physical_targets];
        normalized.operation_deadline_ms = value.operation_deadline_ms;
    } else if (value.action === "ack") {
        if (value.phase !== PHASES.result) {
            throw new ProbeValidationError("phase_mismatch", "Ack request must target a pending result.");
        }
        requirePattern(value.result_id, RESULT_ID_PATTERN, "result ID");
        normalized.result_id = value.result_id;
    } else if (TERMINAL_PHASES.has(value.phase)) {
        throw new ProbeValidationError("phase_mismatch", "Resume request cannot target a terminal phase.");
    }
    return deepFreeze(normalized);
}

function phaseDeadline(now, operationDeadline, window) {
    requireSafeMilliseconds(now, "current time");
    requireSafeMilliseconds(operationDeadline, "operation deadline");
    const deadline = Math.min(checkedAdd(now, window, "phase deadline"), operationDeadline);
    if (deadline <= now) throw new ProbeValidationError("deadline_expired", "No time remains for the proof phase.");
    return deadline;
}

function fullPhaseDeadline(now, operationDeadline, window) {
    requireSafeMilliseconds(now, "current time");
    requireSafeMilliseconds(operationDeadline, "operation deadline");
    const deadline = checkedAdd(now, window, "full phase deadline");
    if (deadline > operationDeadline) {
        throw new ProbeValidationError(
            "deadline_expired",
            "A full proof window does not remain within operation authority.",
        );
    }
    return deadline;
}

function fullPhaseWindowFits(now, operationDeadline, window) {
    try {
        fullPhaseDeadline(now, operationDeadline, window);
        return true;
    } catch {
        return false;
    }
}

function createArmRecord(request, candidateSetTopic, now, profile = BRT_PROFILE) {
    requireSetTopic(candidateSetTopic);
    const record = {
        schema: STATE_SCHEMA,
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: profile.profile_id,
        profile_version: profile.profile_version,
        candidate_ieee: request.candidate.ieee_address,
        candidate_set_topic: candidateSetTopic,
        operation_id: request.operation_id,
        bound_boot_id: request.boot_id,
        phase: PHASES.physical1,
        generation: 1,
        operation_deadline_ms: request.operation_deadline_ms,
        last_request_deadline_ms: request.request_deadline_ms,
        expected_proof_deadline_ms: phaseDeadline(now, request.operation_deadline_ms, LIMITS.physicalProofMs),
        intended_target: request.intended_target,
        challenge_target: challengeTarget(request.intended_target, profile),
        physical_targets: [...request.physical_targets],
        restore_required: false,
        remediation_after_restore: false,
        restore_attempts: 0,
        consumed_request_ids: [request.request_id],
        used_sequences: [],
        proofs: [],
        expected_proof: expectedProof(PURPOSES.physical1, null, request.physical_targets[0], profile),
        outcome: null,
        failure_code: null,
        result_id: null,
        result_not_before_ms: 0,
        cleanup_allowed: false,
    };
    return validateRecoveryRecord(record, profile);
}

function transitionRecord(record, changes, profile = BRT_PROFILE) {
    if (record.generation >= LIMITS.generation) {
        throw new ProbeValidationError("generation_exhausted", "Probe generation capacity is exhausted.");
    }
    if (
        Object.hasOwn(changes, "operation_deadline_ms") &&
        changes.operation_deadline_ms !== record.operation_deadline_ms
    ) {
        throw new ProbeValidationError("deadline_mismatch", "Operation authority is immutable.");
    }
    return validateRecoveryRecord({...record, ...changes, generation: record.generation + 1}, profile);
}

function terminalRecord(record, outcome, now, failureCode = record.failure_code, profile = BRT_PROFILE) {
    requireSafeMilliseconds(now, "terminal time");
    const resultNotBefore = checkedAdd(now, LIMITS.resultSettleMs, "result settling time");
    if (resultNotBefore >= record.operation_deadline_ms) {
        throw new ProbeValidationError(
            "deadline_expired",
            "Result settling cannot complete within operation authority.",
        );
    }
    const draft = {
        ...record,
        phase: PHASES.result,
        generation: record.generation + 1,
        operation_deadline_ms: record.operation_deadline_ms,
        expected_proof_deadline_ms: 0,
        restore_required: false,
        remediation_after_restore: false,
        expected_proof: null,
        outcome,
        failure_code: failureCode,
        result_id: null,
        result_not_before_ms: resultNotBefore,
        cleanup_allowed: false,
    };
    draft.result_id = calculateResultId(draft);
    return validateRecoveryRecord(draft, profile);
}

function terminalAuthorityAllows(record, now) {
    try {
        return checkedAdd(now, LIMITS.resultSettleMs, "result settling time")
            < record.operation_deadline_ms;
    } catch {
        return false;
    }
}

function remediationRecord(record, failureCode, restoreRequired, profile = BRT_PROFILE) {
    validateFailureCode(failureCode);
    const changes = {
        phase: PHASES.remediation,
        expected_proof: null,
        expected_proof_deadline_ms: 0,
        restore_required: restoreRequired,
        remediation_after_restore: false,
        outcome: null,
        failure_code: failureCode,
        result_id: null,
        result_not_before_ms: 0,
        cleanup_allowed: false,
    };
    if (record.generation < LIMITS.generation) {
        return transitionRecord(record, changes, profile);
    }
    return validateRecoveryRecord({...record, ...changes}, profile);
}

function restoreRecord(
    record,
    sequence,
    failureCode,
    now,
    profile = BRT_PROFILE,
    boundBootId = record.bound_boot_id,
    remediationAfterRestore = (
        record.remediation_after_restore ||
        record.phase === PHASES.remediation ||
        REMEDIATION_AFTER_RESTORE_CODES.has(failureCode)
    ),
) {
    if (record.restore_attempts >= LIMITS.restoreAttempts) {
        throw new ProbeValidationError("restore_exhausted", "Restore attempt limit is exhausted.");
    }
    if (failureCode !== null) validateFailureCode(failureCode);
    const used = [...record.used_sequences];
    requireSequenceSlots(
        used,
        LIMITS.restoreAttempts - record.restore_attempts + LIMITS.unclaimedSafetyAttempts,
        "Claimed restore",
    );
    requireGeneratedSequence(sequence, "restore sequence");
    if (used.includes(sequence) || used.length >= LIMITS.usedSequences) {
        throw new ProbeValidationError("duplicate_sequence", "Restore sequence is not fresh.");
    }
    return transitionRecord(record, {
        phase: PHASES.restore,
        bound_boot_id: boundBootId,
        expected_proof_deadline_ms: fullPhaseDeadline(
            now,
            record.operation_deadline_ms,
            LIMITS.directProofMs,
        ),
        used_sequences: [...used, sequence],
        expected_proof: expectedProof(PURPOSES.restore, sequence, record.intended_target, profile),
        restore_required: true,
        remediation_after_restore: remediationAfterRestore,
        restore_attempts: record.restore_attempts + 1,
        outcome: null,
        failure_code: failureCode,
        result_id: null,
        result_not_before_ms: 0,
        cleanup_allowed: false,
    }, profile);
}

function reuseRestoreRecord(
    record,
    bootId,
    now,
    profile = BRT_PROFILE,
    remediationAfterRestore = record.remediation_after_restore,
) {
    if (record.phase !== PHASES.restore || record.restore_attempts < 1) {
        throw new ProbeValidationError("phase_mismatch", "No persisted restore can be reused.");
    }
    return transitionRecord(record, {
        bound_boot_id: bootId,
        expected_proof_deadline_ms: fullPhaseDeadline(
            now,
            record.operation_deadline_ms,
            LIMITS.directProofMs,
        ),
        failure_code: record.failure_code ?? "restart_recovery",
        remediation_after_restore: remediationAfterRestore,
    }, profile);
}

function nextConsumed(record, request) {
    if (request.boot_id === record.bound_boot_id) {
        if (record.consumed_request_ids.includes(request.request_id)) {
            throw new ProbeValidationError("request_replay", "Request ID was already consumed.");
        }
        if (record.consumed_request_ids.length >= LIMITS.consumedRequestIds) {
            throw new ProbeValidationError("request_id_bound", "Request capacity is exhausted for this boot.");
        }
        return [...record.consumed_request_ids, request.request_id];
    }
    return [request.request_id];
}

function validateRequestFreshness(request, now, previousDeadline = null) {
    requireSafeMilliseconds(now, "current time");
    if (request.request_deadline_ms <= now || request.request_deadline_ms > now + MAX_REQUEST_WINDOW_MS) {
        throw new ProbeValidationError("stale_request", "Request deadline is stale or too far ahead.");
    }
    if (previousDeadline !== null && request.request_deadline_ms <= previousDeadline) {
        throw new ProbeValidationError("stale_request", "Request deadline did not advance monotonically.");
    }
}

export function defaultJournalPath(moduleUrl = import.meta.url) {
    const extensionFile = fileURLToPath(moduleUrl);
    const dataParent = path.dirname(path.dirname(extensionFile));
    return path.join(dataParent, "true_family_brt_probe.state.json");
}

function journalRecoveryIdentity(record) {
    return canonicalJson({
        build_id: record.build_id,
        candidate_ieee: record.candidate_ieee,
        candidate_set_topic: record.candidate_set_topic,
        challenge_target: record.challenge_target,
        intended_target: record.intended_target,
        operation_deadline_ms: record.operation_deadline_ms,
        operation_id: record.operation_id,
        physical_targets: record.physical_targets,
        profile_id: record.profile_id,
        profile_version: record.profile_version,
        protocol_id: record.protocol_id,
        protocol_version: record.protocol_version,
        schema: record.schema,
    });
}

function journalEvidenceMayRequireRestore(record) {
    if (
        record.restore_required ||
        record.restore_attempts > 0 ||
        record.phase === PHASES.challenge ||
        record.phase === PHASES.restore
    ) return true;
    if (
        (record.phase === PHASES.result || record.phase === PHASES.quiescent) &&
        record.outcome !== OUTCOMES.failedSafe
    ) return true;
    return record.proofs.some(
        (proof) => proof.purpose === PURPOSES.challenge || proof.purpose === PURPOSES.restore,
    );
}

function synthesizeJournalRecovery(evidence, profile) {
    const highestGeneration = Math.max(...evidence.map((item) => item.record.generation));
    const source = evidence
        .filter((item) => item.record.generation === highestGeneration)
        .sort((left, right) => left.canonical.localeCompare(right.canonical))[0]
        .record;
    return remediationRecord(
        source,
        "journal_uncertain",
        evidence.some((item) => journalEvidenceMayRequireRestore(item.record)),
        profile,
    );
}

export class AtomicProbeJournal {
    constructor(filePath, {boundaryHook = undefined, profile = BRT_PROFILE} = {}) {
        if (typeof filePath !== "string" || !path.isAbsolute(filePath) || path.basename(filePath) !== "true_family_brt_probe.state.json") {
            throw new ProbeJournalError("Probe journal path must be the exact absolute state filename.");
        }
        this.filePath = filePath;
        this.parentPath = path.dirname(filePath);
        this.boundaryHook = boundaryHook;
        this.profile = profile;
    }

    async load() {
        const matches = await this.#matchingTemps();
        const temps = [];
        for (const entry of matches) {
            temps.push(await this.#readEvidence(
                path.join(this.parentPath, entry.name),
                entry,
                "Temporary probe journal",
            ));
        }
        const main = await this.#readMainEvidence();
        if (!main && temps.length === 0) return null;
        if (main && temps.length === 0) return main.record;

        const evidence = main ? [main, ...temps] : temps;
        const identities = new Set(evidence.map((item) => journalRecoveryIdentity(item.record)));
        if (identities.size !== 1) {
            throw new ProbeJournalError(
                "Probe journal recovery evidence has conflicting immutable identity.",
                {manualRemediation: true},
            );
        }

        const recoveryRecord = synthesizeJournalRecovery(evidence, this.profile);
        let durableRecovery;
        try {
            durableRecovery = await this.write(recoveryRecord);
        } catch (error) {
            throw new ProbeJournalError(
                "Probe journal remediation recovery could not be persisted.",
                {cause: error, recoveryRecord},
            );
        }
        try {
            await this.#deleteTemps(temps);
        } catch (error) {
            throw new ProbeJournalError(
                "Probe journal remediation is durable but evidence cleanup failed.",
                {cause: error, recoveryRecord: durableRecovery},
            );
        }
        return durableRecovery;
    }

    async write(record) {
        const normalized = validateRecoveryRecord(record, this.profile);
        const text = canonicalJson(normalized, LIMITS.stateJsonBytes);
        const temporaryPath = path.join(
            this.parentPath,
            `.true_family_brt_probe.${process.pid}.${randomBytes(12).toString("hex")}.tmp`,
        );
        let handle;
        let directory;
        let renamed = false;
        let temporaryCreated = false;
        try {
            handle = await open(temporaryPath, "wx", 0o600);
            temporaryCreated = true;
            await this.#boundary(JOURNAL_BOUNDARIES.tempOpen);
            await handle.writeFile(text, {encoding: "utf8"});
            await this.#boundary(JOURNAL_BOUNDARIES.tempWrite);
            await handle.sync();
            await this.#boundary(JOURNAL_BOUNDARIES.tempFsync);
            await handle.close();
            handle = undefined;
            await this.#boundary(JOURNAL_BOUNDARIES.tempClose);
            await rename(temporaryPath, this.filePath);
            renamed = true;
            await this.#boundary(JOURNAL_BOUNDARIES.rename);
            try {
                await chmod(this.filePath, 0o600);
            } catch (error) {
                if (!["ENOSYS", "ENOTSUP", "EOPNOTSUPP", "EPERM"].includes(error?.code)) throw error;
            }
            await this.#boundary(JOURNAL_BOUNDARIES.chmod);
            directory = await open(this.parentPath, "r");
            await this.#boundary(JOURNAL_BOUNDARIES.directoryOpen);
            await directory.sync();
            await this.#boundary(JOURNAL_BOUNDARIES.directoryFsync);
            await directory.close();
            directory = undefined;
            await this.#boundary(JOURNAL_BOUNDARIES.directoryClose);
            await this.#boundary(JOURNAL_BOUNDARIES.postRename);
            return normalized;
        } catch (error) {
            if (handle) await handle.close().catch(() => undefined);
            if (directory) await directory.close().catch(() => undefined);
            if (!renamed && temporaryCreated) await unlink(temporaryPath).catch(() => undefined);
            if (renamed) {
                throw new ProbeJournalUncertainError("Probe journal may have committed after rename.", {cause: error});
            }
            throw new ProbeJournalError("Probe journal write failed before rename.", {cause: error});
        }
    }

    async #matchingTemps() {
        let entries;
        try {
            entries = await readdir(this.parentPath, {withFileTypes: true});
        } catch (error) {
            throw new ProbeJournalError("Probe journal directory is unreadable.", {cause: error});
        }
        const matches = entries
            .filter((entry) => TEMP_FILE_PATTERN.test(entry.name))
            .sort((left, right) => left.name.localeCompare(right.name));
        if (matches.length > LIMITS.orphanTemps) {
            throw new ProbeJournalError("Too many orphan probe state files exist.");
        }
        return matches;
    }

    async #readMainEvidence() {
        try {
            return await this.#readEvidence(this.filePath, null, "Probe journal");
        } catch (error) {
            if (error?.cause?.code === "ENOENT") return null;
            throw error;
        }
    }

    async #readEvidence(filePath, entry, label) {
        let metadata;
        try {
            metadata = await lstat(filePath);
        } catch (error) {
            throw new ProbeJournalError(`${label} metadata is unreadable.`, {cause: error});
        }
        if (
            (entry && !entry.isFile()) ||
            metadata.isSymbolicLink() ||
            !metadata.isFile() ||
            metadata.size < 2 ||
            metadata.size > LIMITS.stateJsonBytes
        ) {
            throw new ProbeJournalError(`${label} is not an exact bounded regular file.`);
        }
        try {
            const text = await readFile(filePath, {encoding: "utf8"});
            const record = validateRecoveryRecord(
                parseCanonicalObject(text, LIMITS.stateJsonBytes),
                this.profile,
            );
            return Object.freeze({
                canonical: canonicalJson(record, LIMITS.stateJsonBytes),
                filePath,
                record,
            });
        } catch (error) {
            throw new ProbeJournalError(`${label} is corrupt or incompatible.`, {cause: error});
        }
    }

    async #deleteTemps(evidence) {
        if (evidence.length === 0) return;
        const directory = await open(this.parentPath, "r");
        try {
            await this.#boundary(JOURNAL_BOUNDARIES.cleanupPreUnlinkDirectoryFsync);
            await directory.sync();
            for (const item of evidence) {
                await this.#boundary(JOURNAL_BOUNDARIES.cleanupUnlink);
                await unlink(item.filePath);
            }
            await this.#boundary(JOURNAL_BOUNDARIES.cleanupPostUnlinkDirectoryFsync);
            await directory.sync();
        } finally {
            await directory.close();
        }
    }

    async #boundary(name) {
        if (this.boundaryHook) await this.boundaryHook(name);
    }
}

export class BoundedSerialQueue {
    constructor(limit, onOverflow) {
        requirePositiveInteger(limit, "queue limit");
        this.limit = limit;
        this.onOverflow = onOverflow;
        this.pending = 0;
        this.closed = false;
        this.tail = Promise.resolve();
    }

    enqueue(operation, {force = false} = {}) {
        if (this.closed && !force) return Promise.resolve(undefined);
        if (!force && this.pending >= this.limit) {
            this.onOverflow?.();
            return Promise.resolve(undefined);
        }
        this.pending += 1;
        const result = this.tail.then(operation);
        const settled = result.finally(() => {
            this.pending -= 1;
        });
        this.tail = settled.catch(() => undefined);
        return settled;
    }

    close() {
        this.closed = true;
    }

    async drain() {
        while (true) {
            const tail = this.tail;
            await tail;
            if (tail === this.tail) return;
        }
    }
}

export function systemScheduler() {
    return {
        schedule(delay, callback) {
            return setTimeout(callback, delay);
        },
        cancel(handle) {
            clearTimeout(handle);
        },
    };
}

export async function defaultDispatchRace(operation, timeoutMs, stopPromise) {
    let timer;
    const observed = Promise.resolve(operation).then(
        (value) => ({status: "fulfilled", value}),
        (error) => ({status: "rejected", error}),
    );
    const timeout = new Promise((resolve) => {
        timer = setTimeout(() => resolve({status: "timeout"}), timeoutMs);
    });
    const stopped = stopPromise.then(() => ({status: "stopped"}));
    const result = await Promise.race([observed, timeout, stopped]);
    clearTimeout(timer);
    return result;
}

export async function defaultTimeoutRace(operation, timeoutMs) {
    let timer;
    const observed = Promise.resolve(operation).then(
        (value) => ({status: "fulfilled", value}),
        (error) => ({status: "rejected", error}),
    );
    const timeout = new Promise((resolve) => {
        timer = setTimeout(() => resolve({status: "timeout"}), timeoutMs);
    });
    const result = await Promise.race([observed, timeout]);
    clearTimeout(timer);
    return result;
}

export class PhysicalProbeCore {
    constructor({
        journal,
        bootId,
        resolveCandidate,
        dispatchCommand,
        publish,
        baseTopic,
        now = Date.now,
        nextSequence = (used) => randomDistinctSequence(used),
        scheduler = systemScheduler(),
        dispatchRace = defaultDispatchRace,
        timeoutRace = defaultTimeoutRace,
        profile = BRT_PROFILE,
        pendingLimit = LIMITS.pendingWork,
    }) {
        if (!journal || typeof journal.load !== "function" || typeof journal.write !== "function") {
            throw new TypeError("Physical probe requires a journal adapter.");
        }
        requirePattern(bootId, BOOT_ID_PATTERN, "boot ID");
        requireBaseTopic(baseTopic);
        if (
            typeof resolveCandidate !== "function" ||
            typeof dispatchCommand !== "function" ||
            typeof publish !== "function" ||
            typeof scheduler?.schedule !== "function" ||
            typeof scheduler?.cancel !== "function" ||
            typeof dispatchRace !== "function" ||
            typeof timeoutRace !== "function"
        ) {
            throw new TypeError("Physical probe adapters are incomplete.");
        }
        this.journal = journal;
        this.bootId = bootId;
        this.resolveCandidate = resolveCandidate;
        this.dispatchCommand = dispatchCommand;
        this.publish = publish;
        this.baseTopic = baseTopic;
        this.now = now;
        this.nextSequence = nextSequence;
        this.scheduler = scheduler;
        this.dispatchRace = dispatchRace;
        this.timeoutRace = timeoutRace;
        this.profile = profile;
        this.record = null;
        this.remediationRequired = false;
        this.safetyOnly = false;
        this.ready = false;
        this.startRequested = false;
        this.stopping = false;
        this.stopped = false;
        this.consumedNonces = new Set();
        this.timerHandle = null;
        this.timerToken = 0;
        this.pendingPublications = new Map();
        this.publicationRetryHandles = new Map();
        this.inFlightDispatches = new Set();
        this.authorizationEpoch = 0;
        this.overflowLatched = false;
        this.schedulerFailureLatched = false;
        this.safetyUnclaimedPending = false;
        this.journalBlocked = false;
        this.unclaimedSafetyRestores = new Map();
        this.stopSafetyIssued = false;
        this.stopPromise = new Promise((resolve) => {
            this.resolveStop = resolve;
        });
        this.queue = new BoundedSerialQueue(pendingLimit, () => this.latchQueueOverflow());
    }

    get candidateSetTopic() {
        return this.record?.candidate_set_topic ?? null;
    }

    start() {
        if (this.startRequested) return this.startPromise;
        this.startRequested = true;
        this.startPromise = this.queue.enqueue(() => this.#startImpl(), {force: true});
        return this.startPromise;
    }

    handleRequest(request) {
        return this.queue.enqueue(() => this.#handleRequestImpl(request));
    }

    handleFrame(event) {
        return this.queue.enqueue(() => this.#runFailClosedHandler(
            () => this.#handleFrameImpl(event),
            "frame",
        ));
    }

    handleCandidateSet(relativeTopic) {
        return this.queue.enqueue(() => this.#runFailClosedHandler(
            () => this.#handleCandidateSetImpl(relativeTopic),
            "candidate-write",
        ));
    }

    handleControlDrift() {
        return this.queue.enqueue(() => this.#runFailClosedHandler(
            () => this.#handleControlDriftImpl(),
            "control-drift",
        ));
    }

    requestStop() {
        if (this.stopping) return;
        this.stopping = true;
        this.#latchSafetyOnly();
        this.#cancelTimer();
        this.resolveStop();
        this.queue.close();
    }

    async stop() {
        if (this.stopRunPromise) return this.stopRunPromise;
        this.requestStop();
        this.stopRunPromise = this.queue.enqueue(() => this.#stopImpl(), {force: true});
        await this.stopRunPromise;
        await this.queue.drain();
        this.stopped = true;
    }

    latchQueueOverflow() {
        if (this.stopping || this.overflowLatched) return;
        this.overflowLatched = true;
        this.remediationRequired = true;
        this.#latchSafetyOnly();
        this.#supersedeResultPublication();
        this.#cancelTimer();
        this.#enqueueSafetyTask(() => this.#handleQueueOverflow());
    }

    async #startImpl() {
        if (this.stopping) return;
        const loaded = await this.#boundedJournalLoad();
        if (loaded.status !== "fulfilled") {
            const recoveryRecord = loaded.status === "rejected"
                ? loaded.error?.recoveryRecord
                : null;
            if (recoveryRecord) {
                try {
                    const normalized = validateRecoveryRecord(recoveryRecord, this.profile);
                    if (
                        normalized.phase !== PHASES.remediation ||
                        normalized.failure_code !== "journal_uncertain" ||
                        normalized.cleanup_allowed
                    ) {
                        throw new ProbeValidationError(
                            "remediation_state",
                            "Journal recovery evidence is not safe remediation.",
                        );
                    }
                    this.journalBlocked = true;
                    this.#installInMemoryRemediation(normalized);
                    if (normalized.restore_required) {
                        await this.#dispatchUnclaimedSafetyRestore(normalized, {
                            key: `journal-load-recovery-${normalized.generation}`,
                        });
                    }
                } catch {
                    this.remediationRequired = true;
                    this.record = null;
                    this.#latchSafetyOnly();
                }
            } else {
                this.remediationRequired = true;
                this.record = null;
                this.#latchSafetyOnly();
                if (loaded.status === "timeout") this.journalBlocked = true;
            }
        } else {
            try {
                this.record = loaded.value === null ? null : validateRecoveryRecord(loaded.value, this.profile);
                this.#invalidateDispatchAuthorizations();
            } catch {
                this.remediationRequired = true;
                this.record = null;
                this.#latchSafetyOnly();
            }
        }
        if (this.stopping) return;
        if (!this.overflowLatched) {
            try {
                if (this.remediationRequired) {
                    this.#latchSafetyOnly();
                } else if (
                    (this.record?.phase === PHASES.result || this.record?.phase === PHASES.quiescent) &&
                    this.record.bound_boot_id !== this.bootId
                ) {
                    this.#latchSafetyOnly();
                    this.#supersedeResultPublication();
                    await this.#enterRemediation("restart_recovery", true, {
                        unclaimedKey: `startup-terminal-${this.record.generation}`,
                    });
                } else if (this.record?.phase === PHASES.remediation) {
                    this.#latchSafetyOnly();
                    if (this.record.restore_required) {
                        this.remediationRequired = false;
                        await this.#recoverRestoreRequired("restart_recovery", {
                            source: this.record,
                            remediationAfterRestore: true,
                            unclaimedKey: "startup-remediation",
                        });
                    } else {
                        this.remediationRequired = true;
                    }
                } else if (this.record?.phase === PHASES.challenge) {
                    this.#latchSafetyOnly();
                    await this.#recoverRestoreRequired("restart_recovery", {
                        source: this.record,
                        unclaimedKey: "startup-challenge",
                    });
                } else if (this.record?.phase === PHASES.restore) {
                    this.#latchSafetyOnly();
                    await this.#recoverRestoreRequired("restart_recovery", {
                        source: this.record,
                        reuseExisting: true,
                        unclaimedKey: "startup-restore",
                    });
                } else if (
                    this.record &&
                    ACTIVE_PHASES.has(this.record.phase) &&
                    this.record.expected_proof_deadline_ms <= this.now()
                ) {
                    await this.#handleProofTimeout();
                }
            } catch {
                await this.#recoverAfterSafetyPersistenceFailure("restart_recovery", "startup-failure");
            }
        }
        if (this.stopping) return;
        this.ready = !this.remediationRequired && !this.safetyOnly;
        this.#scheduleForRecord();
        if (this.ready) this.#firePublication(TOPICS.ready, readyMessage(this.bootId, this.profile));
        this.#fireStatus();
        if (this.record?.phase === PHASES.result && !this.remediationRequired) this.#fireResult();
    }

    async #handleRequestImpl(rawRequest) {
        let request;
        let durable = false;
        let uncertain = false;
        try {
            request = normalizeRequest(rawRequest, this.profile);
            this.#requireOperational();
            if (request.boot_id !== this.bootId) {
                throw new ProbeValidationError("boot_mismatch", "Request is not bound to the current boot.");
            }
            if (this.consumedNonces.has(request.nonce)) {
                throw new ProbeValidationError("nonce_replay", "Request nonce was already consumed.");
            }
            if (this.consumedNonces.size >= LIMITS.consumedRequestIds) {
                throw new ProbeValidationError("nonce_bound", "Nonce capacity is exhausted for this boot.");
            }
            const now = this.now();
            validateRequestFreshness(request, now, this.record?.last_request_deadline_ms ?? null);
            let result;
            if (request.action === "arm") result = await this.#arm(request, now);
            else if (request.action === "resume") result = await this.#resume(request, now);
            else result = await this.#acknowledge(request);
            durable = result.durable;
            uncertain = result.uncertain;
            if (durable) this.consumedNonces.add(request.nonce);
            const accepted = result.accepted !== false;
            const response = responseMessage({
                bootId: this.bootId,
                requestId: request.request_id,
                operationId: request.operation_id,
                action: request.action,
                accepted,
                phase: this.remediationRequired ? PHASES.remediation : this.record?.phase ?? "idle",
                generation: this.record?.generation ?? 0,
                errorCode: result.errorCode ?? (uncertain ? "journal_uncertain" : null),
            });
            this.#firePublication(request.action === "ack" ? TOPICS.ackResponse : TOPICS.response, response);
            this.#fireStatus();
            return response;
        } catch (error) {
            if (durable || error instanceof ProbeJournalUncertainError) {
                const response = responseMessage({
                    bootId: this.bootId,
                    requestId: safePattern(rawRequest?.request_id, REQUEST_ID_PATTERN),
                    operationId: safePattern(rawRequest?.operation_id, OPERATION_ID_PATTERN),
                    action: ["arm", "resume", "ack"].includes(rawRequest?.action) ? rawRequest.action : "invalid",
                    accepted: true,
                    phase: PHASES.remediation,
                    generation: this.record?.generation ?? 0,
                    errorCode: "journal_uncertain",
                });
                this.#firePublication(rawRequest?.action === "ack" ? TOPICS.ackResponse : TOPICS.response, response);
                return response;
            }
            const response = responseMessage({
                bootId: this.bootId,
                requestId: safePattern(rawRequest?.request_id, REQUEST_ID_PATTERN),
                operationId: safePattern(rawRequest?.operation_id, OPERATION_ID_PATTERN),
                action: ["arm", "resume", "ack"].includes(rawRequest?.action) ? rawRequest.action : "invalid",
                accepted: false,
                phase: this.remediationRequired ? PHASES.remediation : this.record?.phase ?? "idle",
                generation: this.record?.generation ?? 0,
                errorCode: safeErrorCode(error),
            });
            this.#firePublication(rawRequest?.action === "ack" ? TOPICS.ackResponse : TOPICS.response, response);
            return response;
        }
    }

    async #arm(request, now) {
        if (this.record && this.record.phase !== PHASES.quiescent) {
            throw new ProbeValidationError("operation_active", "A probe operation is already active.");
        }
        const expectedGeneration = this.record?.generation ?? 0;
        if (request.phase !== PHASES.quiescent || request.generation !== expectedGeneration) {
            throw new ProbeValidationError("generation_mismatch", "Arm request does not match current quiescence.");
        }
        if (this.record?.operation_id === request.operation_id) {
            throw new ProbeValidationError("operation_replay", "Operation ID was already used by the current record.");
        }
        if (
            request.operation_deadline_ms <= request.request_deadline_ms ||
            request.operation_deadline_ms > now + MAX_OPERATION_WINDOW_MS
        ) {
            throw new ProbeValidationError("stale_request", "Operation deadline is invalid.");
        }
        const recordBeforeResolution = this.record;
        const resolved = await this.#resolveCandidateBounded(request.candidate, {
            deadlineMs: Math.min(request.request_deadline_ms, request.operation_deadline_ms),
        });
        const currentNow = this.#revalidateRequestAfterResolution(
            request,
            recordBeforeResolution,
        );
        const next = createArmRecord(request, resolved.set_topic, currentNow, this.profile);
        return this.#commit(next);
    }

    async #resume(request, now) {
        const record = this.#matchingRecordRequest(request);
        if (record.restore_required || TERMINAL_PHASES.has(record.phase) || now >= record.operation_deadline_ms) {
            throw new ProbeValidationError("deadline_expired", "This phase cannot be resumed.");
        }
        const resolved = await this.#resolveCandidateBounded(record.candidate_ieee, {
            deadlineMs: Math.min(request.request_deadline_ms, record.operation_deadline_ms),
        });
        const currentNow = this.#revalidateRequestAfterResolution(request, record);
        if (resolved?.set_topic !== record.candidate_set_topic) {
            throw new ProbeValidationError("identity_mismatch", "Candidate set topic changed during the operation.");
        }
        let expected = record.expected_proof;
        let usedSequences = record.used_sequences;
        let dispatch = false;
        if (record.phase === PHASES.noop) {
            const sequence = this.#nextSequence(
                record.used_sequences,
                POST_NOOP_SEQUENCE_RESERVE,
                "No-op resume",
            );
            usedSequences = [...record.used_sequences, sequence];
            expected = expectedProof(PURPOSES.noop, sequence, record.intended_target, this.profile);
            dispatch = true;
        }
        const window = record.phase === PHASES.noop ? LIMITS.directProofMs : LIMITS.physicalProofMs;
        const next = transitionRecord(record, {
            bound_boot_id: this.bootId,
            consumed_request_ids: nextConsumed(record, request),
            last_request_deadline_ms: request.request_deadline_ms,
            expected_proof_deadline_ms: phaseDeadline(currentNow, record.operation_deadline_ms, window),
            used_sequences: usedSequences,
            expected_proof: expected,
        }, this.profile);
        const commit = await this.#commit(next);
        if (commit.durable && !commit.uncertain && dispatch && !this.stopping) {
            try {
                await this.#dispatchExpected();
            } catch {
                await this.#handleDurableDispatchFailure();
            }
        }
        return commit;
    }

    async #handleDurableDispatchFailure() {
        const record = this.record;
        if (!record || this.remediationRequired || TERMINAL_PHASES.has(record.phase)) return;
        try {
            if (
                record.phase === PHASES.physical1 ||
                record.phase === PHASES.physical2 ||
                record.phase === PHASES.noop
            ) {
                await this.#failSafe("dispatch_failed");
                return;
            }
            await this.#enterRemediation("dispatch_failed", record.restore_required);
        } catch {
            await this.#enterRemediation("dispatch_failed", Boolean(this.record?.restore_required));
        }
    }

    async #acknowledge(request) {
        const record = this.#matchingRecordRequest(request);
        if (record.bound_boot_id !== this.bootId || request.boot_id !== this.bootId) {
            throw new ProbeValidationError(
                "boot_mismatch",
                "Result acknowledgement must match the record and current boot.",
            );
        }
        if (record.phase !== PHASES.result || request.result_id !== record.result_id) {
            throw new ProbeValidationError("result_mismatch", "Acknowledgement does not match the pending result.");
        }
        const expiryKey = `result-deadline-${record.generation}`;
        const now = this.now();
        if (now >= record.operation_deadline_ms) {
            await this.#invalidateResultForDrift("deadline_expired", expiryKey);
            throw new ProbeValidationError("deadline_expired", "Result operation deadline has expired.");
        }
        if (now < record.result_not_before_ms) {
            throw new ProbeValidationError("result_settling", "Result acknowledgement is still settling.");
        }
        let resolved;
        try {
            resolved = await this.#resolveCandidateBounded(record.candidate_ieee, {
                deadlineMs: Math.min(request.request_deadline_ms, record.operation_deadline_ms),
            });
        } catch (error) {
            if (this.now() >= record.operation_deadline_ms) {
                await this.#invalidateResultForDrift("deadline_expired", expiryKey);
                throw new ProbeValidationError("deadline_expired", "Result operation deadline expired during resolution.");
            }
            await this.#invalidateResultForDrift("identity_mismatch", "ack-identity");
            throw error;
        }
        try {
            this.#revalidateRequestAfterResolution(request, record);
        } catch (error) {
            if (this.now() >= record.operation_deadline_ms) {
                await this.#invalidateResultForDrift("deadline_expired", expiryKey);
                throw new ProbeValidationError("deadline_expired", "Result operation deadline expired during resolution.");
            }
            throw error;
        }
        if (resolved?.set_topic !== record.candidate_set_topic) {
            await this.#invalidateResultForDrift("identity_mismatch", "ack-topic");
            throw new ProbeValidationError("identity_mismatch", "Candidate identity changed before acknowledgement.");
        }
        const next = transitionRecord(record, {
            phase: PHASES.quiescent,
            bound_boot_id: this.bootId,
            consumed_request_ids: nextConsumed(record, request),
            last_request_deadline_ms: request.request_deadline_ms,
            expected_proof_deadline_ms: 0,
            cleanup_allowed: true,
        }, this.profile);
        const commit = await this.#commit(next, {defendIntended: true});
        if (!commit.durable || commit.uncertain) return commit;
        const committedAt = this.now();
        if (this.overflowLatched) {
            await this.#enterRemediation("queue_overflow", true, {
                unclaimedKey: "queue-overflow",
            });
            return {...commit, accepted: false, errorCode: "queue_overflow"};
        }
        if (
            committedAt >= record.operation_deadline_ms ||
            committedAt >= request.request_deadline_ms ||
            this.record?.operation_id !== next.operation_id ||
            this.record?.generation !== next.generation ||
            this.record?.bound_boot_id !== this.bootId
        ) {
            await this.#enterRemediation("deadline_expired", true, {
                unclaimedKey: `ack-post-commit-${next.generation}`,
            });
            return {...commit, errorCode: "deadline_expired"};
        }
        this.#supersedeResultPublication();
        return commit;
    }

    #matchingRecordRequest(request) {
        if (
            !this.record ||
            request.operation_id !== this.record.operation_id ||
            request.phase !== this.record.phase ||
            request.generation !== this.record.generation
        ) {
            throw new ProbeValidationError("generation_mismatch", "Request does not match the durable record.");
        }
        if (request.request_deadline_ms <= this.record.last_request_deadline_ms) {
            throw new ProbeValidationError("stale_request", "Request deadline did not advance.");
        }
        nextConsumed(this.record, request);
        return this.record;
    }

    #revalidateRequestAfterResolution(request, expectedRecord) {
        this.#requireOperational();
        if (request.boot_id !== this.bootId) {
            throw new ProbeValidationError("boot_mismatch", "Request is not bound to the current boot.");
        }
        if (this.consumedNonces.has(request.nonce)) {
            throw new ProbeValidationError("nonce_replay", "Request nonce was already consumed.");
        }
        const now = this.now();
        validateRequestFreshness(
            request,
            now,
            expectedRecord?.last_request_deadline_ms ?? null,
        );
        const current = this.record;
        if (expectedRecord === null) {
            if (current !== null || request.generation !== 0 || request.phase !== PHASES.quiescent) {
                throw new ProbeValidationError("generation_mismatch", "Request authority changed during resolution.");
            }
        } else if (
            !current ||
            current.operation_id !== expectedRecord.operation_id ||
            current.generation !== expectedRecord.generation ||
            current.phase !== expectedRecord.phase
        ) {
            throw new ProbeValidationError("generation_mismatch", "Request authority changed during resolution.");
        }
        const operationDeadline = request.action === "arm"
            ? request.operation_deadline_ms
            : expectedRecord.operation_deadline_ms;
        if (now >= operationDeadline) {
            throw new ProbeValidationError("deadline_expired", "Operation deadline expired during resolution.");
        }
        return now;
    }

    async #resolveCandidateBounded(candidateOrIeee, {deadlineMs = null} = {}) {
        let timeoutMs = LIMITS.candidateResolutionMs;
        if (deadlineMs !== null) {
            requireSafeMilliseconds(deadlineMs, "candidate-resolution deadline");
            timeoutMs = Math.min(timeoutMs, deadlineMs - this.now());
            if (timeoutMs <= 0) {
                throw new ProbeValidationError("deadline_expired", "Candidate-resolution authority has expired.");
            }
        }
        let outcome;
        try {
            outcome = await this.timeoutRace(
                Promise.resolve().then(() => this.resolveCandidate(candidateOrIeee)),
                timeoutMs,
            );
        } catch (error) {
            outcome = {status: "rejected", error};
        }
        if (outcome?.status === "fulfilled") return outcome.value;
        if (outcome?.status === "timeout") {
            throw new ProbeValidationError("candidate_timeout", "Candidate resolution timed out.");
        }
        if (outcome?.status === "rejected" && outcome.error) throw outcome.error;
        throw new ProbeValidationError("candidate_resolution", "Candidate resolution failed.");
    }

    async #runFailClosedHandler(operation, label) {
        const source = this.record;
        try {
            return await operation();
        } catch {
            const current = this.record ?? source;
            const restoreSource = this.#recordNeedsSafetyRestore(current) ? current : source;
            const restoreRequired = this.#recordNeedsSafetyRestore(restoreSource);
            try {
                await this.#enterRemediation("dispatch_failed", restoreRequired, {
                    restoreSource,
                    unclaimedKey: `${label}-failure-${current?.generation ?? 0}`,
                });
            } catch {
                this.remediationRequired = true;
                this.#latchSafetyOnly();
                this.#cancelTimer();
                this.#supersedeResultPublication();
            }
            return null;
        }
    }

    #recordNeedsSafetyRestore(record) {
        return Boolean(record && (record.restore_required || RESULT_PHASES.has(record.phase)));
    }

    async #handleFrameImpl(event) {
        if (!this.startRequested || this.stopping || this.remediationRequired || !this.record) return null;
        if (this.safetyOnly && this.record.phase !== PHASES.restore) return null;
        if (this.record.bound_boot_id !== this.bootId && ACTIVE_PHASES.has(this.record.phase)) return null;
        let frame;
        try {
            frame = parseProbeFrame(event, this.record.candidate_ieee, this.profile);
        } catch (error) {
            if (
                error instanceof ProbeValidationError &&
                this.record.phase === PHASES.result
            ) {
                await this.#invalidateResultForDrift(
                    "competing_frame",
                    `result-malformed-frame-${this.record.generation}`,
                );
            } else if (error instanceof ProbeValidationError && error.code === "competing_frame") {
                await this.#handleCompeting("competing_frame");
            } else if (ACTIVE_PHASES.has(this.record.phase)) {
                await this.#handleCompeting("competing_frame");
            }
            return null;
        }
        if (frame === null) return null;

        if (this.record.phase === PHASES.result) {
            const finalProof = this.record.proofs.at(-1);
            const isSettlingRestoreDuplicate = (
                this.now() < this.record.result_not_before_ms &&
                finalProof?.purpose === PURPOSES.restore &&
                finalProof.frame_kind === frame.frame_kind &&
                finalProof.sequence === frame.sequence &&
                finalProof.target === frame.target
            );
            if (isSettlingRestoreDuplicate) {
                return deepFreeze({classification: "duplicate", ...frame});
            }
            await this.#invalidateResultForDrift("competing_frame", "result-frame-drift");
            return null;
        }

        const duplicate = this.record.proofs.find(
            (proof) => proof.frame_kind === frame.frame_kind && proof.sequence === frame.sequence && proof.target === frame.target,
        );
        if (duplicate) return deepFreeze({classification: "duplicate", ...frame});
        const sequenceConflict = this.record.proofs.some((proof) => proof.sequence === frame.sequence);
        if (sequenceConflict) {
            await this.#handleCompeting("competing_frame");
            return null;
        }
        if (!ACTIVE_PHASES.has(this.record.phase) || this.remediationRequired) return null;
        if (this.now() >= this.record.expected_proof_deadline_ms) {
            await this.#handleProofTimeout();
            return null;
        }
        let proof;
        try {
            proof = observedProof(this.record.expected_proof, frame);
            if (
                (proof.purpose === PURPOSES.physical1 || proof.purpose === PURPOSES.physical2) &&
                this.record.used_sequences.includes(proof.sequence)
            ) {
                throw new ProbeValidationError("competing_frame", "Physical proof sequence is not fresh.");
            }
        } catch {
            await this.#handleCompeting("proof_mismatch");
            return null;
        }
        if (proof.purpose === PURPOSES.physical1 || proof.purpose === PURPOSES.physical2) {
            const proofRecord = this.record;
            let resolved;
            try {
                resolved = await this.#resolveCandidateBounded(proofRecord.candidate_ieee, {
                    deadlineMs: Math.min(
                        proofRecord.expected_proof_deadline_ms,
                        proofRecord.operation_deadline_ms,
                    ),
                });
            } catch {
                if (this.now() >= proofRecord.expected_proof_deadline_ms) await this.#handleProofTimeout();
                else await this.#handleCompeting("identity_mismatch");
                return null;
            }
            if (
                this.remediationRequired ||
                this.overflowLatched ||
                this.record?.operation_id !== proofRecord.operation_id ||
                this.record?.generation !== proofRecord.generation ||
                this.record?.phase !== proofRecord.phase
            ) return null;
            if (this.now() >= proofRecord.expected_proof_deadline_ms) {
                await this.#handleProofTimeout();
                return null;
            }
            if (
                resolved?.candidate?.ieee_address !== proofRecord.candidate_ieee ||
                resolved?.set_topic !== proofRecord.candidate_set_topic
            ) {
                await this.#handleCompeting("identity_mismatch");
                return null;
            }
        }
        await this.#acceptProof(proof);
        return proof;
    }

    async #acceptProof(proof) {
        const record = this.record;
        let used = record.used_sequences;
        if (proof.purpose === PURPOSES.physical1 || proof.purpose === PURPOSES.physical2) used = [...used, proof.sequence];
        else if (!used.includes(proof.sequence)) throw new ProbeValidationError("proof_mismatch", "Response sequence was never dispatched.");
        const proofs = [...record.proofs, proof];
        const now = this.now();
        if (record.phase === PHASES.physical1) {
            const next = transitionRecord(record, {
                phase: PHASES.physical2,
                used_sequences: used,
                proofs,
                expected_proof: expectedProof(PURPOSES.physical2, null, record.physical_targets[1], this.profile),
                expected_proof_deadline_ms: phaseDeadline(now, record.operation_deadline_ms, LIMITS.physicalProofMs),
            }, this.profile);
            await this.#commit(next);
            this.#fireStatus();
            return;
        }
        if (record.phase === PHASES.physical2) {
            const sequence = this.#nextSequence(
                used,
                POST_NOOP_SEQUENCE_RESERVE,
                "Initial no-op",
            );
            const next = transitionRecord(record, {
                phase: PHASES.noop,
                used_sequences: [...used, sequence],
                proofs,
                expected_proof: expectedProof(PURPOSES.noop, sequence, record.intended_target, this.profile),
                expected_proof_deadline_ms: phaseDeadline(now, record.operation_deadline_ms, LIMITS.directProofMs),
            }, this.profile);
            const commit = await this.#commit(next);
            if (commit.durable && !commit.uncertain && !this.stopping) await this.#dispatchExpected();
            return;
        }
        if (record.phase === PHASES.noop) {
            const sequence = this.#nextSequence(
                used,
                POST_CHALLENGE_SEQUENCE_RESERVE,
                "Challenge",
            );
            const next = transitionRecord(record, {
                phase: PHASES.challenge,
                used_sequences: [...used, sequence],
                proofs,
                expected_proof: expectedProof(PURPOSES.challenge, sequence, record.challenge_target, this.profile),
                expected_proof_deadline_ms: phaseDeadline(now, record.operation_deadline_ms, LIMITS.directProofMs),
                restore_required: true,
            }, this.profile);
            const commit = await this.#commit(next);
            if (commit.durable && !commit.uncertain && !this.stopping) await this.#dispatchExpected();
            return;
        }
        if (record.phase === PHASES.challenge) {
            const withProof = {...record, proofs};
            await this.#startRestore(record.failure_code, withProof);
            return;
        }
        if (record.phase === PHASES.restore) {
            if (record.remediation_after_restore) {
                await this.#enterRemediation(
                    record.failure_code ?? "restart_recovery",
                    false,
                );
                return;
            }
            if (!terminalAuthorityAllows(record, now)) {
                await this.#enterRemediation("deadline_expired", false);
                return;
            }
            const outcome = record.failure_code ? OUTCOMES.failedRestored : OUTCOMES.verified;
            const next = terminalRecord(
                {...record, used_sequences: used, proofs},
                outcome,
                now,
                record.failure_code,
                this.profile,
            );
            const commit = await this.#commit(next, {defendIntended: true});
            if (
                commit.durable &&
                !commit.uncertain &&
                !this.remediationRequired &&
                !this.overflowLatched
            ) {
                if (!terminalAuthorityAllows(this.record, this.now())) {
                    await this.#enterRemediation("deadline_expired", false);
                    return;
                }
                this.safetyOnly = false;
                this.ready = true;
                this.#scheduleForRecord();
                this.#fireResult();
                this.#fireStatus();
                this.#firePublication(TOPICS.ready, readyMessage(this.bootId, this.profile));
            }
        }
    }

    async #handleCandidateSetImpl(relativeTopic) {
        if (
            !this.record ||
            !isCandidateWriteTopic(
                relativeTopic,
                this.record.candidate_set_topic,
                this.record.candidate_ieee,
            ) ||
            this.stopping ||
            this.remediationRequired
        ) return;
        if (this.record.phase === PHASES.quiescent || this.record.phase === PHASES.remediation) return;
        if (
            this.record.phase === PHASES.challenge ||
            this.record.phase === PHASES.restore ||
            this.record.phase === PHASES.result
        ) {
            this.#latchSafetyOnly();
        }
        if (this.record.phase === PHASES.result) {
            await this.#invalidateResultForDrift("competing_write", "result-set-drift");
            return;
        }
        await this.#handleCompeting("competing_write");
    }

    async #handleControlDriftImpl() {
        if (!this.record || this.stopping || this.remediationRequired) return;
        if (this.record.phase === PHASES.quiescent || this.record.phase === PHASES.remediation) return;
        if (
            this.record.phase === PHASES.challenge ||
            this.record.phase === PHASES.restore ||
            this.record.phase === PHASES.result
        ) this.#latchSafetyOnly();
        await this.#handleCompeting("control_drift");
    }

    async #handleCompeting(code) {
        if (!this.record || this.stopping || this.remediationRequired) return;
        if (this.record.phase === PHASES.physical1 || this.record.phase === PHASES.physical2 || this.record.phase === PHASES.noop) {
            await this.#failSafe(code);
        } else if (this.record.phase === PHASES.challenge) {
            await this.#startRestore(code);
        } else if (this.record.phase === PHASES.restore) {
            await this.#retryRestore(code);
        } else if (this.record.phase === PHASES.result) {
            await this.#invalidateResultForDrift(code, "result-frame-drift");
        }
    }

    async #handleProofTimeout() {
        if (!this.record || this.stopping || this.remediationRequired) return;
        this.#invalidateDispatchAuthorizations();
        if (this.record.phase === PHASES.physical1 || this.record.phase === PHASES.physical2 || this.record.phase === PHASES.noop) {
            if (this.record.bound_boot_id !== this.bootId) {
                await this.#enterRemediation("deadline_expired", false);
                return;
            }
            await this.#failSafe("deadline_expired");
        } else if (this.record.phase === PHASES.challenge) {
            await this.#startRestore("deadline_expired");
        } else if (this.record.phase === PHASES.restore) {
            await this.#retryRestore("deadline_expired");
        }
    }

    async #failSafe(code) {
        const source = this.record;
        if (
            !source ||
            this.remediationRequired ||
            source.restore_required ||
            TERMINAL_PHASES.has(source.phase)
        ) return;
        if (source.bound_boot_id !== this.bootId) {
            await this.#enterRemediation(code, false);
            return;
        }
        const now = this.now();
        if (!terminalAuthorityAllows(source, now)) {
            await this.#enterRemediation("deadline_expired", false);
            return;
        }
        let commit;
        try {
            const next = terminalRecord(source, OUTCOMES.failedSafe, now, code, this.profile);
            commit = await this.#commit(next, {defendIntended: true});
        } catch {
            await this.#enterRemediation(code, false, {
                restoreSource: source,
                unclaimedKey: `fail-safe-${source.generation}`,
            });
            return;
        }
        if (commit.durable && !commit.uncertain && !this.remediationRequired && !this.overflowLatched) {
            if (!terminalAuthorityAllows(this.record, this.now())) {
                await this.#enterRemediation("deadline_expired", false);
                return;
            }
            this.#fireResult();
            this.#fireStatus();
        }
    }

    async #startRestore(code, sourceRecord = this.record) {
        if (!sourceRecord || this.stopping || this.remediationRequired) return;
        this.#latchSafetyOnly();
        this.#cancelTimer();
        if (sourceRecord.restore_attempts >= LIMITS.restoreAttempts) {
            await this.#enterRemediation("restore_exhausted", true, {
                restoreSource: sourceRecord,
                unclaimedKey: "restore-exhausted",
            });
            return;
        }
        const now = this.now();
        if (!fullPhaseWindowFits(now, sourceRecord.operation_deadline_ms, LIMITS.directProofMs)) {
            await this.#enterRemediation("deadline_expired", true, {
                restoreSource: sourceRecord,
                unclaimedKey: `restore-deadline-${sourceRecord.generation}`,
            });
            return;
        }
        try {
            const sequence = this.#nextSequence(
                sourceRecord.used_sequences,
                claimedRestoreReserveAfterNext(sourceRecord),
                "Claimed restore",
            );
            const next = restoreRecord(
                sourceRecord,
                sequence,
                code === undefined ? "restart_recovery" : code,
                now,
                this.profile,
            );
            const commit = await this.#commit(next);
            if (commit.durable && !commit.uncertain && !this.stopping) {
                await this.#dispatchExpected();
            }
        } catch {
            await this.#enterRemediation(code ?? "dispatch_failed", true, {
                restoreSource: this.record ?? sourceRecord,
                unclaimedKey: `restore-transition-${sourceRecord.generation}`,
            });
        }
    }

    async #retryRestore(code) {
        if (
            !this.record ||
            this.record.phase !== PHASES.restore ||
            this.stopping ||
            this.remediationRequired
        ) return;
        if (this.record.restore_attempts >= LIMITS.restoreAttempts) {
            await this.#enterRemediation("restore_exhausted", true, {unclaimedKey: "retry-exhausted"});
            return;
        }
        await this.#startRestore(code, this.record);
    }

    async #invalidateResultForDrift(code, unclaimedKey) {
        if (!this.record || this.record.phase !== PHASES.result || this.stopping) return;
        this.#supersedeResultPublication();
        await this.#enterRemediation(code, true, {unclaimedKey});
    }

    async #enterRemediation(
        code,
        restoreRequired,
        {
            restoreAttempted = false,
            restoreSource = this.record,
            unclaimedKey = `remediation-${code}`,
        } = {},
    ) {
        this.#latchSafetyOnly();
        this.#cancelTimer();
        this.#supersedeResultPublication();
        this.remediationRequired = true;
        if (restoreRequired && !restoreAttempted && restoreSource) {
            await this.#dispatchUnclaimedSafetyRestore(restoreSource, {key: unclaimedKey});
        }
        if (!this.record) {
            this.#fireStatus();
            return false;
        }
        const persisted = await this.#persistRemediation(code, restoreRequired);
        this.#fireStatus();
        return persisted;
    }

    async #dispatchExpected({allowStopping = false} = {}) {
        if (
            !this.record?.expected_proof ||
            (!allowStopping && this.stopping) ||
            this.remediationRequired ||
            this.safetyUnclaimedPending ||
            (this.safetyOnly && this.record.phase !== PHASES.restore)
        ) return;
        const capture = this.#captureExpectedAuthorization({allowStopping});
        if (!capture) return;
        if (!this.#expectedAuthorizationAllows(capture)) {
            if (
                capture.safety &&
                this.#recordMatchesAuthorization(capture) &&
                this.now() >= capture.invocationDeadline
            ) {
                await this.#enterRemediation("deadline_expired", true, {
                    restoreSource: this.record,
                    unclaimedKey: `claimed-restore-deadline-${capture.generation}`,
                });
                return;
            }
            if (
                !capture.safety &&
                this.#recordMatchesAuthorization(capture) &&
                this.now() >= capture.invocationDeadline
            ) {
                if (capture.phase === PHASES.noop) await this.#failSafe("dispatch_failed");
                else if (capture.phase === PHASES.challenge) await this.#startRestore("dispatch_failed");
            }
            return;
        }
        const observation = {endpointInvoked: false};
        const operation = this.#authorizedExpectedDispatch(capture, observation);
        let outcome;
        try {
            outcome = await this.dispatchRace(operation, LIMITS.dispatchMs, this.stopPromise);
        } catch {
            outcome = {status: "rejected"};
        }
        const endpointInvoked = this.#dispatchOutcomeWasInvoked(outcome, observation);
        if (outcome.status === "fulfilled" && !endpointInvoked) outcome = {status: "aborted"};
        const recordStillMatches = this.#recordMatchesAuthorization(capture, {checkEpoch: false});
        if (outcome.status !== "fulfilled") this.#invalidateDispatchAuthorizations();
        if ((!allowStopping && this.stopping) || this.remediationRequired || outcome.status === "stopped") return;
        if (!recordStillMatches || this.safetyOnly && !capture.safety) return;
        if (outcome.status === "fulfilled") {
            this.#fireStatus();
            return;
        }
        const code = outcome.status === "timeout" ? "dispatch_timeout" : "dispatch_failed";
        if (capture.phase === PHASES.noop) await this.#failSafe(code);
        else if (capture.phase === PHASES.challenge) await this.#startRestore(code);
        else if (capture.phase === PHASES.restore) {
            await this.#enterRemediation(code, true, {
                restoreSource: this.record,
                unclaimedKey: `claimed-restore-dispatch-${capture.generation}`,
            });
        }
    }

    async #dispatchUnclaimedSafetyRestore(
        record,
        {additionalUsed = [], allowStopping = false, key = "unclaimed"} = {},
    ) {
        if (!record || (!allowStopping && this.stopping)) return false;
        const existing = this.unclaimedSafetyRestores.get(key);
        if (existing) {
            const endpointInvoked = existing.status === "completed"
                ? true
                : await existing.operation;
            if (allowStopping && endpointInvoked) this.stopSafetyIssued = true;
            return endpointInvoked;
        }
        const operation = this.#attemptUnclaimedSafetyRestore(record, {
            additionalUsed,
            allowStopping,
        });
        const state = {status: "in_flight", operation};
        this.unclaimedSafetyRestores.set(key, state);
        let endpointInvoked = false;
        try {
            endpointInvoked = await operation;
        } catch {
            endpointInvoked = false;
        }
        if (endpointInvoked) {
            this.unclaimedSafetyRestores.set(key, {status: "completed"});
            if (allowStopping) this.stopSafetyIssued = true;
        } else if (this.unclaimedSafetyRestores.get(key) === state) {
            this.unclaimedSafetyRestores.delete(key);
        }
        return endpointInvoked;
    }

    async #attemptUnclaimedSafetyRestore(record, {additionalUsed, allowStopping}) {
        const used = new Set([...record.used_sequences, ...additionalUsed]);
        let anyEndpointInvoked = false;
        for (let attempt = 0; attempt < LIMITS.unclaimedSafetyAttempts; attempt += 1) {
            if (!allowStopping && this.stopping) break;
            let sequence;
            try {
                sequence = this.#nextSequence([...used]);
                used.add(sequence);
            } catch {
                continue;
            }
            const capture = this.#captureUnclaimedSafetyAuthorization(
                record,
                sequence,
                allowStopping,
            );
            if (!capture) break;
            const observation = {endpointInvoked: false};
            const operation = this.#authorizedUnclaimedSafetyDispatch(capture, observation);
            let outcome;
            try {
                outcome = await this.timeoutRace(operation, LIMITS.safetyRestoreMs);
            } catch {
                outcome = {status: "rejected"};
            }
            const endpointInvoked = this.#dispatchOutcomeWasInvoked(outcome, observation);
            anyEndpointInvoked ||= endpointInvoked;
            if (outcome.status === "fulfilled" && endpointInvoked) return true;
            this.#invalidateDispatchAuthorizations();
        }
        return anyEndpointInvoked;
    }

    async #commit(next, {allowStopping = false, defendIntended = false} = {}) {
        if (!allowStopping) this.#throwIfStopping();
        if (this.journalBlocked) {
            return this.#reconcileUncertain(next, {writeStillPending: true, defendIntended});
        }
        const outcome = await this.timeoutRace(
            Promise.resolve().then(() => this.journal.write(next)),
            LIMITS.journalMs,
        );
        if (outcome.status === "timeout") {
            this.journalBlocked = true;
            return this.#reconcileUncertain(next, {writeStillPending: true, defendIntended});
        }
        if (outcome.status === "rejected") {
            const error = outcome.error;
            if (!(error instanceof ProbeJournalUncertainError) && !error?.mayHaveCommitted) throw error;
            return this.#reconcileUncertain(next, {writeStillPending: false, defendIntended});
        }
        try {
            this.record = validateRecoveryRecord(outcome.value, this.profile);
            this.#invalidateDispatchAuthorizations();
        } catch {
            return this.#reconcileUncertain(next, {writeStillPending: false, defendIntended});
        }
        this.#scheduleForRecord();
        return {durable: true, uncertain: false};
    }

    async #reconcileUncertain(
        intended,
        {writeStillPending, suppressSafetyRestore = false, defendIntended = false},
    ) {
        let observed = this.record;
        if (writeStillPending) {
            this.journalBlocked = true;
        } else {
            const loaded = await this.#boundedJournalLoad();
            if (loaded.status === "fulfilled" && loaded.value !== null) {
                try {
                    observed = validateRecoveryRecord(loaded.value, this.profile);
                } catch {
                    observed = this.record;
                    this.journalBlocked = true;
                }
            } else if (loaded.status !== "fulfilled") {
                this.journalBlocked = true;
            }
        }
        if (observed) this.record = observed;
        this.#latchSafetyOnly();
        this.#cancelTimer();
        this.#supersedeResultPublication();
        const restoreRecordForDefense = defendIntended
            ? intended
            : observed?.restore_required
                ? observed
                : intended.restore_required
                    ? intended
                    : null;
        if (
            !suppressSafetyRestore &&
            restoreRecordForDefense &&
            this.record
        ) {
            await this.#dispatchUnclaimedSafetyRestore(restoreRecordForDefense, {
                additionalUsed: intended.used_sequences,
                allowStopping: this.stopping,
                key: this.stopping ? "stop" : `journal-uncertain-${intended.generation}`,
            });
        }
        this.remediationRequired = true;
        if (!writeStillPending) {
            await this.#persistRemediation("journal_uncertain", Boolean(restoreRecordForDefense));
        }
        this.#fireStatus();
        return {durable: true, uncertain: true};
    }

    #scheduleForRecord() {
        this.#cancelTimer();
        if (
            this.stopping ||
            this.remediationRequired ||
            !this.record ||
            this.safetyUnclaimedPending ||
            (this.safetyOnly && this.record.phase !== PHASES.restore)
        ) return;
        const token = ++this.timerToken;
        let delay;
        if (ACTIVE_PHASES.has(this.record.phase)) {
            delay = Math.max(0, this.record.expected_proof_deadline_ms - this.now());
        } else if (this.record.phase === PHASES.result) {
            delay = Math.max(
                0,
                Math.min(
                    LIMITS.resultRetryMs,
                    this.record.operation_deadline_ms - this.now(),
                ),
            );
        } else {
            return;
        }
        try {
            this.timerHandle = this.scheduler.schedule(delay, () => {
                this.timerHandle = null;
                void this.queue.enqueue(() => this.#onTimer(token)).catch(() => this.latchQueueOverflow());
            });
        } catch {
            if (this.record.phase === PHASES.result) {
                this.timerHandle = null;
                return;
            }
            this.#latchSafetyOnly();
            this.timerHandle = null;
            this.safetyUnclaimedPending = Boolean(this.record?.restore_required);
            if (!this.schedulerFailureLatched) {
                this.schedulerFailureLatched = true;
                this.#enqueueSafetyTask(() => this.#handleSchedulerFailure());
            }
        }
    }

    async #onTimer(token) {
        if (token !== this.timerToken || this.stopping || this.remediationRequired || !this.record) return;
        if (this.record.phase === PHASES.result) {
            if (this.now() >= this.record.operation_deadline_ms) {
                await this.#invalidateResultForDrift(
                    "deadline_expired",
                    `result-deadline-${this.record.generation}`,
                );
                return;
            }
            this.#fireResult();
            this.#fireStatus();
            this.#scheduleForRecord();
            return;
        }
        if (this.now() < this.record.expected_proof_deadline_ms) {
            this.#scheduleForRecord();
            return;
        }
        await this.#handleProofTimeout();
    }

    #cancelTimer() {
        if (this.timerHandle !== null) {
            try {
                this.scheduler.cancel(this.timerHandle);
            } catch {
                // The synchronous state latch below still invalidates every old token.
            }
        }
        this.timerHandle = null;
        this.timerToken += 1;
    }

    #firePublication(topic, payload) {
        if (this.stopping) return;
        let state = this.pendingPublications.get(topic);
        if (!state) {
            state = {latest: null, version: 0, running: false};
            this.pendingPublications.set(topic, state);
        }
        state.latest = payload;
        state.version += 1;
        if (!state.running && !this.publicationRetryHandles.has(topic)) this.#startPublicationAttempt(topic, state);
    }

    #fireStatus() {
        this.#firePublication(TOPICS.status, statusMessage(this.bootId, this.record, this.remediationRequired, this.profile));
    }

    #fireResult() {
        if (
            this.record?.phase === PHASES.result &&
            this.record.bound_boot_id === this.bootId
        ) {
            this.#firePublication(TOPICS.result, resultMessage(this.bootId, this.record));
        }
    }

    #nextSequence(used, reserveAfterAllocation = 0, label = "Command") {
        requireSequenceSlots(used, 1 + reserveAfterAllocation, label);
        const sequence = this.nextSequence([...used]);
        requireGeneratedSequence(sequence, "generated sequence");
        if (used.includes(sequence)) {
            throw new ProbeValidationError("duplicate_sequence", "Generated sequence is not fresh.");
        }
        return sequence;
    }

    #invalidateDispatchAuthorizations() {
        this.authorizationEpoch += 1;
    }

    #latchSafetyOnly() {
        this.safetyOnly = true;
        this.ready = false;
        this.#invalidateDispatchAuthorizations();
        this.#supersedePublication(TOPICS.ready);
    }

    #captureExpectedAuthorization({allowStopping = false} = {}) {
        const record = this.record;
        const expected = record?.expected_proof;
        if (!record || !expected || expected.sequence === null) return null;
        const safety = expected.purpose === PURPOSES.restore;
        const commandDeadline = Math.min(
            record.operation_deadline_ms,
            record.expected_proof_deadline_ms,
        );
        const invocationDeadline = safety
            ? commandDeadline
            : commandDeadline - ENDPOINT_COMMAND_TIMEOUT_MS;
        return Object.freeze({
            allowStopping,
            authorizationEpoch: this.authorizationEpoch,
            operationId: record.operation_id,
            generation: record.generation,
            phase: record.phase,
            purpose: expected.purpose,
            sequence: expected.sequence,
            target: expected.target,
            candidateIeee: record.candidate_ieee,
            candidateSetTopic: record.candidate_set_topic,
            intendedTarget: record.intended_target,
            invocationDeadline,
            resolutionDeadline: invocationDeadline ?? commandDeadline,
            safety,
        });
    }

    #recordMatchesAuthorization(capture, {checkEpoch = true} = {}) {
        const record = this.record;
        const expected = record?.expected_proof;
        return Boolean(
            record &&
            expected &&
            (!checkEpoch || capture.authorizationEpoch === this.authorizationEpoch) &&
            record.operation_id === capture.operationId &&
            record.generation === capture.generation &&
            record.phase === capture.phase &&
            record.candidate_ieee === capture.candidateIeee &&
            record.candidate_set_topic === capture.candidateSetTopic &&
            record.intended_target === capture.intendedTarget &&
            expected.purpose === capture.purpose &&
            expected.sequence === capture.sequence &&
            expected.target === capture.target
        );
    }

    #expectedAuthorizationAllows(capture) {
        if (!this.#recordMatchesAuthorization(capture)) return false;
        if (capture.safety) {
            return Boolean(
                capture.purpose === PURPOSES.restore &&
                capture.target === capture.intendedTarget &&
                this.record?.restore_required &&
                this.now() < capture.invocationDeadline &&
                !this.remediationRequired &&
                !this.safetyUnclaimedPending &&
                (capture.allowStopping || !this.stopping)
            );
        }
        return Boolean(
            (capture.purpose === PURPOSES.noop || capture.purpose === PURPOSES.challenge) &&
            this.now() < capture.invocationDeadline &&
            !this.stopping &&
            !this.stopped &&
            !this.remediationRequired &&
            !this.safetyOnly &&
            !this.safetyUnclaimedPending &&
            this.ready
        );
    }

    #authorizedExpectedDispatch(capture, observation) {
        return Promise.resolve().then(async () => {
            if (!this.#expectedAuthorizationAllows(capture)) return DISPATCH_NOT_INVOKED;
            const resolved = await this.#resolveCandidateBounded(capture.candidateIeee, {
                deadlineMs: capture.resolutionDeadline,
            });
            if (!this.#expectedAuthorizationAllows(capture)) return DISPATCH_NOT_INVOKED;
            if (
                resolved?.candidate?.ieee_address !== capture.candidateIeee ||
                resolved?.set_topic !== capture.candidateSetTopic
            ) {
                throw new ProbeValidationError("identity_mismatch", "Candidate identity changed before dispatch.");
            }
            if (!this.#expectedAuthorizationAllows(capture)) return DISPATCH_NOT_INVOKED;
            return this.#invokeDispatch(capture.candidateIeee, capture.sequence, capture.target, {
                purpose: capture.purpose,
                safety: capture.safety,
                invocationDeadline: capture.invocationDeadline,
                observation,
            });
        });
    }

    #authorizedUnclaimedSafetyDispatch(capture, observation) {
        return Promise.resolve().then(async () => {
            if (!this.#unclaimedSafetyAuthorizationAllows(capture)) return DISPATCH_NOT_INVOKED;
            const resolved = await this.#resolveCandidateBounded(capture.candidateIeee);
            if (!this.#unclaimedSafetyAuthorizationAllows(capture)) return DISPATCH_NOT_INVOKED;
            if (resolved?.candidate?.ieee_address !== capture.candidateIeee) {
                return DISPATCH_NOT_INVOKED;
            }
            if (!this.#unclaimedSafetyAuthorizationAllows(capture)) return DISPATCH_NOT_INVOKED;
            return this.#invokeDispatch(capture.candidateIeee, capture.sequence, capture.intendedTarget, {
                purpose: PURPOSES.restore,
                safety: true,
                invocationDeadline: null,
                observation,
            });
        });
    }

    #dispatchOutcomeWasInvoked(outcome, observation) {
        // Custom races may omit fulfilled values; the adapter marker remains authoritative.
        return Boolean(
            observation.endpointInvoked ||
            outcome?.value?.[DISPATCH_RESULT_BRAND] === "endpoint-invoked"
        );
    }

    #captureUnclaimedSafetyAuthorization(record, sequence, allowStopping) {
        const current = this.record;
        if (
            !current ||
            current.operation_id !== record.operation_id ||
            current.candidate_ieee !== record.candidate_ieee ||
            current.intended_target !== record.intended_target
        ) return null;
        return Object.freeze({
            allowStopping,
            authorizationEpoch: this.authorizationEpoch,
            operationId: current.operation_id,
            generation: current.generation,
            candidateIeee: current.candidate_ieee,
            intendedTarget: current.intended_target,
            sequence,
        });
    }

    #unclaimedSafetyAuthorizationAllows(capture) {
        const record = this.record;
        return Boolean(
            record &&
            capture.authorizationEpoch === this.authorizationEpoch &&
            record.operation_id === capture.operationId &&
            record.generation === capture.generation &&
            record.candidate_ieee === capture.candidateIeee &&
            record.intended_target === capture.intendedTarget &&
            (this.safetyOnly || this.remediationRequired || this.stopping) &&
            (capture.allowStopping || !this.stopping)
        );
    }

    #requireOperational() {
        if (!this.ready || this.stopping || this.stopped || this.remediationRequired || this.safetyOnly) {
            throw new ProbeValidationError("not_ready", "Probe is not accepting command-capable work.");
        }
    }

    #throwIfStopping() {
        if (this.stopping || this.stopped) throw new ProbeValidationError("stopping", "Probe is stopping.");
    }

    #enqueueSafetyTask(operation) {
        if (this.stopping) return;
        void this.queue.enqueue(operation, {force: true}).catch(() => {
            this.remediationRequired = true;
            this.#latchSafetyOnly();
        });
    }

    async #handleQueueOverflow() {
        const source = this.record;
        const restoreRequired = Boolean(
            source && (
                source.restore_required ||
                source.phase === PHASES.result ||
                source.phase === PHASES.quiescent
            ),
        );
        const key = "queue-overflow";
        if (restoreRequired) await this.#dispatchUnclaimedSafetyRestore(source, {key});
        await this.#enterRemediation("queue_overflow", restoreRequired, {
            restoreAttempted: restoreRequired,
            unclaimedKey: key,
        });
    }

    async #handleSchedulerFailure() {
        this.schedulerFailureLatched = false;
        const source = this.record;
        if (source?.restore_required) {
            await this.#dispatchUnclaimedSafetyRestore(source, {
                key: `scheduler-${source.generation}`,
            });
            this.safetyUnclaimedPending = false;
            await this.#enterRemediation("dispatch_failed", true, {
                restoreAttempted: true,
                unclaimedKey: `scheduler-${source.generation}`,
            });
            return;
        }
        this.safetyUnclaimedPending = false;
        await this.#enterRemediation("dispatch_failed", false);
    }

    async #recoverRestoreRequired(
        code,
        {
            source = this.record,
            reuseExisting = false,
            remediationAfterRestore = source?.remediation_after_restore ?? false,
            unclaimedKey = `restore-${code}`,
        } = {},
    ) {
        if (!source) return false;
        this.#latchSafetyOnly();
        this.#cancelTimer();
        const canClaim = this.#canBeginClaimedRestore(source, {reuseExisting});
        if (canClaim) {
            try {
                const next = reuseExisting
                    ? reuseRestoreRecord(
                        source,
                        this.bootId,
                        this.now(),
                        this.profile,
                        remediationAfterRestore,
                    )
                    : restoreRecord(
                        source,
                        this.#nextSequence(
                            source.used_sequences,
                            claimedRestoreReserveAfterNext(source),
                            "Recovery restore",
                        ),
                        code,
                        this.now(),
                        this.profile,
                        this.bootId,
                        remediationAfterRestore,
                    );
                const commit = await this.#commit(next);
                if (commit.durable && !commit.uncertain && !this.remediationRequired) {
                    await this.#dispatchExpected();
                    return true;
                }
                return false;
            } catch {
                // A definite recovery persistence failure still requires a safety restore.
            }
        }
        await this.#enterRemediation(code, true, {
            restoreSource: source,
            unclaimedKey,
        });
        return false;
    }

    #canBeginClaimedRestore(record, {reuseExisting = false} = {}) {
        if (!fullPhaseWindowFits(this.now(), record.operation_deadline_ms, LIMITS.directProofMs)) {
            return false;
        }
        if (reuseExisting) return record.phase === PHASES.restore;
        if (record.restore_attempts >= LIMITS.restoreAttempts) return false;
        const purposes = record.proofs.map((proof) => proof.purpose);
        return arrayVariantMatches([
            [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop],
            [PURPOSES.physical1, PURPOSES.physical2, PURPOSES.noop, PURPOSES.challenge],
        ], purposes);
    }

    async #recoverAfterSafetyPersistenceFailure(code, key) {
        this.#latchSafetyOnly();
        const restoreRequired = this.#recordNeedsSafetyRestore(this.record);
        if (restoreRequired) {
            await this.#dispatchUnclaimedSafetyRestore(this.record, {key});
        }
        this.remediationRequired = true;
        await this.#persistRemediation(code, restoreRequired);
        this.#fireStatus();
    }

    async #persistRemediation(code, restoreRequired) {
        if (!this.record) return false;
        let next;
        try {
            if (
                this.record.phase === PHASES.remediation &&
                this.record.failure_code === code &&
                this.record.restore_required === restoreRequired
            ) return !this.journalBlocked;
            next = remediationRecord(this.record, code, restoreRequired, this.profile);
        } catch {
            return false;
        }
        if (this.journalBlocked || this.stopping) {
            this.#installInMemoryRemediation(next);
            return false;
        }
        let outcome;
        try {
            outcome = await this.timeoutRace(
                Promise.resolve().then(() => this.journal.write(next)),
                LIMITS.journalMs,
            );
        } catch (error) {
            outcome = {status: "rejected", error};
        }
        if (outcome.status === "timeout") {
            this.journalBlocked = true;
            await this.#reconcileUncertain(next, {
                writeStillPending: true,
                suppressSafetyRestore: restoreRequired,
            });
            this.#installInMemoryRemediation(next);
            return false;
        }
        if (outcome.status !== "fulfilled") {
            this.journalBlocked = true;
            this.#installInMemoryRemediation(next);
            return false;
        }
        try {
            this.record = validateRecoveryRecord(outcome.value, this.profile);
            this.#invalidateDispatchAuthorizations();
            return true;
        } catch {
            this.journalBlocked = true;
            this.#installInMemoryRemediation(next);
            return false;
        }
    }

    #installInMemoryRemediation(record) {
        this.record = validateRecoveryRecord(record, this.profile);
        if (this.record.phase !== PHASES.remediation || this.record.cleanup_allowed) {
            throw new ProbeValidationError("remediation_state", "In-memory remediation synthesis failed closed.");
        }
        this.remediationRequired = true;
        this.#latchSafetyOnly();
    }

    async #boundedJournalLoad() {
        try {
            return await this.timeoutRace(
                Promise.resolve().then(() => this.journal.load()),
                LIMITS.journalMs,
            );
        } catch (error) {
            return {status: "rejected", error};
        }
    }

    #invokeDispatch(
        ieeeAddress,
        sequence,
        target,
        {purpose, safety, invocationDeadline, observation},
    ) {
        if (safety && target !== this.record?.intended_target) {
            throw new ProbeValidationError("safety_target", "Safety dispatch must target the intended value.");
        }
        if (invocationDeadline !== null && this.now() >= invocationDeadline) {
            return Promise.resolve(DISPATCH_NOT_INVOKED);
        }
        const markInvoked = () => {
            observation.endpointInvoked = true;
        };
        let operation;
        try {
            operation = Promise.resolve(this.dispatchCommand(
                ieeeAddress,
                sequence,
                target,
                {purpose, safety, invocationDeadline, markInvoked},
            ));
        } catch (error) {
            operation = Promise.reject(error);
        }
        const entry = {operation, purpose, safety};
        this.inFlightDispatches.add(entry);
        operation.then(
            () => this.inFlightDispatches.delete(entry),
            () => this.inFlightDispatches.delete(entry),
        );
        return operation.then(() => (
            observation.endpointInvoked ? DISPATCH_INVOKED : DISPATCH_NOT_INVOKED
        ));
    }

    async #stopImpl() {
        const challengeOperations = [...this.inFlightDispatches]
            .filter((entry) => entry.purpose === PURPOSES.challenge)
            .map((entry) => entry.operation);
        if (challengeOperations.length > 0) {
            await this.timeoutRace(Promise.allSettled(challengeOperations), LIMITS.stopDrainMs);
        }
        const source = this.record;
        const restoreNeeded = Boolean(source?.restore_required || challengeOperations.length > 0);
        if (restoreNeeded && source && !this.stopSafetyIssued) {
            let restoreSource = source;
            if (
                source.phase === PHASES.challenge &&
                !this.journalBlocked &&
                this.#canBeginClaimedRestore(source)
            ) {
                try {
                    const next = restoreRecord(
                        source,
                        this.#nextSequence(
                            source.used_sequences,
                            claimedRestoreReserveAfterNext(source),
                            "Stop restore",
                        ),
                        "restart_recovery",
                        this.now(),
                        this.profile,
                    );
                    const commit = await this.#commit(next, {allowStopping: true});
                    if (commit.durable && !commit.uncertain) restoreSource = this.record;
                } catch {
                    restoreSource = this.record ?? source;
                }
            }
            if (this.stopSafetyIssued) {
                this.#cancelAllPublicationRetries();
                return;
            }
            const sequence = restoreSource.phase === PHASES.restore
                ? restoreSource.expected_proof.sequence
                : null;
            if (sequence !== null) {
                const capture = this.#captureExpectedAuthorization({allowStopping: true});
                let endpointInvoked = false;
                if (capture) {
                    const observation = {endpointInvoked: false};
                    let outcome;
                    try {
                        outcome = await this.timeoutRace(
                            this.#authorizedExpectedDispatch(capture, observation),
                            LIMITS.safetyRestoreMs,
                        );
                    } catch {
                        outcome = {status: "rejected"};
                    }
                    endpointInvoked = this.#dispatchOutcomeWasInvoked(outcome, observation);
                    if (endpointInvoked) this.stopSafetyIssued = true;
                    if (outcome.status !== "fulfilled" || !endpointInvoked) {
                        this.#invalidateDispatchAuthorizations();
                    }
                }
                if (!endpointInvoked) {
                    await this.#dispatchUnclaimedSafetyRestore(restoreSource, {
                        additionalUsed: [sequence],
                        allowStopping: true,
                        key: "stop",
                    });
                }
            } else {
                await this.#dispatchUnclaimedSafetyRestore(restoreSource, {
                    allowStopping: true,
                    key: "stop",
                });
            }
        }
        this.#cancelAllPublicationRetries();
    }

    #startPublicationAttempt(topic, state) {
        if (this.stopping || state.running || state.latest === null) return;
        const version = state.version;
        const payload = state.latest;
        state.running = true;
        let operation;
        try {
            operation = Promise.resolve(this.publish(topic, payload));
        } catch (error) {
            operation = Promise.reject(error);
        }
        let timedOut = false;
        operation.then(
            () => {
                if (timedOut && state.latest !== null && !this.stopping) this.#schedulePublicationRetry(topic, 0);
            },
            () => {
                if (timedOut && state.latest !== null && !this.stopping) this.#schedulePublicationRetry(topic, 0);
            },
        );
        void this.timeoutRace(operation, LIMITS.publicationMs).then((outcome) => {
            timedOut = outcome.status === "timeout";
            state.running = false;
            if (this.stopping || state.latest === null) return;
            if (state.version !== version) {
                this.#startPublicationAttempt(topic, state);
            } else if (outcome.status !== "fulfilled") {
                this.#schedulePublicationRetry(topic, LIMITS.resultRetryMs);
            }
        }).catch(() => {
            state.running = false;
            if (!this.stopping && state.latest !== null) this.#schedulePublicationRetry(topic, LIMITS.resultRetryMs);
        });
    }

    #schedulePublicationRetry(topic, delay) {
        if (this.stopping || this.publicationRetryHandles.has(topic)) return;
        const state = this.pendingPublications.get(topic);
        if (!state?.latest) return;
        try {
            const handle = this.scheduler.schedule(delay, () => {
                this.publicationRetryHandles.delete(topic);
                this.#startPublicationAttempt(topic, state);
            });
            this.publicationRetryHandles.set(topic, handle);
        } catch {
            // Publication failure never changes probe command or recovery state.
        }
    }

    #supersedePublication(topic) {
        const state = this.pendingPublications.get(topic);
        if (state) {
            state.latest = null;
            state.version += 1;
        }
        const handle = this.publicationRetryHandles.get(topic);
        if (handle !== undefined) {
            try {
                this.scheduler.cancel(handle);
            } catch {
                // A stale callback sees the null latest payload and cannot republish.
            }
            this.publicationRetryHandles.delete(topic);
        }
    }

    #supersedeResultPublication() {
        this.#supersedePublication(TOPICS.result);
    }

    #cancelAllPublicationRetries() {
        for (const handle of this.publicationRetryHandles.values()) {
            try {
                this.scheduler.cancel(handle);
            } catch {
                // Stop remains synchronous even if a scheduler adapter is broken.
            }
        }
        this.publicationRetryHandles.clear();
    }
}

export function readyMessage(bootId, profile = BRT_PROFILE) {
    requirePattern(bootId, BOOT_ID_PATTERN, "boot ID");
    return {
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: profile.profile_id,
        profile_version: profile.profile_version,
        boot_id: bootId,
        phase: "ready",
        required_runtime_versions: profile.required_runtime_versions,
        request_topic: TOPICS.request,
        ack_topic: TOPICS.ack,
    };
}

export function statusMessage(bootId, record, remediationRequired = false, profile = BRT_PROFILE) {
    requirePattern(bootId, BOOT_ID_PATTERN, "boot ID");
    requireBoolean(remediationRequired, "remediation state");
    const remediation = remediationRequired || record?.phase === PHASES.remediation;
    if (
        record &&
        RESULT_PHASES.has(record.phase) &&
        record.bound_boot_id !== bootId &&
        !remediation
    ) {
        throw new ProbeValidationError("boot_mismatch", "Status cannot advertise an old-boot result.");
    }
    return {
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: profile.profile_id,
        profile_version: profile.profile_version,
        boot_id: bootId,
        phase: remediation ? PHASES.remediation : record?.phase ?? "idle",
        generation: record?.generation ?? 0,
        operation_id: record?.operation_id ?? null,
        result_id: remediation ? null : record?.result_id ?? null,
        result_not_before_ms: remediation ? 0 : record?.result_not_before_ms ?? 0,
        identity: record ? maskIeee(record.candidate_ieee) : null,
        restore_required: record?.restore_required ?? false,
        restore_attempts: record?.restore_attempts ?? 0,
        cleanup_allowed: remediation ? false : record?.cleanup_allowed ?? false,
    };
}

export function resultMessage(bootId, record) {
    requirePattern(bootId, BOOT_ID_PATTERN, "boot ID");
    if (!record || !RESULT_PHASES.has(record.phase)) {
        throw new ProbeValidationError("terminal_state", "Result publication requires result state.");
    }
    if (record.bound_boot_id !== bootId) {
        throw new ProbeValidationError("boot_mismatch", "Result publication requires its bound boot.");
    }
    return {
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: record.profile_id,
        profile_version: record.profile_version,
        boot_id: bootId,
        operation_id: record.operation_id,
        result_id: record.result_id,
        result_not_before_ms: record.result_not_before_ms,
        phase: record.phase,
        generation: record.generation,
        identity: maskIeee(record.candidate_ieee),
        outcome: record.outcome,
        failure_code: record.failure_code,
        cleanup_allowed: record.cleanup_allowed,
    };
}

export function responseMessage({bootId, requestId, operationId, action, accepted, phase, generation, errorCode}) {
    requirePattern(bootId, BOOT_ID_PATTERN, "boot ID");
    if (requestId !== null) requirePattern(requestId, REQUEST_ID_PATTERN, "request ID");
    if (operationId !== null) requirePattern(operationId, OPERATION_ID_PATTERN, "operation ID");
    requireText(action, "response action", 16);
    requireBoolean(accepted, "response acceptance");
    requireText(phase, "response phase", 48);
    requireIntegerRange(generation, 0, LIMITS.generation, "response generation");
    if (errorCode !== null) requireText(errorCode, "response error code", 48);
    return {
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        boot_id: bootId,
        request_id: requestId,
        operation_id: operationId,
        action,
        accepted,
        phase,
        generation,
        error_code: errorCode,
    };
}

function safePattern(value, pattern) {
    return typeof value === "string" && pattern.test(value) ? value : null;
}

function safeErrorCode(error) {
    if (error instanceof ProbeValidationError && typeof error.code === "string" && /^[a-z_]{3,48}$/.test(error.code)) return error.code;
    if (error instanceof ProbeJournalError) return "journal_unavailable";
    return "request_rejected";
}

function arrayVariantMatches(variants, actual) {
    const encoded = canonicalJson(actual);
    return variants.some((variant) => canonicalJson(variant) === encoded);
}

function validateTarget(value, profile, label) {
    requireIntegerRange(value, profile.minimum_target, profile.maximum_target, label);
    if ((value - profile.minimum_target) % profile.target_step !== 0) {
        throw new ProbeValidationError("target_step", `${label} is not on the profile step.`);
    }
}

function checkedAdd(value, increment, label) {
    requireSafeMilliseconds(value, label);
    requirePositiveInteger(increment, `${label} increment`);
    const result = value + increment;
    if (!Number.isSafeInteger(result)) throw new ProbeValidationError("integer_range", `${label} exceeds safe milliseconds.`);
    return result;
}

function requireText(value, label, maximum) {
    if (
        typeof value !== "string" ||
        scalarLength(value) === 0 ||
        scalarLength(value) > maximum ||
        BOUNDARY_WHITESPACE_PATTERN.test(value) ||
        /[\u0000-\u001f]/u.test(value) ||
        !isWellFormedUnicode(value)
    ) {
        throw new ProbeValidationError("malformed_text", `${label} must be canonical bounded text.`);
    }
}

function requireSetTopic(value) {
    requireText(value, "candidate set topic", 160);
    if (!value.endsWith("/set") || value.startsWith("/") || value.includes("//") || value.includes("+") || value.includes("#")) {
        throw new ProbeValidationError("mqtt_topic", "Candidate set topic is not exact.");
    }
}

function requirePattern(value, pattern, label) {
    if (typeof value !== "string" || !pattern.test(value)) {
        throw new ProbeValidationError("malformed_identifier", `${label} is malformed.`);
    }
}

function requireBoolean(value, label) {
    if (typeof value !== "boolean") throw new ProbeValidationError("strict_boolean", `${label} must be boolean.`);
}

function requireSafeInteger(value, label) {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new ProbeValidationError("strict_integer", `${label} must be a safe integer.`);
    }
}

function requireSafeMilliseconds(value, label) {
    requireIntegerRange(value, 0, MAX_SAFE_INTEGER, label);
}

function requireIntegerRange(value, minimum, maximum, label) {
    requireSafeInteger(value, label);
    if (value < minimum || value > maximum) {
        throw new ProbeValidationError("integer_range", `${label} is outside its range.`);
    }
}

function requirePositiveInteger(value, label) {
    requireIntegerRange(value, 1, MAX_SAFE_INTEGER, label);
}

function requireUint16(value, label) {
    requireIntegerRange(value, 0, 0xffff, label);
}

function requireGeneratedSequence(value, label) {
    requireIntegerRange(value, 0, 0xfffe, label);
}

function requireBaseTopic(baseTopic) {
    requireText(baseTopic, "MQTT base topic", 128);
    if (baseTopic.includes("+") || baseTopic.includes("#") || baseTopic.startsWith("/") || baseTopic.endsWith("/")) {
        throw new ProbeValidationError("mqtt_topic", "MQTT base topic is not exact.");
    }
}

/** Thin Zigbee2MQTT 2.12.1 external-extension adapter. */
export default class TrueFamilyBrtProbeExtension {
    constructor(
        zigbee,
        mqtt,
        _state,
        _publishEntityState,
        eventBus,
        _enableDisableExtension,
        _restartCallback,
        _addExtension,
        settings,
        _logger,
    ) {
        this.zigbee = zigbee;
        this.mqtt = mqtt;
        this.eventBus = eventBus;
        for (const method of [
            "onMQTTMessage",
            "onDeviceMessage",
            "onEntityRenamed",
            "onGroupMembersChanged",
            "removeListeners",
        ]) {
            if (typeof this.eventBus?.[method] !== "function") {
                throw new TypeError(`Physical probe requires pinned eventBus.${method}().`);
            }
        }
        this.baseTopic = settings?.get?.()?.mqtt?.base_topic;
        requireBaseTopic(this.baseTopic);
        this.stopping = false;
        this.callbacksClosed = false;
        this.started = false;
        this.core = new PhysicalProbeCore({
            journal: new AtomicProbeJournal(defaultJournalPath()),
            bootId: createBootId(),
            baseTopic: this.baseTopic,
            resolveCandidate: async (candidateOrIeee) => inspectCandidate(this.zigbee, candidateOrIeee),
            dispatchCommand: (
                ieeeAddress,
                sequence,
                target,
                {safety = false, invocationDeadline = null, markInvoked} = {},
            ) => {
                if (this.stopping && !safety) return;
                const {endpoint} = inspectCandidate(this.zigbee, ieeeAddress);
                if (this.stopping && !safety) return;
                if (!safety && Date.now() >= invocationDeadline) return;
                const command = buildTuyaCommand(sequence, target);
                markInvoked();
                return endpoint.command(command.cluster, command.command, command.payload, command.options);
            },
            publish: async (topic, payload) => {
                await this.mqtt.publish(topic, canonicalJson(payload), {
                    clientOptions: {qos: 1, retain: false},
                    skipLog: true,
                    skipReceive: true,
                });
            },
        });
        this.onMQTTMessage = (data) => this.#onMQTTEnvelope(data);
        this.onDeviceMessage = (data) => this.#onDeviceEnvelope(data);
        this.onEntityRenamed = (data) => this.#onEntityRenamedEnvelope(data);
        this.onGroupMembersChanged = (data) => this.#onGroupMembersChangedEnvelope(data);
    }

    async start() {
        if (this.started) return this.startPromise;
        this.started = true;
        this.startPromise = this.core.start();
        this.eventBus.onMQTTMessage(this, this.onMQTTMessage);
        this.eventBus.onDeviceMessage(this, this.onDeviceMessage);
        this.eventBus.onEntityRenamed(this, this.onEntityRenamed);
        this.eventBus.onGroupMembersChanged(this, this.onGroupMembersChanged);
        await this.startPromise;
    }

    async stop() {
        if (this.stopPromise) return this.stopPromise;
        this.stopping = true;
        this.core.requestStop();
        this.stopPromise = (async () => {
            await this.core.stop();
            this.callbacksClosed = true;
            this.eventBus.removeListeners(this);
        })();
        return this.stopPromise;
    }

    #onMQTTEnvelope(data) {
        if (this.callbacksClosed || !data || typeof data.topic !== "string" || typeof data.message !== "string") return;
        const requestTopic = `${this.baseTopic}/${TOPICS.request}`;
        const ackTopic = `${this.baseTopic}/${TOPICS.ack}`;
        if (data.topic === requestTopic || data.topic === ackTopic) {
            if (!this.stopping) void this.#handleRequestEnvelope(data, data.topic === ackTopic);
            return;
        }
        const baseMarker = `${this.baseTopic}/`;
        let baseIndex = data.topic.indexOf(baseMarker);
        while (baseIndex > 0 && data.topic[baseIndex - 1] !== "/") {
            baseIndex = data.topic.indexOf(baseMarker, baseIndex + 1);
        }
        if (baseIndex < 0) return;
        const relative = data.topic.slice(baseIndex + baseMarker.length);
        if (isDangerousControlTopic(relative)) {
            if (!this.stopping) void this.core.handleControlDrift().catch(() => undefined);
            return;
        }
        if (baseIndex !== 0) return;
        const record = this.core.record;
        if (
            !record ||
            !isCandidateWriteTopic(relative, record.candidate_set_topic, record.candidate_ieee)
        ) return;
        void this.core.handleCandidateSet(relative).catch(() => undefined);
    }

    #onDeviceEnvelope(data) {
        if (this.callbacksClosed || !data || typeof data !== "object") return;
        const clusterMatches = data.cluster === BRT_PROFILE.cluster_name || data.cluster === BRT_PROFILE.cluster_id;
        if (data.endpoint?.ID !== BRT_PROFILE.endpoint_id || !clusterMatches) return;
        if (this.core.record?.candidate_ieee && data.device?.ieeeAddr !== this.core.record.candidate_ieee) return;
        void this.core.handleFrame(data).catch(() => undefined);
    }

    #onEntityRenamedEnvelope(data) {
        if (this.callbacksClosed || this.stopping || !data || typeof data !== "object") return;
        const candidateIeee = this.core.record?.candidate_ieee;
        const entity = data.entity;
        if (
            candidateIeee &&
            (
                entity?.ieeeAddr === candidateIeee ||
                entity?.ID === candidateIeee ||
                entity?.zh?.ieeeAddr === candidateIeee
            )
        ) void this.core.handleControlDrift().catch(() => undefined);
    }

    #onGroupMembersChangedEnvelope(data) {
        if (this.callbacksClosed || this.stopping || !data || typeof data !== "object") return;
        const endpoint = data.endpoint;
        if (
            this.core.record?.candidate_ieee &&
            endpoint?.deviceIeeeAddress === this.core.record.candidate_ieee &&
            endpoint?.ID === BRT_PROFILE.endpoint_id
        ) void this.core.handleControlDrift().catch(() => undefined);
    }

    async #handleRequestEnvelope(data, ackTopic) {
        let request;
        try {
            request = parseCanonicalObject(data.message);
        } catch {
            await this.core.handleRequest({action: ackTopic ? "ack" : "invalid"});
            return;
        }
        if (ackTopic !== (request.action === "ack")) {
            await this.core.handleRequest({action: ackTopic ? "ack" : "invalid"});
            return;
        }
        await this.core.handleRequest(request);
    }

}
