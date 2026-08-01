import assert from "node:assert/strict";
import {
    mkdtemp,
    readFile,
    readdir,
    rm,
    stat,
    writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {pathToFileURL} from "node:url";

import TrueFamilyBrtProbeExtension, {
    AtomicProbeJournal,
    BRT_PROFILE,
    BoundedSerialQueue,
    BUILD_ID,
    ENDPOINT_COMMAND_TIMEOUT_MS,
    EXTENSION_IDENTITY,
    FRAME_KINDS,
    JOURNAL_BOUNDARIES,
    LIMITS,
    OUTCOMES,
    PHASES,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    PURPOSES,
    PhysicalProbeCore,
    ProbeJournalError,
    ProbeJournalUncertainError,
    ProbeValidationError,
    REQUIRED_RUNTIME_VERSIONS,
    RESIDUAL_DEPLOYMENT_CONTRACT,
    STATE_SCHEMA,
    TOPICS,
    buildTuyaCommand,
    calculateResultId,
    canonicalDigest,
    canonicalJson,
    challengeTarget,
    createBootId,
    defaultDispatchRace,
    defaultJournalPath,
    defaultTimeoutRace,
    inspectCandidate,
    isDangerousControlTopic,
    maskIeee,
    normalizeCandidateIdentity,
    normalizeCommandProof,
    normalizeRequest,
    parseCanonicalObject,
    parseCandidateWriteTopic,
    parseProbeFrame,
    randomDistinctSequence,
    readyMessage,
    responseMessage,
    resultMessage,
    statusMessage,
    isCandidateWriteTopic,
    validateRecoveryRecord,
} from "../../custom_components/true_family/probe/true_family_brt_probe.mjs";

const NOW = 1_800_000_000_000;
const BOOT = `tfpp-boot-${"1".repeat(32)}`;
const SECOND_BOOT = `tfpp-boot-${"2".repeat(32)}`;
const THIRD_BOOT = `tfpp-boot-${"3".repeat(32)}`;
const OPERATION = `tfpp-op-${"3".repeat(24)}`;
const SECOND_OPERATION = `tfpp-op-${"4".repeat(24)}`;
const REQUEST = `tfpp-req-${"5".repeat(24)}`;
const SECOND_REQUEST = `tfpp-req-${"6".repeat(24)}`;
const NONCE = `tfpp-nonce-${"8".repeat(32)}`;
const SECOND_NONCE = `tfpp-nonce-${"9".repeat(32)}`;
const IEEE = "0xa4c1380000000001";
const SET_TOPIC = "candidate-valve/set";
const BASE_TOPIC = "zigbee2mqtt";
const FIXTURES = JSON.parse(
    await readFile(new URL("../fixtures/physical_probe_vectors.json", import.meta.url), "utf8"),
);

function candidate(overrides = {}) {
    const fingerprint = overrides.manufacturer_fingerprint ?? "_TZE200_b6wax7g0";
    const alias = BRT_PROFILE.resolved_aliases.find(
        (item) => item.manufacturer_fingerprint === fingerprint,
    );
    return {
        ieee_address: IEEE,
        model: alias?.model ?? "BRT-100-TRV",
        vendor: alias?.vendor ?? "Moes",
        zigbee_model: "TS0601",
        manufacturer_fingerprint: fingerprint,
        endpoint_id: 1,
        cluster_name: "manuSpecificTuya",
        cluster_id: 0xef00,
        ...overrides,
    };
}

function armRequest(overrides = {}) {
    return {
        ...structuredClone(FIXTURES.arm_request),
        ...overrides,
    };
}

function ackRequest(record, overrides = {}) {
    return {
        action: "ack",
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: BRT_PROFILE.profile_id,
        profile_version: BRT_PROFILE.profile_version,
        boot_id: BOOT,
        request_id: SECOND_REQUEST,
        operation_id: record.operation_id,
        nonce: SECOND_NONCE,
        phase: PHASES.result,
        generation: record.generation,
        request_deadline_ms: NOW + 20_000,
        result_id: record.result_id,
        ...overrides,
    };
}

function resumeRequest(record, overrides = {}) {
    return {
        action: "resume",
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: BRT_PROFILE.profile_id,
        profile_version: BRT_PROFILE.profile_version,
        boot_id: BOOT,
        request_id: SECOND_REQUEST,
        operation_id: record.operation_id,
        nonce: SECOND_NONCE,
        phase: record.phase,
        generation: record.generation,
        request_deadline_ms: NOW + 20_000,
        ...overrides,
    };
}

function frame(kind, sequence, target, overrides = {}) {
    const command = buildTuyaCommand(0, target);
    return {
        type: kind,
        device: {ieeeAddr: IEEE},
        endpoint: {ID: 1, deviceIeeeAddress: IEEE},
        linkquality: 100,
        groupID: 0,
        cluster: "manuSpecificTuya",
        data: {seq: sequence, dpValues: command.payload.dpValues},
        meta: {rawData: Buffer.from([0xde, 0xad])},
        ...overrides,
    };
}

function fixtureFrame(vector) {
    return {
        type: vector.type,
        device: {ieeeAddr: IEEE},
        endpoint: {ID: 1, deviceIeeeAddress: IEEE},
        groupID: 0,
        cluster: "manuSpecificTuya",
        data: {
            seq: vector.sequence,
            dpValues: [{
                dp: vector.datapoint ?? 2,
                datatype: vector.datatype ?? 2,
                data: Buffer.from(vector.data),
            }],
        },
    };
}

function exhaustedRemediationRecord() {
    return validateRecoveryRecord({
        ...FIXTURES.remediation_restore_record,
        restore_attempts: LIMITS.restoreAttempts,
    });
}

class MemoryJournal {
    constructor(record = null, {loadError = null, uncertainAt = null, failAt = null, beforeWrite = null} = {}) {
        this.record = record;
        this.loadError = loadError;
        this.uncertainAt = uncertainAt;
        this.failAt = failAt;
        this.beforeWrite = beforeWrite;
        this.writes = [];
        this.writeAttempts = 0;
    }

    async load() {
        if (this.loadError) throw this.loadError;
        return this.record;
    }

    async write(record) {
        const normalized = validateRecoveryRecord(record);
        const writeNumber = ++this.writeAttempts;
        if (this.beforeWrite) await this.beforeWrite(normalized, writeNumber);
        if (this.failAt === writeNumber) throw new ProbeJournalError("definite write failure");
        this.record = normalized;
        this.writes.push(normalized);
        if (this.uncertainAt === writeNumber) {
            throw new ProbeJournalUncertainError("post-rename uncertainty");
        }
        return normalized;
    }
}

class FakeScheduler {
    constructor({failWhen = null} = {}) {
        this.tasks = [];
        this.nextId = 1;
        this.failWhen = failWhen;
    }

    schedule(delay, callback) {
        if (this.failWhen?.(delay, this.tasks)) throw new Error("scheduler unavailable");
        const task = {id: this.nextId++, delay, callback, cancelled: false};
        this.tasks.push(task);
        return task.id;
    }

    cancel(handle) {
        const task = this.tasks.find((item) => item.id === handle);
        if (task) task.cancelled = true;
    }

    fireNext() {
        const task = this.tasks.find((item) => !item.cancelled);
        assert.ok(task, "expected a scheduled task");
        task.cancelled = true;
        task.callback();
        return task;
    }

    activeCount() {
        return this.tasks.filter((item) => !item.cancelled).length;
    }
}

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return {promise, resolve, reject};
}

function coreHarness({
    record = null,
    loadError = null,
    uncertainAt = null,
    failAt = null,
    beforeWrite = null,
    bootId = BOOT,
    sequences = [100, 101, 102, 103, 104, 105],
    onDispatch = null,
    onPublish = null,
    onResolve = null,
    dispatchRace = undefined,
    timeoutRace = undefined,
    pendingLimit = LIMITS.pendingWork,
    nowRef = {value: NOW},
    scheduler = new FakeScheduler(),
    journalAdapter = null,
    nextSequence = null,
} = {}) {
    const journal = journalAdapter ?? new MemoryJournal(
        record,
        {loadError, uncertainAt, failAt, beforeWrite},
    );
    const commands = [];
    const publications = [];
    const resolved = [];
    const remaining = [...sequences];
    const options = {
        journal,
        bootId,
        baseTopic: "zigbee2mqtt",
        now: () => nowRef.value,
        scheduler,
        pendingLimit,
        nextSequence: nextSequence ?? ((used) => {
            const sequence = remaining.shift();
            assert.notEqual(sequence, undefined, "sequence fixture exhausted");
            assert.ok(!used.includes(sequence));
            return sequence;
        }),
        resolveCandidate: async (value) => {
            resolved.push(value);
            const defaultResult = {
                candidate: typeof value === "string" ? candidate() : value,
                set_topic: SET_TOPIC,
            };
            return onResolve ? onResolve(value, resolved.length, defaultResult) : defaultResult;
        },
        dispatchCommand: (ieeeAddress, sequence, target, {
            purpose = null,
            safety = false,
            markInvoked,
        } = {}) => {
            const command = {
                ieeeAddress,
                sequence,
                target,
                durableGeneration: journal.record?.generation,
                purpose,
                safety,
            };
            markInvoked();
            commands.push(command);
            if (onDispatch) return onDispatch(command);
        },
        publish: async (topic, payload) => {
            publications.push({topic, payload: structuredClone(payload)});
            if (onPublish) return onPublish(topic, payload);
        },
    };
    if (dispatchRace) options.dispatchRace = dispatchRace;
    if (timeoutRace) options.timeoutRace = timeoutRace;
    const core = new PhysicalProbeCore(options);
    return {core, journal, commands, publications, resolved, scheduler, remaining, nowRef};
}

async function settle() {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
}

async function fireTimer(harness, {advance = true} = {}) {
    const task = harness.scheduler.fireNext();
    if (advance) harness.nowRef.value += task.delay;
    await harness.core.handleFrame({});
    await settle();
    return task;
}

async function armCore(harness, overrides = {}) {
    await harness.core.start();
    const response = await harness.core.handleRequest(armRequest(overrides));
    assert.equal(response.accepted, true);
    return harness.core.record;
}

async function advanceToChallenge(harness) {
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.deepEqual(harness.commands.at(-1), {
        ieeeAddress: IEEE,
        sequence: 100,
        target: 21,
        durableGeneration: 3,
        purpose: PURPOSES.noop,
        safety: false,
    });
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    assert.equal(harness.core.record.phase, PHASES.challenge);
    assert.equal(harness.commands.at(-1).sequence, 101);
    return harness.core.record;
}

async function advanceToResult(harness) {
    await advanceToChallenge(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(harness.commands.at(-1).sequence, 102);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
    assert.equal(harness.core.record.phase, PHASES.result);
    return harness.core.record;
}

async function journalEvidenceRecords() {
    const harness = coreHarness();
    const armed = await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    const physical2 = harness.core.record;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    const noop = harness.core.record;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    const challenge = harness.core.record;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    const restore = harness.core.record;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
    const result = harness.core.record;
    harness.nowRef.value = result.result_not_before_ms;
    await harness.core.handleRequest(ackRequest(result));
    const quiescent = harness.core.record;

    const safeHarness = coreHarness();
    await armCore(safeHarness);
    await safeHarness.core.handleCandidateSet(SET_TOPIC);
    return {
        armed,
        challenge,
        failedSafe: safeHarness.core.record,
        noop,
        physical2,
        quiescent,
        restore,
        result,
    };
}

function journalTempPath(directory, marker) {
    return path.join(
        directory,
        `.true_family_brt_probe.${process.pid}.${marker.repeat(24)}.tmp`,
    );
}

async function writeJournalRecord(filePath, record) {
    await writeFile(filePath, canonicalJson(record, LIMITS.stateJsonBytes));
}

function withUsedSequenceCount(record, count, changes = {}) {
    const draft = structuredClone({...record, ...changes});
    for (let sequence = 1_000; draft.used_sequences.length < count; sequence += 1) {
        if (!draft.used_sequences.includes(sequence)) draft.used_sequences.push(sequence);
    }
    return validateRecoveryRecord(draft);
}

test("pins protocol v2, exact upstream requirements, and the residual writer fence", () => {
    assert.equal(PROTOCOL_VERSION, 2);
    assert.equal(STATE_SCHEMA, "true-family-physical-probe-state-v2");
    assert.deepEqual(REQUIRED_RUNTIME_VERSIONS, {
        zigbee2mqtt: "2.12.1",
        zigbee_herdsman: "10.6.1",
        zigbee_herdsman_converters: "26.76.0",
    });
    assert.equal(BRT_PROFILE.profile_version, 2);
    assert.deepEqual(BRT_PROFILE.resolved_aliases, [
        {manufacturer_fingerprint: "_TZE200_b6wax7g0", model: "BRT-100-TRV", vendor: "Moes"},
        {manufacturer_fingerprint: "_TZE200_qsoecqlk", model: "Powerswitch-ZK(W)", vendor: "Sibling"},
        {manufacturer_fingerprint: "_TZE200_6y7kyjga", model: "BRT-100-TRV", vendor: "Moes"},
    ]);
    assert.equal(EXTENSION_IDENTITY.required_runtime_versions, REQUIRED_RUNTIME_VERSIONS);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.source_enforces_broker_fence, false);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.frontend_must_be_disabled, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.exact_external_extension_allowlist_required, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.all_candidate_write_aliases_exclusive_acl_required, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.all_bridge_control_requests_must_be_denied, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.candidate_name_and_group_membership_must_be_frozen, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.orchestrator_publish_deny_by_default_required, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.orchestrator_subscription_allowlist_required, true);
    assert.equal(Object.hasOwn(
        RESIDUAL_DEPLOYMENT_CONTRACT,
        "candidate_set_topic_exclusive_acl_required",
    ), false);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.dynamic_extension_converter_mutation_must_be_denied, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.single_loader_journal_ownership_required, true);
    assert.equal(RESIDUAL_DEPLOYMENT_CONTRACT.bridge_extensions_privacy_preflight_required, true);
    assert.throws(() => { BRT_PROFILE.resolved_aliases[0].model = "changed"; }, TypeError);
    assert.equal(Object.isFrozen(BRT_PROFILE), true);
});

test("uses the shared Python/Node canonical, digest, request, record, and result vectors", () => {
    for (const vector of FIXTURES.canonical_vectors) {
        assert.equal(canonicalJson(vector.value), vector.canonical, vector.name);
        assert.equal(canonicalDigest(vector.value, vector.domain), vector.digest, vector.name);
    }
    assert.deepEqual(normalizeRequest(FIXTURES.arm_request), FIXTURES.arm_request);
    assert.deepEqual(validateRecoveryRecord(FIXTURES.armed_record), FIXTURES.armed_record);
    const terminal = validateRecoveryRecord(FIXTURES.verified_record);
    assert.equal(terminal.result_id, FIXTURES.result.result_id);
    assert.equal(calculateResultId(terminal), FIXTURES.result.result_id);
    for (const name of [
        "failed_safe_record",
        "failed_restored_record",
        "remediation_restore_record",
        "remediation_claimed_restore_record",
    ]) {
        assert.deepEqual(validateRecoveryRecord(FIXTURES[name]), FIXTURES[name], name);
    }
    for (const name of ["verified_record", "failed_safe_record", "failed_restored_record"]) {
        assert.equal(
            FIXTURES[name].operation_deadline_ms,
            FIXTURES.armed_record.operation_deadline_ms,
            name,
        );
    }
    for (const vector of FIXTURES.deadline_immutability_vectors) {
        assert.equal(
            validateRecoveryRecord(FIXTURES[vector.record]).operation_deadline_ms,
            vector.operation_deadline_ms,
            vector.name,
        );
        assert.equal(
            vector.operation_deadline_ms,
            FIXTURES.armed_record.operation_deadline_ms,
            vector.name,
        );
    }
    assert.equal(
        FIXTURES.claimed_restore_window.last_valid_start_ms + LIMITS.directProofMs,
        FIXTURES.claimed_restore_window.operation_deadline_ms,
    );
    assert.equal(
        FIXTURES.claimed_restore_window.first_invalid_start_ms + LIMITS.directProofMs,
        FIXTURES.claimed_restore_window.operation_deadline_ms + 1,
    );
    for (const vector of FIXTURES.terminal_authority_vectors) {
        const record = {
            ...FIXTURES.failed_safe_record,
            result_not_before_ms: vector.result_not_before_ms,
        };
        if (vector.valid) assert.deepEqual(validateRecoveryRecord(record), record, vector.name);
        else assert.throws(() => validateRecoveryRecord(record), ProbeValidationError, vector.name);
    }
    const [controlVector, generationVector] = FIXTURES.failure_generation_parity_vectors;
    const controlRecord = {
        ...FIXTURES.armed_record,
        phase: PHASES.result,
        generation: controlVector.expected_generation,
        expected_proof: null,
        expected_proof_deadline_ms: 0,
        outcome: OUTCOMES.failedSafe,
        failure_code: controlVector.failure_code,
        result_id: null,
        result_not_before_ms: NOW + LIMITS.resultSettleMs,
    };
    controlRecord.result_id = calculateResultId(controlRecord);
    assert.deepEqual(validateRecoveryRecord(controlRecord), controlRecord);
    const generationRemediation = {
        ...FIXTURES.armed_record,
        phase: PHASES.remediation,
        generation: generationVector.expected_generation,
        expected_proof: null,
        expected_proof_deadline_ms: 0,
        outcome: null,
        failure_code: generationVector.failure_code,
        result_id: null,
        result_not_before_ms: 0,
    };
    assert.deepEqual(validateRecoveryRecord(generationRemediation), generationRemediation);
    assert.deepEqual(normalizeRequest(FIXTURES.resume_request), FIXTURES.resume_request);
    assert.deepEqual(normalizeRequest(FIXTURES.ack_request), FIXTURES.ack_request);
    assert.deepEqual(readyMessage(BOOT), FIXTURES.public_messages.ready);
    assert.deepEqual(
        statusMessage(BOOT, FIXTURES.remediation_restore_record, true),
        FIXTURES.public_messages.status,
    );
    assert.deepEqual(
        resultMessage(BOOT, FIXTURES.failed_safe_record),
        FIXTURES.public_messages.failed_safe_result,
    );
    assert.deepEqual(
        resultMessage(BOOT, FIXTURES.failed_restored_record),
        FIXTURES.public_messages.failed_restored_result,
    );
    assert.deepEqual(responseMessage({
        bootId: BOOT,
        requestId: SECOND_REQUEST,
        operationId: OPERATION,
        action: "resume",
        accepted: false,
        phase: PHASES.remediation,
        generation: 5,
        errorCode: "queue_overflow",
    }), FIXTURES.public_messages.response);
    const parityValues = {
        failed_safe_record: FIXTURES.failed_safe_record,
        remediation_claimed_restore_record: FIXTURES.remediation_claimed_restore_record,
        remediation_status: FIXTURES.public_messages.status,
        resume_request: FIXTURES.resume_request,
        ack_request: FIXTURES.ack_request,
        utf8_public_text: {
            message: "Physical proof café £ €",
            phase: PHASES.remediation,
        },
    };
    for (const artifact of FIXTURES.parity_artifacts) {
        const value = parityValues[artifact.name];
        assert.equal(canonicalJson(value), artifact.canonical, artifact.name);
        assert.equal(canonicalDigest(value), artifact.sha256, artifact.name);
        assert.deepEqual(
            Buffer.from(canonicalJson(value), "utf8"),
            Buffer.from(artifact.canonical, "utf8"),
            artifact.name,
        );
    }
    assert.equal(canonicalJson(FIXTURES.canonical_vectors[1].value).includes("café"), true);
});

test("canonical JSON rejects noncanonical, unsafe, duplicate, and oversized values", () => {
    assert.deepEqual(parseCanonicalObject('{"a":1,"b":2}'), {a: 1, b: 2});
    for (const invalid of ['{"b":2,"a":1}', '{"a":1, "b":2}', "[]", "", '{"a":1,"a":2}']) {
        assert.throws(() => parseCanonicalObject(invalid), ProbeValidationError);
    }
    assert.throws(() => canonicalJson({number: Number.MAX_SAFE_INTEGER + 1}), ProbeValidationError);
    assert.throws(() => canonicalJson({text: "x".repeat(513)}), ProbeValidationError);
    assert.throws(() => canonicalJson({invalid: "\ud800"}), ProbeValidationError);
});

test("normalizes only the exact BRT identity and masks public IEEE output", () => {
    for (const alias of BRT_PROFILE.resolved_aliases) {
        const identity = candidate({manufacturer_fingerprint: alias.manufacturer_fingerprint});
        assert.deepEqual(normalizeCandidateIdentity(identity), identity);
    }
    assert.equal(maskIeee(IEEE), "...0001");
    assert.equal(challengeTarget(21), 22);
    assert.equal(challengeTarget(35), 34);
    for (const mutation of [
        {model: "Other"},
        {manufacturer_fingerprint: "_TZE200_aaaaaaaa"},
        {endpoint_id: 2},
        {cluster_id: 6},
        {extra: true},
        {
            manufacturer_fingerprint: "_TZE200_qsoecqlk",
            model: "BRT-100-TRV",
            vendor: "Moes",
        },
        {
            manufacturer_fingerprint: "_TZE200_b6wax7g0",
            model: "Powerswitch-ZK(W)",
            vendor: "Sibling",
        },
    ]) {
        assert.throws(() => normalizeCandidateIdentity(candidate(mutation)), ProbeValidationError);
    }
    for (const vector of FIXTURES.invalid_boundary_text_vectors) {
        const value = vector.value ?? `BRT-100-TRV${String.fromCharCode(vector.utf16_code_unit)}`;
        assert.throws(
            () => normalizeCandidateIdentity(candidate({model: value})),
            ProbeValidationError,
            vector.name,
        );
    }
});

test("resolves the exact live definition, endpoint, and candidate set topic", () => {
    const endpoint = {
        ID: 1,
        deviceIeeeAddress: IEEE,
        command: async () => undefined,
        hasPendingRequests: () => false,
        supportsInputCluster: (value) => value === "manuSpecificTuya" || value === 0xef00,
    };
    const device = {
        ieeeAddr: IEEE,
        ID: IEEE,
        name: "candidate-valve",
        isDevice: () => true,
        definition: {model: "BRT-100-TRV", vendor: "Moes"},
        zh: {
            modelID: "TS0601",
            manufacturerName: "_TZE200_b6wax7g0",
            endpoints: [endpoint],
            getEndpoint: () => endpoint,
        },
        endpoint: () => endpoint,
    };
    const resolved = inspectCandidate({resolveEntity: () => device}, candidate());
    assert.equal(resolved.endpoint, endpoint);
    assert.equal(resolved.set_topic, SET_TOPIC);
    assert.throws(
        () => inspectCandidate({resolveEntity: () => ({...device, name: "bad/#"})}, candidate()),
        ProbeValidationError,
    );
});

test("accepts all three pinned live aliases and rejects every cross-combination", () => {
    for (const alias of BRT_PROFILE.resolved_aliases) {
        const endpoint = {
            ID: 1,
            deviceIeeeAddress: IEEE,
            command: async () => undefined,
            hasPendingRequests: () => false,
            supportsInputCluster: () => true,
        };
        const device = {
            ieeeAddr: IEEE,
            ID: IEEE,
            name: "candidate-valve",
            isDevice: () => true,
            definition: {model: alias.model, vendor: alias.vendor},
            zh: {
                modelID: "TS0601",
                manufacturerName: alias.manufacturer_fingerprint,
                endpoints: [endpoint],
                getEndpoint: () => endpoint,
            },
            endpoint: () => endpoint,
        };
        assert.deepEqual(
            inspectCandidate(
                {resolveEntity: () => device},
                candidate({manufacturer_fingerprint: alias.manufacturer_fingerprint}),
            ).candidate,
            candidate({manufacturer_fingerprint: alias.manufacturer_fingerprint}),
        );
        assert.throws(
            () => inspectCandidate(
                {resolveEntity: () => ({
                    ...device,
                    definition: {model: "BRT-100-TRV", vendor: "Moes"},
                })},
                alias.manufacturer_fingerprint === "_TZE200_qsoecqlk"
                    ? candidate({manufacturer_fingerprint: alias.manufacturer_fingerprint})
                    : candidate({
                        manufacturer_fingerprint: alias.manufacturer_fingerprint,
                        model: "Powerswitch-ZK(W)",
                        vendor: "Sibling",
                    }),
            ),
            ProbeValidationError,
        );
    }
});

test("candidate inspection requires empty selected and device-wide endpoint queues", () => {
    let commands = 0;
    const selected = {
        ID: 1,
        deviceIeeeAddress: IEEE,
        command: () => { commands += 1; },
        hasPendingRequests: () => false,
        supportsInputCluster: () => true,
    };
    const other = {
        ID: 2,
        deviceIeeeAddress: IEEE,
        hasPendingRequests: () => false,
    };
    const device = {
        ieeeAddr: IEEE,
        ID: IEEE,
        name: "candidate-valve",
        isDevice: () => true,
        definition: {model: "BRT-100-TRV", vendor: "Moes"},
        zh: {
            modelID: "TS0601",
            manufacturerName: "_TZE200_b6wax7g0",
            endpoints: [selected, other],
            getEndpoint: () => selected,
        },
        endpoint: () => selected,
    };
    assert.equal(inspectCandidate({resolveEntity: () => device}, candidate()).endpoint, selected);
    assert.equal(commands, 0);
});

test("candidate inspection fails closed on missing or pending queue APIs without commanding", () => {
    let commands = 0;
    const endpoint = {
        ID: 1,
        deviceIeeeAddress: IEEE,
        command: () => { commands += 1; },
        hasPendingRequests: () => false,
        supportsInputCluster: () => true,
    };
    const makeDevice = (selected, endpoints = [selected]) => ({
        ieeeAddr: IEEE,
        ID: IEEE,
        name: "candidate-valve",
        isDevice: () => true,
        definition: {model: "BRT-100-TRV", vendor: "Moes"},
        zh: {
            modelID: "TS0601",
            manufacturerName: "_TZE200_b6wax7g0",
            endpoints,
            getEndpoint: () => selected,
        },
        endpoint: () => selected,
    });
    for (const device of [
        makeDevice({...endpoint, hasPendingRequests: undefined}),
        makeDevice({...endpoint, hasPendingRequests: () => true}),
        makeDevice(endpoint, [endpoint, {ID: 2, hasPendingRequests: () => true}]),
        makeDevice(endpoint, [endpoint, {ID: 2}]),
    ]) {
        assert.throws(
            () => inspectCandidate({resolveEntity: () => device}, candidate()),
            (error) => error instanceof ProbeValidationError && error.code === "pending_requests",
        );
    }
    assert.equal(commands, 0);
});

test("candidate write-topic parser conservatively covers Number-coerced aliases", () => {
    const accepted = new Map([
        ["candidate-valve/set", {root_kind: "friendly", endpoint: null, attribute: null}],
        ["candidate-valve/set/system_mode", {root_kind: "friendly", endpoint: null, attribute: "system_mode"}],
        ["candidate-valve/1/set", {root_kind: "friendly", endpoint: "1", attribute: null}],
        ["candidate-valve/1/set/occupied_heating_setpoint", {
            root_kind: "friendly",
            endpoint: "1",
            attribute: "occupied_heating_setpoint",
        }],
        [`${IEEE}/set`, {root_kind: "ieee", endpoint: null, attribute: null}],
        [`${IEEE}/set/system_mode`, {root_kind: "ieee", endpoint: null, attribute: "system_mode"}],
        [`${IEEE}/1/set`, {root_kind: "ieee", endpoint: "1", attribute: null}],
        [`${IEEE}/1/set/occupied_heating_setpoint`, {
            root_kind: "ieee",
            endpoint: "1",
            attribute: "occupied_heating_setpoint",
        }],
        ["candidate-valve/ 1/set/current_heating_setpoint", {
            root_kind: "friendly",
            endpoint: " 1",
            attribute: "current_heating_setpoint",
        }],
        ["candidate-valve/1 /set/current_heating_setpoint", {
            root_kind: "friendly",
            endpoint: "1 ",
            attribute: "current_heating_setpoint",
        }],
        ["candidate-valve/0001/set", {root_kind: "friendly", endpoint: "0001", attribute: null}],
        ["candidate-valve/0x1/set", {root_kind: "friendly", endpoint: "0x1", attribute: null}],
        ["candidate-valve/1e0/set", {root_kind: "friendly", endpoint: "1e0", attribute: null}],
        ["candidate-valve/\t1/set", {root_kind: "friendly", endpoint: "\t1", attribute: null}],
        ["candidate-valve/1\v/set", {root_kind: "friendly", endpoint: "1\v", attribute: null}],
        ["candidate-valve/\f1/set", {root_kind: "friendly", endpoint: "\f1", attribute: null}],
        ["candidate-valve/1\r/set", {root_kind: "friendly", endpoint: "1\r", attribute: null}],
        ["candidate-valve/\n1/set", {root_kind: "friendly", endpoint: "\n1", attribute: null}],
        ["candidate-valve/\t\v\f\r\n1\t/set", {
            root_kind: "friendly",
            endpoint: "\t\v\f\r\n1\t",
            attribute: null,
        }],
        ["candidate-valve/set/system_mode/deep/path", {
            root_kind: "friendly",
            endpoint: null,
            attribute: "system_mode/deep/path",
        }],
        ["candidate-valve/1/set/system_mode/deep/path", {
            root_kind: "friendly",
            endpoint: "1",
            attribute: "system_mode/deep/path",
        }],
        ["candidate-valve//set", {root_kind: "friendly", endpoint: "", attribute: null}],
    ]);
    for (const [topic, parsed] of accepted) {
        assert.deepEqual(parseCandidateWriteTopic(topic, SET_TOPIC, IEEE), parsed, topic);
        assert.equal(isCandidateWriteTopic(topic, SET_TOPIC, IEEE), true, topic);
    }
    const numericWhitespace = [
        "\u0009",
        "\u000b",
        "\u000c",
        "\u0020",
        "\u00a0",
        "\u1680",
        "\u2000",
        "\u2001",
        "\u2002",
        "\u2003",
        "\u2004",
        "\u2005",
        "\u2006",
        "\u2007",
        "\u2008",
        "\u2009",
        "\u200a",
        "\u2028",
        "\u2029",
        "\u202f",
        "\u205f",
        "\u3000",
        "\ufeff",
        "\u000a",
        "\u000d",
    ];
    for (const whitespace of numericWhitespace) {
        const endpoint = `${whitespace}1${whitespace}`;
        assert.equal(Number(endpoint), 1, `numeric whitespace U+${whitespace.codePointAt(0).toString(16)}`);
        assert.deepEqual(parseCandidateWriteTopic(
            `candidate-valve/${endpoint}/set`,
            SET_TOPIC,
            IEEE,
        ), {
            root_kind: "friendly",
            endpoint,
            attribute: null,
        });
    }
    for (const topic of [
        "other-valve/set",
        "candidate-valve/get",
        "candidate-valvex/1/set",
        "candidate-valve/setter",
        "candidate-valve/1/setter/value",
        "candidate-valve/1/get",
        `${BASE_TOPIC}/candidate-valve/set`,
        `${IEEE}0/set`,
        "bridge/request/extension/save",
        "candidate-valve/1/set/#",
        "candidate-valve/+/set/value",
        "candidate-valve/1/set/\u0000value",
        `candidate-valve/1/set/${"é".repeat(32_760)}`,
        "candidate-valve/1/set/\ud800",
    ]) {
        assert.equal(parseCandidateWriteTopic(topic, SET_TOPIC, IEEE), null, topic);
        assert.equal(isCandidateWriteTopic(topic, SET_TOPIC, IEEE), false, topic);
    }
    const longEndpoint = `${"0".repeat(60_000)}1`;
    const longEndpointTopic = `candidate-valve/${longEndpoint}/set/current_heating_setpoint`;
    assert.ok(Buffer.byteLength(longEndpointTopic, "utf8") < 65_535);
    assert.deepEqual(parseCandidateWriteTopic(longEndpointTopic, SET_TOPIC, IEEE), {
        root_kind: "friendly",
        endpoint: longEndpoint,
        attribute: "current_heating_setpoint",
    });
    const longWhitespaceEndpoint = `${"\t\v\f\r\n".repeat(10_000)}1`;
    const longWhitespaceTopic = `${IEEE}/${longWhitespaceEndpoint}/set`;
    assert.ok(Buffer.byteLength(longWhitespaceTopic, "utf8") < 65_535);
    assert.equal(Number(longWhitespaceEndpoint), 1);
    assert.deepEqual(parseCandidateWriteTopic(longWhitespaceTopic, SET_TOPIC, IEEE), {
        root_kind: "ieee",
        endpoint: longWhitespaceEndpoint,
        attribute: null,
    });
    const longAttribute = "a".repeat(2_000);
    assert.deepEqual(parseCandidateWriteTopic(
        `${IEEE}/0x1/set/${longAttribute}`,
        SET_TOPIC,
        IEEE,
    ), {
        root_kind: "ieee",
        endpoint: "0x1",
        attribute: longAttribute,
    });
});

test("dangerous control topic helper matches raw and repeated-prefix aliases", () => {
    assert.equal(isDangerousControlTopic(TOPICS.request), false);
    assert.equal(isDangerousControlTopic(TOPICS.ack), false);
    for (const topic of [
        "bridge/request/action",
        "bridge/request/device/rename",
        "bridge/request/group/members/add",
        "prefix/bridge/request/backup",
        "zigbee2mqtt/bridge/request/restart",
        `${TOPICS.request}/bridge/request/extension/save`,
    ]) assert.equal(isDangerousControlTopic(topic), true, topic);
    assert.equal(isDangerousControlTopic("bridge/response/backup"), false);
});

test("encodes one exact Tuya DP2 dataRequest command", () => {
    const command = buildTuyaCommand(0x1234, 21);
    assert.equal(command.cluster, "manuSpecificTuya");
    assert.equal(command.command, "dataRequest");
    assert.equal(command.payload.seq, 0x1234);
    assert.deepEqual(command.payload.dpValues[0], {
        dp: 2,
        datatype: 2,
        data: Buffer.from([0, 0, 0, 21]),
    });
    assert.deepEqual(command.options, {
        disableDefaultResponse: true,
        sendPolicy: "immediate",
        disableRecovery: true,
        timeout: ENDPOINT_COMMAND_TIMEOUT_MS,
    });
    assert.equal(ENDPOINT_COMMAND_TIMEOUT_MS, 5_000);
    assert.ok(ENDPOINT_COMMAND_TIMEOUT_MS < LIMITS.dispatchMs);
    assert.ok(ENDPOINT_COMMAND_TIMEOUT_MS < LIMITS.directProofMs);
    assert.throws(() => buildTuyaCommand(true, 21), ProbeValidationError);
    assert.throws(() => buildTuyaCommand(0xffff, 21), ProbeValidationError);
    assert.throws(() => buildTuyaCommand(1, 36), ProbeValidationError);
    assert.deepEqual(parseProbeFrame(frame(FRAME_KINDS.response, 0xffff, 18), IEEE), {
        frame_kind: FRAME_KINDS.response,
        sequence: 0xffff,
        target: 18,
    });
});

test("classifies shared DP2 response, report, and companion vectors exactly", () => {
    const [responseVector, reportVector, ...companionVectors] = FIXTURES.frames;
    assert.deepEqual(parseProbeFrame(fixtureFrame(responseVector), IEEE), {
        frame_kind: FRAME_KINDS.response,
        sequence: 500,
        target: 18,
    });
    assert.throws(
        () => parseProbeFrame(fixtureFrame(reportVector), IEEE),
        (error) => error instanceof ProbeValidationError && error.code === "competing_frame",
    );
    for (const companionVector of companionVectors) {
        assert.equal(parseProbeFrame(fixtureFrame(companionVector), IEEE), null);
    }
});

test("rejects malformed or ambiguous DP2 frames and ignores unrelated traffic", () => {
    assert.equal(parseProbeFrame(frame(FRAME_KINDS.response, 1, 18, {device: {ieeeAddr: "0xa4c1380000000002"}}), IEEE), null);
    assert.equal(parseProbeFrame(frame(FRAME_KINDS.response, 1, 18, {endpoint: {ID: 2, deviceIeeeAddress: IEEE}}), IEEE), null);
    assert.equal(parseProbeFrame(frame(FRAME_KINDS.response, 1, 18, {cluster: "genOnOff"}), IEEE), null);
    assert.throws(() => parseProbeFrame(frame(FRAME_KINDS.response, 1, 18, {groupID: 1}), IEEE), ProbeValidationError);
    assert.throws(() => parseProbeFrame(frame(FRAME_KINDS.response, 1, 18, {
        data: {seq: 1, dpValues: [buildTuyaCommand(1, 18).payload.dpValues[0], {dp: 5, datatype: 4, data: Buffer.from([0])}]},
    }), IEEE), ProbeValidationError);
    assert.throws(() => parseProbeFrame(frame(FRAME_KINDS.response, 1, 18, {
        data: {seq: 1, dpValues: [{dp: 2, datatype: 2, data: Buffer.from([18])}]},
    }), IEEE), ProbeValidationError);
});

test("shared invalid proof vectors reject range, step, and unknown-field drift", () => {
    for (const vector of FIXTURES.invalid_proofs) {
        const profile = {
            ...BRT_PROFILE,
            minimum_target: vector.profile.minimum_target,
            maximum_target: vector.profile.maximum_target,
            target_step: vector.profile.target_step,
        };
        assert.throws(
            () => normalizeCommandProof(vector.proof, profile),
            ProbeValidationError,
            vector.name,
        );
    }
});

test("strictly validates disjoint arm, resume, and ack request fields", () => {
    assert.deepEqual(normalizeRequest(armRequest()), armRequest());
    const resume = {
        action: "resume",
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        profile_id: BRT_PROFILE.profile_id,
        profile_version: BRT_PROFILE.profile_version,
        boot_id: BOOT,
        request_id: SECOND_REQUEST,
        operation_id: OPERATION,
        nonce: SECOND_NONCE,
        phase: PHASES.physical1,
        generation: 1,
        request_deadline_ms: NOW + 20_000,
    };
    assert.deepEqual(normalizeRequest(resume), resume);
    assert.throws(() => normalizeRequest({...resume, candidate: candidate()}), ProbeValidationError);
    assert.throws(() => normalizeRequest({...armRequest(), extra: true}), ProbeValidationError);
    assert.throws(() => normalizeRequest({...armRequest(), generation: false}), ProbeValidationError);
});

test("expired active operation cannot be revived by a fresh resume request", async () => {
    const nowRef = {value: NOW};
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.armed_record),
        nowRef,
    });
    await harness.core.start();
    nowRef.value = NOW + 120_000;
    const response = await harness.core.handleRequest({
        ...FIXTURES.resume_request,
        phase: PHASES.physical1,
        generation: 1,
        request_deadline_ms: nowRef.value + 10_000,
    });
    assert.equal(response.accepted, false);
    assert.equal(response.error_code, "deadline_expired");
    assert.equal(harness.journal.writes.length, 0);
});

test("expired previous-boot pre-challenge phases enter no-result remediation", async () => {
    const builder = coreHarness();
    await armCore(builder);
    const records = [builder.core.record];
    await builder.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    records.push(builder.core.record);
    await builder.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    records.push(builder.core.record);
    assert.deepEqual(records.map((record) => record.phase), [
        PHASES.physical1,
        PHASES.physical2,
        PHASES.noop,
    ]);

    for (const record of records) {
        const nowRef = {value: record.expected_proof_deadline_ms};
        const restarted = coreHarness({
            record,
            bootId: SECOND_BOOT,
            nowRef,
        });
        await restarted.core.start();
        assert.equal(restarted.core.record.phase, PHASES.remediation, record.phase);
        assert.equal(restarted.core.record.failure_code, "deadline_expired", record.phase);
        assert.equal(restarted.core.record.restore_required, false, record.phase);
        assert.equal(restarted.core.record.result_id, null, record.phase);
        assert.equal(restarted.core.record.outcome, null, record.phase);
        assert.equal(restarted.core.record.cleanup_allowed, false, record.phase);
        assert.equal(restarted.commands.length, 0, record.phase);
        assert.equal(
            restarted.publications.some(
                (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
            ),
            false,
            record.phase,
        );
    }
});

test("unexpired previous-boot active record requires explicit resume and rebinds", async () => {
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.armed_record),
        bootId: SECOND_BOOT,
    });
    await harness.core.start();
    assert.equal(harness.core.record.bound_boot_id, BOOT);
    const response = await harness.core.handleRequest(resumeRequest(harness.core.record, {
        boot_id: SECOND_BOOT,
    }));
    assert.equal(response.accepted, true);
    assert.equal(harness.core.record.bound_boot_id, SECOND_BOOT);
    assert.equal(harness.core.record.phase, PHASES.physical1);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    assert.equal(harness.core.record.phase, PHASES.physical2);
    assert.equal(harness.core.record.result_id, null);
});

test("old-bound result cannot be acknowledged or advertised by current boot", async () => {
    const record = validateRecoveryRecord(FIXTURES.verified_record);
    assert.throws(() => resultMessage(SECOND_BOOT, record), ProbeValidationError);
    assert.throws(() => statusMessage(SECOND_BOOT, record), ProbeValidationError);
    const remediatingStatus = statusMessage(SECOND_BOOT, record, true);
    assert.equal(remediatingStatus.phase, PHASES.remediation);
    assert.equal(remediatingStatus.result_id, null);
    assert.equal(remediatingStatus.cleanup_allowed, false);

    const harness = coreHarness({record});
    await harness.core.start();
    harness.core.bootId = SECOND_BOOT;
    harness.nowRef.value = record.result_not_before_ms;
    const response = await harness.core.handleRequest(ackRequest(record, {
        boot_id: SECOND_BOOT,
    }));
    assert.equal(response.accepted, false);
    assert.equal(response.error_code, "boot_mismatch");
    assert.equal(harness.core.record.phase, PHASES.result);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("arm, resume, and ACK revalidate request deadlines after resolution", async () => {
    const armNow = {value: NOW};
    const arm = coreHarness({
        nowRef: armNow,
        onResolve: (_value, _count, defaultResult) => {
            armNow.value = NOW + 10_000;
            return defaultResult;
        },
    });
    await arm.core.start();
    const armResponse = await arm.core.handleRequest(armRequest());
    assert.equal(armResponse.accepted, false);
    assert.equal(armResponse.error_code, "stale_request");
    assert.equal(arm.core.record, null);

    const resumeNow = {value: NOW};
    const resume = coreHarness({
        record: validateRecoveryRecord(FIXTURES.armed_record),
        nowRef: resumeNow,
        onResolve: (_value, _count, defaultResult) => {
            resumeNow.value = NOW + 20_000;
            return defaultResult;
        },
    });
    await resume.core.start();
    const resumeResponse = await resume.core.handleRequest(
        resumeRequest(resume.core.record),
    );
    assert.equal(resumeResponse.accepted, false);
    assert.equal(resumeResponse.error_code, "stale_request");
    assert.equal(resume.core.record.generation, FIXTURES.armed_record.generation);

    const ackNow = {value: FIXTURES.verified_record.result_not_before_ms};
    const ack = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef: ackNow,
        onResolve: (_value, _count, defaultResult) => {
            ackNow.value = NOW + 20_000;
            return defaultResult;
        },
    });
    await ack.core.start();
    const ackResponse = await ack.core.handleRequest(ackRequest(ack.core.record));
    assert.equal(ackResponse.accepted, false);
    assert.equal(ackResponse.error_code, "stale_request");
    assert.equal(ack.core.record.phase, PHASES.result);
    assert.equal(ack.core.record.cleanup_allowed, false);
});

test("ACK after the operation deadline never grants cleanup", async () => {
    const nowRef = {value: FIXTURES.verified_record.operation_deadline_ms};
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef,
        sequences: [200, 201, 202],
    });
    await harness.core.start();
    const response = await harness.core.handleRequest(ackRequest(harness.core.record, {
        request_deadline_ms: nowRef.value + 10_000,
    }));
    assert.equal(response.accepted, false);
    assert.equal(response.error_code, "deadline_expired");
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("ACK crossing the operation deadline during resolution invalidates the result", async () => {
    const deadline = FIXTURES.verified_record.operation_deadline_ms;
    const nowRef = {value: deadline - 1_000};
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef,
        sequences: [200, 201, 202],
        onResolve: (_value, _count, defaultResult) => {
            nowRef.value = deadline;
            return defaultResult;
        },
    });
    await harness.core.start();
    const response = await harness.core.handleRequest(ackRequest(harness.core.record, {
        request_deadline_ms: deadline + 1_000,
    }));
    assert.equal(response.accepted, false);
    assert.equal(response.error_code, "deadline_expired");
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("ACK journal commit crossing its deadline cannot grant cleanup", async () => {
    const nowRef = {value: FIXTURES.verified_record.result_not_before_ms};
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef,
        sequences: [200, 201, 202],
        beforeWrite: (record) => {
            if (record.phase === PHASES.quiescent) {
                nowRef.value = FIXTURES.verified_record.operation_deadline_ms;
            }
        },
    });
    await harness.core.start();
    const response = await harness.core.handleRequest(ackRequest(harness.core.record));
    assert.equal(response.accepted, true);
    assert.equal(response.error_code, "deadline_expired");
    assert.equal(response.phase, PHASES.remediation);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("timed-out ACK write completing late is restore-only after restart", async () => {
    const writeGate = deferred();
    let timeoutAckWrite = false;
    const nowRef = {value: FIXTURES.verified_record.result_not_before_ms};
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef,
        sequences: [200, 201, 202],
        beforeWrite: async (record) => {
            if (record.phase === PHASES.quiescent) await writeGate.promise;
        },
        timeoutRace: async (operation, timeoutMs) => {
            if (timeoutAckWrite && timeoutMs === LIMITS.journalMs) {
                timeoutAckWrite = false;
                Promise.resolve(operation).catch(() => undefined);
                return {status: "timeout"};
            }
            return defaultTimeoutRace(operation, timeoutMs);
        },
    });
    await harness.core.start();
    timeoutAckWrite = true;
    const response = await harness.core.handleRequest(ackRequest(harness.core.record));
    assert.equal(response.accepted, true);
    assert.equal(response.error_code, "journal_uncertain");
    assert.equal(response.phase, PHASES.remediation);
    assert.equal(harness.core.journalBlocked, true);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.scheduler.activeCount(), 0);
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);

    writeGate.resolve();
    while (harness.journal.record.phase !== PHASES.quiescent) await settle();
    await harness.core.stop();
    const restarted = coreHarness({
        record: harness.journal.record,
        bootId: SECOND_BOOT,
        sequences: [210, 211, 212],
    });
    await restarted.core.start();
    assert.equal(restarted.core.record.phase, PHASES.remediation);
    assert.equal(restarted.core.record.cleanup_allowed, false);
    assert.equal(restarted.core.ready, false);
    assert.equal(restarted.publications.some((item) => item.topic === TOPICS.ready), false);
    assert.deepEqual(restarted.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("prior-boot quiescent remediation persistence failure stays fail closed", async () => {
    const acknowledged = coreHarness();
    const result = await advanceToResult(acknowledged);
    acknowledged.nowRef.value = result.result_not_before_ms;
    await acknowledged.core.handleRequest(ackRequest(result));
    assert.equal(acknowledged.journal.record.phase, PHASES.quiescent);
    await acknowledged.core.stop();

    const restarted = coreHarness({
        record: acknowledged.journal.record,
        bootId: SECOND_BOOT,
        failAt: 1,
        sequences: [200, 201, 202],
    });
    await restarted.core.start();
    assert.equal(restarted.core.journalBlocked, true);
    assert.equal(restarted.core.record.phase, PHASES.remediation);
    assert.equal(restarted.core.record.cleanup_allowed, false);
    assert.equal(restarted.journal.record.phase, PHASES.quiescent);
    assert.equal(restarted.publications.some((item) => item.topic === TOPICS.ready), false);
    assert.deepEqual(restarted.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("result timer expiry remediates without republishing stale result", async () => {
    const nowRef = {value: NOW};
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef,
        sequences: [200, 201, 202],
    });
    await harness.core.start();
    const resultPublications = harness.publications.filter(
        (item) => item.topic === TOPICS.result,
    ).length;
    nowRef.value = harness.core.record.operation_deadline_ms;
    await fireTimer(harness, {advance: false});
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(
        harness.publications.filter((item) => item.topic === TOPICS.result).length,
        resultPublications,
    );
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
    assert.equal(harness.scheduler.activeCount(), 0);
});

test("stale late ACK after deadline invalidation is harmless and deduplicated", async () => {
    const deadline = FIXTURES.verified_record.operation_deadline_ms;
    const nowRef = {value: deadline};
    const staleResult = validateRecoveryRecord(FIXTURES.verified_record);
    const harness = coreHarness({
        record: staleResult,
        nowRef,
        sequences: [200, 201, 202],
    });
    await harness.core.start();
    const first = await harness.core.handleRequest(ackRequest(staleResult, {
        request_deadline_ms: deadline + 10_000,
    }));
    assert.equal(first.error_code, "deadline_expired");
    const commandCount = harness.commands.length;
    const late = await harness.core.handleRequest(ackRequest(staleResult, {
        request_id: `tfpp-req-${"7".repeat(24)}`,
        nonce: `tfpp-nonce-${"a".repeat(32)}`,
        request_deadline_ms: deadline + 20_000,
    }));
    assert.equal(late.accepted, false);
    assert.equal(late.phase, PHASES.remediation);
    assert.equal(harness.commands.length, commandCount);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("timer-expiry persistence failure cannot revive stale result after restart", async () => {
    const nowRef = {value: NOW};
    const poisoned = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        nowRef,
        failAt: 1,
        sequences: [200, 201, 202],
    });
    await poisoned.core.start();
    nowRef.value = poisoned.core.record.operation_deadline_ms;
    await fireTimer(poisoned, {advance: false});
    assert.equal(poisoned.core.journalBlocked, true);
    assert.equal(poisoned.core.record.phase, PHASES.remediation);
    assert.equal(poisoned.core.record.cleanup_allowed, false);
    assert.equal(poisoned.journal.record.phase, PHASES.result);

    const restarted = coreHarness({
        record: poisoned.journal.record,
        bootId: SECOND_BOOT,
        sequences: [210, 211, 212],
    });
    await restarted.core.start();
    assert.equal(restarted.core.record.phase, PHASES.remediation);
    assert.equal(restarted.core.record.result_id, null);
    assert.equal(restarted.core.record.cleanup_allowed, false);
    assert.equal(restarted.publications.some((item) => item.topic === TOPICS.ready), false);
    assert.equal(restarted.publications.some((item) => item.topic === TOPICS.result), false);
    assert.deepEqual(restarted.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("hanging request resolution releases FIFO for timer and stop safety", async () => {
    const timerResolver = deferred();
    const timerHarness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.armed_record),
        onResolve: () => timerResolver.promise,
        timeoutRace: async (operation, timeoutMs) => {
            if (timeoutMs === LIMITS.candidateResolutionMs) {
                Promise.resolve(operation).catch(() => undefined);
                return {status: "timeout"};
            }
            return defaultTimeoutRace(operation, timeoutMs);
        },
    });
    await timerHarness.core.start();
    const timedOut = await timerHarness.core.handleRequest(
        resumeRequest(timerHarness.core.record),
    );
    assert.equal(timedOut.error_code, "candidate_timeout");
    await fireTimer(timerHarness);
    assert.equal(timerHarness.core.record.outcome, OUTCOMES.failedSafe);
    timerResolver.resolve({candidate: candidate(), set_topic: SET_TOPIC});
    await settle();
    assert.equal(timerHarness.commands.length, 0);

    const stopResolver = deferred();
    const releaseTimeout = deferred();
    const stopHarness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.armed_record),
        onResolve: () => stopResolver.promise,
        timeoutRace: async (operation, timeoutMs) => {
            if (timeoutMs === LIMITS.candidateResolutionMs) {
                Promise.resolve(operation).catch(() => undefined);
                await releaseTimeout.promise;
                return {status: "timeout"};
            }
            return defaultTimeoutRace(operation, timeoutMs);
        },
    });
    await stopHarness.core.start();
    const resolving = stopHarness.core.handleRequest(resumeRequest(stopHarness.core.record));
    while (stopHarness.resolved.length === 0) await settle();
    stopHarness.core.requestStop();
    releaseTimeout.resolve();
    const stoppedRequest = await resolving;
    assert.equal(stoppedRequest.accepted, false);
    await stopHarness.core.stop();
    assert.equal(stopHarness.core.stopped, true);
    assert.equal(stopHarness.commands.length, 0);
    stopResolver.resolve({candidate: candidate(), set_topic: SET_TOPIC});
    await settle();
    assert.equal(stopHarness.commands.length, 0);
});

test("durably consumed resume remains accepted when post-commit handling fails", async () => {
    const harness = coreHarness({
        failAt: 5,
        onDispatch: (command) => {
            if (command.sequence === 101) throw new Error("resume dispatch failed");
        },
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(harness.core.record.phase, PHASES.noop);
    const response = await harness.core.handleRequest({
        ...FIXTURES.resume_request,
        generation: harness.core.record.generation,
        request_deadline_ms: NOW + 20_000,
    });
    assert.equal(response.accepted, true);
    assert.equal(response.phase, PHASES.remediation);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.outcome, null);
    assert.equal(harness.core.record.result_id, null);
    assert.ok(harness.core.record.consumed_request_ids.includes(SECOND_REQUEST));
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("maximum no-op resumes preserve three claimed and three unclaimed restores", async () => {
    let safetyDispatches = 0;
    const harness = coreHarness({
        sequences: Array.from({length: 14}, (_value, index) => 100 + index),
        onDispatch: (command) => {
            if (!command.safety) return;
            safetyDispatches += 1;
            if (safetyDispatches > LIMITS.restoreAttempts) {
                throw new Error("force the complete unclaimed safety batch");
            }
        },
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(harness.core.record.phase, PHASES.noop);

    const noopMaximum = FIXTURES.sequence_capacity_policy.phase_vectors.find(
        (item) => item.phase === PHASES.noop,
    ).maximum_used_sequences;
    const allowedResumes = noopMaximum - harness.core.record.used_sequences.length;
    for (let index = 0; index < allowedResumes; index += 1) {
        const current = harness.core.record;
        const response = await harness.core.handleRequest(resumeRequest(current, {
            request_id: `tfpp-req-${(0x700 + index).toString(16).padStart(24, "0")}`,
            nonce: `tfpp-nonce-${(0x700 + index).toString(16).padStart(32, "0")}`,
            request_deadline_ms: NOW + 20_000 + index,
        }));
        assert.equal(response.accepted, true, index);
    }
    assert.equal(harness.core.record.used_sequences.length, noopMaximum);

    const beforeRejectedResume = structuredClone(harness.core.record);
    const commandBoundary = harness.commands.length;
    const rejected = await harness.core.handleRequest(resumeRequest(harness.core.record, {
        request_id: `tfpp-req-${"f".repeat(24)}`,
        nonce: `tfpp-nonce-${"f".repeat(32)}`,
        request_deadline_ms: NOW + 30_000,
    }));
    assert.equal(rejected.accepted, false);
    assert.equal(rejected.error_code, "sequence_bound");
    assert.deepEqual(harness.core.record, beforeRejectedResume);
    assert.equal(harness.commands.length, commandBoundary);

    const noopSequence = harness.core.record.expected_proof.sequence;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, noopSequence, 21));
    assert.equal(harness.core.record.phase, PHASES.challenge);
    assert.equal(
        LIMITS.usedSequences - harness.core.record.used_sequences.length,
        LIMITS.restoreAttempts + LIMITS.unclaimedSafetyAttempts,
    );
    const challengeSequence = harness.core.record.expected_proof.sequence;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, challengeSequence, 22));
    await fireTimer(harness);
    await fireTimer(harness);
    await fireTimer(harness);

    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.failure_code, "restore_exhausted");
    assert.equal(harness.core.record.used_sequences.length, LIMITS.usedSequences - 3);
    const safetyCommands = harness.commands.filter((command) => command.safety);
    assert.equal(safetyCommands.length, 6);
    assert.deepEqual(
        safetyCommands.map(({sequence, target}) => ({sequence, target})),
        [108, 109, 110, 111, 112, 113].map((sequence) => ({sequence, target: 21})),
    );
});

test("validates exact v2 recovery fields, deadlines, attempts, and old-schema rejection", () => {
    assert.deepEqual(validateRecoveryRecord(FIXTURES.armed_record), FIXTURES.armed_record);
    for (const mutation of [
        {schema: "true-family-physical-probe-state-v1"},
        {protocol_version: 1},
        {expected_proof_deadline_ms: 0},
        {restore_attempts: 1},
        {candidate_set_topic: "bad/#"},
        {unknown: true},
    ]) {
        assert.throws(() => validateRecoveryRecord({...FIXTURES.armed_record, ...mutation}), ProbeValidationError);
    }
});

test("shared sequence-capacity policy accepts each phase maximum and rejects one more", async () => {
    const policy = FIXTURES.sequence_capacity_policy;
    assert.equal(LIMITS.usedSequences, policy.maximum_used_sequences);
    assert.equal(LIMITS.restoreAttempts, policy.claimed_restore_attempts);
    assert.equal(LIMITS.unclaimedSafetyAttempts, policy.unclaimed_safety_attempts);
    const records = await journalEvidenceRecords();
    const bases = new Map([
        [`${PHASES.physical1}:0`, records.armed],
        [`${PHASES.physical2}:0`, records.physical2],
        [`${PHASES.noop}:0`, records.noop],
        [`${PHASES.challenge}:0`, records.challenge],
        [`${PHASES.restore}:1`, records.restore],
        [`${PHASES.restore}:2`, {...records.restore, restore_attempts: 2}],
        [`${PHASES.restore}:3`, {...records.restore, restore_attempts: 3}],
        [`${PHASES.result}:1`, records.result],
        [`${PHASES.quiescent}:1`, records.quiescent],
        [`${PHASES.remediation}:0`, FIXTURES.remediation_restore_record],
    ]);
    for (const vector of policy.phase_vectors) {
        const key = `${vector.phase}:${vector.restore_attempts}`;
        const base = structuredClone(bases.get(key));
        assert.ok(base, key);
        const used = [...base.used_sequences];
        for (let sequence = 1_000; used.length < vector.maximum_used_sequences; sequence += 1) {
            if (!used.includes(sequence)) used.push(sequence);
        }
        const maximum = validateRecoveryRecord({...base, used_sequences: used});
        assert.equal(maximum.used_sequences.length, vector.maximum_used_sequences, key);
        assert.throws(
            () => validateRecoveryRecord({
                ...base,
                used_sequences: [...used, 2_000],
            }),
            (error) => error instanceof ProbeValidationError && error.code === "sequence_bound",
            key,
        );
    }
});

test("generation limit permits only in-place safety remediation", async () => {
    const vector = FIXTURES.failure_generation_parity_vectors[1];
    const source = validateRecoveryRecord({
        ...FIXTURES.armed_record,
        generation: vector.source_generation,
    });
    const transition = coreHarness({record: source});
    await transition.core.start();
    await transition.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    assert.equal(transition.core.record.phase, PHASES.remediation);
    assert.equal(transition.core.record.generation, LIMITS.generation);
    assert.equal(transition.core.record.restore_required, false);

    const terminal = coreHarness({record: source});
    await terminal.core.start();
    await terminal.core.handleCandidateSet(SET_TOPIC);
    assert.equal(terminal.core.record.phase, PHASES.remediation);
    assert.equal(terminal.core.record.generation, LIMITS.generation);
    assert.equal(terminal.core.record.restore_required, false);

    const remediation = coreHarness({record: source});
    await remediation.core.start();
    remediation.core.latchQueueOverflow();
    await remediation.core.queue.drain();
    assert.equal(remediation.core.record.phase, PHASES.remediation);
    assert.equal(remediation.core.record.generation, vector.expected_generation);
    assert.equal(remediation.core.record.failure_code, vector.failure_code);
    assert.equal(remediation.core.record.cleanup_allowed, false);
    assert.equal(remediation.core.record.result_id, null);
});

test("challenged transition failures immediately restore unclaimed and remediate", async () => {
    for (const variant of ["generation", "journal"]) {
        const harness = coreHarness();
        await advanceToChallenge(harness);
        if (variant === "generation") {
            const exhausted = validateRecoveryRecord({
                ...harness.core.record,
                generation: LIMITS.generation,
            });
            harness.core.record = exhausted;
            harness.journal.record = exhausted;
        } else {
            harness.journal.failAt = harness.journal.writeAttempts + 1;
        }
        const commandBoundary = harness.commands.length;
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
        assert.equal(harness.core.record.phase, PHASES.remediation, variant);
        assert.equal(harness.journal.record.phase, PHASES.remediation, variant);
        assert.equal(harness.core.record.restore_required, true, variant);
        assert.equal(harness.core.record.result_id, null, variant);
        assert.equal(harness.core.record.cleanup_allowed, false, variant);
        assert.equal(harness.scheduler.activeCount(), 0, variant);
        assert.deepEqual(
            harness.commands.slice(commandBoundary).map(({target, purpose, safety}) => ({
                target,
                purpose,
                safety,
            })),
            [{target: 21, purpose: PURPOSES.restore, safety: true}],
            variant,
        );
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
        assert.equal(harness.core.record.phase, PHASES.remediation, variant);
    }
});

test("definite sequence allocation failures latch before any later proof progress", async () => {
    const prechallenge = coreHarness({nextSequence: () => 65_535});
    await armCore(prechallenge);
    await prechallenge.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await prechallenge.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(prechallenge.core.record.phase, PHASES.remediation);
    assert.equal(prechallenge.core.record.restore_required, false);
    assert.equal(prechallenge.core.record.result_id, null);
    assert.equal(prechallenge.commands.length, 0);
    assert.equal(prechallenge.scheduler.activeCount(), 0);

    const challenged = coreHarness();
    await advanceToChallenge(challenged);
    let allocation = 0;
    challenged.core.nextSequence = (used) => {
        allocation += 1;
        return allocation === 1 ? used[0] : 200 + allocation;
    };
    const commandBoundary = challenged.commands.length;
    await challenged.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(challenged.core.record.phase, PHASES.remediation);
    assert.equal(challenged.core.record.restore_required, true);
    assert.equal(challenged.core.record.result_id, null);
    assert.equal(challenged.scheduler.activeCount(), 0);
    assert.deepEqual(
        challenged.commands.slice(commandBoundary).map(({target, purpose, safety}) => ({
            target,
            purpose,
            safety,
        })),
        [{target: 21, purpose: PURPOSES.restore, safety: true}],
    );
});

test("runs the complete response-only physical, no-op, challenge, restore, and ack flow", async () => {
    const harness = coreHarness();
    const terminal = await advanceToResult(harness);
    assert.deepEqual(harness.commands.map(({sequence, target}) => ({sequence, target})), [
        {sequence: 100, target: 21},
        {sequence: 101, target: 22},
        {sequence: 102, target: 21},
    ]);
    assert.deepEqual(harness.commands.map((item) => item.durableGeneration), [3, 4, 5]);
    assert.equal(terminal.outcome, OUTCOMES.verified);
    assert.equal(terminal.restore_attempts, 1);
    assert.equal(terminal.result_id, FIXTURES.result.result_id);
    assert.equal(terminal.cleanup_allowed, false);
    await settle();
    const terminalStatus = harness.publications
        .filter((item) => item.topic === TOPICS.status)
        .at(-1).payload;
    assert.equal(terminalStatus.generation, terminal.generation);
    assert.equal(terminalStatus.result_id, terminal.result_id);
    harness.nowRef.value = terminal.result_not_before_ms;
    const response = await harness.core.handleRequest(ackRequest(terminal));
    assert.equal(response.accepted, true);
    assert.equal(harness.core.record.phase, PHASES.quiescent);
    assert.equal(harness.core.record.cleanup_allowed, true);
});

test("result settling permits only immediate final-restore duplicates", async () => {
    const immediate = coreHarness();
    const result = await advanceToResult(immediate);
    const duplicate = await immediate.core.handleFrame(
        frame(FRAME_KINDS.response, 102, 21),
    );
    assert.equal(duplicate.classification, "duplicate");
    assert.equal(immediate.core.record.phase, PHASES.result);

    const earlier = coreHarness();
    await advanceToResult(earlier);
    await earlier.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(earlier.core.record.phase, PHASES.remediation);
    assert.equal(earlier.core.record.cleanup_allowed, false);

    const expired = coreHarness();
    const expiredResult = await advanceToResult(expired);
    expired.nowRef.value = expiredResult.result_not_before_ms + 1;
    await expired.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
    assert.equal(expired.core.record.phase, PHASES.remediation);

    assert.equal(result.result_not_before_ms, NOW + LIMITS.resultSettleMs);
});

test("ACK is blocked during settling and accepted at the durable boundary", async () => {
    const harness = coreHarness();
    const result = await advanceToResult(harness);
    const early = await harness.core.handleRequest(ackRequest(result));
    assert.equal(early.accepted, false);
    assert.equal(early.error_code, "result_settling");
    assert.equal(harness.core.record.phase, PHASES.result);
    harness.nowRef.value = result.result_not_before_ms;
    const accepted = await harness.core.handleRequest(ackRequest(result));
    assert.equal(accepted.accepted, true);
    assert.equal(harness.core.record.phase, PHASES.quiescent);
    assert.equal(harness.core.record.result_not_before_ms, result.result_not_before_ms);
});

test("every previous-boot result fails into restore-only remediation", async () => {
    for (const name of ["verified_record", "failed_safe_record", "failed_restored_record"]) {
        const loaded = validateRecoveryRecord(FIXTURES[name]);
        const restarted = coreHarness({
            record: loaded,
            bootId: SECOND_BOOT,
            sequences: [200, 201, 202],
        });
        await restarted.core.start();
        assert.equal(restarted.core.record.phase, PHASES.remediation, name);
        assert.equal(restarted.core.record.result_id, null, name);
        assert.equal(restarted.core.record.cleanup_allowed, false, name);
        assert.equal(restarted.core.ready, false, name);
        assert.deepEqual(
            restarted.commands.map(({target, safety}) => ({target, safety})),
            [{target: loaded.intended_target, safety: true}],
            name,
        );
        assert.equal(restarted.publications.some((item) => item.topic === TOPICS.ready), false, name);
        assert.equal(restarted.publications.some((item) => item.topic === TOPICS.result), false, name);
        const staleAck = await restarted.core.handleRequest(ackRequest(loaded, {
            boot_id: SECOND_BOOT,
        }));
        assert.equal(staleAck.accepted, false, name);
        assert.equal(staleAck.phase, PHASES.remediation, name);
        assert.equal(restarted.core.record.cleanup_allowed, false, name);
    }
});

test("serializes a request behind startup before exposing readiness", async () => {
    const harness = coreHarness();
    const starting = harness.core.start();
    const requesting = harness.core.handleRequest(armRequest());
    await starting;
    const response = await requesting;
    assert.equal(response.accepted, true);
    assert.equal(harness.core.record.phase, PHASES.physical1);
    assert.equal(harness.publications.some((item) => item.topic === TOPICS.ready), true);
});

test("bounded queue decrements pending before sequential completion is observed", async () => {
    let overflows = 0;
    const queue = new BoundedSerialQueue(1, () => { overflows += 1; });
    const order = [];
    await queue.enqueue(async () => { order.push(1); });
    assert.equal(queue.pending, 0);
    await queue.enqueue(async () => { order.push(2); });
    assert.deepEqual(order, [1, 2]);
    assert.equal(overflows, 0);
    assert.equal(queue.pending, 0);
});

test("revalidates the exact candidate set topic before every command", async () => {
    const harness = coreHarness({
        onResolve: (_value, count, defaultResult) => ({
            ...defaultResult,
            set_topic: count === 4 ? "renamed-valve/set" : SET_TOPIC,
        }),
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(harness.commands.length, 0);
    assert.equal(harness.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(harness.core.record.failure_code, "dispatch_failed");
});

test("strict invocation deadline rejects late fulfilled no-op and challenge resolution", async () => {
    let noop;
    noop = coreHarness({
        onResolve: (_value, count, defaultResult) => {
            if (count === 4) {
                noop.nowRef.value = noop.core.record.expected_proof_deadline_ms
                    - ENDPOINT_COMMAND_TIMEOUT_MS;
            }
            return defaultResult;
        },
    });
    await armCore(noop);
    await noop.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await noop.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(noop.commands.length, 0);
    assert.equal(noop.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(noop.core.record.failure_code, "dispatch_failed");

    let challenge;
    challenge = coreHarness({
        onResolve: (_value, count, defaultResult) => {
            if (count === 5) {
                challenge.nowRef.value = challenge.core.record.expected_proof_deadline_ms
                    - ENDPOINT_COMMAND_TIMEOUT_MS;
            }
            return defaultResult;
        },
    });
    await armCore(challenge);
    await challenge.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await challenge.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await challenge.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    assert.equal(challenge.commands.some((item) => item.target === 22), false);
    assert.deepEqual(
        challenge.commands.map(({target, safety}) => ({target, safety})),
        [
            {target: 21, safety: false},
            {target: 21, safety: true},
        ],
    );
    assert.equal(challenge.core.record.phase, PHASES.restore);
});

test("failed-safe terminalization preserves and strictly bounds operation authority", async () => {
    const operationDeadline = NOW + 120_000;
    const valid = coreHarness();
    await armCore(valid);
    valid.nowRef.value = operationDeadline - LIMITS.resultSettleMs - 1;
    await valid.core.handleCandidateSet(SET_TOPIC);
    assert.equal(valid.core.record.phase, PHASES.result);
    assert.equal(valid.core.record.operation_deadline_ms, operationDeadline);
    assert.equal(valid.core.record.result_not_before_ms, operationDeadline - 1);

    for (const remaining of [LIMITS.resultSettleMs, LIMITS.resultSettleMs - 1]) {
        const harness = coreHarness();
        await armCore(harness);
        const publicationBoundary = harness.publications.length;
        harness.nowRef.value = operationDeadline - remaining;
        await harness.core.handleCandidateSet(SET_TOPIC);
        assert.equal(harness.core.record.phase, PHASES.remediation, remaining);
        assert.equal(harness.core.record.restore_required, false, remaining);
        assert.equal(harness.core.record.result_id, null, remaining);
        assert.equal(harness.core.record.cleanup_allowed, false, remaining);
        assert.equal(harness.core.record.operation_deadline_ms, operationDeadline, remaining);
        assert.equal(
            harness.publications.slice(publicationBoundary).some(
                (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
            ),
            false,
            remaining,
        );
    }
});

test("challenge responses claim restore only when the original deadline fits a full window", async () => {
    async function reachLateChallenge(harness, operationDeadline) {
        await armCore(harness, {operation_deadline_ms: operationDeadline});
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
        harness.nowRef.value = NOW + 12_000;
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
        harness.nowRef.value = NOW + 21_000;
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
        assert.equal(harness.core.record.phase, PHASES.challenge);
    }

    const earlyDeadline = NOW + 40_000;
    const early = coreHarness();
    await armCore(early, {operation_deadline_ms: earlyDeadline});
    await early.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await early.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await early.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    early.nowRef.value = NOW + 3_000;
    await early.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(early.core.record.phase, PHASES.restore);
    assert.equal(early.core.record.operation_deadline_ms, earlyDeadline);
    assert.equal(early.core.record.expected_proof_deadline_ms, NOW + 13_000);

    for (const [label, proofTime] of [
        ["near", NOW + 22_000],
        ["after", NOW + 30_001],
    ]) {
        const operationDeadline = NOW + 30_000;
        const harness = coreHarness();
        await reachLateChallenge(harness, operationDeadline);
        const commandBoundary = harness.commands.length;
        harness.nowRef.value = proofTime;
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
        assert.equal(harness.core.record.phase, PHASES.remediation, label);
        assert.equal(harness.core.record.operation_deadline_ms, operationDeadline, label);
        assert.equal(harness.core.record.restore_required, true, label);
        assert.equal(harness.core.record.result_id, null, label);
        assert.equal(harness.core.record.cleanup_allowed, false, label);
        assert.equal(harness.scheduler.activeCount(), 0, label);
        assert.deepEqual(
            harness.commands.slice(commandBoundary).map(({target, purpose, safety}) => ({
                target,
                purpose,
                safety,
            })),
            [{target: 21, purpose: PURPOSES.restore, safety: true}],
            label,
        );
    }
});

test("challenge timeout claims early restore but remediates unclaimed at original deadline", async () => {
    const early = coreHarness();
    const earlyDeadline = NOW + 120_000;
    await advanceToChallenge(early);
    await fireTimer(early);
    assert.equal(early.core.record.phase, PHASES.restore);
    assert.equal(early.core.record.operation_deadline_ms, earlyDeadline);
    assert.equal(
        early.core.record.expected_proof_deadline_ms,
        NOW + (2 * LIMITS.directProofMs),
    );

    const lateDeadline = NOW + 30_000;
    const late = coreHarness();
    await armCore(late, {operation_deadline_ms: lateDeadline});
    await late.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    late.nowRef.value = NOW + 12_000;
    await late.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    late.nowRef.value = NOW + 21_000;
    await late.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    const commandBoundary = late.commands.length;
    await fireTimer(late);
    assert.equal(late.nowRef.value, lateDeadline);
    assert.equal(late.core.record.phase, PHASES.remediation);
    assert.equal(late.core.record.operation_deadline_ms, lateDeadline);
    assert.equal(late.core.record.restore_required, true);
    assert.equal(late.core.record.result_id, null);
    assert.equal(late.scheduler.activeCount(), 0);
    assert.deepEqual(
        late.commands.slice(commandBoundary).map(({target, purpose, safety}) => ({
            target,
            purpose,
            safety,
        })),
        [{target: 21, purpose: PURPOSES.restore, safety: true}],
    );
});

test("claimed restore commit reaching its deadline immediately falls back unclaimed", async () => {
    const operationDeadline = NOW + 40_000;
    const nowRef = {value: NOW};
    const harness = coreHarness({
        nowRef,
        beforeWrite: (record) => {
            if (record.phase === PHASES.restore) nowRef.value = operationDeadline;
        },
    });
    await armCore(harness, {operation_deadline_ms: operationDeadline});
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    const commandBoundary = harness.commands.length;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.operation_deadline_ms, operationDeadline);
    assert.equal(harness.core.record.restore_required, true);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.scheduler.activeCount(), 0);
    assert.deepEqual(
        harness.commands.slice(commandBoundary).map(({target, purpose, safety}) => ({
            target,
            purpose,
            safety,
        })),
        [{target: 21, purpose: PURPOSES.restore, safety: true}],
    );
});

test("restore proof at strict settling boundary enters no-result remediation", async () => {
    const operationDeadline = NOW + 20_000;
    const harness = coreHarness();
    await armCore(harness, {operation_deadline_ms: operationDeadline});
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    harness.nowRef.value = NOW + 9_000;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    harness.nowRef.value = NOW + 10_000;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(harness.core.record.phase, PHASES.restore);
    const terminalOperationDeadline = harness.core.record.operation_deadline_ms;
    const publicationBoundary = harness.publications.length;
    harness.nowRef.value = terminalOperationDeadline - LIMITS.resultSettleMs;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, false);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.core.record.operation_deadline_ms, terminalOperationDeadline);
    assert.equal(
        harness.publications.slice(publicationBoundary).some(
            (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
        ),
        false,
    );
});

test("terminal journal time drift suppresses result and READY publication", async () => {
    for (const committedAt of [
        NOW + 120_000 - LIMITS.resultSettleMs,
        NOW + 120_000,
    ]) {
        const nowRef = {value: NOW};
        const harness = coreHarness({
            nowRef,
            beforeWrite: (record) => {
                if (record.phase === PHASES.result) nowRef.value = committedAt;
            },
        });
        await armCore(harness);
        const publicationBoundary = harness.publications.length;
        await harness.core.handleCandidateSet(SET_TOPIC);
        assert.equal(harness.core.record.phase, PHASES.remediation, committedAt);
        assert.equal(harness.core.record.restore_required, false, committedAt);
        assert.equal(harness.core.record.result_id, null, committedAt);
        assert.equal(harness.core.record.cleanup_allowed, false, committedAt);
        assert.equal(harness.core.record.operation_deadline_ms, NOW + 120_000, committedAt);
        assert.equal(
            harness.publications.slice(publicationBoundary).some(
                (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
            ),
            false,
            committedAt,
        );
    }
});

test("uncertain terminal result persistence chooses restore-required remediation", async () => {
    const harness = coreHarness({
        uncertainAt: 2,
        sequences: [200, 201, 202],
    });
    await armCore(harness);
    await harness.core.handleCandidateSet(SET_TOPIC);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, true);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("physical proof acceptance revalidates immutable identity and queue inspection", async () => {
    for (const variant of ["topic", "identity", "pending"]) {
        const harness = coreHarness({
            onResolve: (_value, count, defaultResult) => {
                if (count !== 2) return defaultResult;
                if (variant === "topic") return {...defaultResult, set_topic: "renamed-valve/set"};
                if (variant === "identity") {
                    return {
                        ...defaultResult,
                        candidate: {...defaultResult.candidate, ieee_address: "0xa4c1380000000002"},
                    };
                }
                throw new ProbeValidationError("pending_requests", "queue changed");
            },
        });
        await armCore(harness);
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
        assert.equal(harness.core.record.outcome, OUTCOMES.failedSafe, variant);
        assert.equal(harness.core.record.failure_code, "identity_mismatch", variant);
        assert.equal(harness.core.record.cleanup_allowed, false, variant);
        assert.equal(harness.commands.length, 0, variant);
    }
});

test("control drift fails safe before challenge and restores after challenge or result", async () => {
    const early = coreHarness();
    await armCore(early);
    await early.core.handleControlDrift();
    assert.equal(early.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(early.core.record.failure_code, "control_drift");
    assert.equal(early.commands.length, 0);

    const challenged = coreHarness();
    await advanceToChallenge(challenged);
    const challengeBoundary = challenged.commands.length;
    await challenged.core.handleControlDrift();
    assert.equal(challenged.core.record.phase, PHASES.restore);
    assert.deepEqual(
        challenged.commands.slice(challengeBoundary).map(({target, safety}) => ({target, safety})),
        [{target: 21, safety: true}],
    );

    const result = coreHarness();
    await advanceToResult(result);
    const resultBoundary = result.commands.length;
    await result.core.handleControlDrift();
    assert.equal(result.core.record.phase, PHASES.remediation);
    assert.deepEqual(
        result.commands.slice(resultBoundary).map(({target, safety}) => ({target, safety})),
        [{target: 21, safety: true}],
    );
});

test("timed-out delayed challenge resolver cannot invoke after restore advances", async () => {
    const challengeResolver = deferred();
    let dispatchRaces = 0;
    const harness = coreHarness({
        onResolve: (_value, count, defaultResult) => count === 5
            ? challengeResolver.promise.then(() => defaultResult)
            : defaultResult,
        dispatchRace: async (operation) => {
            dispatchRaces += 1;
            if (dispatchRaces === 2) {
                Promise.resolve(operation).catch(() => undefined);
                return {status: "timeout"};
            }
            await operation;
            return {status: "fulfilled"};
        },
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    assert.equal(harness.core.record.phase, PHASES.restore);
    assert.equal(harness.commands.some((item) => item.target === 22), false);
    assert.equal(harness.commands.at(-1).target, 21);
    challengeResolver.resolve();
    await settle();
    assert.equal(harness.commands.some((item) => item.target === 22), false);
});

test("delayed no-op resolver cannot invoke after overflow enters remediation", async () => {
    const noopResolver = deferred();
    const harness = coreHarness({
        onResolve: (_value, count, defaultResult) => count === 4
            ? noopResolver.promise.then(() => defaultResult)
            : defaultResult,
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    const advancing = harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    while (harness.resolved.length < 4) await settle();
    harness.core.latchQueueOverflow();
    noopResolver.resolve();
    await advancing;
    await harness.core.queue.drain();
    assert.equal(harness.commands.length, 0);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.ready, false);
});

test("default dispatch race preserves fulfilled values", async () => {
    const stopGate = deferred();
    const value = Object.freeze({kind: "dispatch-complete"});
    const outcome = await defaultDispatchRace(Promise.resolve(value), 1_000, stopGate.promise);
    assert.equal(outcome.status, "fulfilled");
    assert.equal(outcome.value, value);
});

test("a stale authorization with no endpoint invocation is not dispatch success", async () => {
    const harness = coreHarness({
        dispatchRace: async (operation) => {
            Promise.resolve(operation).catch(() => undefined);
            return {status: "fulfilled"};
        },
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await settle();
    assert.equal(harness.commands.length, 0);
    assert.equal(harness.core.record.phase, PHASES.result);
    assert.equal(harness.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(harness.core.record.failure_code, "dispatch_failed");
});

test("ignores companion frames but treats every DP2 dataReport as competing", async () => {
    const companion = coreHarness();
    await armCore(companion);
    await companion.core.handleFrame(fixtureFrame(FIXTURES.frames[2]));
    await companion.core.handleFrame(fixtureFrame(FIXTURES.frames[3]));
    assert.equal(companion.core.record.phase, PHASES.physical1);

    const report = coreHarness();
    await armCore(report);
    await report.core.handleFrame(fixtureFrame(FIXTURES.frames[1]));
    assert.equal(report.core.record.phase, PHASES.result);
    assert.equal(report.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(report.core.record.failure_code, "competing_frame");
    assert.equal(report.commands.length, 0);

    const unrelated = coreHarness();
    await advanceToChallenge(unrelated);
    const commandBoundary = unrelated.commands.length;
    await unrelated.core.handleFrame({
        device: {ieeeAddr: "0xa4c1380000000002"},
        endpoint: {ID: 1},
        cluster: "manuSpecificTuya",
        data: null,
    });
    assert.equal(unrelated.core.record.phase, PHASES.challenge);
    assert.equal(unrelated.core.remediationRequired, false);
    assert.equal(unrelated.commands.length, commandBoundary);
});

test("ignores exact normalized duplicates and rejects same-sequence semantic changes", async () => {
    const duplicate = coreHarness();
    await armCore(duplicate);
    await duplicate.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    const generation = duplicate.core.record.generation;
    const classification = await duplicate.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    assert.equal(classification.classification, "duplicate");
    assert.equal(duplicate.core.record.generation, generation);

    await duplicate.core.handleFrame(frame(FRAME_KINDS.response, 500, 21));
    assert.equal(duplicate.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(duplicate.core.record.failure_code, "competing_frame");
});

test("times out physical and no-op proofs without dispatching an unsafe command", async () => {
    const physical = coreHarness();
    await armCore(physical);
    const physicalTimer = await fireTimer(physical);
    assert.equal(physicalTimer.delay, LIMITS.physicalProofMs);
    assert.equal(physical.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(physical.commands.length, 0);

    const noop = coreHarness();
    await armCore(noop);
    await noop.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await noop.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(noop.commands.length, 1);
    const noopTimer = await fireTimer(noop);
    assert.equal(noopTimer.delay, LIMITS.directProofMs);
    assert.equal(noop.core.record.outcome, OUTCOMES.failedSafe);
});

test("challenge timeout restores and restore timeouts stop after three attempts", async () => {
    const harness = coreHarness();
    await advanceToChallenge(harness);
    await fireTimer(harness);
    assert.equal(harness.core.record.phase, PHASES.restore);
    assert.equal(harness.core.record.restore_attempts, 1);
    assert.deepEqual(harness.commands.at(-1), {
        ieeeAddress: IEEE,
        sequence: 102,
        target: 21,
        durableGeneration: 5,
        purpose: PURPOSES.restore,
        safety: true,
    });
    await fireTimer(harness);
    assert.equal(harness.core.record.restore_attempts, 2);
    await fireTimer(harness);
    assert.equal(harness.core.record.restore_attempts, 3);
    await fireTimer(harness);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.failure_code, "restore_exhausted");
    assert.equal(harness.commands.filter((item) => item.target === 21).length, 5);
    assert.equal(harness.commands.at(-1).safety, true);
});

test("queue overflow after challenge enters immediate unclaimed restore remediation", async () => {
    const harness = coreHarness();
    await advanceToChallenge(harness);
    harness.core.latchQueueOverflow();
    assert.equal(harness.core.remediationRequired, true);
    assert.equal(harness.core.safetyOnly, true);
    assert.equal(harness.core.ready, false);
    await harness.core.queue.drain();
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.failure_code, "queue_overflow");
    assert.equal(harness.core.remediationRequired, true);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.core.record.expected_proof, null);
    assert.deepEqual(
        harness.commands.slice(-1).map(({target, purpose, safety}) => ({target, purpose, safety})),
        [{target: 21, purpose: PURPOSES.restore, safety: true}],
    );
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, true);
});

test("overflow remediation does not depend on claimed restore scheduling", async () => {
    const scheduler = new FakeScheduler();
    const harness = coreHarness({scheduler});
    await advanceToChallenge(harness);
    const scheduledBeforeOverflow = scheduler.tasks.length;
    const commandsBeforeOverflow = harness.commands.length;
    harness.core.latchQueueOverflow();
    await harness.core.queue.drain();
    assert.equal(harness.commands.length, commandsBeforeOverflow + 1);
    assert.deepEqual(
        harness.commands.slice(commandsBeforeOverflow).map(({target, purpose, safety}) => ({target, purpose, safety})),
        [{target: 21, purpose: PURPOSES.restore, safety: true}],
    );
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.journal.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, true);
    assert.equal(harness.core.record.expected_proof, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.scheduler.activeCount(), 0);
    assert.equal(scheduler.tasks.length, scheduledBeforeOverflow);
});

test("overflow latch blocks queued terminal restore proof and future ACK authority", async () => {
    const resultWrite = deferred();
    let blockResultWrite = false;
    const harness = coreHarness({
        pendingLimit: 2,
        beforeWrite: async (_record, writeNumber) => {
            if (blockResultWrite && writeNumber === 6) await resultWrite.promise;
        },
    });
    await advanceToChallenge(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(harness.core.record.phase, PHASES.restore);
    blockResultWrite = true;
    const publicationBoundary = harness.publications.length;
    const commandBoundary = harness.commands.length;
    const terminalProof = harness.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
    while (harness.journal.writeAttempts < 6) await settle();
    const futureAck = harness.core.handleRequest(ackRequest(FIXTURES.verified_record));
    const dropped = harness.core.handleRequest(armRequest({
        request_id: SECOND_REQUEST,
        nonce: SECOND_NONCE,
    }));
    assert.equal(harness.core.remediationRequired, true);
    assert.equal(harness.core.safetyOnly, true);
    assert.equal(harness.core.ready, false);
    resultWrite.resolve();
    await terminalProof;
    const ackResponse = await futureAck;
    assert.equal(await dropped, undefined);
    await harness.core.queue.drain();
    assert.equal(ackResponse.accepted, false);
    assert.equal(ackResponse.phase, PHASES.remediation);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.deepEqual(
        harness.commands.slice(commandBoundary).map(({target, safety}) => ({target, safety})),
        [{target: 21, safety: true}],
    );
    assert.equal(
        harness.publications.slice(publicationBoundary).some(
            (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
        ),
        false,
    );
});

test("scheduler failure after challenge sends only an unclaimed restore", async () => {
    const scheduler = new FakeScheduler({
        failWhen: (_delay, tasks) => tasks.length === 3,
    });
    const harness = coreHarness({scheduler});
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    await harness.core.queue.drain();
    assert.equal(harness.commands.some((item) => item.target === 22), false);
    assert.deepEqual(
        harness.commands.map(({sequence, target, safety}) => ({sequence, target, safety})),
        [
            {sequence: 100, target: 21, safety: false},
            {sequence: 102, target: 21, safety: true},
        ],
    );
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, true);
});

test("unclaimed safety restore retries after sequence allocation failure", async () => {
    let allocations = 0;
    const harness = coreHarness({
        record: exhaustedRemediationRecord(),
        bootId: SECOND_BOOT,
        nextSequence: (used) => {
            allocations += 1;
            if (allocations === 1) throw new Error("allocator unavailable");
            assert.equal(used.includes(200), false);
            return 200;
        },
    });
    await harness.core.start();
    assert.equal(allocations, 2);
    assert.deepEqual(harness.commands.map(({sequence, target, safety}) => ({sequence, target, safety})), [
        {sequence: 200, target: 21, safety: true},
    ]);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("unclaimed safety restore retries resolver failure with a fresh sequence", async () => {
    const harness = coreHarness({
        record: exhaustedRemediationRecord(),
        bootId: SECOND_BOOT,
        sequences: [200, 201],
        onResolve: (_value, count, defaultResult) => {
            if (count === 1) throw new Error("resolver unavailable");
            return defaultResult;
        },
    });
    await harness.core.start();
    assert.equal(harness.resolved.length, 2);
    assert.deepEqual(harness.commands.map(({sequence, target, safety}) => ({sequence, target, safety})), [
        {sequence: 201, target: 21, safety: true},
    ]);
});

test("unclaimed endpoint rejection retries exactly three intended-target commands", async () => {
    const harness = coreHarness({
        record: exhaustedRemediationRecord(),
        bootId: SECOND_BOOT,
        sequences: [200, 201, 202],
        onDispatch: (command) => {
            assert.equal(command.target, 21);
            throw new Error("endpoint rejected");
        },
    });
    await harness.core.start();
    assert.equal(harness.commands.length, LIMITS.unclaimedSafetyAttempts);
    assert.deepEqual(harness.commands.map(({sequence, target, safety}) => ({sequence, target, safety})), [
        {sequence: 200, target: 21, safety: true},
        {sequence: 201, target: 21, safety: true},
        {sequence: 202, target: 21, safety: true},
    ]);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("unclaimed endpoint timeout retries boundedly and late calls remain intended-only", async () => {
    const dispatchGates = [];
    let safetyRaces = 0;
    let harness;
    harness = coreHarness({
        record: exhaustedRemediationRecord(),
        bootId: SECOND_BOOT,
        sequences: [200, 201, 202],
        onDispatch: (command) => {
            assert.equal(command.target, 21);
            const gate = deferred();
            dispatchGates.push(gate);
            return gate.promise;
        },
        timeoutRace: async (operation, timeoutMs) => {
            if (timeoutMs !== LIMITS.safetyRestoreMs) {
                return defaultTimeoutRace(operation, timeoutMs);
            }
            safetyRaces += 1;
            Promise.resolve(operation).catch(() => undefined);
            while (harness.commands.length < safetyRaces) await settle();
            return {status: "timeout"};
        },
    });
    await harness.core.start();
    assert.equal(safetyRaces, LIMITS.unclaimedSafetyAttempts);
    assert.deepEqual(harness.commands.map(({sequence, target, safety}) => ({sequence, target, safety})), [
        {sequence: 200, target: 21, safety: true},
        {sequence: 201, target: 21, safety: true},
        {sequence: 202, target: 21, safety: true},
    ]);
    for (const gate of dispatchGates) gate.resolve();
    await settle();
    assert.equal(harness.commands.every((item) => item.target === 21), true);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("restore-required remediation restart is restore-only and never command-ready", async () => {
    const normal = coreHarness({
        record: validateRecoveryRecord(FIXTURES.remediation_restore_record),
        bootId: SECOND_BOOT,
        sequences: [200],
    });
    await normal.core.start();
    assert.equal(normal.core.record.phase, PHASES.restore);
    assert.equal(normal.core.ready, false);
    assert.equal(normal.core.safetyOnly, true);
    assert.equal(normal.publications.some((item) => item.topic === TOPICS.ready), false);
    assert.deepEqual(normal.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
    const recoveredProof = await normal.core.handleFrame(frame(
        FRAME_KINDS.response,
        normal.core.record.expected_proof.sequence,
        21,
    ));
    assert.equal(recoveredProof?.purpose, PURPOSES.restore);
    assert.equal(normal.core.record.phase, PHASES.remediation);
    assert.equal(normal.core.record.restore_required, false);

    const exhaustedRecord = validateRecoveryRecord({
        ...FIXTURES.remediation_restore_record,
        restore_attempts: LIMITS.restoreAttempts,
    });
    const exhausted = coreHarness({
        record: exhaustedRecord,
        bootId: SECOND_BOOT,
        sequences: [300],
    });
    await exhausted.core.start();
    assert.equal(exhausted.core.record.phase, PHASES.remediation);
    assert.equal(exhausted.core.record.restore_required, true);
    assert.equal(exhausted.core.ready, false);
    assert.deepEqual(exhausted.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("durable remediation-after-restore intent survives two restarts", async () => {
    const first = coreHarness({
        record: validateRecoveryRecord(FIXTURES.remediation_claimed_restore_record),
        bootId: SECOND_BOOT,
    });
    await first.core.start();
    assert.equal(first.core.record.phase, PHASES.restore);
    assert.equal(first.core.record.remediation_after_restore, true);
    assert.equal(first.core.record.bound_boot_id, SECOND_BOOT);
    assert.equal(first.publications.some((item) => item.topic === TOPICS.ready), false);

    const second = coreHarness({
        record: first.journal.record,
        bootId: THIRD_BOOT,
    });
    await second.core.start();
    assert.equal(second.core.record.phase, PHASES.restore);
    assert.equal(second.core.record.remediation_after_restore, true);
    assert.equal(second.core.record.bound_boot_id, THIRD_BOOT);
    const sequence = second.core.record.expected_proof.sequence;
    await second.core.handleFrame(frame(FRAME_KINDS.response, sequence, 21));
    assert.equal(second.core.record.phase, PHASES.remediation);
    assert.equal(second.core.record.restore_required, false);
    assert.equal(second.core.record.cleanup_allowed, false);
    assert.equal(second.core.ready, false);
    assert.equal(second.publications.some((item) => item.topic === TOPICS.ready), false);
});

test("dispatch timeout fails safe before challenge and falls back unclaimed after challenge", async () => {
    const timeoutRace = async () => ({status: "timeout"});
    const preChallenge = coreHarness({dispatchRace: timeoutRace});
    await armCore(preChallenge);
    await preChallenge.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await preChallenge.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(preChallenge.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(preChallenge.core.record.failure_code, "dispatch_timeout");

    let calls = 0;
    const afterChallenge = coreHarness({
        dispatchRace: async (operation) => {
            await operation;
            calls += 1;
            return calls === 1 ? {status: "fulfilled"} : {status: "timeout"};
        },
    });
    await armCore(afterChallenge);
    await afterChallenge.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await afterChallenge.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    await afterChallenge.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    assert.equal(afterChallenge.core.record.phase, PHASES.remediation);
    assert.equal(afterChallenge.core.record.failure_code, "dispatch_timeout");
    assert.equal(afterChallenge.core.record.restore_attempts, 1);
    assert.equal(afterChallenge.core.record.restore_required, true);
    assert.equal(afterChallenge.core.record.result_id, null);
    assert.equal(afterChallenge.core.record.cleanup_allowed, false);
    assert.equal(afterChallenge.scheduler.activeCount(), 0);
    assert.deepEqual(
        afterChallenge.commands.slice(-2).map(({target, purpose, safety}) => ({
            target,
            purpose,
            safety,
        })),
        [
            {target: 21, purpose: PURPOSES.restore, safety: true},
            {target: 21, purpose: PURPOSES.restore, safety: true},
        ],
    );
});

test("publication rejection or non-settlement never gates persistence or command dispatch", async () => {
    const rejected = coreHarness({onPublish: async () => { throw new Error("offline"); }});
    await advanceToChallenge(rejected);
    assert.equal(rejected.commands.length, 2);

    const never = deferred();
    const pending = coreHarness({onPublish: () => never.promise});
    await advanceToChallenge(pending);
    assert.equal(pending.commands.length, 2);
    pending.core.requestStop();
    never.resolve();
    await pending.core.stop();
});

test("safety state cancels stale READY retries while status remains authoritative", async () => {
    const readyGate = deferred();
    let readyAttempts = 0;
    let timeoutReady = false;
    const harness = coreHarness({
        onPublish: (topic) => {
            if (topic === TOPICS.ready) {
                readyAttempts += 1;
                if (readyAttempts === 1) {
                    timeoutReady = true;
                    return readyGate.promise;
                }
            }
        },
        timeoutRace: async (operation, timeoutMs) => {
            if (timeoutMs === LIMITS.publicationMs && timeoutReady) {
                timeoutReady = false;
                Promise.resolve(operation).catch(() => undefined);
                return {status: "timeout"};
            }
            return defaultTimeoutRace(operation, timeoutMs);
        },
    });
    await harness.core.start();
    await settle();
    assert.equal(readyAttempts, 1);
    assert.equal(harness.scheduler.activeCount(), 1);
    harness.core.latchQueueOverflow();
    await harness.core.queue.drain();
    assert.equal(harness.scheduler.activeCount(), 0);
    readyGate.resolve();
    await settle();
    assert.equal(readyAttempts, 1);
    const status = harness.publications
        .filter((item) => item.topic === TOPICS.status)
        .at(-1).payload;
    assert.equal(status.phase, PHASES.remediation);
});

test("retries result publication until durable acknowledgement", async () => {
    const harness = coreHarness();
    const result = await advanceToResult(harness);
    await settle();
    const before = harness.publications.filter((item) => item.topic === TOPICS.result).length;
    assert.equal(before, 1);
    await fireTimer(harness);
    const retried = harness.publications.filter((item) => item.topic === TOPICS.result).length;
    assert.equal(retried, 2);
    await harness.core.handleRequest(ackRequest(result));
    assert.equal(harness.scheduler.activeCount(), 0);
});

test("synchronous stop prevents queued callbacks and every later command", async () => {
    const harness = coreHarness();
    await armCore(harness);
    const queued = harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    harness.core.requestStop();
    await queued;
    await harness.core.stop();
    assert.equal(harness.commands.length, 0);
    assert.equal(harness.core.record.phase, PHASES.physical1);
});

test("stop while awaiting challenge proof persists restore and places safety restore last", async () => {
    const harness = coreHarness();
    await advanceToChallenge(harness);
    await harness.core.stop();
    assert.deepEqual(harness.commands.slice(-2).map(({target, safety}) => ({target, safety})), [
        {target: 22, safety: false},
        {target: 21, safety: true},
    ]);
    assert.equal(harness.core.record.phase, PHASES.restore);
    assert.equal(harness.core.record.restore_required, true);
    assert.equal(harness.core.stopped, true);
});

test("stop during challenge dispatch waits boundedly and tolerates late completion", async () => {
    const challengeGate = deferred();
    let stopDrainTimedOut = false;
    const timeoutRace = async (operation, timeoutMs) => {
        if (timeoutMs === LIMITS.stopDrainMs && !stopDrainTimedOut) {
            stopDrainTimedOut = true;
            Promise.resolve(operation).catch(() => undefined);
            return {status: "timeout"};
        }
        return defaultTimeoutRace(operation, timeoutMs);
    };
    const harness = coreHarness({
        timeoutRace,
        onDispatch: (command) => command.purpose === PURPOSES.challenge
            ? challengeGate.promise
            : undefined,
    });
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    const challengeProcessing = harness.core.handleFrame(
        frame(FRAME_KINDS.response, 100, 21),
    );
    while (!harness.commands.some((item) => item.purpose === PURPOSES.challenge)) {
        await settle();
    }
    const stopping = harness.core.stop();
    await challengeProcessing;
    await stopping;
    assert.deepEqual(harness.commands.slice(-2).map(({target, purpose}) => ({target, purpose})), [
        {target: 22, purpose: PURPOSES.challenge},
        {target: 21, purpose: PURPOSES.restore},
    ]);
    const commandCount = harness.commands.length;
    challengeGate.resolve();
    await settle();
    assert.equal(harness.commands.length, commandCount);
});

test("stop completes when its intended-target safety dispatch rejects", async () => {
    const harness = coreHarness({
        onDispatch: (command) => {
            if (command.safety) throw new Error("restore transport failed");
        },
    });
    await advanceToChallenge(harness);
    await harness.core.stop();
    assert.equal(harness.core.stopped, true);
    assert.equal(harness.core.record.phase, PHASES.restore);
    assert.equal(harness.commands.at(-1).target, 21);
    assert.equal(harness.commands.at(-1).safety, true);
});

test("concurrent stop request does not duplicate in-flight unclaimed safety work", async () => {
    let harness;
    harness = coreHarness({
        uncertainAt: 5,
        beforeWrite: (_record, writeNumber) => {
            if (writeNumber === 5) harness.core.requestStop();
        },
    });
    await advanceToChallenge(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    await Promise.all([harness.core.stop(), harness.core.stop()]);
    const safetyCommands = harness.commands.filter((item) => item.safety);
    assert.deepEqual(safetyCommands.map(({sequence, target}) => ({sequence, target})), [
        {sequence: 103, target: 21},
    ]);
    assert.equal(harness.core.stopSafetyIssued, true);
    assert.equal(harness.core.stopped, true);
});

test("stop keeps durable intent and does not claim a zero-invocation restore", async () => {
    const harness = coreHarness({
        onResolve: (_value, count, defaultResult) => {
            if (count >= 6) throw new Error("resolver unavailable");
            return defaultResult;
        },
    });
    await advanceToChallenge(harness);
    await harness.core.stop();
    assert.equal(harness.core.stopSafetyIssued, false);
    assert.equal(harness.core.record.phase, PHASES.restore);
    assert.equal(harness.core.record.restore_required, true);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.commands.filter((item) => item.safety).length, 0);

    const restarted = coreHarness({
        record: harness.journal.record,
        bootId: SECOND_BOOT,
    });
    await restarted.core.start();
    assert.deepEqual(restarted.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("stop wins a hanging dispatch race and late rejection remains observed", async () => {
    const gate = deferred();
    const harness = coreHarness({onDispatch: () => gate.promise});
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    const processing = harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    while (harness.commands.length === 0) await settle();
    harness.core.requestStop();
    await processing;
    gate.reject(new Error("late failure"));
    await settle();
    await harness.core.stop();
    assert.equal(harness.commands.length, 1);
});

test("restart from challenge sends restore only and never resends the challenge", async () => {
    const first = coreHarness();
    const challenge = await advanceToChallenge(first);
    const restarted = coreHarness({record: challenge, bootId: SECOND_BOOT, sequences: [200]});
    await restarted.core.start();
    assert.deepEqual(restarted.commands, [{
        ieeeAddress: IEEE,
        sequence: 200,
        target: 21,
        durableGeneration: challenge.generation + 1,
        purpose: PURPOSES.restore,
        safety: true,
    }]);
    assert.equal(restarted.core.record.failure_code, "restart_recovery");
    assert.equal(restarted.core.record.restore_attempts, 1);
    assert.equal(restarted.core.record.operation_deadline_ms, challenge.operation_deadline_ms);
});

test("restart from restore reuses the persisted sequence without consuming an attempt", async () => {
    const first = coreHarness();
    await advanceToChallenge(first);
    await first.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    const restoring = first.core.record;
    const restarted = coreHarness({record: restoring, bootId: SECOND_BOOT});
    await restarted.core.start();
    assert.deepEqual(restarted.commands.map(({sequence, target}) => ({sequence, target})), [
        {sequence: restoring.expected_proof.sequence, target: 21},
    ]);
    assert.equal(restarted.core.record.restore_attempts, restoring.restore_attempts);
    assert.equal(restarted.core.record.bound_boot_id, SECOND_BOOT);
    assert.equal(restarted.core.record.operation_deadline_ms, restoring.operation_deadline_ms);
});

test("restart after original deadline uses unclaimed restore and durable remediation", async () => {
    const first = coreHarness();
    const challenge = await advanceToChallenge(first);
    await first.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    const restoring = first.core.record;

    for (const [label, source] of [["challenge", challenge], ["restore", restoring]]) {
        const nowRef = {value: source.operation_deadline_ms + 1};
        const restarted = coreHarness({
            record: source,
            bootId: SECOND_BOOT,
            nowRef,
            sequences: [200, 201, 202],
        });
        await restarted.core.start();
        assert.equal(restarted.core.record.phase, PHASES.remediation, label);
        assert.equal(
            restarted.core.record.operation_deadline_ms,
            source.operation_deadline_ms,
            label,
        );
        assert.equal(restarted.core.record.restore_required, true, label);
        assert.equal(restarted.core.record.result_id, null, label);
        assert.equal(restarted.core.record.cleanup_allowed, false, label);
        assert.equal(restarted.scheduler.activeCount(), 0, label);
        assert.deepEqual(
            restarted.commands.map(({target, purpose, safety}) => ({target, purpose, safety})),
            [{target: 21, purpose: PURPOSES.restore, safety: true}],
            label,
        );
        assert.equal(
            restarted.publications.some(
                (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
            ),
            false,
            label,
        );
    }
});

test("restore proof after original deadline cannot create a result or cleanup authority", async () => {
    const first = coreHarness();
    await advanceToChallenge(first);
    await first.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    const restoring = first.core.record;
    const restarted = coreHarness({
        record: restoring,
        bootId: SECOND_BOOT,
        sequences: [200, 201, 202],
    });
    await restarted.core.start();
    const restoreSequence = restarted.core.record.expected_proof.sequence;
    const publicationBoundary = restarted.publications.length;
    restarted.nowRef.value = restoring.operation_deadline_ms + 1;
    await restarted.core.handleFrame(
        frame(FRAME_KINDS.response, restoreSequence, 21),
    );
    assert.equal(restarted.core.record.phase, PHASES.remediation);
    assert.equal(
        restarted.core.record.operation_deadline_ms,
        restoring.operation_deadline_ms,
    );
    assert.equal(restarted.core.record.restore_required, true);
    assert.equal(restarted.core.record.result_id, null);
    assert.equal(restarted.core.record.cleanup_allowed, false);
    assert.equal(restarted.scheduler.activeCount(), 0);
    assert.equal(
        restarted.publications.slice(publicationBoundary).some(
            (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
        ),
        false,
    );
});

test("definite startup recovery write failure sends one unclaimed restore then persists remediation", async () => {
    const first = coreHarness();
    const challenge = await advanceToChallenge(first);
    const restarted = coreHarness({
        record: challenge,
        bootId: SECOND_BOOT,
        failAt: 1,
        sequences: [200, 201],
    });
    await restarted.core.start();
    assert.equal(restarted.core.remediationRequired, true);
    assert.deepEqual(restarted.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
    assert.equal(restarted.core.ready, false);
    assert.equal(restarted.journal.record.phase, PHASES.remediation);
    assert.equal(restarted.journal.record.restore_required, true);
});

test("journal load failure starts in remediation and accepts no command-capable request", async () => {
    const harness = coreHarness({loadError: new ProbeJournalError("corrupt")});
    await harness.core.start();
    assert.equal(harness.core.remediationRequired, true);
    const response = await harness.core.handleRequest(armRequest());
    assert.equal(response.accepted, false);
    assert.equal(response.phase, PHASES.remediation);
    assert.equal(harness.commands.length, 0);
});

test("post-rename uncertainty before challenge latches remediation and sends no command", async () => {
    const harness = coreHarness({uncertainAt: 1});
    await harness.core.start();
    const response = await harness.core.handleRequest(armRequest());
    assert.equal(response.accepted, true);
    assert.equal(response.error_code, "journal_uncertain");
    assert.equal(harness.core.remediationRequired, true);
    assert.equal(harness.commands.length, 0);
});

test("post-rename uncertainty after challenge permits only an unclaimed intended-target restore", async () => {
    const harness = coreHarness({uncertainAt: 5});
    await advanceToChallenge(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(harness.core.remediationRequired, true);
    assert.deepEqual(harness.commands.map(({sequence, target}) => ({sequence, target})), [
        {sequence: 100, target: 21},
        {sequence: 101, target: 22},
        {sequence: 103, target: 21},
    ]);
    assert.equal(harness.journal.record.phase, PHASES.remediation);
    assert.equal(harness.journal.record.restore_required, true);
});

test("restore write timeout skips reconciliation load and invokes intended safety", async () => {
    const writeGate = deferred();
    let journalOperation = 0;
    const timeoutRace = async (operation, timeoutMs) => {
        if (timeoutMs === LIMITS.journalMs) {
            journalOperation += 1;
            if (journalOperation === 6) {
                Promise.resolve(operation).catch(() => undefined);
                return {status: "timeout"};
            }
        }
        return defaultTimeoutRace(operation, timeoutMs);
    };
    const harness = coreHarness({
        timeoutRace,
        beforeWrite: (_record, writeNumber) => writeNumber === 5
            ? writeGate.promise
            : undefined,
    });
    await advanceToChallenge(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 101, 22));
    assert.equal(harness.core.remediationRequired, true);
    assert.equal(harness.core.journalBlocked, true);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.scheduler.activeCount(), 0);
    assert.equal(journalOperation, 6);
    assert.deepEqual(harness.commands.map(({target, purpose}) => ({target, purpose})), [
        {target: 21, purpose: PURPOSES.noop},
        {target: 22, purpose: PURPOSES.challenge},
        {target: 21, purpose: PURPOSES.restore},
    ]);
    assert.equal(harness.journal.writeAttempts, 5);
    const count = harness.commands.length;
    writeGate.resolve();
    while (harness.journal.record.phase !== PHASES.restore) await settle();
    assert.equal(harness.commands.length, count);
    assert.equal(harness.commands.filter((item) => item.target === 22).length, 1);
    assert.equal(harness.core.remediationRequired, true);
    assert.equal(harness.journal.writeAttempts, 5);
});

test("a definite active transition persistence failure latches no-result remediation", async () => {
    const harness = coreHarness({failAt: 3});
    await armCore(harness);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
    assert.equal(harness.commands.length, 0);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.journal.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, false);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.scheduler.activeCount(), 0);
    await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.commands.length, 0);
});

test("competing report plus definite fail-safe write error cannot later verify", async () => {
    const harness = coreHarness({failAt: 2});
    await armCore(harness);
    const publicationBoundary = harness.publications.length;
    await harness.core.handleFrame(frame(FRAME_KINDS.report, 700, 18));
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.journal.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, false);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.scheduler.activeCount(), 0);
    for (const candidateFrame of [
        frame(FRAME_KINDS.response, 500, 18),
        frame(FRAME_KINDS.response, 501, 21),
        frame(FRAME_KINDS.response, 100, 21),
        frame(FRAME_KINDS.response, 101, 22),
        frame(FRAME_KINDS.response, 102, 21),
    ]) await harness.core.handleFrame(candidateFrame);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.commands.length, 0);
    assert.equal(
        harness.publications.slice(publicationBoundary).some(
            (item) => item.topic === TOPICS.result || item.topic === TOPICS.ready,
        ),
        false,
    );
});

test("candidate-write and control fail-safe write errors latch remediation", async () => {
    for (const kind of ["candidate-write", "control"]) {
        const harness = coreHarness({failAt: 2});
        await armCore(harness);
        if (kind === "candidate-write") await harness.core.handleCandidateSet(SET_TOPIC);
        else await harness.core.handleControlDrift();
        assert.equal(harness.core.record.phase, PHASES.remediation, kind);
        assert.equal(harness.journal.record.phase, PHASES.remediation, kind);
        assert.equal(harness.core.record.restore_required, false, kind);
        assert.equal(harness.core.record.result_id, null, kind);
        assert.equal(harness.core.record.cleanup_allowed, false, kind);
        assert.equal(harness.scheduler.activeCount(), 0, kind);
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
        assert.equal(harness.core.record.phase, PHASES.remediation, kind);
    }
});

test("writer-fence observation fails safe before challenge", async () => {
    const harness = coreHarness();
    await armCore(harness);
    await harness.core.handleCandidateSet(SET_TOPIC);
    assert.equal(harness.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(harness.core.record.failure_code, "competing_write");
    assert.equal(harness.commands.length, 0);
});

test("friendly and IEEE write aliases trigger active drift", async () => {
    for (const topic of [
        "candidate-valve/set/system_mode",
        `${IEEE}/1/set/occupied_heating_setpoint`,
        "candidate-valve/ 1/set/current_heating_setpoint/deep/path",
        `${IEEE}/0x1/set/current_heating_setpoint`,
        "candidate-valve/\t\v\f\r\n1/set/current_heating_setpoint",
    ]) {
        const harness = coreHarness();
        await armCore(harness);
        await harness.core.handleCandidateSet(topic);
        assert.equal(harness.core.record.phase, PHASES.result, topic);
        assert.equal(harness.core.record.failure_code, "competing_write", topic);
        assert.equal(harness.commands.length, 0, topic);
    }
});

test("writer-fence observation after challenge restores then requires remediation", async () => {
    const harness = coreHarness();
    await advanceToChallenge(harness);
    await harness.core.handleCandidateSet(SET_TOPIC);
    assert.equal(harness.core.record.phase, PHASES.restore);
    assert.equal(harness.commands.at(-1).target, 21);
    const sequence = harness.core.record.expected_proof.sequence;
    await harness.core.handleFrame(frame(FRAME_KINDS.response, sequence, 21));
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("writer-fence observation invalidates a pending result and cannot produce a second success", async () => {
    const harness = coreHarness();
    await advanceToResult(harness);
    await harness.core.handleCandidateSet(SET_TOPIC);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.commands.at(-1).target, 21);
    assert.equal(harness.commands.at(-1).safety, true);
});

test("candidate-relevant malformed DP2 supersedes every pending result", async () => {
    const validDatapoint = buildTuyaCommand(0, 21).payload.dpValues[0];
    const malformedFrames = [
        ["target-range", frame(FRAME_KINDS.response, 700, 21, {
            data: {
                seq: 700,
                dpValues: [{...validDatapoint, data: Buffer.from([0, 0, 0, 36])}],
            },
        })],
        ["datatype", frame(FRAME_KINDS.response, 701, 21, {
            data: {seq: 701, dpValues: [{...validDatapoint, datatype: 1}]},
        })],
        ["data-length", frame(FRAME_KINDS.response, 702, 21, {
            data: {
                seq: 702,
                dpValues: [{...validDatapoint, data: Buffer.from([0, 0, 21])}],
            },
        })],
        ["multi-dp", frame(FRAME_KINDS.response, 703, 21, {
            data: {
                seq: 703,
                dpValues: [validDatapoint, {dp: 5, datatype: 4, data: Buffer.from([0])}],
            },
        })],
        ["unknown-fields", frame(FRAME_KINDS.response, 704, 21, {
            data: {seq: 704, dpValues: [validDatapoint], unknown: true},
        })],
        ["sequence", frame(FRAME_KINDS.response, 705, 21, {
            data: {seq: true, dpValues: [validDatapoint]},
        })],
        ["report", frame(FRAME_KINDS.report, 706, 21)],
        ["group", frame(FRAME_KINDS.response, 707, 21, {groupID: 1})],
    ];
    for (const [label, malformedFrame] of malformedFrames) {
        const harness = coreHarness();
        const result = await advanceToResult(harness);
        const commandBoundary = harness.commands.length;
        await harness.core.handleFrame(malformedFrame);
        assert.equal(harness.core.record.phase, PHASES.remediation, label);
        assert.equal(harness.core.record.failure_code, "competing_frame", label);
        assert.equal(harness.core.record.result_id, null, label);
        assert.equal(harness.core.record.cleanup_allowed, false, label);
        assert.deepEqual(
            harness.commands.slice(commandBoundary).map(({target, purpose, safety}) => ({
                target,
                purpose,
                safety,
            })),
            [{target: 21, purpose: PURPOSES.restore, safety: true}],
            label,
        );
        const staleAck = await harness.core.handleRequest(ackRequest(result));
        assert.equal(staleAck.accepted, false, label);
        assert.equal(harness.core.record.phase, PHASES.remediation, label);
    }
});

test("unrelated non-DP and noncandidate traffic leaves a pending result intact", async () => {
    const harness = coreHarness();
    const result = await advanceToResult(harness);
    const commandBoundary = harness.commands.length;
    const unrelatedFrames = [
        frame(FRAME_KINDS.response, 700, 21, {
            data: {
                seq: 700,
                dpValues: [{dp: 5, datatype: 4, data: Buffer.from([0])}],
            },
        }),
        frame(FRAME_KINDS.response, 701, 21, {
            device: {ieeeAddr: "0xa4c1380000000002"},
        }),
        frame(FRAME_KINDS.response, 702, 21, {cluster: "genOnOff"}),
    ];
    for (const unrelatedFrame of unrelatedFrames) {
        assert.equal(await harness.core.handleFrame(unrelatedFrame), null);
        assert.deepEqual(harness.core.record, result);
    }
    assert.equal(harness.commands.length, commandBoundary);
});

test("result drift retains capacity for all three unclaimed safety attempts", async () => {
    const maximum = FIXTURES.sequence_capacity_policy.phase_vectors.find(
        (item) => item.phase === PHASES.result,
    ).maximum_used_sequences;
    const result = withUsedSequenceCount(FIXTURES.verified_record, maximum);
    const harness = coreHarness({
        record: result,
        sequences: [200, 201, 202],
        onDispatch: () => {
            throw new Error("exercise every unclaimed attempt");
        },
    });
    await harness.core.start();
    await harness.core.handleCandidateSet(SET_TOPIC);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.used_sequences.length, maximum);
    assert.deepEqual(
        harness.commands.map(({sequence, target, purpose, safety}) => ({
            sequence,
            target,
            purpose,
            safety,
        })),
        [200, 201, 202].map((sequence) => ({
            sequence,
            target: 21,
            purpose: PURPOSES.restore,
            safety: true,
        })),
    );
});

test("restart records at sequence capacity retain claimed and unclaimed recovery", async () => {
    const records = await journalEvidenceRecords();
    const challengeMaximum = FIXTURES.sequence_capacity_policy.phase_vectors.find(
        (item) => item.phase === PHASES.challenge,
    ).maximum_used_sequences;
    const challenge = withUsedSequenceCount(records.challenge, challengeMaximum);
    const claimed = coreHarness({
        record: challenge,
        bootId: SECOND_BOOT,
        sequences: [200],
    });
    await claimed.core.start();
    assert.equal(claimed.core.record.phase, PHASES.restore);
    assert.equal(claimed.core.record.used_sequences.length, challengeMaximum + 1);
    assert.deepEqual(
        claimed.commands.map(({sequence, target, safety}) => ({sequence, target, safety})),
        [{sequence: 200, target: 21, safety: true}],
    );

    const resultMaximum = FIXTURES.sequence_capacity_policy.phase_vectors.find(
        (item) => item.phase === PHASES.result,
    ).maximum_used_sequences;
    const result = withUsedSequenceCount(records.result, resultMaximum);
    const unclaimed = coreHarness({
        record: result,
        bootId: SECOND_BOOT,
        sequences: [200, 201, 202],
        onDispatch: () => {
            throw new Error("exercise every restart safety attempt");
        },
    });
    await unclaimed.core.start();
    assert.equal(unclaimed.core.record.phase, PHASES.remediation);
    assert.equal(unclaimed.core.ready, false);
    assert.deepEqual(
        unclaimed.commands.map(({sequence, target, safety}) => ({sequence, target, safety})),
        [200, 201, 202].map((sequence) => ({sequence, target: 21, safety: true})),
    );
});

test("all failed pending-result variants drift directly to remediation with unclaimed restore", async () => {
    for (const recordName of ["failed_safe_record", "failed_restored_record"]) {
        const harness = coreHarness({
            record: validateRecoveryRecord(FIXTURES[recordName]),
            sequences: [200],
        });
        await harness.core.start();
        await harness.core.handleCandidateSet(SET_TOPIC);
        assert.equal(harness.core.record.phase, PHASES.remediation, recordName);
        assert.equal(harness.core.record.cleanup_allowed, false, recordName);
        assert.equal(harness.core.record.result_id, null, recordName);
        assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
            {target: 21, safety: true},
        ], recordName);
    }
});

test("all result variants fail closed on friendly and IEEE alias drift", async () => {
    const variants = ["verified_record", "failed_safe_record", "failed_restored_record"];
    const aliases = [
        "candidate-valve/\r\n1/set/system_mode/deep/path",
        `${IEEE}/\t1\v/set/system_mode`,
    ];
    for (const [index, recordName] of variants.entries()) {
        const harness = coreHarness({
            record: validateRecoveryRecord(FIXTURES[recordName]),
            sequences: [200 + index],
        });
        await harness.core.start();
        await harness.core.handleCandidateSet(aliases[index % aliases.length]);
        assert.equal(harness.core.record.phase, PHASES.remediation, recordName);
        assert.equal(harness.core.record.result_id, null, recordName);
        assert.equal(harness.core.record.cleanup_allowed, false, recordName);
        assert.equal(harness.commands.at(-1).target, 21, recordName);
        assert.equal(harness.commands.at(-1).safety, true, recordName);
    }
});

test("failed result-remediation persistence poisons memory and stale restart result", async () => {
    for (const [index, recordName] of [
        "verified_record",
        "failed_safe_record",
        "failed_restored_record",
    ].entries()) {
        const staleResult = validateRecoveryRecord(FIXTURES[recordName]);
        const poisoned = coreHarness({
            record: staleResult,
            failAt: 1,
            sequences: [210 + index],
        });
        await poisoned.core.start();
        await poisoned.core.handleCandidateSet(`${IEEE}/set/system_mode`);
        assert.equal(poisoned.core.journalBlocked, true, recordName);
        assert.equal(poisoned.core.record.phase, PHASES.remediation, recordName);
        assert.equal(poisoned.core.record.result_id, null, recordName);
        assert.equal(poisoned.core.record.cleanup_allowed, false, recordName);
        assert.equal(poisoned.journal.record.phase, PHASES.result, recordName);

        const staleAck = await poisoned.core.handleRequest(ackRequest(staleResult));
        assert.equal(staleAck.accepted, false, recordName);
        await poisoned.core.handleFrame(frame(FRAME_KINDS.response, 102, 21));
        assert.equal(poisoned.core.record.phase, PHASES.remediation, recordName);
        assert.equal(poisoned.core.record.cleanup_allowed, false, recordName);

        const restarted = coreHarness({
            record: poisoned.journal.record,
            bootId: SECOND_BOOT,
            sequences: [220 + index],
        });
        await restarted.core.start();
        assert.equal(restarted.core.record.phase, PHASES.remediation, recordName);
        assert.equal(restarted.core.record.result_id, null, recordName);
        assert.equal(restarted.core.record.cleanup_allowed, false, recordName);
        assert.equal(restarted.publications.some((item) => item.topic === TOPICS.ready), false, recordName);
        assert.equal(restarted.publications.some((item) => item.topic === TOPICS.result), false, recordName);
        assert.deepEqual(
            restarted.commands.map(({target, safety}) => ({target, safety})),
            [{target: staleResult.intended_target, safety: true}],
            recordName,
        );
    }
});

test("queue overflow while result is pending supersedes it into restore-required remediation", async () => {
    const harness = coreHarness();
    await advanceToResult(harness);
    const before = harness.commands.length;
    harness.core.latchQueueOverflow();
    await harness.core.queue.drain();
    assert.equal(harness.commands.length, before + 1);
    assert.equal(harness.commands.at(-1).target, 21);
    assert.equal(harness.commands.at(-1).safety, true);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.restore_required, true);
    assert.equal(harness.core.record.result_id, null);
    assert.equal(harness.core.record.cleanup_allowed, false);
});

test("candidate rename before ACK blocks cleanup and sends only unclaimed restore", async () => {
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        sequences: [200],
        onResolve: (_value, _count, defaultResult) => ({
            ...defaultResult,
            set_topic: "renamed-valve/set",
        }),
    });
    await harness.core.start();
    harness.nowRef.value = harness.core.record.result_not_before_ms;
    const response = await harness.core.handleRequest(ackRequest(harness.core.record));
    assert.equal(response.accepted, false);
    assert.equal(response.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.deepEqual(harness.commands.map(({target, safety}) => ({target, safety})), [
        {target: 21, safety: true},
    ]);
});

test("candidate identity resolution failure before ACK fails closed when restore cannot resolve", async () => {
    const harness = coreHarness({
        record: validateRecoveryRecord(FIXTURES.verified_record),
        sequences: [200],
        onResolve: () => { throw new ProbeValidationError("identity_mismatch", "changed"); },
    });
    await harness.core.start();
    harness.nowRef.value = harness.core.record.result_not_before_ms;
    const response = await harness.core.handleRequest(ackRequest(harness.core.record));
    assert.equal(response.accepted, false);
    assert.equal(response.phase, PHASES.remediation);
    assert.equal(harness.core.record.phase, PHASES.remediation);
    assert.equal(harness.core.record.cleanup_allowed, false);
    assert.equal(harness.commands.length, 0);
});

test("hung result publication retries and remediation status supersedes stale result", async () => {
    const firstResult = deferred();
    let forcePublicationTimeout = false;
    let resultAttempts = 0;
    const timeoutRace = async (operation, timeoutMs) => {
        if (timeoutMs === LIMITS.publicationMs && forcePublicationTimeout) {
            forcePublicationTimeout = false;
            Promise.resolve(operation).catch(() => undefined);
            return {status: "timeout"};
        }
        return defaultTimeoutRace(operation, timeoutMs);
    };
    const harness = coreHarness({
        timeoutRace,
        onPublish: (topic) => {
            if (topic === TOPICS.result) {
                resultAttempts += 1;
                if (resultAttempts === 1) {
                    forcePublicationTimeout = true;
                    return firstResult.promise;
                }
            }
        },
    });
    const result = await advanceToResult(harness);
    await settle();
    await fireTimer(harness);
    await fireTimer(harness);
    await settle();
    assert.ok(resultAttempts >= 2);

    const stale = deferred();
    let staleTimeout = false;
    let staleAttempts = 0;
    const staleHarness = coreHarness({
        sequences: [100, 101, 102, 103],
        timeoutRace: async (operation, timeoutMs) => {
            if (timeoutMs === LIMITS.publicationMs && staleTimeout) {
                staleTimeout = false;
                Promise.resolve(operation).catch(() => undefined);
                return {status: "timeout"};
            }
            return defaultTimeoutRace(operation, timeoutMs);
        },
        onPublish: (topic) => {
            if (topic === TOPICS.result) {
                staleAttempts += 1;
                if (staleAttempts === 1) {
                    staleTimeout = true;
                    return stale.promise;
                }
            }
        },
    });
    const staleResult = await advanceToResult(staleHarness);
    await settle();
    await staleHarness.core.handleCandidateSet(SET_TOPIC);
    stale.resolve();
    await settle();
    assert.equal(staleAttempts, 1);
    const statuses = staleHarness.publications
        .filter((item) => item.topic === TOPICS.status)
        .map((item) => item.payload);
    const latestStatus = statuses.at(-1);
    assert.equal(latestStatus.phase, PHASES.remediation);
    assert.ok(latestStatus.generation > staleResult.generation);
    assert.equal(staleHarness.core.record.result_id, null);
});

test("bounded queue overflow synchronously latches remediation", async () => {
    const loadGate = deferred();
    const journal = new MemoryJournal();
    journal.load = () => loadGate.promise;
    const scheduler = new FakeScheduler();
    const core = new PhysicalProbeCore({
        journal,
        bootId: BOOT,
        baseTopic: "zigbee2mqtt",
        scheduler,
        pendingLimit: 1,
        resolveCandidate: async (value) => ({candidate: value, set_topic: SET_TOPIC}),
        dispatchCommand: async () => assert.fail("overflow dispatched a command"),
        publish: async () => undefined,
    });
    const starting = core.start();
    const dropped = core.handleRequest(armRequest());
    assert.equal(core.safetyOnly, true);
    assert.equal(core.ready, false);
    loadGate.resolve(null);
    await starting;
    assert.equal(await dropped, undefined);
    await core.queue.drain();
    const response = await core.handleRequest(armRequest({request_id: SECOND_REQUEST, nonce: SECOND_NONCE}));
    assert.equal(response.accepted, false);
    assert.equal(response.phase, PHASES.remediation);
});

test("early timers reschedule and exact proof deadline fails safe in either order", async () => {
    const early = coreHarness();
    await armCore(early);
    await fireTimer(early, {advance: false});
    assert.equal(early.core.record.phase, PHASES.physical1);
    assert.equal(early.scheduler.activeCount(), 1);

    const ordered = coreHarness();
    await armCore(ordered);
    ordered.nowRef.value = ordered.core.record.expected_proof_deadline_ms;
    const frameFirst = ordered.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
    ordered.scheduler.fireNext();
    await frameFirst;
    await ordered.core.queue.drain();
    assert.equal(ordered.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(ordered.core.record.failure_code, "deadline_expired");

    const exact = coreHarness();
    await armCore(exact);
    exact.nowRef.value = exact.core.record.expected_proof_deadline_ms;
    exact.scheduler.fireNext();
    await exact.core.queue.drain();
    assert.equal(exact.core.record.outcome, OUTCOMES.failedSafe);
});

test("default adapter uses one core FIFO and relative MQTT publication topics", async () => {
    const callbacks = {};
    const removed = [];
    const mqttPublications = [];
    const endpointCommands = [];
    const endpoint = {
        ID: 1,
        deviceIeeeAddress: IEEE,
        hasPendingRequests: () => false,
        supportsInputCluster: () => true,
        command: async (...args) => endpointCommands.push(args),
    };
    const device = {
        ieeeAddr: IEEE,
        ID: IEEE,
        name: "candidate-valve",
        isDevice: () => true,
        definition: {model: "BRT-100-TRV", vendor: "Moes"},
        zh: {
            modelID: "TS0601",
            manufacturerName: "_TZE200_b6wax7g0",
            endpoints: [endpoint],
            getEndpoint: () => endpoint,
        },
        endpoint: () => endpoint,
    };
    const eventBus = {
        onMQTTMessage: (_owner, callback) => { callbacks.mqtt = callback; },
        onDeviceMessage: (_owner, callback) => { callbacks.device = callback; },
        onEntityRenamed: (_owner, callback) => { callbacks.renamed = callback; },
        onGroupMembersChanged: (_owner, callback) => { callbacks.group = callback; },
        removeListeners: (owner) => removed.push(owner),
    };
    const extension = new TrueFamilyBrtProbeExtension(
        {resolveEntity: () => device},
        {
            publish: async (relativeTopic, payload, options) => {
                mqttPublications.push({
                    relativeTopic,
                    effectiveTopic: `${BASE_TOPIC}/${relativeTopic}`,
                    payload: JSON.parse(payload),
                    options,
                });
            },
        },
        null,
        null,
        eventBus,
        null,
        null,
        null,
        {get: () => ({mqtt: {base_topic: BASE_TOPIC}})},
        null,
    );
    extension.core.journal = new MemoryJournal();
    extension.core.scheduler = new FakeScheduler();
    extension.core.now = () => NOW;
    extension.core.nextSequence = (() => {
        const sequences = [100, 101, 102];
        return () => sequences.shift();
    })();
    await extension.start();
    await settle();
    assert.equal(endpointCommands.length, 0);
    assert.ok(mqttPublications.some((item) => item.relativeTopic === TOPICS.ready));
    assert.ok(mqttPublications.some(
        (item) => item.effectiveTopic === `${BASE_TOPIC}/${TOPICS.ready}`,
    ));
    assert.ok(mqttPublications.every((item) => item.relativeTopic.startsWith("bridge/")));
    assert.ok(mqttPublications.every(
        (item) => item.effectiveTopic === `${BASE_TOPIC}/${item.relativeTopic}`,
    ));
    assert.equal(mqttPublications.some(
        (item) => item.effectiveTopic.startsWith(`${BASE_TOPIC}/${BASE_TOPIC}/`),
    ), false);
    assert.ok(mqttPublications.every((item) => (
        item.options.clientOptions.qos === 1 &&
        item.options.clientOptions.retain === false &&
        item.options.skipLog === true &&
        item.options.skipReceive === true
    )));

    callbacks.mqtt({
        topic: `${BASE_TOPIC}/${TOPICS.ack}`,
        message: "not-json",
    });
    await extension.core.queue.drain();
    await settle();
    const malformedAck = mqttPublications
        .filter((item) => item.relativeTopic === TOPICS.ackResponse)
        .at(-1).payload;
    assert.deepEqual(malformedAck, {
        protocol_id: PROTOCOL_ID,
        protocol_version: PROTOCOL_VERSION,
        build_id: BUILD_ID,
        boot_id: extension.core.bootId,
        request_id: null,
        operation_id: null,
        action: "ack",
        accepted: false,
        phase: "idle",
        generation: 0,
        error_code: "unexpected_fields",
    });

    callbacks.mqtt({
        topic: `${BASE_TOPIC}/${TOPICS.request}`,
        message: canonicalJson(FIXTURES.ack_request),
    });
    await extension.core.queue.drain();
    await settle();
    const mismatchedNormal = mqttPublications
        .filter((item) => item.relativeTopic === TOPICS.response)
        .at(-1).payload;
    assert.equal(mismatchedNormal.action, "invalid");
    assert.equal(mismatchedNormal.accepted, false);

    callbacks.mqtt({topic: `${BASE_TOPIC}/unrelated`, message: "{}"});
    await extension.core.queue.drain();
    assert.equal(extension.core.record, null);
    callbacks.mqtt({
        topic: `${BASE_TOPIC}/${TOPICS.request}`,
        message: canonicalJson(armRequest({boot_id: extension.core.bootId})),
    });
    await extension.core.queue.drain();
    assert.equal(extension.core.record.phase, PHASES.physical1);
    callbacks.device(frame(FRAME_KINDS.response, 500, 18));
    await extension.core.queue.drain();
    callbacks.device(frame(FRAME_KINDS.response, 501, 21));
    await extension.core.queue.drain();
    assert.equal(endpointCommands.length, 1);
    assert.equal(endpointCommands[0][0], "manuSpecificTuya");
    assert.equal(endpointCommands[0][1], "dataRequest");
    assert.equal(endpointCommands[0][2].seq, 100);
    assert.deepEqual(endpointCommands[0][3], {
        disableDefaultResponse: true,
        sendPolicy: "immediate",
        disableRecovery: true,
        timeout: ENDPOINT_COMMAND_TIMEOUT_MS,
    });

    callbacks.mqtt({
        topic: `${BASE_TOPIC}/${IEEE}/\t\v\f\r\n0x1/set/system_mode/deep/path`,
        message: "heat",
    });
    await extension.core.queue.drain();
    assert.equal(extension.core.record.outcome, OUTCOMES.failedSafe);
    assert.equal(extension.core.record.failure_code, "competing_write");

    callbacks.mqtt({
        topic: `${BASE_TOPIC}/candidate-valve/\r\n1/set/system_mode/result/drift`,
        message: "off",
    });
    await extension.core.queue.drain();
    assert.equal(extension.core.record.phase, PHASES.remediation);
    assert.equal(extension.core.record.result_id, null);
    assert.equal(extension.core.record.cleanup_allowed, false);
    assert.ok(endpointCommands.some((args) => args[2].dpValues[0].data.readUInt32BE(0) === 21));

    const commandCountBeforeStop = endpointCommands.length;
    await extension.stop();
    assert.deepEqual(removed, [extension]);
    const commandCountAfterStop = endpointCommands.length;
    assert.ok(commandCountAfterStop >= commandCountBeforeStop);
    callbacks.device(frame(FRAME_KINDS.response, 100, 21));
    await settle();
    assert.equal(endpointCommands.length, commandCountAfterStop);
});

test("default adapter requires and reacts to pinned control, rename, and group APIs", async () => {
    const settings = {get: () => ({mqtt: {base_topic: BASE_TOPIC}})};
    assert.throws(() => new TrueFamilyBrtProbeExtension(
        {},
        {},
        null,
        null,
        {
            onMQTTMessage: () => undefined,
            onDeviceMessage: () => undefined,
            onEntityRenamed: () => undefined,
            removeListeners: () => undefined,
        },
        null,
        null,
        null,
        settings,
        null,
    ), /onGroupMembersChanged/u);

    for (const kind of ["raw_action", "repeated_prefix", "rename", "group"]) {
        const callbacks = {};
        const endpointCommands = [];
        const endpoint = {
            ID: 1,
            deviceIeeeAddress: IEEE,
            hasPendingRequests: () => false,
            supportsInputCluster: () => true,
            command: async (...args) => endpointCommands.push(args),
        };
        const device = {
            ieeeAddr: IEEE,
            ID: IEEE,
            name: "candidate-valve",
            isDevice: () => true,
            definition: {model: "BRT-100-TRV", vendor: "Moes"},
            zh: {
                ieeeAddr: IEEE,
                modelID: "TS0601",
                manufacturerName: "_TZE200_b6wax7g0",
                endpoints: [endpoint],
                getEndpoint: () => endpoint,
            },
            endpoint: () => endpoint,
        };
        const eventBus = {
            onMQTTMessage: (_owner, callback) => { callbacks.mqtt = callback; },
            onDeviceMessage: (_owner, callback) => { callbacks.device = callback; },
            onEntityRenamed: (_owner, callback) => { callbacks.renamed = callback; },
            onGroupMembersChanged: (_owner, callback) => { callbacks.group = callback; },
            removeListeners: () => undefined,
        };
        const extension = new TrueFamilyBrtProbeExtension(
            {resolveEntity: () => device},
            {publish: async () => undefined},
            null,
            null,
            eventBus,
            null,
            null,
            null,
            settings,
            null,
        );
        extension.core.journal = new MemoryJournal();
        extension.core.scheduler = new FakeScheduler();
        extension.core.now = () => NOW;
        await extension.start();
        await extension.core.handleRequest(armRequest({boot_id: extension.core.bootId}));
        if (kind === "raw_action") {
            callbacks.mqtt({topic: `${BASE_TOPIC}/bridge/request/action`, message: "{}"});
        } else if (kind === "repeated_prefix") {
            callbacks.mqtt({
                topic: `${BASE_TOPIC}/${BASE_TOPIC}/bridge/request/device/rename`,
                message: "{}",
            });
        } else if (kind === "rename") {
            callbacks.renamed({entity: device, from: "candidate-valve", to: "renamed"});
        } else {
            callbacks.group({group: {}, action: "add", endpoint});
        }
        await extension.core.queue.drain();
        assert.equal(extension.core.record.outcome, OUTCOMES.failedSafe, kind);
        assert.equal(extension.core.record.failure_code, "control_drift", kind);
        assert.equal(extension.core.record.cleanup_allowed, false, kind);
        assert.equal(endpointCommands.length, 0, kind);
        await extension.stop();
    }
});

test("default adapter rechecks invocation deadline after synchronous inspection", async () => {
    const originalDateNow = Date.now;
    const callbacks = {};
    const endpointCommands = [];
    let extension;
    let resolveCalls = 0;
    let dispatchNow = NOW;
    const endpoint = {
        ID: 1,
        deviceIeeeAddress: IEEE,
        hasPendingRequests: () => false,
        supportsInputCluster: () => true,
        command: async (...args) => endpointCommands.push(args),
    };
    const device = {
        ieeeAddr: IEEE,
        ID: IEEE,
        name: "candidate-valve",
        isDevice: () => true,
        definition: {model: "BRT-100-TRV", vendor: "Moes"},
        zh: {
            modelID: "TS0601",
            manufacturerName: "_TZE200_b6wax7g0",
            endpoints: [endpoint],
            getEndpoint: () => endpoint,
        },
        endpoint: () => endpoint,
    };
    const eventBus = {
        onMQTTMessage: (_owner, callback) => { callbacks.mqtt = callback; },
        onDeviceMessage: (_owner, callback) => { callbacks.device = callback; },
        onEntityRenamed: (_owner, callback) => { callbacks.renamed = callback; },
        onGroupMembersChanged: (_owner, callback) => { callbacks.group = callback; },
        removeListeners: () => undefined,
    };
    try {
        Date.now = () => dispatchNow;
        extension = new TrueFamilyBrtProbeExtension(
            {
                resolveEntity: () => {
                    resolveCalls += 1;
                    if (resolveCalls === 5) {
                        dispatchNow = extension.core.record.expected_proof_deadline_ms
                            - ENDPOINT_COMMAND_TIMEOUT_MS;
                    }
                    return device;
                },
            },
            {publish: async () => undefined},
            null,
            null,
            eventBus,
            null,
            null,
            null,
            {get: () => ({mqtt: {base_topic: BASE_TOPIC}})},
            null,
        );
        extension.core.journal = new MemoryJournal();
        extension.core.scheduler = new FakeScheduler();
        extension.core.now = () => dispatchNow;
        extension.core.nextSequence = () => 100;
        await extension.start();
        await extension.core.handleRequest(armRequest({boot_id: extension.core.bootId}));
        await extension.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
        await extension.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
        assert.equal(resolveCalls, 5);
        assert.equal(endpointCommands.length, 0);
        assert.equal(extension.core.record.outcome, OUTCOMES.failedSafe);
        assert.equal(extension.core.record.failure_code, "dispatch_failed");
    } finally {
        Date.now = originalDateNow;
        if (extension) await extension.stop();
    }
});

test("newer failed-safe temp is durably remediated and stale main cannot resume", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-newer-safe-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    const temporary = journalTempPath(directory, "a");
    try {
        const records = await journalEvidenceRecords();
        await writeJournalRecord(file, records.armed);
        await writeJournalRecord(temporary, records.failedSafe);
        const journal = new AtomicProbeJournal(file);
        const recovered = await journal.load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.failure_code, "journal_uncertain");
        assert.equal(recovered.generation, records.failedSafe.generation + 1);
        assert.equal(recovered.restore_required, false);
        assert.equal(recovered.result_id, null);
        assert.equal(recovered.cleanup_allowed, false);
        assert.equal((await readdir(directory)).some((name) => name.endsWith(".tmp")), false);

        const persisted = await new AtomicProbeJournal(file).load();
        assert.deepEqual(persisted, recovered);
        const restarted = coreHarness({
            journalAdapter: new AtomicProbeJournal(file),
            bootId: SECOND_BOOT,
        });
        await restarted.core.start();
        assert.equal(restarted.core.record.phase, PHASES.remediation);
        assert.equal(restarted.core.ready, false);
        assert.equal(restarted.commands.length, 0);
        const response = await restarted.core.handleRequest(resumeRequest(records.armed, {
            boot_id: SECOND_BOOT,
        }));
        assert.equal(response.accepted, false);
        assert.equal(restarted.core.record.phase, PHASES.remediation);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("newer challenged, restore, result, and quiescent evidence requires restore remediation", async () => {
    const records = await journalEvidenceRecords();
    const cases = [
        ["noop-challenge", records.noop, records.challenge, true],
        ["challenge-restore", records.challenge, records.restore, false],
        ["challenge-result", records.challenge, records.result, false],
        ["challenge-quiescent", records.challenge, records.quiescent, false],
    ];
    for (const [label, main, temporaryRecord, verifyStartup] of cases) {
        const directory = await mkdtemp(path.join(os.tmpdir(), `tfpp-${label}-`));
        const file = path.join(directory, "true_family_brt_probe.state.json");
        const temporary = journalTempPath(directory, "b");
        try {
            await writeJournalRecord(file, main);
            await writeJournalRecord(temporary, temporaryRecord);
            const recovered = await new AtomicProbeJournal(file).load();
            assert.equal(recovered.phase, PHASES.remediation, label);
            assert.equal(recovered.failure_code, "journal_uncertain", label);
            assert.equal(recovered.generation, temporaryRecord.generation + 1, label);
            assert.equal(recovered.restore_required, true, label);
            assert.equal(recovered.result_id, null, label);
            assert.equal(recovered.cleanup_allowed, false, label);
            assert.equal((await readdir(directory)).some((name) => name.endsWith(".tmp")), false, label);
            if (verifyStartup) {
                const restarted = coreHarness({
                    journalAdapter: new AtomicProbeJournal(file),
                    bootId: SECOND_BOOT,
                    sequences: [200, 201, 202],
                });
                await restarted.core.start();
                assert.equal(restarted.core.ready, false);
                assert.equal(restarted.commands.some((item) => item.target === 22), false);
                assert.deepEqual(
                    restarted.commands.map(({target, purpose, safety}) => ({target, purpose, safety})),
                    [{target: 21, purpose: PURPOSES.restore, safety: true}],
                );
            }
        } finally {
            await rm(directory, {recursive: true, force: true});
        }
    }
});

test("exact canonical duplicate temps force durable journal remediation", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-duplicate-temps-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    try {
        const records = await journalEvidenceRecords();
        await writeJournalRecord(file, records.challenge);
        await writeJournalRecord(journalTempPath(directory, "c"), records.challenge);
        await writeJournalRecord(journalTempPath(directory, "d"), records.challenge);
        const recovered = await new AtomicProbeJournal(file).load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.failure_code, "journal_uncertain");
        assert.equal(recovered.generation, records.challenge.generation + 1);
        assert.equal(recovered.restore_required, true);
        assert.equal(recovered.result_id, null);
        assert.equal(recovered.cleanup_allowed, false);
        assert.equal((await readdir(directory)).some((name) => name.endsWith(".tmp")), false);
        assert.deepEqual(await new AtomicProbeJournal(file).load(), recovered);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("temp cleanup boundaries retain durable remediation across repeated restart", async () => {
    const records = await journalEvidenceRecords();
    const phases = [
        ["prechallenge", records.noop, false],
        ["challenge", records.challenge, true],
        ["restore", records.restore, true],
        ["result", records.result, true],
    ];
    const failures = [
        ["pre-unlink-fsync", JOURNAL_BOUNDARIES.cleanupPreUnlinkDirectoryFsync, true],
        ["unlink", JOURNAL_BOUNDARIES.cleanupUnlink],
        ["post-unlink-fsync", JOURNAL_BOUNDARIES.cleanupPostUnlinkDirectoryFsync, false],
    ];
    let caseIndex = 0;
    for (const [phaseLabel, record, restoreRequired] of phases) {
        for (const [failureLabel, boundary, tempSurvives = true] of failures) {
            const label = `${phaseLabel}-${failureLabel}`;
            const directory = await mkdtemp(path.join(os.tmpdir(), `tfpp-duplicate-${label}-`));
            const file = path.join(directory, "true_family_brt_probe.state.json");
            const marker = "0123456789ab"[caseIndex];
            const temporary = journalTempPath(directory, marker);
            caseIndex += 1;
            try {
                await writeJournalRecord(file, record);
                await writeJournalRecord(temporary, record);
                let injected = false;
                const journal = new AtomicProbeJournal(file, {
                    boundaryHook: (current) => {
                        if (!injected && current === boundary) {
                            injected = true;
                            throw new Error(`simulated duplicate ${failureLabel} failure`);
                        }
                    },
                });
                const first = coreHarness({
                    journalAdapter: journal,
                    bootId: SECOND_BOOT,
                    sequences: [200, 201, 202],
                });
                await first.core.start();
                assert.equal(injected, true, label);
                assert.equal(first.core.record.phase, PHASES.remediation, label);
                assert.equal(first.core.record.failure_code, "journal_uncertain", label);
                assert.equal(first.core.record.restore_required, restoreRequired, label);
                assert.equal(first.core.ready, false, label);
                assert.equal(first.core.journalBlocked, true, label);
                assert.equal(
                    (await readdir(directory)).includes(path.basename(temporary)),
                    tempSurvives,
                    label,
                );
                assert.deepEqual(
                    first.commands.map(({target, purpose, safety}) => ({target, purpose, safety})),
                    restoreRequired
                        ? [{target: 21, purpose: PURPOSES.restore, safety: true}]
                        : [],
                    label,
                );
                const persisted = validateRecoveryRecord(JSON.parse(await readFile(file, "utf8")));
                assert.equal(persisted.phase, PHASES.remediation, label);
                assert.equal(persisted.failure_code, "journal_uncertain", label);

                const second = coreHarness({
                    journalAdapter: new AtomicProbeJournal(file),
                    bootId: THIRD_BOOT,
                    sequences: [300, 301, 302],
                });
                await second.core.start();
                assert.ok(
                    [PHASES.remediation, PHASES.restore].includes(second.core.record.phase),
                    label,
                );
                assert.equal(second.core.ready, false, label);
                assert.equal(second.core.safetyOnly, true, label);
                assert.equal(second.commands.some((command) => command.target === 22), false, label);
                assert.equal(
                    second.commands.every((command) => command.target === 21 && command.safety),
                    true,
                    label,
                );
            } finally {
                await rm(directory, {recursive: true, force: true});
            }
        }
    }
});

test("lower-generation same-operation temp forces durable journal remediation", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-lower-coherent-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    try {
        const records = await journalEvidenceRecords();
        assert.ok(records.armed.generation < records.failedSafe.generation);
        await writeJournalRecord(file, records.failedSafe);
        await writeJournalRecord(journalTempPath(directory, "e"), records.armed);
        const recovered = await new AtomicProbeJournal(file).load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.failure_code, "journal_uncertain");
        assert.equal(recovered.generation, records.failedSafe.generation + 1);
        assert.equal(recovered.restore_required, false);
        assert.equal(recovered.result_id, null);
        assert.equal(recovered.cleanup_allowed, false);
        assert.equal((await readdir(directory)).some((name) => name.endsWith(".tmp")), false);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("lower restore-required evidence controls remediation even when main is newer", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-lower-restore-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    try {
        const records = await journalEvidenceRecords();
        const newerMain = validateRecoveryRecord({
            ...records.physical2,
            generation: records.restore.generation + 1,
        });
        assert.ok(records.restore.generation < newerMain.generation);
        await writeJournalRecord(file, newerMain);
        await writeJournalRecord(journalTempPath(directory, "f"), records.restore);
        const recovered = await new AtomicProbeJournal(file).load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.generation, newerMain.generation + 1);
        assert.equal(recovered.restore_required, true);
        assert.equal(recovered.result_id, null);
        assert.equal(recovered.cleanup_allowed, false);
        assert.equal((await readdir(directory)).some((name) => name.endsWith(".tmp")), false);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("multiple mixed coherent temps synthesize one highest-evidence remediation", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-mixed-coherent-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    try {
        const records = await journalEvidenceRecords();
        await writeJournalRecord(file, records.challenge);
        await writeJournalRecord(journalTempPath(directory, "1"), records.challenge);
        await writeJournalRecord(journalTempPath(directory, "2"), records.noop);
        await writeJournalRecord(journalTempPath(directory, "3"), records.restore);
        const recovered = await new AtomicProbeJournal(file).load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.failure_code, "journal_uncertain");
        assert.equal(recovered.generation, records.restore.generation + 1);
        assert.equal(recovered.restore_required, true);
        assert.equal(recovered.result_id, null);
        assert.equal(recovered.cleanup_allowed, false);
        assert.equal((await readdir(directory)).some((name) => name.endsWith(".tmp")), false);
        assert.deepEqual(await new AtomicProbeJournal(file).load(), recovered);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("same-generation divergent coherent temp is durably remediated", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-divergent-temp-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    const temporary = journalTempPath(directory, "4");
    try {
        const records = await journalEvidenceRecords();
        const divergent = validateRecoveryRecord({
            ...records.challenge,
            expected_proof_deadline_ms: records.challenge.expected_proof_deadline_ms + 1,
        });
        await writeJournalRecord(file, records.challenge);
        await writeJournalRecord(temporary, divergent);
        const journal = new AtomicProbeJournal(file);
        const recovered = await journal.load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.failure_code, "journal_uncertain");
        assert.equal(recovered.generation, records.challenge.generation + 1);
        assert.equal(recovered.restore_required, true);
        assert.equal(recovered.result_id, null);
        assert.equal(recovered.cleanup_allowed, false);
        assert.deepEqual(validateRecoveryRecord(JSON.parse(await readFile(file, "utf8"))), recovered);
        assert.equal((await readdir(directory)).includes(path.basename(temporary)), false);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("lower-generation conflicting operation is preserved for manual remediation", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-conflict-temp-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    const temporary = journalTempPath(directory, "5");
    try {
        const records = await journalEvidenceRecords();
        const other = coreHarness();
        const otherOperation = await armCore(other, {operation_id: SECOND_OPERATION});
        assert.ok(otherOperation.generation < records.challenge.generation);
        await writeJournalRecord(file, records.challenge);
        await writeJournalRecord(temporary, otherOperation);
        const journal = new AtomicProbeJournal(file);
        await assert.rejects(journal.load(), (error) => {
            assert.ok(error instanceof ProbeJournalError);
            assert.equal(error.manualRemediation, true);
            assert.equal(error.recoveryRecord, null);
            return true;
        });
        assert.deepEqual(validateRecoveryRecord(JSON.parse(await readFile(file, "utf8"))), records.challenge);
        assert.ok((await readdir(directory)).includes(path.basename(temporary)));
        const restarted = coreHarness({journalAdapter: journal, bootId: SECOND_BOOT});
        await restarted.core.start();
        assert.equal(restarted.core.record, null);
        assert.equal(restarted.core.ready, false);
        assert.equal(restarted.commands.length, 0);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("failed journal recovery write preserves evidence and startup uses carried remediation", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-recovery-write-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    const temporary = journalTempPath(directory, "1");
    const duplicate = journalTempPath(directory, "2");
    try {
        const records = await journalEvidenceRecords();
        await writeJournalRecord(file, records.noop);
        await writeJournalRecord(temporary, records.challenge);
        await writeJournalRecord(duplicate, records.noop);
        const journal = new AtomicProbeJournal(file, {
            boundaryHook: (boundary) => {
                if (boundary === JOURNAL_BOUNDARIES.tempWrite) {
                    throw new Error("recovery write failed");
                }
            },
        });
        await assert.rejects(journal.load(), (error) => {
            assert.ok(error instanceof ProbeJournalError);
            assert.equal(error.recoveryRecord.phase, PHASES.remediation);
            assert.equal(error.recoveryRecord.restore_required, true);
            assert.equal(error.recoveryRecord.cleanup_allowed, false);
            return true;
        });
        assert.deepEqual(validateRecoveryRecord(JSON.parse(await readFile(file, "utf8"))), records.noop);
        assert.deepEqual(
            (await readdir(directory)).filter((name) => name.endsWith(".tmp")).sort(),
            [path.basename(temporary), path.basename(duplicate)],
        );

        const restarted = coreHarness({
            journalAdapter: journal,
            bootId: SECOND_BOOT,
            sequences: [200, 201, 202],
        });
        await restarted.core.start();
        assert.equal(restarted.core.record.phase, PHASES.remediation);
        assert.equal(restarted.core.record.failure_code, "journal_uncertain");
        assert.equal(restarted.core.ready, false);
        assert.equal(restarted.core.journalBlocked, true);
        assert.deepEqual(
            restarted.commands.map(({target, purpose, safety}) => ({target, purpose, safety})),
            [{target: 21, purpose: PURPOSES.restore, safety: true}],
        );
        assert.equal(restarted.commands.some((item) => item.target === 22), false);
        assert.deepEqual(
            (await readdir(directory)).filter((name) => name.endsWith(".tmp")).sort(),
            [path.basename(temporary), path.basename(duplicate)],
        );
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("pre-rename AtomicProbeJournal timeout preserves temp and safety-only authority", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-late-journal-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    const preRenameGate = deferred();
    const lateWriteFinished = deferred();
    let tempCloseCount = 0;
    let journalOperations = 0;
    try {
        const journal = new AtomicProbeJournal(file, {
            boundaryHook: async (boundary) => {
                if (boundary === JOURNAL_BOUNDARIES.tempClose) {
                    tempCloseCount += 1;
                    if (tempCloseCount === 4) await preRenameGate.promise;
                }
                if (boundary === JOURNAL_BOUNDARIES.postRename && tempCloseCount === 4) {
                    lateWriteFinished.resolve();
                }
            },
        });
        const harness = coreHarness({
            journalAdapter: journal,
            timeoutRace: async (operation, timeoutMs) => {
                if (timeoutMs === LIMITS.journalMs) {
                    journalOperations += 1;
                    if (journalOperations === 5) {
                        Promise.resolve(operation).catch(() => undefined);
                        return {status: "timeout"};
                    }
                }
                return defaultTimeoutRace(operation, timeoutMs);
            },
        });
        await armCore(harness);
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 500, 18));
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 501, 21));
        await harness.core.handleFrame(frame(FRAME_KINDS.response, 100, 21));
        assert.equal(harness.core.remediationRequired, true);
        assert.equal(harness.core.safetyOnly, true);
        assert.equal(harness.core.ready, false);
        assert.equal(harness.core.record.cleanup_allowed, false);
        assert.equal(harness.scheduler.activeCount(), 0);
        assert.equal(harness.commands.some((item) => item.target === 22), false);
        assert.equal(harness.commands.at(-1).target, 21);
        assert.equal(harness.commands.at(-1).safety, true);
        const commandCount = harness.commands.length;
        assert.equal(
            (await readdir(directory)).filter((name) => name.endsWith(".tmp")).length,
            1,
        );

        preRenameGate.resolve();
        await lateWriteFinished.promise;
        const lateRecord = await journal.load();
        assert.equal(lateRecord.phase, PHASES.challenge);
        assert.equal(lateRecord.restore_required, true);
        assert.equal(harness.core.remediationRequired, true);
        assert.equal(harness.commands.length, commandCount);
        const rejected = await harness.core.handleRequest(armRequest({
            request_id: SECOND_REQUEST,
            nonce: SECOND_NONCE,
        }));
        assert.equal(rejected.accepted, false);
        assert.equal(harness.commands.length, commandCount);
        await harness.core.stop();

        const restarted = coreHarness({
            journalAdapter: journal,
            bootId: SECOND_BOOT,
            sequences: [200, 201, 202],
        });
        await restarted.core.start();
        assert.equal(restarted.commands.some((item) => item.target === 22), false);
        assert.equal(restarted.commands.at(-1).target, 21);
        assert.equal(restarted.commands.at(-1).safety, true);
    } finally {
        preRenameGate.resolve();
        await rm(directory, {recursive: true, force: true});
    }
});

test("atomic journal writes canonical mode-0600 state and classifies rename uncertainty", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-journal-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    try {
        const journal = new AtomicProbeJournal(file);
        await journal.write(FIXTURES.armed_record);
        assert.deepEqual(await journal.load(), validateRecoveryRecord(FIXTURES.armed_record));
        assert.equal((await stat(file)).mode & 0o777, 0o600);
        assert.equal(await readFile(file, "utf8"), canonicalJson(FIXTURES.armed_record, LIMITS.stateJsonBytes));

        const uncertain = new AtomicProbeJournal(file, {
            boundaryHook: async (boundary) => {
                if (boundary === JOURNAL_BOUNDARIES.rename) throw new Error("simulated crash");
            },
        });
        await assert.rejects(uncertain.write(FIXTURES.verified_record), ProbeJournalUncertainError);
        assert.deepEqual(await journal.load(), validateRecoveryRecord(FIXTURES.verified_record));
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("atomic journal recovers lone valid temp and preserves corrupt temp evidence", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "tfpp-orphan-"));
    const file = path.join(directory, "true_family_brt_probe.state.json");
    const orphan = path.join(directory, `.true_family_brt_probe.${process.pid}.${"a".repeat(24)}.tmp`);
    try {
        await writeFile(orphan, canonicalJson(FIXTURES.armed_record, LIMITS.stateJsonBytes));
        const journal = new AtomicProbeJournal(file);
        const recovered = await journal.load();
        assert.equal(recovered.phase, PHASES.remediation);
        assert.equal(recovered.failure_code, "journal_uncertain");
        assert.equal(recovered.restore_required, false);
        assert.equal(recovered.result_id, null);
        assert.equal((await readdir(directory)).includes(path.basename(orphan)), false);
        await writeFile(orphan, "not-json");
        await assert.rejects(journal.load(), ProbeJournalError);
        assert.ok((await readdir(directory)).includes(path.basename(orphan)));
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});

test("random identifiers and sequence allocation are bounded and distinct", () => {
    assert.match(createBootId(() => Buffer.alloc(16, 0xab)), /^tfpp-boot-(?:ab){16}$/);
    assert.equal(randomDistinctSequence([1, 2], () => 3), 3);
    assert.throws(() => randomDistinctSequence([], () => 0xffff), ProbeValidationError);
    assert.throws(() => randomDistinctSequence([1, 1], () => 2), ProbeValidationError);
});

test("journal path derives from production external-extension loader placement", () => {
    const dataDirectory = path.join(os.tmpdir(), "tfpp-z2m-data");
    const extensionPath = path.join(
        dataDirectory,
        "external_extensions",
        "true_family_brt_probe.mjs",
    );
    assert.equal(
        defaultJournalPath(pathToFileURL(extensionPath).href),
        path.join(dataDirectory, "true_family_brt_probe.state.json"),
    );
});

test("source remains unwired, log-free, and explicit about the residual ACL gate", async () => {
    const source = await readFile(
        new URL("../../custom_components/true_family/probe/true_family_brt_probe.mjs", import.meta.url),
        "utf8",
    );
    for (const forbidden of [
        "homeassistant",
        "zigbee-herdsman-converters",
        ".bind(",
        "console.",
        "enableDisableExtension(",
        "restartCallback(",
        "addExtension(",
        "bridge/request/extension/save",
        "bridge/request/extension/remove",
    ]) {
        assert.equal(source.includes(forbidden), false, forbidden);
    }
    assert.equal(source.includes("dedicated broker principal"), true);
    assert.equal(source.includes("disable the Zigbee2MQTT frontend"), true);
    assert.equal(source.includes("actual-spare no-op bench gate remains mandatory"), true);
    assert.equal(source.includes("prove invocation, not delivery"), true);
    assert.equal(source.includes("one loader and one journal"), true);
    assert.equal(source.includes("full IEEE is\n * durable recovery identity"), true);
    assert.equal((source.match(/new BoundedSerialQueue\(/g) ?? []).length, 1);
    assert.deepEqual(Object.keys(TOPICS).sort(), ["ack", "ackResponse", "ready", "request", "response", "result", "status"]);
});
