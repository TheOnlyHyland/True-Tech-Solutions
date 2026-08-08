#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";

import {
    buildSourceInventory,
    canonical,
    decodeVarInt,
    expectedReadbackFromManifest,
    gatewayBackendDisconnectFatal,
    gatewayPolicyDigest,
    gatewayPolicyProjection,
    gatewayAllowsPublish,
    gatewayAllowsSubscribe,
    MqttFrameStream,
    normalizeReadback,
    sha256Bytes,
    topicContractValid,
    validateReadback,
} from "./test_physical_probe_broker_runtime.mjs";

const MANIFEST_SCHEMA = "true-family-pass-b1a-manifest-v1";
const RUNTIME_SCHEMA = "true-family-pass-b1a-runtime-v1";
const REPLICA_SCHEMA = "true-family-pass-b1a-replica-v1";
const FINAL_SCHEMA = "true-family-pass-b1a-composite-policy-foundation-v1";
const BASE_SCHEMA = "true-family-pass-b1a-base-evidence-v1";
const FAILURE_SCHEMA = "true-family-pass-b1a-verifier-failure-v1";
const LAUNCHER_FAILURE_SCHEMA = "true-family-pass-b1a-launcher-failure-v2";
const LAUNCHER_FAILURE_CODE = "verification_failed";
const RUNTIME_FAILURE_SCHEMA = "true-family-pass-b1a-runtime-failure-v2";
const INSTALL_FAILURE_CATEGORIES = [
    "context", "credentials", "broker_connect", "broker_subscribe",
    "command_transport", "command_rejected", "security", "unknown",
];
const LAUNCHER_TOP_LEVEL_FAILURE_STAGES = [
    "startup", "environment", "private_root", "static_shell", "static_verifier", "static_python",
    "pull_node", "pull_mosquitto", "inspect_node", "inspect_mosquitto", "compare", "combine",
    "final_scan_one", "final_scan_two", "cleanup", "finalize",
];
const LAUNCHER_REPLICA_FAILURE_PHASES = [
    "prepare", "networks", "setup", "broker", "install", "gateway", "client_before", "observer_before",
    "readback_before", "backend_before", "restart_one", "after_restart", "observer_after", "client_after",
    "restart_two", "final_auth", "final_backend", "final_readback", "inspect", "verify", "redaction", "cleanup",
];
const LAUNCHER_FAILURE_STAGES = new Set([
    ...LAUNCHER_TOP_LEVEL_FAILURE_STAGES,
    ...[1, 2].flatMap((ordinal) => LAUNCHER_REPLICA_FAILURE_PHASES.map((phase) => `replica_${ordinal}_${phase}`)),
    ...[1, 2].flatMap((ordinal) => INSTALL_FAILURE_CATEGORIES.map((category) => `replica_${ordinal}_install_${category}`)),
]);
const CLASSIFICATION = "ci-only-same-repository-non-authoritative-composite-policy-foundation";
const RUNTIME_HARNESS_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), "test_physical_probe_broker_runtime.mjs");
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SHA256_PREFIX_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const PASSWORD_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_RUNTIME_BYTES = 128 * 1024;
const MAX_FINAL_BYTES = 64 * 1024;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const CLAIM_LIMITS = Object.freeze([
    "pass_b1_not_complete",
    "authorization_not_proven",
    "real_zigbee2mqtt_mqtt_externaljs_source_path_not_proven",
    "permit_consumption_not_proven",
    "writer_fence_not_proven",
    "broker_delivery_to_real_zigbee2mqtt_not_proven",
    "physical_provenance_not_proven",
    "coordinator_radio_valve_not_exercised",
    "independent_attestation_not_proven",
    "malicious_source_resistance_not_proven",
    "household_equivalence_not_proven",
    "same_runner_host_isolation_not_proven",
    "seccomp_not_an_isolation_boundary",
    "backend_fault_injection_not_proven",
    "listener_fault_injection_not_proven",
    "no_loose_spare",
]);

class VerifyFailure extends Error {
    constructor(code) {
        super(code);
        this.code = code;
    }
}

function gate(condition, code) {
    if (!condition) throw new VerifyFailure(code);
}

function exactKeys(value, keys, code) {
    gate(value !== null && typeof value === "object" && !Array.isArray(value), code);
    gate(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), code);
}

function same(left, right) {
    return canonical(left) === canonical(right);
}

function launcherFailureStageProjection(candidate = "startup") {
    return typeof candidate === "string" && LAUNCHER_FAILURE_STAGES.has(candidate) ? candidate : "unknown";
}

function launcherFailureRecord(candidate) {
    return `${canonical({
        schema: LAUNCHER_FAILURE_SCHEMA,
        result: "fail",
        failure_code: LAUNCHER_FAILURE_CODE,
        failure_stage: launcherFailureStageProjection(candidate),
    })}\n`;
}

function sha256File(file) {
    return sha256Bytes(fs.readFileSync(file));
}

function domainDigest(value, domain) {
    const domainBytes = Buffer.from(domain, "utf8");
    const body = Buffer.from(canonical(value), "utf8");
    const prefix = Buffer.alloc(6);
    prefix.writeUInt16BE(domainBytes.length, 0);
    prefix.writeUInt32BE(body.length, 2);
    return sha256Bytes(Buffer.concat([prefix.subarray(0, 2), domainBytes, prefix.subarray(2), body]));
}

function readJson(file, code = "json") {
    try {
        const bytes = fs.readFileSync(file);
        gate(bytes.length > 0 && bytes.length <= MAX_JSON_BYTES, code);
        const text = bytes.toString("utf8");
        gate(Buffer.from(text, "utf8").equals(bytes), code);
        return JSON.parse(text);
    } catch (error) {
        if (error instanceof VerifyFailure) throw error;
        throw new VerifyFailure(code);
    }
}

function readPrivateBytes(file, maximum, code) {
    const metadata = fs.lstatSync(file);
    gate(
        metadata.isFile()
        && !metadata.isSymbolicLink()
        && metadata.uid === process.getuid()
        && metadata.nlink === 1
        && (metadata.mode & 0o777) === 0o600
        && metadata.size > 0
        && metadata.size <= maximum,
        code,
    );
    const handle = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
        const opened = fs.fstatSync(handle);
        gate(opened.dev === metadata.dev && opened.ino === metadata.ino && opened.size === metadata.size, code);
        const bytes = fs.readFileSync(handle);
        gate(bytes.length === metadata.size, code);
        return bytes;
    } finally {
        fs.closeSync(handle);
    }
}

function readPrivateJson(file, code = "private_json") {
    try {
        const bytes = readPrivateBytes(file, MAX_JSON_BYTES, code);
        const text = bytes.toString("utf8");
        gate(Buffer.from(text, "utf8").equals(bytes), code);
        return JSON.parse(text);
    } catch (error) {
        if (error instanceof VerifyFailure) throw error;
        throw new VerifyFailure(code);
    }
}

function writeExclusive(file, bytes) {
    const handle = fs.openSync(file, "wx", 0o600);
    try {
        fs.writeFileSync(handle, bytes);
        fs.fsyncSync(handle);
        fs.fchmodSync(handle, 0o600);
    } finally {
        fs.closeSync(handle);
    }
    const metadata = fs.lstatSync(file);
    gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && metadata.nlink === 1 && metadata.size === bytes.length && (metadata.mode & 0o777) === 0o600, "output_mode");
}

function brokerConfigBytes(manifest) {
    return Buffer.from(`${manifest.broker.config_lines.join("\n")}\n`, "utf8");
}

function policyProjection(manifest) {
    return {
        defaults: manifest.policy.defaults,
        admin_role: manifest.policy.admin_role,
        roles: manifest.policy.roles,
        observer_role: manifest.policy.observer_role,
        clients: manifest.policy.clients,
    };
}

function policyDigest(manifest) {
    return sha256Bytes(Buffer.from(canonical(policyProjection(manifest)), "utf8"));
}

function expectedReadbackDigest(manifest) {
    return sha256Bytes(Buffer.from(canonical(expectedReadbackFromManifest(manifest)), "utf8"));
}

function compositePolicyDigest(manifest) {
    return sha256Bytes(Buffer.from(canonical({
        schema: manifest.composite_policy.schema,
        gateway_policy_sha256: manifest.composite_policy.gateway_policy_sha256,
        broker_policy_sha256: manifest.composite_policy.broker_policy_sha256,
        preflight_acl_digest: manifest.composite_policy.preflight_acl_digest,
    }), "utf8"));
}

export function normalizedLauncherDigest(bytes) {
    const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
    const pattern = /EXPECTED_LAUNCHER_SHA256="([0-9a-f]{64})"/gu;
    const matches = [...text.matchAll(pattern)];
    gate(matches.length === 1, "launcher_normalization");
    const normalized = text.replace(pattern, `EXPECTED_LAUNCHER_SHA256="${"0".repeat(64)}"`);
    return {digest: sha256Bytes(Buffer.from(normalized, "utf8")), literal: matches[0][1]};
}

function validateAcl(acl) {
    exactKeys(acl, ["acltype", "topic", "allow", "priority"], "manifest_acl_shape");
    gate([
        "publishClientSend",
        "publishClientReceive",
        "subscribeLiteral",
        "subscribePattern",
        "unsubscribeLiteral",
        "unsubscribePattern",
    ].includes(acl.acltype), "manifest_acl_type");
    gate(typeof acl.topic === "string" && acl.topic.length > 0 && typeof acl.allow === "boolean", "manifest_acl_value");
    gate(Number.isInteger(acl.priority) && acl.priority >= -1 && acl.priority <= 100_000, "manifest_acl_priority");
}

function roleByName(manifest, name) {
    return [manifest.policy.admin_role, ...manifest.policy.roles, manifest.policy.observer_role].find((role) => role.rolename === name);
}

function roleAcls(manifest, name, type) {
    const role = roleByName(manifest, name);
    gate(role, "manifest_role_missing");
    return role.acls.filter((acl) => acl.acltype === type);
}

function mqttTopicMatches(filter, topic) {
    const filterLevels = filter.split("/");
    const topicLevels = topic.split("/");
    let index = 0;
    for (; index < filterLevels.length; index += 1) {
        const level = filterLevels[index];
        if (level === "#") return index === filterLevels.length - 1;
        if (index >= topicLevels.length || (level !== "+" && level !== topicLevels[index])) return false;
    }
    return index === topicLevels.length;
}

function publishAllowedByManifest(manifest, principal, topic) {
    const acls = roleAcls(manifest, manifest.principals[principal].role, "publishClientSend");
    const matching = acls.filter((acl) => mqttTopicMatches(acl.topic, topic)).toSorted((left, right) => right.priority - left.priority);
    return matching.length > 0 ? matching[0].allow : false;
}

function validatePolicy(manifest) {
    const policy = manifest.policy;
    exactKeys(policy, ["defaults", "admin_role", "roles", "observer_role", "clients", "canonical_sha256", "expected_readback_sha256"], "manifest_policy_shape");
    gate(same(policy.defaults, [
        {acltype: "publishClientSend", allow: false},
        {acltype: "publishClientReceive", allow: false},
        {acltype: "subscribe", allow: false},
        {acltype: "unsubscribe", allow: false},
    ]), "manifest_policy_defaults");
    const roles = [policy.admin_role, ...policy.roles, policy.observer_role];
    gate(roles.length === 6 && new Set(roles.map((role) => role.rolename)).size === roles.length, "manifest_policy_roles");
    for (const role of roles) {
        exactKeys(role, ["rolename", "acls"], "manifest_role_shape");
        gate(typeof role.rolename === "string" && Array.isArray(role.acls), "manifest_role_value");
        for (const acl of role.acls) validateAcl(acl);
        gate(new Set(role.acls.map((acl) => `${acl.acltype}\0${acl.topic}`)).size === role.acls.length, "manifest_acl_duplicate");
    }
    gate(policy.admin_role.rolename === "admin", "manifest_admin_role");
    const adminTopics = policy.admin_role.acls.map((acl) => acl.topic);
    gate(adminTopics.every((topic) => topic === "$CONTROL/dynamic-security/v1" || topic === "$CONTROL/dynamic-security/v1/response"), "manifest_admin_scope");
    gate(!adminTopics.includes("#") && !adminTopics.some((topic) => topic.startsWith("zigbee2mqtt")), "manifest_admin_scope");

    const orchestratorRole = manifest.principals.orchestrator.role;
    const orchestratorPublish = roleAcls(manifest, orchestratorRole, "publishClientSend");
    gate(same(orchestratorPublish.map((acl) => acl.topic).sort(), manifest.topics.request_topics.toSorted()), "manifest_orchestrator_publish");
    gate(orchestratorPublish.every((acl) => acl.allow), "manifest_orchestrator_publish");
    const orchestratorSubscribe = roleAcls(manifest, orchestratorRole, "subscribeLiteral").map((acl) => acl.topic).sort();
    const expectedOrchestratorSubscribe = [manifest.topics.ready, manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response].sort();
    gate(same(orchestratorSubscribe, expectedOrchestratorSubscribe), "manifest_orchestrator_subscribe");
    gate(!orchestratorSubscribe.some((topic) => [manifest.topics.source, manifest.topics.backup, `${manifest.scope.base_topic}/#`].includes(topic)), "manifest_orchestrator_privacy");

    const collectorRole = manifest.principals.collector.role;
    const collectorSubscribe = roleAcls(manifest, collectorRole, "subscribeLiteral").map((acl) => acl.topic).sort();
    gate(same(collectorSubscribe, [manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response].sort()), "manifest_collector_scope");
    gate(roleAcls(manifest, collectorRole, "publishClientSend").length === 0, "manifest_collector_readonly");

    const otherRole = roleByName(manifest, manifest.principals.other.role);
    gate(otherRole.acls.length === 0, "manifest_other_scope");
    const observerRole = policy.observer_role;
    gate(observerRole.rolename === manifest.principals.observer.role && observerRole.acls.length === 2, "manifest_observer_scope");
    gate(observerRole.acls.every((acl) => acl.topic === manifest.topics.source && acl.allow), "manifest_observer_scope");

    const z2mRole = manifest.principals.z2m.role;
    const z2mPublish = roleAcls(manifest, z2mRole, "publishClientSend");
    gate(same(z2mPublish, [{acltype: "publishClientSend", topic: "#", allow: true, priority: 100}]), "manifest_z2m_publish");
    gate(same(roleAcls(manifest, z2mRole, "publishClientReceive"), [{acltype: "publishClientReceive", topic: "#", allow: true, priority: 100}]), "manifest_z2m_receive");
    gate(same(roleAcls(manifest, z2mRole, "subscribePattern"), [{acltype: "subscribePattern", topic: "#", allow: true, priority: 100}]), "manifest_z2m_pattern");
    gate(same(roleAcls(manifest, z2mRole, "subscribeLiteral"), [{acltype: "subscribeLiteral", topic: `${manifest.scope.base_topic}/#`, allow: true, priority: 100}]), "manifest_z2m_literal");
    const z2mRoleAcls = roleByName(manifest, z2mRole).acls;
    gate(z2mRoleAcls.findIndex((acl) => acl.acltype === "subscribeLiteral") < z2mRoleAcls.findIndex((acl) => acl.acltype === "subscribePattern"), "manifest_z2m_acl_order");

    gate(policy.clients.length === 4 && new Set(policy.clients.map((client) => client.principal)).size === 4, "manifest_policy_clients");
    gate(same(policy.clients.map((client) => client.principal).sort(), ["collector", "orchestrator", "other", "z2m"]), "manifest_policy_clients");
    for (const client of policy.clients) {
        exactKeys(client, ["principal", "roles"], "manifest_policy_client_shape");
        gate(Array.isArray(client.roles) && client.roles.length === 1, "manifest_policy_client_roles");
        gate(client.roles[0].rolename === manifest.principals[client.principal].role && client.roles[0].priority === 100, "manifest_policy_client_role");
    }
    gate(policy.canonical_sha256 === "479fe28dfb3e55f42c71c0e874f9c6cc54e6085488507d8dccc8e66938f5f008" && policy.canonical_sha256 === policyDigest(manifest), "manifest_policy_digest");
    gate(policy.expected_readback_sha256 === "1fc47098751a6541b285df1693c44d171b43e5f6621ae441f4bed04a8ddf7706" && policy.expected_readback_sha256 === expectedReadbackDigest(manifest), "manifest_readback_digest");
    exactKeys(manifest.gateway, ["schema", "generation", "frontend_listener_port", "backend_broker_port", "policy_sha256", "runtime_loaded_policy_digest", "credential_files_provisioned", "artifact_files_provisioned", "connect_password_in_transit", "connect_password_decoded", "connect_password_persisted", "broker_ack_authority", "gateway_enforcement", "deep_containment", "qos_enforced", "qos2_stateful", "retain_enforced", "bounded_session_timers", "bidirectional_backpressure", "broker_origin_malformed_latches_gateway", "composite_policy"], "manifest_gateway_shape");
    gate(manifest.gateway.schema === "true-family-pass-b1a-gateway-policy-v1" && manifest.gateway.generation === 1 && manifest.gateway.frontend_listener_port === 18884 && manifest.gateway.backend_broker_port === 18883, "manifest_gateway_identity");
    gate(same({
        runtime_loaded_policy_digest: manifest.gateway.runtime_loaded_policy_digest,
        credential_files_provisioned: manifest.gateway.credential_files_provisioned,
        artifact_files_provisioned: manifest.gateway.artifact_files_provisioned,
        connect_password_in_transit: manifest.gateway.connect_password_in_transit,
        connect_password_decoded: manifest.gateway.connect_password_decoded,
        connect_password_persisted: manifest.gateway.connect_password_persisted,
        broker_ack_authority: manifest.gateway.broker_ack_authority,
        gateway_enforcement: manifest.gateway.gateway_enforcement,
        deep_containment: manifest.gateway.deep_containment,
        qos_enforced: manifest.gateway.qos_enforced,
        qos2_stateful: manifest.gateway.qos2_stateful,
        retain_enforced: manifest.gateway.retain_enforced,
        bounded_session_timers: manifest.gateway.bounded_session_timers,
        bidirectional_backpressure: manifest.gateway.bidirectional_backpressure,
        broker_origin_malformed_latches_gateway: manifest.gateway.broker_origin_malformed_latches_gateway,
        composite_policy: manifest.gateway.composite_policy,
    }, {
        runtime_loaded_policy_digest: true,
        credential_files_provisioned: false,
        artifact_files_provisioned: false,
        connect_password_in_transit: true,
        connect_password_decoded: false,
        connect_password_persisted: false,
        broker_ack_authority: true,
        gateway_enforcement: true,
        deep_containment: true,
        qos_enforced: true,
        qos2_stateful: true,
        retain_enforced: true,
        bounded_session_timers: true,
        bidirectional_backpressure: true,
        broker_origin_malformed_latches_gateway: true,
        composite_policy: true,
    }), "manifest_gateway_contract");
    gate(manifest.gateway.policy_sha256 === "c6c19e4fbf668f946c09c5caaec705ce65403e6f055a1154b7ed1956681b93fb" && manifest.gateway.policy_sha256 === gatewayPolicyDigest(manifest), "manifest_gateway_digest");
    gate(same(gatewayPolicyProjection(manifest).assurances, {credential_files_provisioned: false, artifact_files_provisioned: false, connect_password_in_transit: true, connect_password_decoded: false, connect_password_persisted: false, broker_ack_authority: true, gateway_enforcement: true, broker_origin_malformed_latches_gateway: true, composite_policy: true}), "manifest_gateway_assurances");
    exactKeys(manifest.composite_policy, ["schema", "gateway_policy_sha256", "broker_policy_sha256", "preflight_acl_digest", "effective_sha256"], "manifest_composite_shape");
    gate(manifest.composite_policy.gateway_policy_sha256 === manifest.gateway.policy_sha256 && manifest.composite_policy.broker_policy_sha256 === policy.canonical_sha256 && manifest.composite_policy.preflight_acl_digest === manifest.scope.preflight_acl_digest, "manifest_composite_bindings");
    gate(manifest.composite_policy.effective_sha256 === "beaa7fe3fcc73137748c04c70531fc9dc870b3b650f6b1576185e9c391bce0dc" && manifest.composite_policy.effective_sha256 === compositePolicyDigest(manifest), "manifest_composite_digest");
}

function validateMatrix(manifest) {
    exactKeys(manifest.matrix, ["publish", "subscribe"], "manifest_matrix_shape");
    gate(Array.isArray(manifest.matrix.publish) && manifest.matrix.publish.length === 56, "manifest_publish_matrix");
    gate(Array.isArray(manifest.matrix.subscribe) && manifest.matrix.subscribe.length === 60, "manifest_subscribe_matrix");
    gate(new Set(manifest.matrix.publish.map(canonical)).size === manifest.matrix.publish.length, "manifest_publish_duplicate");
    gate(new Set(manifest.matrix.subscribe.map(canonical)).size === manifest.matrix.subscribe.length, "manifest_subscribe_duplicate");
    gate(sha256Bytes(Buffer.from(canonical(manifest.matrix), "utf8")) === "56286ef18ee53f8d691a61b49751a37ece86d246bb8c5b019c194443f7de78bb", "manifest_matrix_digest");
    for (const item of manifest.matrix.publish) {
        const keys = Object.keys(item).sort();
        gate(same(keys, ["allowed", "principal", "topic"].sort()) || same(keys, ["allowed", "principal", "topic_fixture"].sort()) || same(keys, ["allowed", "principal", "qos", "retain", "topic"].sort()), "manifest_publish_case_shape");
        gate(["orchestrator", "z2m", "collector", "other"].includes(item.principal), "manifest_publish_principal");
        gate(typeof item.allowed === "boolean", "manifest_publish_case");
        if (item.topic !== undefined) gate(typeof item.topic === "string" && !/[+#]/u.test(item.topic), "manifest_publish_case");
        if (item.topic_fixture !== undefined) gate(["bridge_request_depth_32", "bridge_request_depth_100", "maximum", "leading_slash", "trailing_slash", "boundary_space", "boundary_unicode", "control", "overlength", "empty", "wildcard_plus", "wildcard_hash", "malformed_utf8", "c1_delete", "c1_first", "c1_last", "noncharacter_fdd0", "noncharacter_fdef", "noncharacter_fffe", "noncharacter_ffff", "noncharacter_plane_end", "surrogate_utf8"].includes(item.topic_fixture), "manifest_publish_fixture");
        if (item.qos !== undefined) gate([0, 1, 2].includes(item.qos) && typeof item.retain === "boolean", "manifest_publish_envelope");
    }
    for (const item of manifest.matrix.subscribe) {
        const keys = Object.keys(item).sort();
        gate(same(keys, ["allowed", "delivery_topic", "filter", "principal"].sort()) || same(keys, ["allowed", "delivery_topic", "filter_fixture", "principal"].sort()) || same(keys, ["allowed", "delivery_topic", "filter", "principal", "qos"].sort()), "manifest_subscribe_case_shape");
        gate(["orchestrator", "z2m", "collector", "other"].includes(item.principal), "manifest_subscribe_principal");
        gate(typeof item.delivery_topic === "string" && typeof item.allowed === "boolean" && !/[+#]/u.test(item.delivery_topic), "manifest_subscribe_case");
        if (item.filter !== undefined) gate(typeof item.filter === "string", "manifest_subscribe_filter");
        if (item.filter_fixture !== undefined) gate(["maximum", "leading_slash", "trailing_slash", "boundary_space", "boundary_unicode", "control", "overlength", "empty", "malformed_utf8", "c1_delete", "c1_first", "c1_last", "noncharacter_fdd0", "noncharacter_fdef", "noncharacter_fffe", "noncharacter_ffff", "noncharacter_plane_end", "surrogate_utf8"].includes(item.filter_fixture), "manifest_subscribe_fixture");
        if (item.qos !== undefined) gate([0, 1, 2].includes(item.qos), "manifest_subscribe_qos");
        const publisher = manifest.topics.request_topics.includes(item.delivery_topic) ? "orchestrator" : "z2m";
        gate(publishAllowedByManifest(manifest, publisher, item.delivery_topic), "manifest_subscribe_delivery_control");
    }
    const requiredPublishTopics = [
        manifest.topics.arm_request,
        manifest.topics.ack_request,
        manifest.topics.source,
        manifest.topics.backup,
        manifest.topics.candidate_friendly_descendant,
        manifest.topics.candidate_ieee_descendant,
        "zigbee2mqtt/bridge/request/action",
        "zigbee2mqtt/a/b/c/d/e/f/g/h/bridge/request/action",
    ];
    for (const topic of requiredPublishTopics) gate(manifest.matrix.publish.some((item) => item.topic === topic), "manifest_publish_coverage");
    for (const fixture of ["bridge_request_depth_32", "bridge_request_depth_100"]) gate(manifest.matrix.publish.some((item) => item.principal === "z2m" && item.topic_fixture === fixture && item.allowed === false), "manifest_deep_containment");
    gate(manifest.matrix.publish.filter((item) => item.principal === "z2m" && ((item.topic ?? "").includes("/bridge/request/") || String(item.topic_fixture).startsWith("bridge_request_depth_"))).every((item) => item.allowed === false), "manifest_deep_containment");
    gate(manifest.matrix.publish.some((item) => item.principal === "orchestrator" && item.topic === manifest.topics.arm_request && item.qos === 0 && item.retain === false && item.allowed === false), "manifest_qos_case");
    gate(manifest.matrix.publish.some((item) => item.principal === "orchestrator" && item.topic === manifest.topics.arm_request && item.qos === 1 && item.retain === true && item.allowed === false), "manifest_retain_case");
    gate(manifest.matrix.publish.some((item) => item.principal === "z2m" && item.topic === `${manifest.scope.base_topic}/a//b` && item.allowed), "manifest_internal_empty_topic");
    gate(manifest.matrix.publish.some((item) => item.principal === "z2m" && item.topic_fixture === "maximum" && item.allowed), "manifest_topic_maximum");
    gate(manifest.matrix.subscribe.some((item) => item.principal === "z2m" && item.filter_fixture === "maximum" && item.allowed), "manifest_filter_maximum");
    for (const qos of [0, 1, 2]) {
        for (const retain of [false, true]) {
            gate(manifest.matrix.publish.some((item) => item.principal === "z2m" && item.topic === `outside/root/qos${qos}-retain${retain ? 1 : 0}` && item.qos === qos && item.retain === retain && item.allowed), "manifest_z2m_outside_publish_envelope");
        }
        gate(manifest.matrix.subscribe.some((item) => item.principal === "z2m" && item.filter === `outside/root/subscribe-qos${qos}` && item.qos === qos && item.allowed), "manifest_z2m_outside_subscribe_qos");
    }
    for (const fixture of ["leading_slash", "trailing_slash", "boundary_space", "boundary_unicode", "control", "overlength", "empty", "malformed_utf8"]) {
        gate(manifest.matrix.publish.some((item) => item.topic_fixture === fixture && item.allowed === false), "manifest_publish_topic_validity");
        gate(manifest.matrix.subscribe.some((item) => item.filter_fixture === fixture && item.allowed === false), "manifest_subscribe_topic_validity");
    }
    for (const fixture of ["wildcard_plus", "wildcard_hash"]) gate(manifest.matrix.publish.some((item) => item.topic_fixture === fixture && item.allowed === false), "manifest_publish_topic_validity");
    for (const fixture of ["c1_delete", "c1_first", "c1_last", "noncharacter_fdd0", "noncharacter_fdef", "noncharacter_fffe", "noncharacter_ffff", "noncharacter_plane_end", "surrogate_utf8"]) {
        gate(manifest.matrix.publish.some((item) => item.topic_fixture === fixture && item.allowed === false), "manifest_publish_mqtt_utf8");
        gate(manifest.matrix.subscribe.some((item) => item.filter_fixture === fixture && item.allowed === false), "manifest_subscribe_mqtt_utf8");
    }
    for (const filter of [`${manifest.scope.base_topic}/#`, `${manifest.scope.base_topic}/+`, `${manifest.scope.base_topic}/bridge/#`, "#", "+", `$share/b1a/${manifest.scope.base_topic}/#`]) {
        gate(manifest.matrix.subscribe.some((item) => item.filter === filter), "manifest_subscribe_coverage");
    }
    gate(manifest.matrix.subscribe.some((item) => item.principal === "z2m" && item.filter === "$share/b1a/outside/root" && item.allowed === false), "manifest_concrete_shared_denial");
    gate(manifest.matrix.subscribe.some((item) => item.principal === "z2m" && item.filter === `${manifest.scope.base_topic}/#` && item.allowed), "manifest_z2m_root_filter");
    gate(manifest.matrix.subscribe.some((item) => item.principal === "z2m" && item.filter === `${manifest.scope.base_topic}/a//b` && item.allowed), "manifest_internal_empty_filter");
    gate(manifest.matrix.subscribe.filter((item) => item.filter === `${manifest.scope.base_topic}/#` && item.principal !== "z2m").every((item) => !item.allowed), "manifest_broad_filter_denial");
}

function validatePreflightBinding(manifest) {
    const plan = manifest.preflight_acl;
    const effective = plan.effective_policy;
    exactKeys(plan, ["schema", "scope_digest", "policy_digest", "effective_policy"], "preflight_acl_plan_shape");
    exactKeys(effective, ["schema", "topic_contract", "enforcement", "scope", "principals", "global_denies"], "preflight_acl_effective_shape");
    gate(plan.schema === "true-family-physical-probe-acl-plan-v2" && effective.schema === plan.schema, "preflight_acl_schema");
    gate(plan.policy_digest === manifest.scope.preflight_acl_digest && domainDigest(effective, "true-family-physical-probe/acl/v2") === plan.policy_digest, "preflight_acl_digest");
    const scopeProjection = {base_topic: manifest.scope.base_topic, friendly_name: manifest.scope.friendly_name, candidate_ieee: manifest.scope.candidate_ieee, set_topic: manifest.scope.set_topic};
    gate(domainDigest(scopeProjection, "true-family-physical-probe/scope/v1") === plan.scope_digest, "preflight_scope_digest");
    exactKeys(effective.topic_contract, ["maximum_codepoints", "mqtt_utf8_exclusions", "boundaries", "concrete_topic_wildcards", "internal_empty_segments", "shared_subscriptions", "zigbee2mqtt_exact_base_wildcard_subscription", "adjacent_bridge_request_publish"], "preflight_topic_contract_shape");
    exactKeys(effective.topic_contract.boundaries, ["leading_slash", "trailing_slash", "leading_or_trailing_whitespace"], "preflight_topic_boundaries_shape");
    gate(same(effective.topic_contract, {
        maximum_codepoints: 256,
        mqtt_utf8_exclusions: ["null-and-c0-controls", "c1-controls", "utf16-surrogates", "noncharacters-fdd0-fdef", "plane-end-noncharacters"],
        boundaries: {leading_slash: false, trailing_slash: false, leading_or_trailing_whitespace: false},
        concrete_topic_wildcards: false,
        internal_empty_segments: true,
        shared_subscriptions: false,
        zigbee2mqtt_exact_base_wildcard_subscription: `${manifest.scope.base_topic}/#`,
        adjacent_bridge_request_publish: false,
    }), "preflight_topic_contract");
    exactKeys(manifest.topic_oracle, ["schema", "maximum_codepoints", "valid_codepoints", "invalid_codepoints", "valid_topics", "invalid_topics"], "preflight_topic_oracle_shape");
    gate(manifest.topic_oracle.schema === "true-family-pass-b1a-topic-oracle-v1" && manifest.topic_oracle.maximum_codepoints === effective.topic_contract.maximum_codepoints, "preflight_topic_oracle_limit");
    for (const topic of manifest.topic_oracle.valid_topics) gate(topicContractValid(topic), "preflight_topic_oracle_valid");
    for (const topic of manifest.topic_oracle.invalid_topics) gate(!topicContractValid(topic), "preflight_topic_oracle_invalid");
    for (const codepoint of manifest.topic_oracle.valid_codepoints) gate(topicContractValid(`safe/${String.fromCodePoint(codepoint)}/topic`), "preflight_topic_oracle_valid_codepoint");
    for (const codepoint of manifest.topic_oracle.invalid_codepoints) gate(!topicContractValid(`safe/${String.fromCodePoint(codepoint)}/topic`), "preflight_topic_oracle_invalid_codepoint");
    gate(same(effective.enforcement, {
        anonymous_access: "disabled",
        superuser_bypass: "disabled",
        dedicated_listener: true,
        effective_readback_complete: true,
    }), "preflight_enforcement");
    gate(effective.scope.base_topic === manifest.scope.base_topic && effective.scope.candidate_set_topic === `${manifest.scope.base_topic}/${manifest.scope.set_topic}`, "preflight_acl_scope");
    gate(same(effective.scope.candidate_publish_roots, [manifest.topics.candidate_friendly, manifest.topics.candidate_ieee]), "preflight_candidate_roots");
    const orchestrator = effective.principals.orchestrator;
    gate(orchestrator.publish_default === "deny" && orchestrator.subscribe_default === "deny", "preflight_orchestrator_defaults");
    gate(same(orchestrator.publish_allow, manifest.topics.request_topics.map((topic) => ({topic, qos: 1, retain: false}))), "preflight_orchestrator_publish");
    gate(same(orchestrator.subscribe_allow, [manifest.topics.ready, manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response]), "preflight_orchestrator_subscribe");
    const z2m = effective.principals.zigbee2mqtt;
    gate(same(z2m, {
        publish_default: "allow",
        subscribe_default: "allow",
        subscribe_filters: [`${manifest.scope.base_topic}/#`],
        bridge_request_publish: "deny",
    }), "preflight_z2m");
    for (const principal of ["admin_recovery", "other", "anonymous"]) {
        gate(same(effective.principals[principal], {publish_default: "deny", subscribe_default: "deny"}), "preflight_denied_principal");
    }
    gate(same(effective.global_denies, {
        unknown_principals: true,
        non_zigbee2mqtt_candidate_publish_subtrees: true,
        bridge_request_publish_slash_containment: true,
        bridge_request_publish_exceptions: manifest.topics.request_topics,
    }), "preflight_global_denies");
}

export function validateManifest(manifest) {
    exactKeys(manifest, [
        "schema", "manifest_version", "pass", "classification", "authoritative", "pass_b1_complete", "authorization", "loose_spare_used",
        "trust_boundary", "images", "broker", "gateway", "composite_policy", "containers", "credentials", "principals", "authentication", "scope", "preflight_acl", "topic_oracle", "topics", "policy", "matrix",
        "source_privacy", "artifact", "evidence", "cleanup", "bindings",
    ], "manifest_shape");
    exactKeys(manifest.images, ["node", "mosquitto"], "manifest_images_shape");
    exactKeys(manifest.images.node, ["tag", "child", "index_reference_sha256", "platform", "version", "expected_env", "expected_labels", "expected_entrypoint", "expected_command"], "manifest_node_shape");
    exactKeys(manifest.images.mosquitto, ["tag", "index_reference_sha256", "child", "oci_config_digest", "platform", "version", "upstream_source_sha256", "expected_env", "expected_labels", "expected_entrypoint", "expected_command", "dynamic_security_plugin", "mosquitto_ctrl"], "manifest_mosquitto_shape");
    exactKeys(manifest.broker, ["listener_port", "network", "config_lines", "config_sha256", "forbidden_directives", "forbidden_exact_lines", "dynamic_security"], "manifest_broker_shape");
    exactKeys(manifest.broker.network, ["driver", "internal", "published_ports", "per_replica", "planes", "gateway_only_dual_homed"], "manifest_network_shape");
    exactKeys(manifest.broker.dynamic_security, ["only_authentication_authority", "bootstrap_method", "bootstrap_password_boundary", "plaintext_password_in_docker_create_or_inspect", "control_success_requires_correlated_response", "check_retain_source_configured", "check_retain_source_behavior_tested", "retained_persistence_behavior_tested", "application_credential_acl_samples_tested", "broker_native_qos_retain", "composite_policy"], "manifest_dynsec_shape");
    exactKeys(manifest.containers, ["runtime_user", "broker_user", "read_only_root", "cap_drop_all", "no_new_privileges", "private_ipc", "private_cgroup_namespace", "init", "restart", "log_driver", "log_options", "client_limits", "broker_limits", "forbidden_mount_destinations", "topology"], "manifest_containers_shape");
    exactKeys(manifest.containers.log_options, ["max-file", "max-size"], "manifest_log_shape");
    exactKeys(manifest.containers.client_limits, ["memory_bytes", "memory_swap_bytes", "nano_cpus", "pids", "nofile", "core", "tmpfs_bytes"], "manifest_limits_shape");
    exactKeys(manifest.containers.broker_limits, ["memory_bytes", "memory_swap_bytes", "nano_cpus", "pids", "nofile", "core", "tmpfs_bytes"], "manifest_limits_shape");
    exactKeys(manifest.containers.topology, ["broker_networks", "gateway_networks", "admin_networks", "observer_networks", "application_probe_networks", "client_networks", "setup_networks", "host_ports", "client_broker_dns", "client_broker_tcp", "same_runner_host_isolation_proven"], "manifest_topology_shape");
    exactKeys(manifest.credentials, ["admin_schema", "frontend_schema", "observer_schema", "root_mode", "file_mode", "password_bytes", "password_encoding", "stdout", "evidence", "artifacts", "private_root_only", "deleted_before_pass"], "manifest_credentials_shape");
    exactKeys(manifest.authentication, ["wrong_client_id", "anonymous_client_id", "unknown_client_id", "unknown_username", "accepted_negative_reason_classes"], "manifest_auth_shape");
    exactKeys(manifest.scope, ["base_topic", "friendly_name", "candidate_ieee", "set_topic", "preflight_acl_digest"], "manifest_scope_shape");
    exactKeys(manifest.topics, ["arm_request", "ack_request", "ready", "status", "result", "response", "ack_response", "source", "backup", "candidate_friendly", "candidate_friendly_set", "candidate_friendly_descendant", "candidate_ieee", "candidate_ieee_descendant", "native_outside", "native_retained_sentinel", "request_topics"], "manifest_topics_shape");
    exactKeys(manifest.source_privacy, ["synthetic_publisher", "real_externaljs_path", "inventory_shape", "principals", "denied_filters", "source_canary", "raw_source_emitted", "retained_clear", "restart_old_replay_expected"], "manifest_source_shape");
    exactKeys(manifest.artifact, ["path", "filename", "byte_length", "sha256"], "manifest_artifact_shape");
    exactKeys(manifest.evidence, ["runtime_schema", "replica_schema", "gateway_startup_schema", "final_schema", "failure_schema", "failure_record", "runtime_failure_record", "replicas", "normalized_byte_identical", "uploaded_artifacts", "stdout_records", "raw_stderr", "max_runtime_bytes", "max_final_bytes", "claim_limits"], "manifest_evidence_shape");
    exactKeys(manifest.evidence.failure_record, ["exact_keys", "failure_code", "top_level_stages", "replica_ordinals", "replica_phases", "install_failure_categories", "invalid_stage", "only_diagnostic_field", "max_bytes"], "manifest_failure_record_shape");
    exactKeys(manifest.evidence.runtime_failure_record, ["schema", "exact_keys", "categories", "detailed_mode", "generic_error_category", "other_mode_category", "max_bytes"], "manifest_runtime_failure_record_shape");
    exactKeys(manifest.cleanup, ["label", "root_pattern", "root_mode", "find_mode", "symlinks_followed", "files_chmodded", "zero_labeled_containers_before_delete", "zero_labeled_networks_before_delete", "run_watchdog_seconds", "workflow_timeout_seconds", "longest_bounded_command_seconds", "nominal_headroom_if_watchdog_started_at_job_start_seconds", "nominal_headroom_after_longest_command_seconds", "workflow_timeout_cleanup_guaranteed", "private_root_removal_attempted_after_cleanup_failure", "credentials_absent_before_pass", "root_absent_before_pass"], "manifest_cleanup_shape");
    exactKeys(manifest.bindings, ["launcher_normalization", "launcher_normalized_sha256", "runtime_harness_sha256", "verifier_sha256", "workflow_sha256", "preflight_source_sha256", "preflight_fixture_sha256", "preflight_test_sha256", "b0_preservation"], "manifest_bindings_shape");
    exactKeys(manifest.bindings.b0_preservation, ["launcher_sha256", "workflow_sha256", "manifest_sha256", "runtime_harness_sha256", "verifier_sha256", "preflight_fixture_sha256"], "manifest_b0_shape");
    gate(manifest.schema === MANIFEST_SCHEMA && manifest.manifest_version === 1 && manifest.pass === "B1A", "manifest_identity");
    gate(manifest.classification === CLASSIFICATION && manifest.authoritative === false && manifest.pass_b1_complete === false && manifest.authorization === false && manifest.loose_spare_used === false, "manifest_classification");
    gate(same(manifest.trust_boundary, {
        same_repository_reviewed_source: true,
        ci_only: true,
        independently_attested: false,
        malicious_source_resistant: false,
        household_equivalent: false,
    }), "manifest_trust_boundary");
    gate(manifest.images.node.child === "docker.io/library/node:20.19.2-bookworm-slim@sha256:ae5e29a169a6dbe7f45d552d73674001cc00913a0a8a5967c57a34f92e940ec8", "manifest_node_image");
    gate(manifest.images.node.index_reference_sha256 === "sha256:7cd3fbc830c75c92256fe1122002add9a1c025831af8770cd0bf8e45688ef661", "manifest_node_index");
    gate(manifest.images.mosquitto.tag === "eclipse-mosquitto:2.0.22" && manifest.images.mosquitto.index_reference_sha256 === "sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c", "manifest_mosquitto_index");
    gate(manifest.images.mosquitto.child === "docker.io/library/eclipse-mosquitto@sha256:54c90ecc78645241b6aa272b2a5ac8fc20b0eaf02cc4dd431c0cc8d2fd4447dd", "manifest_mosquitto_image");
    gate(manifest.images.mosquitto.oci_config_digest === "sha256:93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3", "manifest_mosquitto_config");
    gate(manifest.images.mosquitto.version === "2.0.22" && manifest.images.mosquitto.upstream_source_sha256 === "2f752589ef7db40260b633fbdb536e9a04b446a315138d64a7ff3c14e2de6b68", "manifest_mosquitto_source");
    gate(manifest.images.node.platform === "linux/amd64" && manifest.images.mosquitto.platform === "linux/amd64", "manifest_platform");
    gate(manifest.images.node.tag === "node:20.19.2-bookworm-slim" && manifest.images.node.version === "20.19.2", "manifest_node_version");
    gate(same(manifest.images.node.expected_env, ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NODE_VERSION=20.19.2", "YARN_VERSION=1.22.22"]), "manifest_node_environment");
    gate(same(manifest.images.node.expected_labels, {}) && same(manifest.images.node.expected_entrypoint, ["docker-entrypoint.sh"]) && same(manifest.images.node.expected_command, ["node"]), "manifest_node_config");
    gate(manifest.images.mosquitto.dynamic_security_plugin === "/usr/lib/mosquitto_dynamic_security.so" && manifest.images.mosquitto.mosquitto_ctrl === "/usr/bin/mosquitto_ctrl", "manifest_mosquitto_paths");
    gate(same(manifest.images.mosquitto.expected_env, [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "VERSION=2.0.22",
        "DOWNLOAD_SHA256=2f752589ef7db40260b633fbdb536e9a04b446a315138d64a7ff3c14e2de6b68",
        "GPG_KEYS=A0D6EEA1DCAE49A635A3B2F0779B22DFB3E717B7",
    ]), "manifest_mosquitto_environment");
    gate(same(manifest.images.mosquitto.expected_labels, {
        "org.opencontainers.image.authors": "Roger Light <roger@atchoo.org>",
        "org.opencontainers.image.description": "Eclipse Mosquitto MQTT Broker",
        "org.opencontainers.image.documentation": "https://mosquitto.org/documentation/",
        "org.opencontainers.image.licenses": "EPL-2.0 OR BSD-3-Clause",
        "org.opencontainers.image.source": "https://github.com/eclipse-mosquitto/mosquitto",
        "org.opencontainers.image.title": "eclipse-mosquitto",
        "org.opencontainers.image.url": "https://mosquitto.org/",
        "org.opencontainers.image.version": "2.0.22",
    }), "manifest_mosquitto_labels");
    gate(same(manifest.images.mosquitto.expected_entrypoint, ["/docker-entrypoint.sh"]) && same(manifest.images.mosquitto.expected_command, ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]), "manifest_mosquitto_command");
    gate(manifest.broker.listener_port === 18883 && same(manifest.broker.network, {driver: "bridge", internal: true, published_ports: false, per_replica: true, planes: ["backend", "frontend"], gateway_only_dual_homed: true}), "manifest_broker_network");
    gate(same(manifest.broker.config_lines, [
        "per_listener_settings false",
        "listener 18883 0.0.0.0",
        "protocol mqtt",
        "allow_anonymous false",
        "persistence true",
        "persistence_file mosquitto.db",
        "persistence_location /mosquitto/data/",
        "autosave_interval 1",
        "autosave_on_changes true",
        "check_retain_source true",
        "max_packet_size 1048576",
        "message_size_limit 524288",
        "max_inflight_messages 20",
        "max_queued_messages 100",
        "plugin /usr/lib/mosquitto_dynamic_security.so",
        "plugin_opt_config_file /mosquitto/data/dynamic-security.json",
        "connection_messages false",
        "log_dest stderr",
        "log_type error",
        "log_type warning",
        "log_timestamp false",
    ]), "manifest_broker_config");
    gate(same(manifest.broker.forbidden_directives, ["acl_file", "password_file", "bridge", "connection", "remote_username", "remote_password", "use_username_as_clientid", "port", "user"]), "manifest_broker_forbidden_directives");
    gate(same(manifest.broker.forbidden_exact_lines, ["allow_anonymous true", "user root"]), "manifest_broker_forbidden_lines");
    const config = brokerConfigBytes(manifest);
    gate(sha256Bytes(config) === manifest.broker.config_sha256, "manifest_broker_config_digest");
    const configText = config.toString("utf8");
    for (const required of [
        "listener 18883 0.0.0.0\n", "allow_anonymous false\n", "persistence true\n", "check_retain_source true\n",
        "plugin /usr/lib/mosquitto_dynamic_security.so\n", "plugin_opt_config_file /mosquitto/data/dynamic-security.json\n",
    ]) gate(configText.includes(required), "manifest_broker_config");
    const configDirectives = manifest.broker.config_lines.map((line) => line.trim().split(/\s+/u)[0]);
    gate(configDirectives.filter((directive) => directive === "listener").length === 1, "manifest_broker_listener");
    gate(!configDirectives.some((directive) => manifest.broker.forbidden_directives.includes(directive)), "manifest_broker_forbidden");
    gate(!manifest.broker.config_lines.some((line) => manifest.broker.forbidden_exact_lines.includes(line.trim())), "manifest_broker_forbidden");
    gate(same(manifest.broker.dynamic_security, {
        only_authentication_authority: true,
        bootstrap_method: "official-mosquitto-ctrl-isolated-setup-container",
        bootstrap_password_boundary: "mode-0600-file-read-then-transient-private-setup-process-argument",
        plaintext_password_in_docker_create_or_inspect: false,
        control_success_requires_correlated_response: true,
        check_retain_source_configured: true,
        check_retain_source_behavior_tested: false,
        retained_persistence_behavior_tested: true,
        application_credential_acl_samples_tested: true,
        broker_native_qos_retain: false,
        composite_policy: true,
    }), "manifest_dynsec_boundary");
    gate(same(manifest.containers, {
        runtime_user: "host-runner-numeric-nonroot",
        broker_user: "host-runner-numeric-nonroot",
        read_only_root: true,
        cap_drop_all: true,
        no_new_privileges: true,
        private_ipc: true,
        private_cgroup_namespace: true,
        init: true,
        restart: "no",
        log_driver: "json-file",
        log_options: {"max-file": "1", "max-size": "1m"},
        client_limits: {memory_bytes: 268_435_456, memory_swap_bytes: 268_435_456, nano_cpus: 1_000_000_000, pids: 64, nofile: 256, core: 0, tmpfs_bytes: 16_777_216},
        broker_limits: {memory_bytes: 134_217_728, memory_swap_bytes: 134_217_728, nano_cpus: 500_000_000, pids: 32, nofile: 256, core: 0, tmpfs_bytes: 16_777_216},
        forbidden_mount_destinations: ["/homeassistant", "/addons", "/addon_configs", "/github/workspace", "/run/docker.sock", "/var/run/docker.sock", "/dev"],
        topology: {
            broker_networks: ["backend"], gateway_networks: ["backend", "frontend"], admin_networks: ["backend"], observer_networks: ["backend"], application_probe_networks: ["backend"], client_networks: ["frontend"], setup_networks: [],
            host_ports: false, client_broker_dns: false, client_broker_tcp: false, same_runner_host_isolation_proven: false,
        },
    }), "manifest_container_policy");
    gate(same(manifest.credentials, {
        admin_schema: "true-family-pass-b1a-admin-credential-v1",
        frontend_schema: "true-family-pass-b1a-frontend-credentials-v1",
        observer_schema: "true-family-pass-b1a-observer-credential-v1",
        root_mode: "0700",
        file_mode: "0600",
        password_bytes: 32,
        password_encoding: "base64url-no-padding",
        stdout: false,
        evidence: false,
        artifacts: false,
        private_root_only: true,
        deleted_before_pass: true,
    }), "manifest_credential_policy");
    gate(manifest.scope.base_topic === "zigbee2mqtt" && manifest.scope.friendly_name === "spare-brt-100" && manifest.scope.candidate_ieee === "0xa4c1380000000001", "manifest_scope");
    gate(manifest.scope.preflight_acl_digest === "a6a9ac8d16025af3670a84b2ddd40fb4b0a2f155043402eadff43aeb23bd6cb8", "manifest_preflight_policy");
    gate(manifest.scope.set_topic === "spare-brt-100/set", "manifest_scope");
    gate(same(manifest.topics.request_topics, [manifest.topics.arm_request, manifest.topics.ack_request]), "manifest_request_topics");
    gate(manifest.topics.source === `${manifest.scope.base_topic}/bridge/extensions` && manifest.topics.candidate_friendly_set === `${manifest.scope.base_topic}/${manifest.scope.set_topic}`, "manifest_topic_scope");
    gate(manifest.topics.native_outside === "true-family-b1a/native/outside" && manifest.topics.native_retained_sentinel === "true-family-b1a/native/retained-sentinel", "manifest_native_topics");
    gate(!manifest.topics.native_outside.startsWith(`${manifest.scope.base_topic}/`) && !manifest.topics.native_retained_sentinel.startsWith(`${manifest.scope.base_topic}/`), "manifest_native_topics");
    gate(same(manifest.authentication, {
        wrong_client_id: "tf-b1a-wrong-client",
        anonymous_client_id: "tf-b1a-anonymous-client",
        unknown_client_id: "tf-b1a-unknown-client",
        unknown_username: "tf-b1a-unknown",
        accepted_negative_reason_classes: ["bad_username_or_password", "connection_closed", "not_authorized"],
    }), "manifest_auth_policy");
    const principalKeys = ["admin", "z2m", "orchestrator", "collector", "other", "observer"];
    gate(same(Object.keys(manifest.principals), principalKeys), "manifest_principals");
    const usernames = new Set();
    const clientIds = new Set();
    for (const [key, principal] of Object.entries(manifest.principals)) {
        exactKeys(principal, ["username", "client_id", "role", "purpose"], "manifest_principal_shape");
        gate(principal.username === `tf-b1a-${key}` && principal.client_id === `tf-b1a-${key}-client`, "manifest_principal_identity");
        gate(!usernames.has(principal.username) && !clientIds.has(principal.client_id), "manifest_principal_unique");
        usernames.add(principal.username);
        clientIds.add(principal.client_id);
    }
    gate(manifest.principals.collector.purpose.includes("test-only") && manifest.principals.collector.purpose.includes("not-production"), "manifest_collector_boundary");
    gate(manifest.source_privacy.synthetic_publisher === true && manifest.source_privacy.real_externaljs_path === false && manifest.source_privacy.raw_source_emitted === false, "manifest_source_boundary");
    gate(same(manifest.source_privacy.principals, ["orchestrator", "collector", "other"]), "manifest_source_principals");
    gate(same(manifest.source_privacy.denied_filters, [manifest.topics.source, `${manifest.scope.base_topic}/#`, `$share/b1a/${manifest.scope.base_topic}/#`]), "manifest_source_filters");
    gate(manifest.source_privacy.inventory_shape === "JSON.stringify([{name:artifact.filename,code:exact_utf8_source}])" && manifest.source_privacy.retained_clear === "z2m-zero-length-retained-qos1" && manifest.source_privacy.restart_old_replay_expected === false, "manifest_source_contract");
    gate(manifest.source_privacy.source_canary === "MANDATORY RESIDUAL WRITER FENCE: a future preflight must give Zigbee2MQTT a", "manifest_source_canary");
    gate(manifest.artifact.path === "custom_components/true_family/probe/true_family_brt_probe.mjs" && manifest.artifact.filename === "true_family_brt_probe.mjs" && manifest.artifact.byte_length === 164_691 && manifest.artifact.sha256 === "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1", "manifest_artifact");
    gate(same(manifest.evidence.claim_limits, CLAIM_LIMITS), "manifest_claim_limits");
    gate(manifest.evidence.runtime_schema === RUNTIME_SCHEMA && manifest.evidence.replica_schema === REPLICA_SCHEMA && manifest.evidence.gateway_startup_schema === "true-family-pass-b1a-gateway-startup-v1" && manifest.evidence.final_schema === FINAL_SCHEMA && manifest.evidence.failure_schema === LAUNCHER_FAILURE_SCHEMA, "manifest_evidence_schemas");
    gate(same(manifest.evidence.failure_record, {
        exact_keys: ["failure_code", "failure_stage", "result", "schema"],
        failure_code: LAUNCHER_FAILURE_CODE,
        top_level_stages: LAUNCHER_TOP_LEVEL_FAILURE_STAGES,
        replica_ordinals: [1, 2],
        replica_phases: LAUNCHER_REPLICA_FAILURE_PHASES,
        install_failure_categories: INSTALL_FAILURE_CATEGORIES,
        invalid_stage: "unknown",
        only_diagnostic_field: "failure_stage",
        max_bytes: 256,
    }), "manifest_failure_record");
    gate(same(manifest.evidence.runtime_failure_record, {
        schema: RUNTIME_FAILURE_SCHEMA,
        exact_keys: ["failure_category", "result", "schema"],
        categories: INSTALL_FAILURE_CATEGORIES,
        detailed_mode: "install",
        generic_error_category: "unknown",
        other_mode_category: "unknown",
        max_bytes: 256,
    }), "manifest_runtime_failure_record");
    gate([...LAUNCHER_FAILURE_STAGES].every((stage) => /^[a-z0-9_]+$/u.test(stage) && Buffer.byteLength(launcherFailureRecord(stage), "utf8") <= manifest.evidence.failure_record.max_bytes), "manifest_failure_stages");
    gate(manifest.evidence.replicas === 2 && manifest.evidence.normalized_byte_identical === true && manifest.evidence.uploaded_artifacts === false && manifest.evidence.stdout_records === 1 && manifest.evidence.raw_stderr === false, "manifest_evidence");
    gate(manifest.evidence.max_runtime_bytes === MAX_RUNTIME_BYTES && manifest.evidence.max_final_bytes === MAX_FINAL_BYTES, "manifest_evidence_limits");
    gate(same(manifest.cleanup, {
        label: "true-family-pass-b1a",
        root_pattern: "$RUNNER_TEMP/true-family-pass-b1a.*",
        root_mode: "0700",
        find_mode: "find -P -xdev",
        symlinks_followed: false,
        files_chmodded: false,
        zero_labeled_containers_before_delete: true,
        zero_labeled_networks_before_delete: true,
        run_watchdog_seconds: 1920,
        workflow_timeout_seconds: 2700,
        longest_bounded_command_seconds: 270,
        nominal_headroom_if_watchdog_started_at_job_start_seconds: 780,
        nominal_headroom_after_longest_command_seconds: 510,
        workflow_timeout_cleanup_guaranteed: false,
        private_root_removal_attempted_after_cleanup_failure: true,
        credentials_absent_before_pass: true,
        root_absent_before_pass: true,
    }), "manifest_cleanup");
    for (const value of [manifest.bindings.launcher_normalized_sha256, manifest.bindings.runtime_harness_sha256, manifest.bindings.verifier_sha256, manifest.bindings.workflow_sha256, manifest.bindings.preflight_source_sha256, manifest.bindings.preflight_fixture_sha256, manifest.bindings.preflight_test_sha256, ...Object.values(manifest.bindings.b0_preservation)]) {
        gate(SHA256_PATTERN.test(value), "manifest_binding_digest");
    }
    gate(manifest.bindings.launcher_normalization === "sha256 after replacing the sole EXPECTED_LAUNCHER_SHA256 lowercase-hex literal with 64 zeroes", "manifest_launcher_normalization");
    validatePreflightBinding(manifest);
    validatePolicy(manifest);
    validateMatrix(manifest);
    return manifest;
}

function validateStaticBindings(paths) {
    for (const file of Object.values(paths)) {
        const metadata = fs.lstatSync(file);
        gate(metadata.isFile() && !metadata.isSymbolicLink(), "static_binding_file");
    }
    const manifest = validateManifest(readJson(paths.manifest, "manifest_json"));
    const launcher = normalizedLauncherDigest(fs.readFileSync(paths.launcher));
    gate(launcher.digest === manifest.bindings.launcher_normalized_sha256 && launcher.literal === launcher.digest, "launcher_digest");
    gate(sha256File(paths.runtime) === manifest.bindings.runtime_harness_sha256, "runtime_digest");
    gate(sha256File(paths.verifier) === manifest.bindings.verifier_sha256, "verifier_digest");
    gate(sha256File(paths.workflow) === manifest.bindings.workflow_sha256, "workflow_digest");
    gate(sha256File(paths.artifact) === manifest.artifact.sha256 && fs.statSync(paths.artifact).size === manifest.artifact.byte_length, "artifact_digest");
    gate(sha256File(paths.preflight) === manifest.bindings.preflight_source_sha256, "preflight_digest");
    gate(sha256File(paths.fixture) === manifest.bindings.preflight_fixture_sha256, "fixture_digest");
    gate(sha256File(paths.preflightTest) === manifest.bindings.preflight_test_sha256, "preflight_test_digest");
    readJson(paths.fixture, "preflight_fixture_json");
    gate(fs.readFileSync(paths.artifact, "utf8").includes(manifest.source_privacy.source_canary), "source_canary_binding");
    const b0 = manifest.bindings.b0_preservation;
    gate(sha256File(paths.b0Launcher) === b0.launcher_sha256, "b0_launcher_drift");
    gate(sha256File(paths.b0Workflow) === b0.workflow_sha256, "b0_workflow_drift");
    gate(sha256File(paths.b0Manifest) === b0.manifest_sha256, "b0_manifest_drift");
    gate(sha256File(paths.b0Runtime) === b0.runtime_harness_sha256, "b0_runtime_drift");
    gate(sha256File(paths.b0Verifier) === b0.verifier_sha256, "b0_verifier_drift");
    gate(sha256File(paths.fixture) === b0.preflight_fixture_sha256, "b0_preflight_fixture_drift");
    return manifest;
}

function validateImageInspect(inspect, kind, manifest) {
    gate(kind === "node" || kind === "mosquitto", "image_kind");
    gate(Array.isArray(inspect) && inspect.length === 1, "image_inspect_shape");
    const item = inspect[0];
    const expected = manifest.images[kind];
    gate(item.Os === "linux" && item.Architecture === "amd64", "image_platform");
    gate(SHA256_PREFIX_PATTERN.test(item.Id), "image_config_digest");
    if (kind === "mosquitto") gate(item.Id === expected.oci_config_digest, "image_config_digest");
    const digest = expected.child.split("@")[1];
    const names = kind === "node"
        ? new Set([expected.child, `node@${digest}`, `docker.io/library/node@${digest}`])
        : new Set([expected.child, `eclipse-mosquitto@${digest}`, `docker.io/library/eclipse-mosquitto@${digest}`]);
    gate(Array.isArray(item.RepoDigests) && item.RepoDigests.length > 0 && item.RepoDigests.some((value) => names.has(value)), "image_repo_digest");
    gate(item.RepoDigests.every((value) => /^[^@\s]+@sha256:[0-9a-f]{64}$/u.test(value)), "image_repo_digest");
    gate(same(item.Config?.Env, expected.expected_env), "image_environment");
    gate(same(item.Config?.Labels ?? {}, expected.expected_labels), "image_labels");
    gate(same(item.Config?.Entrypoint, expected.expected_entrypoint) && same(item.Config?.Cmd, expected.expected_command), "image_command");
    return {child: expected.child, config_digest: item.Id, platform: "linux/amd64"};
}

function validateLogConfig(value) {
    gate(same(value, {Type: "json-file", Config: {"max-file": "1", "max-size": "1m"}}), "container_log_config");
}

function numericNonrootUser(value) {
    const match = /^([1-9][0-9]*):([1-9][0-9]*)$/u.exec(value ?? "");
    return match !== null;
}

function validDockerTimestamp(value, {allowZero = false} = {}) {
    if (allowZero && value === "0001-01-01T00:00:00Z") return true;
    return typeof value === "string" && /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/u.test(value);
}

export function containerNetworkAliasesInclude(item, networkName, alias) {
    const aliases = item?.NetworkSettings?.Networks?.[networkName]?.Aliases;
    return Array.isArray(aliases) && aliases.includes(alias);
}

export function setupUsesNetworkNone(item) {
    const networks = item?.NetworkSettings?.Networks;
    return networks !== null && typeof networks === "object" && !Array.isArray(networks)
        && same(Object.keys(networks), ["none"])
        && networks.none !== null && typeof networks.none === "object" && !Array.isArray(networks.none);
}

function validateCommonContainer(item, kind, manifest) {
    const host = item.HostConfig;
    const imageKind = kind === "broker" || kind === "setup" ? "mosquitto" : "node";
    gate(/^[0-9a-f]{64}$/u.test(item.Id) && /^\/tf-pass-b1a-[0-9a-f]{12}-[12]-(?:setup|broker|gateway|install|client-before|observer-before|readback-before|backend-before|readiness-after|readback-after|backend-after|observer-after|client-after|readiness-final|client-final|backend-final|readback-final)$/u.test(item.Name), "container_identity");
    gate(validDockerTimestamp(item.Created) && item.RestartCount === 0 && item.Platform === "linux", "container_identity");
    gate(SHA256_PREFIX_PATTERN.test(item.Image), "container_image_config");
    if (imageKind === "mosquitto") gate(item.Image === manifest.images.mosquitto.oci_config_digest, "container_image_config");
    gate(item.Config?.Image === manifest.images[imageKind].child && numericNonrootUser(item.Config?.User), "container_image_user");
    gate(same(item.Config?.Env, manifest.images[imageKind].expected_env), "container_environment");
    gate(item.Config?.AttachStdin === false && item.Config?.AttachStdout === true && item.Config?.AttachStderr === true && item.Config?.Tty === false && item.Config?.OpenStdin === false && item.Config?.StdinOnce === false, "container_stdio");
    gate(host && host.ReadonlyRootfs === true && host.Privileged === false, "container_root");
    gate(host.IpcMode === "private" && host.CgroupnsMode === "private" && host.PidMode === "" && host.UTSMode === "" && host.UsernsMode === "", "container_namespaces");
    gate(Array.isArray(host.CapDrop) && host.CapDrop.map((value) => value.toUpperCase()).includes("ALL") && (!host.CapAdd || host.CapAdd.length === 0), "container_capabilities");
    gate(Array.isArray(host.SecurityOpt) && host.SecurityOpt.some((value) => value === "no-new-privileges" || value === "no-new-privileges:true"), "container_no_new_privileges");
    gate(host.Init === true && host.RestartPolicy?.Name === "no" && host.RestartPolicy?.MaximumRetryCount === 0, "container_process");
    gate(host.AutoRemove === false && host.ShmSize === manifest.containers[`${kind === "broker" ? "broker" : "client"}_limits`].tmpfs_bytes, "container_process");
    gate(!host.Devices || host.Devices.length === 0, "container_devices");
    gate(!host.DeviceRequests || host.DeviceRequests.length === 0, "container_devices");
    gate(!host.PortBindings || Object.keys(host.PortBindings).length === 0, "container_ports");
    gate(host.PublishAllPorts === false, "container_ports");
    gate(!host.Binds || host.Binds.length === 0, "container_legacy_binds");
    gate(!host.VolumesFrom || host.VolumesFrom.length === 0, "container_volumes_from");
    gate(!host.Links || host.Links.length === 0, "container_links");
    gate(!host.ExtraHosts || host.ExtraHosts.length === 0, "container_extra_hosts");
    gate(!host.GroupAdd || host.GroupAdd.length === 0, "container_groups");
    validateLogConfig(host.LogConfig);
    const limit = kind === "broker" ? manifest.containers.broker_limits : manifest.containers.client_limits;
    gate(host.PidsLimit === limit.pids && host.Memory === limit.memory_bytes && host.MemorySwap === limit.memory_swap_bytes && host.NanoCpus === limit.nano_cpus, "container_limits");
    const ulimits = Object.fromEntries((host.Ulimits ?? []).map((entry) => [entry.Name, [entry.Soft, entry.Hard]]));
    gate(same(ulimits, {core: [0, 0], nofile: [limit.nofile, limit.nofile]}), "container_ulimits");
    const allMounts = item.Mounts ?? [];
    gate(allMounts.every((mount) => mount.Type === "bind" || mount.Type === "tmpfs"), "container_mount_type");
    for (const mount of allMounts) {
        gate(!manifest.containers.forbidden_mount_destinations.some((forbidden) => mount.Destination === forbidden || mount.Destination.startsWith(`${forbidden}/`)), "container_forbidden_mount");
        gate(!String(mount.Source).includes("docker.sock"), "container_docker_socket");
    }
    const observedTmpfs = allMounts.filter((mount) => mount.Type === "tmpfs");
    gate(observedTmpfs.every((mount) => Object.hasOwn(host.Tmpfs ?? {}, mount.Destination) && (mount.Source === "" || mount.Source === undefined) && mount.RW === true), "container_tmpfs_mounts");
    const mounts = allMounts.filter((mount) => mount.Type !== "tmpfs");
    return {host, mounts, imageKind};
}

function validateContainerInspect(inspect, kind, manifest, options = {}) {
    gate(["setup", "broker", "gateway", "install", "client_before", "observer_before", "readback_before", "backend_before", "readiness_after", "readback_after", "backend_after", "observer_after", "client_after", "readiness_final", "client_final", "backend_final", "readback_final"].includes(kind), "container_kind");
    gate(Array.isArray(inspect) && inspect.length === 1, "container_inspect_shape");
    const item = inspect[0];
    const baseKind = kind.startsWith("client_") ? "client" : kind.startsWith("observer_") ? "observer" : kind.startsWith("readback_") ? "readback" : kind.startsWith("readiness_") ? "readiness" : kind.startsWith("backend_") ? "backend" : kind;
    const {host, mounts, imageKind} = validateCommonContainer(item, baseKind, manifest);
    if (options.mountSources) {
        gate(Object.keys(options.mountSources).length === mounts.length, "container_mount_sources");
        for (const mount of mounts) {
            const expectedSource = options.mountSources[mount.Destination];
            gate(typeof expectedSource === "string" && fs.realpathSync(mount.Source) === fs.realpathSync(expectedSource), "container_mount_sources");
        }
    }
    const expectedImageLabels = manifest.images[imageKind].expected_labels;
    const labels = item.Config?.Labels ?? {};
    for (const [key, value] of Object.entries(expectedImageLabels)) gate(labels[key] === value, "container_image_labels");
    gate(/^[0-9a-f]{32}$/u.test(labels[manifest.cleanup.label]), "container_run_label");
    gate(/^[12]$/u.test(labels[`${manifest.cleanup.label}-replica`]), "container_replica_label");
    gate(labels[`${manifest.cleanup.label}-role`] === baseKind, "container_role_label");
    const customLabelKeys = [manifest.cleanup.label, `${manifest.cleanup.label}-replica`, `${manifest.cleanup.label}-role`];
    gate(same(Object.keys(labels).filter((key) => !Object.hasOwn(expectedImageLabels, key)).sort(), customLabelKeys.sort()), "container_labels");
    const expectedNameSuffix = `-${kind.replaceAll("_", "-")}`;
    gate(item.Name.endsWith(expectedNameSuffix), "container_role_name");
    gate(item.State?.Dead === false && item.State?.Paused === false && item.State?.Restarting === false && item.State?.Error === "", "container_state");
    gate(validDockerTimestamp(item.State?.StartedAt) && validDockerTimestamp(item.State?.FinishedAt, {allowZero: true}), "container_timestamps");
    const tmpfs = host.Tmpfs ?? {};
    if (baseKind === "broker") {
        gate(host.NetworkMode.startsWith("tf-pass-b1a-"), "broker_network");
        gate(containerNetworkAliasesInclude(item, host.NetworkMode, "broker"), "broker_network_alias");
        gate(same(item.Config?.Entrypoint, ["/usr/sbin/mosquitto"]) && same(item.Config?.Cmd, ["-c", "/mosquitto/config/pass-b1a.conf"]), "broker_command");
        gate(same(tmpfs, {
            "/mosquitto/log": "rw,noexec,nosuid,nodev,size=16777216,mode=0700",
            "/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
        }), "broker_tmpfs");
        const normalizedMounts = mounts.map((mount) => ({destination: mount.Destination, rw: mount.RW, type: mount.Type})).sort((left, right) => left.destination.localeCompare(right.destination));
        gate(same(normalizedMounts, [
            {destination: "/mosquitto/config/pass-b1a.conf", rw: false, type: "bind"},
            {destination: "/mosquitto/data", rw: true, type: "bind"},
        ]), "broker_mounts");
        gate(item.State?.Running === options.running && item.State?.OOMKilled === false && item.State?.Status === (options.running ? "running" : "exited"), "broker_state");
        gate(options.running ? item.State.Pid > 0 : item.State.Pid === 0, "broker_state");
        if (options.running === false) gate(item.State.ExitCode === 0, "broker_clean_stop");
    } else if (imageKind === "node") {
        const contracts = {
            gateway: {mode: "gateway", duration: 1200, endpoint: "broker", plane: "frontend", running: true},
            install: {mode: "install", duration: 240, endpoint: "broker", plane: "backend", running: false},
            client_before: {mode: "client_before", duration: 240, endpoint: "gateway", plane: "frontend", running: false},
            observer_before: {mode: "observer_before", duration: 120, endpoint: "broker", plane: "backend", running: false},
            readback_before: {mode: "readback_before", duration: 180, endpoint: "broker", plane: "backend", running: false},
            backend_before: {mode: "backend_before", duration: 180, endpoint: "broker", plane: "backend", running: false},
            readiness_after: {mode: "readiness_after", duration: 30, endpoint: "broker", plane: "backend", running: false},
            readback_after: {mode: "readback_after", duration: 180, endpoint: "broker", plane: "backend", running: false},
            backend_after: {mode: "backend_after", duration: 180, endpoint: "broker", plane: "backend", running: false},
            observer_after: {mode: "observer_after", duration: 120, endpoint: "broker", plane: "backend", running: false},
            client_after: {mode: "client_after", duration: 180, endpoint: "gateway", plane: "frontend", running: false},
            readiness_final: {mode: "readiness_final", duration: 30, endpoint: "broker", plane: "backend", running: false},
            client_final: {mode: "client_final", duration: 180, endpoint: "gateway", plane: "frontend", running: false},
            backend_final: {mode: "backend_final", duration: 180, endpoint: "broker", plane: "backend", running: false},
            readback_final: {mode: "readback_final", duration: 180, endpoint: "broker", plane: "backend", running: false},
        };
        const contract = contracts[kind];
        gate(contract && host.NetworkMode.endsWith(`-${contract.plane}`), "runtime_network");
        if (baseKind === "gateway") gate(containerNetworkAliasesInclude(item, host.NetworkMode, "gateway"), "gateway_network_alias");
        gate(same(item.Config?.Entrypoint, ["/usr/bin/timeout"]), "runtime_command");
        gate(same(item.Config?.Cmd, [
            "--foreground", "--signal=TERM", "--kill-after=10s", `${contract.duration}s`, "/usr/bin/env", "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin", "NODE_VERSION=20.19.2", `B1A_MODE=${contract.mode}`,
            `B1A_ENDPOINT_HOST=${contract.endpoint}`, `B1A_ENDPOINT_PORT=${contract.endpoint === "broker" ? 18883 : 18884}`,
            "B1A_LISTEN_HOST=gateway", "B1A_LISTEN_PORT=18884", "B1A_STATUS_PATH=/status/gateway-startup.json",
            "B1A_COORD_DIR=/coord", "B1A_OUTPUT_DIR=/out", "TMPDIR=/tmp",
            "/usr/local/bin/node", "/harness/test_physical_probe_broker_runtime.mjs", "--runtime",
        ]), "runtime_command");
        gate(same(tmpfs, {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"}), "runtime_tmpfs");
        const normalizedMounts = mounts.map((mount) => ({destination: mount.Destination, rw: mount.RW, type: mount.Type})).sort((left, right) => left.destination.localeCompare(right.destination));
        const expectedMounts = [
            {destination: "/harness/test_physical_probe_broker_runtime.mjs", rw: false, type: "bind"},
            {destination: "/input/manifest.json", rw: false, type: "bind"},
            ...(options.expectedMounts ?? []),
        ].sort((left, right) => left.destination.localeCompare(right.destination));
        gate(same(normalizedMounts, expectedMounts), "runtime_mounts");
        gate(item.State?.Running === contract.running && item.State?.Status === (contract.running ? "running" : "exited") && item.State?.Pid === (contract.running ? item.State.Pid : 0) && (contract.running ? item.State.Pid > 0 : item.State.ExitCode === 0) && item.State?.OOMKilled === false, "runtime_state");
    } else {
        gate(host.NetworkMode === "none", "setup_network");
        gate(setupUsesNetworkNone(item), "setup_network");
        gate(same(item.Config?.Entrypoint, ["/bin/ash"]), "setup_command");
        gate(Array.isArray(item.Config?.Cmd) && item.Config.Cmd.length === 2 && item.Config.Cmd[0] === "-ec", "setup_command");
        const script = item.Config.Cmd[1];
        gate(script.includes("cat /run/admin.password") && script.includes("mosquitto_ctrl dynsec init") && !PASSWORD_PATTERN.test(script), "setup_command");
        gate(same(tmpfs, {
            "/mosquitto/data": "rw,noexec,nosuid,nodev,size=16777216,mode=0700",
            "/mosquitto/log": "rw,noexec,nosuid,nodev,size=16777216,mode=0700",
            "/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
        }), "setup_tmpfs");
        const normalizedMounts = mounts.map((mount) => ({destination: mount.Destination, rw: mount.RW, type: mount.Type})).sort((left, right) => left.destination.localeCompare(right.destination));
        gate(same(normalizedMounts, [
            {destination: "/out", rw: true, type: "bind"},
            {destination: "/run/admin.password", rw: false, type: "bind"},
        ]), "setup_mounts");
        gate(item.State?.Running === false && item.State?.Status === "exited" && item.State?.Pid === 0 && item.State?.ExitCode === 0 && item.State?.OOMKilled === false, "setup_state");
    }
    return item;
}

function validateNetworkInspect(inspect, manifest, plane) {
    gate(plane === "backend" || plane === "frontend", "network_plane");
    gate(Array.isArray(inspect) && inspect.length === 1, "network_inspect_shape");
    const item = inspect[0];
    gate(/^[0-9a-f]{64}$/u.test(item.Id) && validDockerTimestamp(item.Created), "network_identity");
    gate(item.Driver === "bridge" && item.Scope === "local" && item.Internal === true && item.Attachable === false && item.Ingress === false && item.ConfigOnly === false, "network_policy");
    gate(new RegExp(`^tf-pass-b1a-[0-9a-f]{16}-[12]-${plane}$`, "u").test(item.Name) && /^[0-9a-f]{32}$/u.test(item.Labels?.[manifest.cleanup.label]), "network_identity");
    gate(/^[12]$/u.test(item.Labels?.[`${manifest.cleanup.label}-replica`]), "network_identity");
    gate(item.Labels?.[`${manifest.cleanup.label}-plane`] === plane, "network_plane_label");
    gate(same(Object.keys(item.Labels ?? {}).sort(), [manifest.cleanup.label, `${manifest.cleanup.label}-replica`, `${manifest.cleanup.label}-plane`].sort()), "network_labels");
    gate(Object.keys(item.Containers ?? {}).every((key) => /^[0-9a-f]{64}$/u.test(key)), "network_container_ids");
    const endpoints = Object.values(item.Containers ?? {});
    gate(endpoints.every((endpoint) => !Object.hasOwn(endpoint, "Aliases")), "network_inspect_api_shape");
    const names = endpoints.map((endpoint) => endpoint.Name.replace(/^tf-pass-b1a-[0-9a-f]{12}-[12]-/u, "")).sort();
    const expected = plane === "backend" ? ["broker", "gateway"] : ["gateway"];
    gate(same(names, expected), "network_containers");
    gate(endpoints.every((endpoint) => typeof endpoint.IPv4Address === "string" && endpoint.IPv4Address.includes("/") && endpoint.IPv6Address === ""), "network_addresses");
    return item;
}

export function cleanupPathAllowed(root, runnerTemp, metadata = {}) {
    if (typeof root !== "string" || typeof runnerTemp !== "string" || root === "" || runnerTemp === "") return false;
    if (!path.posix.isAbsolute(root) || !path.posix.isAbsolute(runnerTemp)) return false;
    if (path.posix.dirname(root) !== runnerTemp) return false;
    if (!/^true-family-pass-b1a\.[A-Za-z0-9]{8,32}$/u.test(path.posix.basename(root))) return false;
    if (metadata.isDirectory !== true || metadata.isSymbolicLink === true || metadata.ownerMatches !== true) return false;
    return true;
}

function principalCredential(manifest, principal) {
    return {
        username: manifest.principals[principal].username,
        client_id: manifest.principals[principal].client_id,
        password: crypto.randomBytes(32).toString("base64url"),
    };
}

function validatePrincipalCredential(value, manifest, principal) {
    exactKeys(value, ["username", "client_id", "password"], "credential_shape");
    gate(value.username === manifest.principals[principal].username && value.client_id === manifest.principals[principal].client_id && PASSWORD_PATTERN.test(value.password), "credential_identity");
}

function validateAdminCredential(value, manifest) {
    exactKeys(value, ["schema", "principal"], "admin_credentials_shape");
    gate(value.schema === manifest.credentials.admin_schema, "admin_credentials_schema");
    validatePrincipalCredential(value.principal, manifest, "admin");
}

function validateFrontendCredential(value, manifest) {
    exactKeys(value, ["schema", "principals", "wrong_password"], "frontend_credentials_shape");
    gate(value.schema === manifest.credentials.frontend_schema && PASSWORD_PATTERN.test(value.wrong_password), "frontend_credentials_schema");
    gate(same(Object.keys(value.principals), ["z2m", "orchestrator", "collector", "other"]), "frontend_credentials_principals");
    for (const principal of Object.keys(value.principals)) validatePrincipalCredential(value.principals[principal], manifest, principal);
}

function validateObserverCredential(value, manifest) {
    exactKeys(value, ["schema", "principal"], "observer_credentials_shape");
    gate(value.schema === manifest.credentials.observer_schema, "observer_credentials_schema");
    validatePrincipalCredential(value.principal, manifest, "observer");
}

function validateCredentialUniqueness(values) {
    const passwords = [];
    for (const value of values) {
        if (value.principal) passwords.push(value.principal.password);
        if (value.wrong_password) passwords.push(value.wrong_password);
        if (value.principals) passwords.push(...Object.values(value.principals).map((principal) => principal.password));
    }
    gate(passwords.length === new Set(passwords).size && passwords.every((password) => PASSWORD_PATTERN.test(password)), "credential_duplicate");
}

function generateAdminCredentials(manifestPath, directory) {
    const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
    const metadata = fs.lstatSync(directory);
    gate(metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && (metadata.mode & 0o777) === 0o700, "credentials_root");
    gate(fs.readdirSync(directory).length === 0, "credentials_root_empty");
    const credentials = {schema: manifest.credentials.admin_schema, principal: principalCredential(manifest, "admin")};
    validateAdminCredential(credentials, manifest);
    writeExclusive(path.join(directory, "admin.json"), Buffer.from(`${canonical(credentials)}\n`, "utf8"));
    writeExclusive(path.join(directory, "admin.password"), Buffer.from(credentials.principal.password, "utf8"));
    const directoryHandle = fs.openSync(directory, "r");
    try {
        fs.fsyncSync(directoryHandle);
    } finally {
        fs.closeSync(directoryHandle);
    }
}

function verifyCredentialSet(manifestPath, adminDirectory, generatedDirectory, observerAfterDirectory) {
    const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
    const admin = readPrivateJson(path.join(adminDirectory, "admin.json"), "admin_credentials_json");
    const frontend = readPrivateJson(path.join(generatedDirectory, "frontend.json"), "frontend_credentials_json");
    const observerBefore = readPrivateJson(path.join(generatedDirectory, "observer-before.json"), "observer_credentials_json");
    validateAdminCredential(admin, manifest);
    validateFrontendCredential(frontend, manifest);
    validateObserverCredential(observerBefore, manifest);
    const values = [admin, frontend, observerBefore];
    if (observerAfterDirectory !== undefined) {
        const observerAfter = readPrivateJson(path.join(observerAfterDirectory, "observer-after.json"), "observer_credentials_json");
        validateObserverCredential(observerAfter, manifest);
        values.push(observerAfter);
    }
    validateCredentialUniqueness(values);
    gate(same(fs.readdirSync(adminDirectory).sort(), ["admin.json", "admin.password"]), "admin_credentials_files");
    gate(same(fs.readdirSync(generatedDirectory).sort(), ["frontend.json", "observer-before.json"]), "generated_credentials_files");
    if (observerAfterDirectory !== undefined) gate(same(fs.readdirSync(observerAfterDirectory), ["observer-after.json"]), "observer_after_credentials_files");
    for (const directory of [adminDirectory, generatedDirectory, ...(observerAfterDirectory === undefined ? [] : [observerAfterDirectory])]) {
        const metadata = fs.lstatSync(directory);
        gate(metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && (metadata.mode & 0o777) === 0o700, "credentials_root");
        for (const name of fs.readdirSync(directory)) {
            const file = fs.lstatSync(path.join(directory, name));
            gate(file.isFile() && !file.isSymbolicLink() && file.uid === process.getuid() && file.nlink === 1 && file.size > 0 && file.size <= MAX_JSON_BYTES && (file.mode & 0o777) === 0o600, "credential_mode");
        }
    }
}

function bindAdminClientId(configPath, manifestPath) {
    const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
    const config = readPrivateJson(configPath, "dynsec_json");
    gate(Array.isArray(config.clients) && config.clients.length === 1, "dynsec_bootstrap_clients");
    const admin = config.clients[0];
    gate(admin.username === manifest.principals.admin.username && !Object.hasOwn(admin, "clientid"), "dynsec_bootstrap_admin");
    admin.clientid = manifest.principals.admin.client_id;
    const temporary = `${configPath}.b1a-new`;
    writeExclusive(temporary, Buffer.from(`${JSON.stringify(config, null, 2)}\n`, "utf8"));
    fs.renameSync(temporary, configPath);
    const directory = fs.openSync(path.dirname(configPath), "r");
    try {
        fs.fsyncSync(directory);
    } finally {
        fs.closeSync(directory);
    }
    const metadata = fs.lstatSync(configPath);
    gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && metadata.nlink === 1 && metadata.size > 0 && metadata.size <= MAX_JSON_BYTES && (metadata.mode & 0o777) === 0o600, "dynsec_mode");
}

function verifyBootstrap(configPath, credentialsPath, manifestPath) {
    const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
    const credentials = readPrivateJson(credentialsPath, "credentials_json");
    validateAdminCredential(credentials, manifest);
    const text = readPrivateBytes(configPath, MAX_JSON_BYTES, "dynsec_json").toString("utf8");
    gate(!text.includes(credentials.principal.password), "dynsec_plaintext_password");
    const config = JSON.parse(text);
    exactKeys(config, ["clients", "roles", "defaultACLAccess"], "dynsec_bootstrap_shape");
    gate(Array.isArray(config.clients) && config.clients.length === 1 && Array.isArray(config.roles) && config.roles.length === 1, "dynsec_bootstrap_count");
    const admin = config.clients[0];
    exactKeys(admin, ["username", "textName", "password", "salt", "iterations", "roles", "clientid"], "dynsec_bootstrap_admin_shape");
    gate(admin.username === manifest.principals.admin.username && admin.clientid === manifest.principals.admin.client_id, "dynsec_bootstrap_admin");
    gate(admin.textName === "Dynsec admin user" && same(admin.roles, [{rolename: "admin"}]), "dynsec_bootstrap_admin");
    gate(typeof admin.password === "string" && typeof admin.salt === "string" && Number.isInteger(admin.iterations) && admin.iterations > 0, "dynsec_bootstrap_hash");
    gate(admin.password !== credentials.principal.password && admin.salt !== credentials.principal.password, "dynsec_bootstrap_hash");
    gate(same(config.roles[0], {
        rolename: "admin",
        acls: [
            {acltype: "publishClientSend", topic: "$CONTROL/dynamic-security/#", allow: true},
            {acltype: "publishClientReceive", topic: "$CONTROL/dynamic-security/#", allow: true},
            {acltype: "subscribePattern", topic: "$CONTROL/dynamic-security/#", allow: true},
            {acltype: "publishClientReceive", topic: "$SYS/#", allow: true},
            {acltype: "subscribePattern", topic: "$SYS/#", allow: true},
            {acltype: "publishClientReceive", topic: "#", allow: true},
            {acltype: "subscribePattern", topic: "#", allow: true},
            {acltype: "unsubscribePattern", topic: "#", allow: true},
        ],
    }), "dynsec_bootstrap_role");
    gate(same(config.defaultACLAccess, {publishClientSend: false, publishClientReceive: true, subscribe: false, unsubscribe: true}), "dynsec_bootstrap_defaults");
}

function sanitizedText(text, sourceText, secrets = []) {
    gate(typeof text === "string" && !text.includes(sourceText), "redaction_source");
    const canaries = [
        "MANDATORY RESIDUAL WRITER FENCE: a future preflight must give Zigbee2MQTT a",
        sourceText.slice(0, 128),
        sourceText.slice(-128),
        sourceText.slice(sourceText.indexOf("export default class"), sourceText.indexOf("export default class") + 128),
    ];
    for (const canary of canaries) gate(canary.length > 0 && !text.includes(canary), "redaction_source_canary");
    for (const secret of secrets) gate(!text.includes(secret), "redaction_password");
}

function sanitizedBytes(bytes, sourceText, secrets = []) {
    gate(Buffer.isBuffer(bytes), "redaction_binary");
    const sourceCanaries = [
        sourceText,
        "MANDATORY RESIDUAL WRITER FENCE: a future preflight must give Zigbee2MQTT a",
        sourceText.slice(0, 128),
        sourceText.slice(-128),
        sourceText.slice(sourceText.indexOf("export default class"), sourceText.indexOf("export default class") + 128),
    ];
    for (const canary of [...sourceCanaries, ...secrets]) {
        const encoded = Buffer.from(canary, "utf8");
        gate(encoded.length > 0 && bytes.indexOf(encoded) === -1, canary === sourceText || sourceCanaries.includes(canary) ? "redaction_source_canary" : "redaction_password");
    }
}

function credentialSecrets(root) {
    const resolvedRoot = path.resolve(root);
    const rootMetadata = fs.lstatSync(resolvedRoot);
    gate(rootMetadata.isDirectory() && !rootMetadata.isSymbolicLink() && rootMetadata.uid === process.getuid() && (rootMetadata.mode & 0o777) === 0o700, "credential_scan_root");
    const directoryContracts = [
        ["credentials", ["admin.json", "admin.password"]],
        ["generated", ["frontend.json", "observer-before.json"]],
        ["observer-after-output", ["observer-after.json"]],
    ];
    for (const [name, expectedFiles] of directoryContracts) {
        const directory = path.join(resolvedRoot, name);
        const metadata = fs.lstatSync(directory);
        gate(path.dirname(directory) === resolvedRoot && metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && (metadata.mode & 0o777) === 0o700, "credential_scan_directory");
        gate(same(fs.readdirSync(directory).sort(), expectedFiles), "credential_scan_directory_contents");
    }
    const files = [
        path.join(resolvedRoot, "credentials", "admin.json"),
        path.join(resolvedRoot, "credentials", "admin.password"),
        path.join(resolvedRoot, "generated", "frontend.json"),
        path.join(resolvedRoot, "generated", "observer-before.json"),
        path.join(resolvedRoot, "observer-after-output", "observer-after.json"),
    ];
    const secrets = [];
    for (const current of files) {
        const metadata = fs.lstatSync(current);
        gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && metadata.nlink === 1 && metadata.size > 0 && metadata.size <= MAX_JSON_BYTES && (metadata.mode & 0o777) === 0o600, "credential_scan_file");
        const bytes = readPrivateBytes(current, MAX_JSON_BYTES, "credential_scan_file");
        const text = bytes.toString("utf8");
        gate(Buffer.from(text, "utf8").equals(bytes), "credential_scan_utf8");
        if (path.basename(current) === "admin.password") {
            gate(PASSWORD_PATTERN.test(text), "credential_scan_password");
            secrets.push(text);
        } else {
            const visit = (value) => {
                if (typeof value === "string" && PASSWORD_PATTERN.test(value)) secrets.push(value);
                else if (value && typeof value === "object") for (const child of Object.values(value)) visit(child);
            };
            visit(JSON.parse(text));
        }
    }
    const unique = [...new Set(secrets)];
    gate(unique.length >= 7, "credential_scan_count");
    return unique;
}

export function scanPathIsExpectedBinary(current, expectedBinaryPath) {
    return path.resolve(current) === path.resolve(expectedBinaryPath);
}

function pathContains(root, candidate) {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function pathsOverlap(left, right) {
    return pathContains(left, right) || pathContains(right, left);
}

function expectedMosquittoDatabase(dataRoot) {
    const resolvedDataRoot = path.resolve(dataRoot);
    const rootMetadata = fs.lstatSync(resolvedDataRoot);
    gate(path.basename(resolvedDataRoot) === "data" && rootMetadata.isDirectory() && !rootMetadata.isSymbolicLink() && rootMetadata.uid === process.getuid() && (rootMetadata.mode & 0o777) === 0o700, "scan_data_root");
    gate(fs.readdirSync(resolvedDataRoot).filter((name) => name === "mosquitto.db").length === 1, "scan_database_count");
    const database = path.join(resolvedDataRoot, "mosquitto.db");
    const metadata = fs.lstatSync(database);
    gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() && metadata.nlink === 1 && metadata.size > 0 && metadata.size <= 1024 * 1024 && (metadata.mode & 0o777) === 0o600, "scan_database_file");
    return database;
}

function scanTree(root, sourceText, secrets, expectedBinaryPath, state) {
    const resolvedRoot = path.resolve(root);
    const pending = [resolvedRoot];
    while (pending.length > 0) {
        const current = pending.pop();
        const metadata = fs.lstatSync(current);
        gate(!metadata.isSymbolicLink(), "scan_symlink");
        const identity = `${metadata.dev}:${metadata.ino}`;
        if (state.seen.has(identity)) continue;
        state.seen.add(identity);
        if (metadata.isDirectory()) {
            for (const name of fs.readdirSync(current)) pending.push(path.join(current, name));
        } else {
            gate(metadata.isFile() && metadata.uid === process.getuid() && metadata.nlink === 1 && metadata.size <= 1024 * 1024 && (metadata.mode & 0o777) === 0o600, "scan_file");
            state.files += 1;
            gate(state.files <= 1_000, "scan_file_count");
            const handle = fs.openSync(current, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
            let bytes;
            try {
                const opened = fs.fstatSync(handle);
                gate(opened.dev === metadata.dev && opened.ino === metadata.ino && opened.size === metadata.size, "scan_file");
                bytes = fs.readFileSync(handle);
            } finally {
                fs.closeSync(handle);
            }
            const binaryMosquittoDatabase = scanPathIsExpectedBinary(current, expectedBinaryPath);
            if (binaryMosquittoDatabase) {
                gate(bytes.length > 0, "scan_binary_size");
                sanitizedBytes(bytes, sourceText, secrets);
                state.binaryFiles.push(path.resolve(current));
            } else {
                const text = bytes.toString("utf8");
                gate(Buffer.from(text, "utf8").equals(bytes), "scan_utf8");
                sanitizedText(text, sourceText, secrets);
            }
        }
    }
}

function scanRedaction(sourceText, manifest, credentialsRoot, dataRoot, stoppedBrokerInspect, roots) {
    const expectedBinaryPath = expectedMosquittoDatabase(dataRoot);
    const resolvedCredentialsRoot = path.resolve(credentialsRoot);
    const secretRoots = ["credentials", "generated", "observer-after-output"].map((name) => path.join(resolvedCredentialsRoot, name));
    gate(!secretRoots.some((secretRoot) => pathsOverlap(dataRoot, secretRoot)) && !roots.some((root) => pathsOverlap(root, dataRoot)), "scan_data_target_once");
    gate(roots.every((root) => !secretRoots.some((secretRoot) => pathsOverlap(root, secretRoot))), "scan_secret_input_excluded");
    const configPath = path.join(resolvedCredentialsRoot, "config", "pass-b1a.conf");
    gate(readPrivateBytes(configPath, MAX_JSON_BYTES, "scan_broker_config").equals(brokerConfigBytes(manifest)), "scan_broker_config");
    const dynamicSecurityPath = path.join(path.resolve(dataRoot), "dynamic-security.json");
    const dynamicSecurityMetadata = fs.lstatSync(dynamicSecurityPath);
    gate(dynamicSecurityMetadata.isFile() && !dynamicSecurityMetadata.isSymbolicLink() && dynamicSecurityMetadata.uid === process.getuid() && dynamicSecurityMetadata.nlink === 1 && dynamicSecurityMetadata.size > 0 && dynamicSecurityMetadata.size <= MAX_JSON_BYTES && (dynamicSecurityMetadata.mode & 0o777) === 0o600, "scan_dynamic_security_file");
    gate(path.dirname(fs.realpathSync(dynamicSecurityPath)) === fs.realpathSync(dataRoot), "scan_dynamic_security_containment");
    validateContainerInspect(readPrivateJson(stoppedBrokerInspect, "scan_broker_inspect"), "broker", manifest, {
        running: false,
        mountSources: {
            "/mosquitto/config/pass-b1a.conf": configPath,
            "/mosquitto/data": path.resolve(dataRoot),
        },
    });
    const secrets = credentialSecrets(credentialsRoot);
    const state = {seen: new Set(), files: 0, binaryFiles: []};
    scanTree(dataRoot, sourceText, secrets, expectedBinaryPath, state);
    for (const root of roots) scanTree(root, sourceText, secrets, expectedBinaryPath, state);
    gate(state.binaryFiles.length === 1 && state.binaryFiles[0] === path.resolve(expectedBinaryPath), "scan_binary_branch");
    return {files_scanned: state.files, binary_files_scanned: state.binaryFiles.length, broker_cleanly_stopped: true};
}

function runtimeFailureCategoryFromBytes(bytes, runtimeMode, contract) {
    gate(runtimeMode === contract.detailed_mode && Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= contract.max_bytes, "runtime_failure_size");
    const text = bytes.toString("utf8");
    gate(Buffer.from(text, "utf8").equals(bytes) && text.endsWith("\n"), "runtime_failure_utf8");
    let value;
    try {
        value = JSON.parse(text);
    } catch {
        throw new VerifyFailure("runtime_failure_json");
    }
    exactKeys(value, contract.exact_keys, "runtime_failure_shape");
    gate(value.schema === contract.schema && value.result === "fail" && contract.categories.includes(value.failure_category), "runtime_failure_identity");
    gate(text === `${canonical(value)}\n`, "runtime_failure_canonical");
    return value.failure_category;
}

function classifyRuntimeFailureFile(runtimeMode, file, manifest) {
    const contract = manifest.evidence.runtime_failure_record;
    const bytes = readPrivateBytes(file, contract.max_bytes, "runtime_failure_file");
    return runtimeFailureCategoryFromBytes(bytes, runtimeMode, contract);
}

function readCanonicalRuntime(file, sourceText, manifest) {
    const bytes = readPrivateBytes(file, manifest.evidence.max_runtime_bytes, "runtime_size");
    const text = bytes.toString("utf8");
    gate(Buffer.from(text, "utf8").equals(bytes) && text.endsWith("\n"), "runtime_utf8");
    sanitizedText(text, sourceText);
    let value;
    try {
        value = JSON.parse(text);
    } catch {
        throw new VerifyFailure("runtime_json");
    }
    gate(text === `${canonical(value)}\n`, "runtime_canonical");
    gate(value.schema === RUNTIME_SCHEMA && value.result === "pass", "runtime_identity");
    return value;
}

function validateSecurity(value) {
    exactKeys(value, ["uid_nonzero", "no_new_privs", "capability_sets_zero", "seccomp_filtering", "read_only_root", "forbidden_host_paths_unavailable", "private_network_interface_only"], "runtime_security_shape");
    gate(Object.values(value).every((item) => item === true), "runtime_security");
}

function validateAuthentication(value, manifest) {
    exactKeys(value, ["correct_frontend_bindings", "ping_round_trip", "wrong_password_broker_reason", "wrong_client_id_gateway_close", "anonymous_gateway_close", "unknown_gateway_close", "admin_frontend_gateway_close", "observer_frontend_gateway_close", "gateway_denials_without_ack_or_publish"], "runtime_auth_shape");
    gate(value.correct_frontend_bindings === true && value.ping_round_trip === true, "runtime_auth_positive");
    gate(["bad_username_or_password", "not_authorized"].includes(value.wrong_password_broker_reason), "runtime_auth_negative");
    for (const key of ["wrong_client_id_gateway_close", "anonymous_gateway_close", "unknown_gateway_close", "admin_frontend_gateway_close", "observer_frontend_gateway_close"]) gate(value[key] === true, "runtime_auth_negative");
    gate(value.gateway_denials_without_ack_or_publish === true, "runtime_auth_no_output_before_close");
    gate(manifest.authentication.accepted_negative_reason_classes.includes(value.wrong_password_broker_reason), "runtime_auth_negative");
}

function validateFrontendNetwork(value) {
    exactKeys(value, ["broker_dns_unresolvable", "broker_tcp_unreachable", "gateway_only_broker_path", "default_route_observed", "host_aliases_probed", "host_alias_docker_api_ports_unreachable", "external_tcp_unreachable", "same_runner_host_isolation_proven"], "runtime_network_shape");
    gate(typeof value.default_route_observed === "boolean", "runtime_default_route_probe");
    for (const key of ["broker_dns_unresolvable", "broker_tcp_unreachable", "gateway_only_broker_path", "host_aliases_probed", "host_alias_docker_api_ports_unreachable", "external_tcp_unreachable"]) gate(value[key] === true, "runtime_network_probe");
    gate(value.same_runner_host_isolation_proven === false, "runtime_host_isolation_limit");
}

function countExpected(items, allowed) {
    return items.filter((item) => item.allowed === allowed).length;
}

function validateControl(value, minimum) {
    exactKeys(value, ["correlation_data_unique", "command_success_from_response_not_puback", "response_count"], "runtime_control_shape");
    gate(value.correlation_data_unique === true && value.command_success_from_response_not_puback === true && Number.isInteger(value.response_count) && value.response_count >= minimum, "runtime_control");
}

function validateInstall(value, manifest) {
    exactKeys(value, ["schema", "result", "phase", "security", "control", "broker_policy_sha256", "generated_credentials", "observer_prepared", "admin_bootstrap_role_narrowed"], "install_shape");
    gate(value.phase === "install", "install_phase");
    validateSecurity(value.security);
    validateControl(value.control, 12);
    gate(value.broker_policy_sha256 === manifest.policy.canonical_sha256, "install_policy");
    gate(same(value.generated_credentials, {frontend_without_admin_or_observer: true, observer_separate: true, passwords_emitted: false}) && value.observer_prepared === true && value.admin_bootstrap_role_narrowed === true, "install_credentials");
}

function validateClientBefore(value, manifest) {
    exactKeys(value, ["schema", "result", "phase", "security", "network", "authentication", "matrix", "enforcement", "source", "request_topics_retained_absent"], "client_before_shape");
    gate(value.phase === "client_before", "client_before_phase");
    validateSecurity(value.security);
    validateFrontendNetwork(value.network);
    validateAuthentication(value.authentication, manifest);
    exactKeys(value.matrix, ["publish", "subscribe"], "client_before_matrix_shape");
    exactKeys(value.matrix.publish, ["cases", "allowed", "denied", "gateway_close_denials", "broker_positive_deliveries", "deep_containment_depths", "qos_enforced", "retain_enforced", "topic_contract_enforced", "pure_oracle_equivalent"], "client_before_publish_shape");
    gate(value.matrix.publish.cases === manifest.matrix.publish.length && value.matrix.publish.allowed === countExpected(manifest.matrix.publish, true) && value.matrix.publish.denied === countExpected(manifest.matrix.publish, false), "client_before_publish_counts");
    gate(value.matrix.publish.gateway_close_denials === value.matrix.publish.denied && value.matrix.publish.broker_positive_deliveries === value.matrix.publish.allowed && value.matrix.publish.qos_enforced === true && value.matrix.publish.retain_enforced === true && value.matrix.publish.topic_contract_enforced === true && value.matrix.publish.pure_oracle_equivalent === true, "client_before_publish_controls");
    gate(same(value.matrix.publish.deep_containment_depths, [0, 8, 32, 100]), "client_before_deep_containment");
    exactKeys(value.matrix.subscribe, ["cases", "allowed", "denied", "gateway_close_denials", "broker_positive_deliveries", "wildcard_enforced", "shared_enforced", "concrete_subscription_policy_enforced", "pure_oracle_equivalent"], "client_before_subscribe_shape");
    gate(value.matrix.subscribe.cases === manifest.matrix.subscribe.length && value.matrix.subscribe.allowed === countExpected(manifest.matrix.subscribe, true) && value.matrix.subscribe.denied === countExpected(manifest.matrix.subscribe, false), "client_before_subscribe_counts");
    gate(value.matrix.subscribe.gateway_close_denials === value.matrix.subscribe.denied && value.matrix.subscribe.broker_positive_deliveries === value.matrix.subscribe.allowed && value.matrix.subscribe.wildcard_enforced === true && value.matrix.subscribe.shared_enforced === true && value.matrix.subscribe.concrete_subscription_policy_enforced === true && value.matrix.subscribe.pure_oracle_equivalent === true, "client_before_subscribe_controls");
    gate(same(value.enforcement, {gateway_exact_enforcement: true, deep_containment: true, qos_enforced: true, qos2_stateful_proxy: true, retain_enforced: true, pure_oracle_matrix_equivalent: true, composite_equivalence_tested: true, broker_native_qos_retain: false}), "client_before_enforcement");
    exactKeys(value.source, ["synthetic_source", "real_externaljs_source_path", "retained_payload_sha256", "source_sha256", "source_acl_privacy_cases", "fresh_gateway_close_proven", "reconnect_gateway_close_proven", "wildcard_and_shared_gateway_close_proven", "retained_source_cleared_by_z2m", "raw_source_emitted"], "client_before_source_shape");
    gate(value.source.synthetic_source === true && value.source.real_externaljs_source_path === false && value.source.source_sha256 === manifest.artifact.sha256 && SHA256_PATTERN.test(value.source.retained_payload_sha256), "client_before_source");
    gate(value.source.source_acl_privacy_cases === manifest.source_privacy.principals.length * manifest.source_privacy.denied_filters.length, "client_before_source");
    for (const key of ["fresh_gateway_close_proven", "reconnect_gateway_close_proven", "wildcard_and_shared_gateway_close_proven", "retained_source_cleared_by_z2m"]) gate(value.source[key] === true, "client_before_source");
    gate(value.source.raw_source_emitted === false && value.request_topics_retained_absent === true, "client_before_source");
}

function validateObserverBefore(value, manifest, sourceBytes) {
    exactKeys(value, ["schema", "result", "phase", "security", "retained_replay_qos1", "payload_sha256", "source_sha256", "backend_only"], "observer_before_shape");
    gate(value.phase === "observer_before", "observer_before_phase");
    validateSecurity(value.security);
    const payload = buildSourceInventory(sourceBytes, manifest.artifact.filename);
    gate(value.retained_replay_qos1 === true && value.payload_sha256 === sha256Bytes(payload) && value.source_sha256 === manifest.artifact.sha256 && value.backend_only === true, "observer_before_source");
}

function validateReadbackRuntime(value, manifest, phase, transition, expectedReadbackSha256) {
    exactKeys(value, ["schema", "result", "phase", "security", "control", "observer_transition", "admin_role_narrow", "readback", "readback_sha256"], "readback_shape");
    gate(value.phase === phase, "readback_phase");
    validateSecurity(value.security);
    validateControl(value.control, 4);
    gate(value.observer_transition === transition && value.admin_role_narrow === true, "readback_transition");
    const normalized = validateReadback(value.readback, expectedReadbackFromManifest(manifest));
    gate(value.readback_sha256 === sha256Bytes(Buffer.from(canonical(normalized), "utf8")) && value.readback_sha256 === expectedReadbackSha256, "readback_digest");
    return value.readback_sha256;
}

function validateObserverAfter(value) {
    exactKeys(value, ["schema", "result", "phase", "security", "old_retained_replay_absent", "positive_nonretained_delivery", "backend_only"], "observer_after_shape");
    gate(value.phase === "observer_after" && value.old_retained_replay_absent === true && value.positive_nonretained_delivery === true && value.backend_only === true, "observer_after");
    validateSecurity(value.security);
}

function validateRestartClient(value, manifest, phase) {
    exactKeys(value, ["schema", "result", "phase", "security", "network", "authentication", "gateway_broker_path", "nonretained_source_positive_control", "request_topics_retained_absent"], "restart_client_shape");
    gate(value.phase === phase, "restart_client_phase");
    validateSecurity(value.security);
    validateFrontendNetwork(value.network);
    validateAuthentication(value.authentication, manifest);
    gate(value.gateway_broker_path === true && value.nonretained_source_positive_control === true && value.request_topics_retained_absent === true, "restart_client_persistence");
}

function validateReadiness(value, phase) {
    exactKeys(value, ["schema", "result", "phase", "security", "authenticated_mqtt_v5_ready", "non_secret_result", "attempts"], "readiness_shape");
    gate(value.phase === phase && value.authenticated_mqtt_v5_ready === true && value.non_secret_result === true, "readiness_result");
    gate(Number.isInteger(value.attempts) && value.attempts >= 1 && value.attempts <= 100, "readiness_attempts");
    validateSecurity(value.security);
}

function validateBackendBefore(value) {
    exactKeys(value, ["schema", "result", "phase", "security", "backend_only_application_credentials", "native_acl_samples", "retained_sentinel_published_qos2", "retained_sentinel_payload_sha256"], "backend_before_shape");
    gate(value.phase === "backend_before" && value.backend_only_application_credentials === true && value.retained_sentinel_published_qos2 === true && SHA256_PATTERN.test(value.retained_sentinel_payload_sha256), "backend_before");
    validateSecurity(value.security);
    gate(same(value.native_acl_samples, {
        z2m_outside_publish_qos2_retain: true,
        z2m_outside_subscribe_qos2: true,
        orchestrator_native_qos_retain_not_enforced: true,
        other_publish_denied: true,
        other_subscribe_denied: true,
        collector_source_subscribe_denied: true,
    }), "backend_native_acl_samples");
}

function validateBackendAfter(value, payloadSha256) {
    exactKeys(value, ["schema", "result", "phase", "security", "backend_only_application_credentials", "retained_sentinel_replayed_after_restart_qos2", "retained_sentinel_cleared_qos2", "retained_sentinel_immediately_absent", "retained_sentinel_payload_sha256"], "backend_after_shape");
    gate(value.phase === "backend_after" && value.backend_only_application_credentials === true, "backend_after");
    validateSecurity(value.security);
    gate(value.retained_sentinel_replayed_after_restart_qos2 === true && value.retained_sentinel_cleared_qos2 === true && value.retained_sentinel_immediately_absent === true && value.retained_sentinel_payload_sha256 === payloadSha256, "backend_after");
}

function validateBackendFinal(value) {
    exactKeys(value, ["schema", "result", "phase", "security", "backend_only_application_credentials", "retained_sentinel_absent_after_clear_and_second_restart", "positive_nonretained_qos2_control"], "backend_final_shape");
    gate(value.phase === "backend_final" && value.backend_only_application_credentials === true && value.retained_sentinel_absent_after_clear_and_second_restart === true && value.positive_nonretained_qos2_control === true, "backend_final");
    validateSecurity(value.security);
}

function verifyReplica(args) {
    gate(args.length === 3, "replica_arguments");
    const [replicaRoot, manifestPath, artifactPath] = args;
    const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
    const sourceBytes = fs.readFileSync(artifactPath);
    const sourceText = sourceBytes.toString("utf8");
    gate(sha256Bytes(sourceBytes) === manifest.artifact.sha256, "replica_artifact");

    const evidenceRoot = path.join(replicaRoot, "evidence");
    const inspectRoot = path.join(replicaRoot, "inspect");
    const dataRoot = path.join(replicaRoot, "data");
    const credentialsRoot = path.join(replicaRoot, "credentials");
    const generatedRoot = path.join(replicaRoot, "generated");
    const observerAfterRoot = path.join(replicaRoot, "observer-after-output");
    const coordRoot = path.join(replicaRoot, "coord");
    const statusRoot = path.join(replicaRoot, "status");
    const configPath = path.join(replicaRoot, "config", "pass-b1a.conf");

    const install = readCanonicalRuntime(path.join(evidenceRoot, "install.json"), sourceText, manifest);
    const clientBefore = readCanonicalRuntime(path.join(evidenceRoot, "client-before.json"), sourceText, manifest);
    const observerBefore = readCanonicalRuntime(path.join(evidenceRoot, "observer-before.json"), sourceText, manifest);
    const readbackBefore = readCanonicalRuntime(path.join(evidenceRoot, "readback-before.json"), sourceText, manifest);
    const backendBefore = readCanonicalRuntime(path.join(evidenceRoot, "backend-before.json"), sourceText, manifest);
    const readinessAfter = readCanonicalRuntime(path.join(evidenceRoot, "readiness-after.json"), sourceText, manifest);
    const readbackAfter = readCanonicalRuntime(path.join(evidenceRoot, "readback-after.json"), sourceText, manifest);
    const backendAfter = readCanonicalRuntime(path.join(evidenceRoot, "backend-after.json"), sourceText, manifest);
    const observerAfter = readCanonicalRuntime(path.join(evidenceRoot, "observer-after.json"), sourceText, manifest);
    const clientAfter = readCanonicalRuntime(path.join(evidenceRoot, "client-after.json"), sourceText, manifest);
    const readinessFinal = readCanonicalRuntime(path.join(evidenceRoot, "readiness-final.json"), sourceText, manifest);
    const clientFinal = readCanonicalRuntime(path.join(evidenceRoot, "client-final.json"), sourceText, manifest);
    const backendFinal = readCanonicalRuntime(path.join(evidenceRoot, "backend-final.json"), sourceText, manifest);
    const readbackFinal = readCanonicalRuntime(path.join(evidenceRoot, "readback-final.json"), sourceText, manifest);
    validateInstall(install, manifest);
    validateClientBefore(clientBefore, manifest);
    validateObserverBefore(observerBefore, manifest, sourceBytes);
    const beforeDigest = validateReadbackRuntime(readbackBefore, manifest, "readback_before", "revoked", manifest.policy.expected_readback_sha256);
    validateBackendBefore(backendBefore);
    validateReadiness(readinessAfter, "readiness_after");
    const afterDigest = validateReadbackRuntime(readbackAfter, manifest, "readback_after", "prepared", manifest.policy.expected_readback_sha256);
    validateBackendAfter(backendAfter, backendBefore.retained_sentinel_payload_sha256);
    validateObserverAfter(observerAfter);
    validateRestartClient(clientAfter, manifest, "client_after");
    validateReadiness(readinessFinal, "readiness_final");
    validateRestartClient(clientFinal, manifest, "client_final");
    validateBackendFinal(backendFinal);
    const finalDigest = validateReadbackRuntime(readbackFinal, manifest, "readback_final", "revoked", manifest.policy.expected_readback_sha256);
    gate(beforeDigest === afterDigest && afterDigest === finalDigest, "replica_readback_restart");

    const startupPath = path.join(statusRoot, "gateway-startup.json");
    const startupBytes = readPrivateBytes(startupPath, MAX_JSON_BYTES, "gateway_startup_file");
    const startupText = startupBytes.toString("utf8");
    const startup = JSON.parse(startupText);
    gate(startupText === `${canonical(startup)}\n`, "gateway_startup_canonical");
    exactKeys(startup, ["schema", "result", "generation", "policy_sha256", "frontend_listener", "backend_broker", "frontend_bound", "credential_files_provisioned", "artifact_files_provisioned", "connect_password_in_transit", "connect_password_decoded", "connect_password_persisted", "broker_ack_authority", "gateway_enforcement", "broker_origin_malformed_latches_gateway", "composite_policy"], "gateway_startup_shape");
    gate(startup.schema === manifest.evidence.gateway_startup_schema && startup.result === "ready" && startup.generation === 1 && startup.policy_sha256 === manifest.gateway.policy_sha256, "gateway_startup_identity");
    gate(startup.frontend_listener === 18884 && startup.backend_broker === "broker:18883" && startup.frontend_bound === true, "gateway_startup_endpoints");
    gate(same({credential_files_provisioned: startup.credential_files_provisioned, artifact_files_provisioned: startup.artifact_files_provisioned, connect_password_in_transit: startup.connect_password_in_transit, connect_password_decoded: startup.connect_password_decoded, connect_password_persisted: startup.connect_password_persisted, broker_ack_authority: startup.broker_ack_authority, gateway_enforcement: startup.gateway_enforcement, broker_origin_malformed_latches_gateway: startup.broker_origin_malformed_latches_gateway, composite_policy: startup.composite_policy}, gatewayPolicyProjection(manifest).assurances), "gateway_startup_assurances");

    const inspect = (name, code = "container_inspect_json") => readPrivateJson(path.join(inspectRoot, `${name}.json`), code);
    const baseline = {"/harness/test_physical_probe_broker_runtime.mjs": RUNTIME_HARNESS_PATH, "/input/manifest.json": manifestPath};
    const mount = (destination, rw) => ({destination, rw, type: "bind"});
    const validateNode = (name, kind, extraSources, extraMounts) => validateContainerInspect(inspect(name), kind, manifest, {mountSources: {...baseline, ...extraSources}, expectedMounts: extraMounts});
    const setup = validateContainerInspect(inspect("setup", "setup_inspect_json"), "setup", manifest, {mountSources: {"/out": dataRoot, "/run/admin.password": path.join(credentialsRoot, "admin.password")}});
    const brokerSources = {"/mosquitto/config/pass-b1a.conf": configPath, "/mosquitto/data": dataRoot};
    const brokerBefore = validateContainerInspect(inspect("broker-before", "broker_inspect_json"), "broker", manifest, {running: true, mountSources: brokerSources});
    const brokerStopped = validateContainerInspect(inspect("broker-stopped", "broker_inspect_json"), "broker", manifest, {running: false, mountSources: brokerSources});
    const brokerAfter = validateContainerInspect(inspect("broker-after", "broker_inspect_json"), "broker", manifest, {running: true, mountSources: brokerSources});
    const brokerStoppedFinal = validateContainerInspect(inspect("broker-stopped-final", "broker_inspect_json"), "broker", manifest, {running: false, mountSources: brokerSources});
    const brokerFinal = validateContainerInspect(inspect("broker-final", "broker_inspect_json"), "broker", manifest, {running: true, mountSources: brokerSources});
    const gateway = validateNode("gateway", "gateway", {"/status": statusRoot}, [mount("/status", true)]);
    const installContainer = validateNode("install", "install", {"/input/admin.json": path.join(credentialsRoot, "admin.json"), "/out": generatedRoot}, [mount("/input/admin.json", false), mount("/out", true)]);
    const clientBeforeContainer = validateNode("client-before", "client_before", {"/input/frontend.json": path.join(generatedRoot, "frontend.json"), "/input/true_family_brt_probe.mjs": artifactPath, "/coord": coordRoot}, [mount("/input/frontend.json", false), mount("/input/true_family_brt_probe.mjs", false), mount("/coord", true)]);
    const observerBeforeContainer = validateNode("observer-before", "observer_before", {"/input/observer.json": path.join(generatedRoot, "observer-before.json"), "/input/true_family_brt_probe.mjs": artifactPath, "/coord": coordRoot}, [mount("/input/observer.json", false), mount("/input/true_family_brt_probe.mjs", false), mount("/coord", true)]);
    const readbackBeforeContainer = validateNode("readback-before", "readback_before", {"/input/admin.json": path.join(credentialsRoot, "admin.json")}, [mount("/input/admin.json", false)]);
    const backendBeforeContainer = validateNode("backend-before", "backend_before", {"/input/frontend.json": path.join(generatedRoot, "frontend.json")}, [mount("/input/frontend.json", false)]);
    const readinessAfterContainer = validateNode("readiness-after", "readiness_after", {"/input/admin.json": path.join(credentialsRoot, "admin.json")}, [mount("/input/admin.json", false)]);
    const readbackAfterContainer = validateNode("readback-after", "readback_after", {"/input/admin.json": path.join(credentialsRoot, "admin.json"), "/out": observerAfterRoot}, [mount("/input/admin.json", false), mount("/out", true)]);
    const backendAfterContainer = validateNode("backend-after", "backend_after", {"/input/frontend.json": path.join(generatedRoot, "frontend.json")}, [mount("/input/frontend.json", false)]);
    const observerAfterContainer = validateNode("observer-after", "observer_after", {"/input/observer.json": path.join(observerAfterRoot, "observer-after.json"), "/coord": coordRoot}, [mount("/input/observer.json", false), mount("/coord", true)]);
    const clientAfterContainer = validateNode("client-after", "client_after", {"/input/frontend.json": path.join(generatedRoot, "frontend.json")}, [mount("/input/frontend.json", false)]);
    const readinessFinalContainer = validateNode("readiness-final", "readiness_final", {"/input/admin.json": path.join(credentialsRoot, "admin.json")}, [mount("/input/admin.json", false)]);
    const clientFinalContainer = validateNode("client-final", "client_final", {"/input/frontend.json": path.join(generatedRoot, "frontend.json")}, [mount("/input/frontend.json", false)]);
    const backendFinalContainer = validateNode("backend-final", "backend_final", {"/input/frontend.json": path.join(generatedRoot, "frontend.json")}, [mount("/input/frontend.json", false)]);
    const readbackFinalContainer = validateNode("readback-final", "readback_final", {"/input/admin.json": path.join(credentialsRoot, "admin.json")}, [mount("/input/admin.json", false)]);

    gate(setup.State.FinishedAt !== "0001-01-01T00:00:00Z", "setup_completion");
    gate([brokerStopped, brokerAfter, brokerStoppedFinal, brokerFinal].every((item) => item.Id === brokerBefore.Id), "broker_restart_identity");
    gate(brokerBefore.State.StartedAt === brokerStopped.State.StartedAt && brokerStopped.State.FinishedAt !== "0001-01-01T00:00:00Z", "broker_restart_stop");
    gate(brokerAfter.State.StartedAt !== brokerBefore.State.StartedAt && brokerAfter.State.FinishedAt === "0001-01-01T00:00:00Z", "broker_restart_start");
    gate(brokerStoppedFinal.State.StartedAt === brokerAfter.State.StartedAt && brokerStoppedFinal.State.FinishedAt !== "0001-01-01T00:00:00Z", "broker_second_restart_stop");
    gate(brokerFinal.State.StartedAt !== brokerAfter.State.StartedAt && brokerFinal.State.FinishedAt === "0001-01-01T00:00:00Z", "broker_second_restart_start");

    const backend = validateNetworkInspect(inspect("network-backend", "network_inspect_json"), manifest, "backend");
    const frontend = validateNetworkInspect(inspect("network-frontend", "network_inspect_json"), manifest, "frontend");
    const inspected = [setup, brokerBefore, brokerStopped, brokerAfter, brokerStoppedFinal, brokerFinal, gateway, installContainer, clientBeforeContainer, observerBeforeContainer, readbackBeforeContainer, backendBeforeContainer, readinessAfterContainer, readbackAfterContainer, backendAfterContainer, observerAfterContainer, clientAfterContainer, readinessFinalContainer, clientFinalContainer, backendFinalContainer, readbackFinalContainer];
    gate(new Set(inspected.map((item) => item.Config.Labels[manifest.cleanup.label])).size === 1 && new Set(inspected.map((item) => item.Config.Labels[`${manifest.cleanup.label}-replica`])).size === 1, "replica_labels");
    gate(backend.Labels[manifest.cleanup.label] === setup.Config.Labels[manifest.cleanup.label] && frontend.Labels[manifest.cleanup.label] === setup.Config.Labels[manifest.cleanup.label], "replica_network_labels");
    gate(brokerBefore.HostConfig.NetworkMode === backend.Name && gateway.HostConfig.NetworkMode === frontend.Name, "replica_primary_networks");
    gate(same(Object.keys(backend.Containers).sort(), [brokerBefore.Id, gateway.Id].sort()), "replica_backend_running_endpoints");
    gate(same(Object.keys(frontend.Containers), [gateway.Id]), "replica_frontend_running_endpoints");
    gate(same(Object.keys(gateway.NetworkSettings.Networks).sort(), [backend.Name, frontend.Name].sort()), "replica_gateway_dual_homed");
    gate(containerNetworkAliasesInclude(brokerBefore, backend.Name, "broker") && containerNetworkAliasesInclude(gateway, frontend.Name, "gateway") && !containerNetworkAliasesInclude(gateway, backend.Name, "broker"), "replica_container_network_aliases");
    const backendMembers = [brokerBefore, brokerStopped, brokerAfter, brokerStoppedFinal, brokerFinal, installContainer, observerBeforeContainer, readbackBeforeContainer, backendBeforeContainer, readinessAfterContainer, readbackAfterContainer, backendAfterContainer, observerAfterContainer, readinessFinalContainer, backendFinalContainer, readbackFinalContainer];
    for (const item of backendMembers) gate(same(Object.keys(item.NetworkSettings?.Networks ?? {}), [backend.Name]), "replica_backend_membership_from_container_inspect");
    for (const item of [clientBeforeContainer, clientAfterContainer, clientFinalContainer]) gate(same(Object.keys(item.NetworkSettings?.Networks ?? {}), [frontend.Name]), "replica_frontend_membership_from_container_inspect");
    gate(setupUsesNetworkNone(setup), "replica_setup_no_network");
    const configBytes = readPrivateBytes(configPath, MAX_JSON_BYTES, "replica_broker_config_file");
    gate(sha256Bytes(configBytes) === manifest.broker.config_sha256 && configBytes.equals(brokerConfigBytes(manifest)), "replica_broker_config");

    return {
        schema: REPLICA_SCHEMA,
        result: "pass",
        pass: "B1A",
        classification: CLASSIFICATION,
        authoritative: false,
        broker: {real_mosquitto: true, version: manifest.images.mosquitto.version, dedicated_listener: true, anonymous_disabled: true, dynamic_security_only: true, persistence_private_bind: true, check_retain_source_configured: true, check_retain_source_behavior_tested: false, exact_readback_before_and_after_restarts: true, application_credential_acl_samples: true, retained_persistence_sentinel: true, clean_two_restarts_exit_zero: true, authenticated_readiness_after_each_restart: true, backend_internal_network: true, published_host_ports: false},
        gateway: {packet_aware_mqtt_v5: true, qos2_state_machine: true, policy_sha256: startup.policy_sha256, composite_policy_sha256: manifest.composite_policy.effective_sha256, runtime_loaded_policy_digest: true, credential_files_provisioned: false, artifact_files_provisioned: false, connect_password_in_transit: true, connect_password_decoded: false, connect_password_persisted: false, broker_ack_authority: true, exact_preflight_envelope_enforcement: true, pure_oracle_matrix_equivalent: true, bounded_handshake_and_idle_timers: true, bidirectional_backpressure: true, parser_and_unsupported_packets_fail_closed: true, broker_origin_malformed_latches_gateway: true, run_wide_listener_healthy: true, sole_dual_homed_container: true, frontend_broker_dns_absent: true, frontend_broker_tcp_absent: true},
        policy: {broker_sha256: manifest.policy.canonical_sha256, gateway_sha256: manifest.gateway.policy_sha256, composite_sha256: manifest.composite_policy.effective_sha256, preflight_acl_schema: manifest.preflight_acl.schema, preflight_acl_sha256: manifest.preflight_acl.policy_digest, expected_readback_sha256: manifest.policy.expected_readback_sha256, observed_before_restart_sha256: beforeDigest, observed_after_restart_sha256: afterDigest, observed_final_sha256: finalDigest, dynamic_security_exact_set_no_extras: true, assignments_acl_priorities_and_order_read_back: true, native_application_samples_exercised: true, gateway_matrix_exercised: true, pure_preflight_oracle_tested_same_run: true, pure_composite_equivalence_tested: true, correlated_control_responses: true},
        native_broker_samples: {...backendBefore.native_acl_samples, backend_only_application_credentials: true, retained_sentinel_replayed_after_restart_qos2: true, retained_sentinel_cleared_qos2: true, retained_sentinel_absent_after_second_restart: true},
        authentication: {exact_principal_client_id_binding: true, wrong_password_denied: true, wrong_client_id_denied: true, anonymous_denied: true, unknown_denied: true, admin_and_observer_frontend_denied: true, gateway_denials_without_ack_or_publish: true, frontend_matrix_before_restart: true, frontend_matrix_after_first_restart: true, frontend_matrix_after_second_restart: true, reason_classes: {wrong_password: clientBefore.authentication.wrong_password_broker_reason, wrong_client_id: "connection_closed", anonymous: "connection_closed", unknown: "connection_closed"}},
        matrix: {publish_cases: clientBefore.matrix.publish.cases, publish_allowed: clientBefore.matrix.publish.allowed, publish_denied: clientBefore.matrix.publish.denied, subscribe_cases: clientBefore.matrix.subscribe.cases, subscribe_allowed: clientBefore.matrix.subscribe.allowed, subscribe_denied: clientBefore.matrix.subscribe.denied, gateway_publish_close_denials: clientBefore.matrix.publish.gateway_close_denials, gateway_subscribe_close_denials: clientBefore.matrix.subscribe.gateway_close_denials, deep_containment_denied_depths: clientBefore.matrix.publish.deep_containment_depths, qos_enforced: true, qos2_proxy_exercised: true, retain_enforced: true, strict_mqtt_utf8_enforced: true, wildcard_and_shared_subscriptions_denied: true, source_and_candidate_privacy_enforced: true, positive_broker_ack_and_delivery_controls: true, pure_oracle_equivalent: true},
        retained_source: {synthetic_publisher: true, real_externaljs_path: false, mqtt_payload_sha256: observerBefore.payload_sha256, source_sha256: observerBefore.source_sha256, observer_replay_qos1_retained: true, fresh_and_reconnect_privacy: true, wildcard_and_shared_privacy: true, raw_source_emitted: false, cleared_before_restart: true, absent_after_restart: true, request_topics_retained_absent: true, native_sentinel_replayed_after_restart_qos2: true, native_sentinel_absent_after_clear_and_second_restart: true},
        limitations: {check_retain_source_behavior_tested: false, backend_fault_injection_tested: false, listener_fault_injection_tested: false, same_runner_host_isolation_proven: false, seccomp_isolation_boundary: false, permit_consumption: false, writer_fence: false, real_zigbee2mqtt_mqtt_externaljs_source_path: false, physical_provenance: false, coordinator_radio_valve_exercised: false},
        security: {clients_nonroot: true, broker_nonroot: true, gateway_nonroot: true, read_only_roots: true, cap_drop_all: true, no_new_privileges: true, seccomp_filter_observed: true, bounded_resources: true, forbidden_host_paths_absent: true, exact_two_internal_networks: true, host_aliases_and_external_route_probed: true, same_runner_host_isolation_proven: false},
        container_image_config_digests: {node: gateway.Image, mosquitto: brokerBefore.Image},
        normalized_random_fields_removed_after_shape_validation: true,
    };
}

function canonicalFile(file, maximum, schema) {
    const bytes = readPrivateBytes(file, maximum, "canonical_file_size");
    const text = bytes.toString("utf8");
    gate(Buffer.from(text, "utf8").equals(bytes) && text.endsWith("\n"), "canonical_file_utf8");
    const value = JSON.parse(text);
    gate(value.schema === schema && text === `${canonical(value)}\n`, "canonical_file_identity");
    return {value, text};
}

function validateReplicaEvidence(value, manifest, sourceBytes) {
    exactKeys(value, ["schema", "result", "pass", "classification", "authoritative", "broker", "gateway", "policy", "native_broker_samples", "authentication", "matrix", "retained_source", "limitations", "security", "container_image_config_digests", "normalized_random_fields_removed_after_shape_validation"], "replica_evidence_shape");
    gate(value.schema === REPLICA_SCHEMA && value.result === "pass" && value.pass === "B1A" && value.classification === CLASSIFICATION && value.authoritative === false, "replica_evidence_identity");
    gate(same(value.broker, {
        real_mosquitto: true,
        version: "2.0.22",
        dedicated_listener: true,
        anonymous_disabled: true,
        dynamic_security_only: true,
        persistence_private_bind: true,
        check_retain_source_configured: true,
        check_retain_source_behavior_tested: false,
        exact_readback_before_and_after_restarts: true,
        application_credential_acl_samples: true,
        retained_persistence_sentinel: true,
        clean_two_restarts_exit_zero: true,
        authenticated_readiness_after_each_restart: true,
        backend_internal_network: true,
        published_host_ports: false,
    }), "replica_evidence_broker");
    gate(same(value.gateway, {
        packet_aware_mqtt_v5: true,
        qos2_state_machine: true,
        policy_sha256: manifest.gateway.policy_sha256,
        composite_policy_sha256: manifest.composite_policy.effective_sha256,
        runtime_loaded_policy_digest: true,
        credential_files_provisioned: false,
        artifact_files_provisioned: false,
        connect_password_in_transit: true,
        connect_password_decoded: false,
        connect_password_persisted: false,
        broker_ack_authority: true,
        exact_preflight_envelope_enforcement: true,
        pure_oracle_matrix_equivalent: true,
        bounded_handshake_and_idle_timers: true,
        bidirectional_backpressure: true,
        parser_and_unsupported_packets_fail_closed: true,
        broker_origin_malformed_latches_gateway: true,
        run_wide_listener_healthy: true,
        sole_dual_homed_container: true,
        frontend_broker_dns_absent: true,
        frontend_broker_tcp_absent: true,
    }), "replica_evidence_gateway");
    gate(same(value.policy, {
        broker_sha256: manifest.policy.canonical_sha256,
        gateway_sha256: manifest.gateway.policy_sha256,
        composite_sha256: manifest.composite_policy.effective_sha256,
        preflight_acl_schema: "true-family-physical-probe-acl-plan-v2",
        preflight_acl_sha256: manifest.preflight_acl.policy_digest,
        expected_readback_sha256: manifest.policy.expected_readback_sha256,
        observed_before_restart_sha256: manifest.policy.expected_readback_sha256,
        observed_after_restart_sha256: manifest.policy.expected_readback_sha256,
        observed_final_sha256: manifest.policy.expected_readback_sha256,
        dynamic_security_exact_set_no_extras: true,
        assignments_acl_priorities_and_order_read_back: true,
        native_application_samples_exercised: true,
        gateway_matrix_exercised: true,
        pure_preflight_oracle_tested_same_run: true,
        pure_composite_equivalence_tested: true,
        correlated_control_responses: true,
    }), "replica_evidence_policy");
    gate(same(value.native_broker_samples, {
        z2m_outside_publish_qos2_retain: true,
        z2m_outside_subscribe_qos2: true,
        orchestrator_native_qos_retain_not_enforced: true,
        other_publish_denied: true,
        other_subscribe_denied: true,
        collector_source_subscribe_denied: true,
        backend_only_application_credentials: true,
        retained_sentinel_replayed_after_restart_qos2: true,
        retained_sentinel_cleared_qos2: true,
        retained_sentinel_absent_after_second_restart: true,
    }), "replica_evidence_native_broker_samples");
    exactKeys(value.authentication, ["exact_principal_client_id_binding", "wrong_password_denied", "wrong_client_id_denied", "anonymous_denied", "unknown_denied", "admin_and_observer_frontend_denied", "gateway_denials_without_ack_or_publish", "frontend_matrix_before_restart", "frontend_matrix_after_first_restart", "frontend_matrix_after_second_restart", "reason_classes"], "replica_evidence_auth_shape");
    gate(Object.entries(value.authentication).filter(([key]) => key !== "reason_classes").every(([, item]) => item === true), "replica_evidence_auth");
    exactKeys(value.authentication.reason_classes, ["wrong_password", "wrong_client_id", "anonymous", "unknown"], "replica_evidence_auth_reasons");
    gate(Object.values(value.authentication.reason_classes).every((item) => manifest.authentication.accepted_negative_reason_classes.includes(item)), "replica_evidence_auth_reasons");
    exactKeys(value.matrix, ["publish_cases", "publish_allowed", "publish_denied", "subscribe_cases", "subscribe_allowed", "subscribe_denied", "gateway_publish_close_denials", "gateway_subscribe_close_denials", "deep_containment_denied_depths", "qos_enforced", "qos2_proxy_exercised", "retain_enforced", "strict_mqtt_utf8_enforced", "wildcard_and_shared_subscriptions_denied", "source_and_candidate_privacy_enforced", "positive_broker_ack_and_delivery_controls", "pure_oracle_equivalent"], "replica_evidence_matrix_shape");
    gate(value.matrix.publish_cases === manifest.matrix.publish.length && value.matrix.publish_allowed === countExpected(manifest.matrix.publish, true) && value.matrix.publish_denied === countExpected(manifest.matrix.publish, false), "replica_evidence_matrix");
    gate(value.matrix.subscribe_cases === manifest.matrix.subscribe.length && value.matrix.subscribe_allowed === countExpected(manifest.matrix.subscribe, true) && value.matrix.subscribe_denied === countExpected(manifest.matrix.subscribe, false), "replica_evidence_matrix");
    gate(value.matrix.gateway_publish_close_denials === value.matrix.publish_denied && value.matrix.gateway_subscribe_close_denials === value.matrix.subscribe_denied, "replica_evidence_matrix");
    gate(same(value.matrix.deep_containment_denied_depths, [0, 8, 32, 100]), "replica_evidence_matrix");
    for (const key of ["qos_enforced", "qos2_proxy_exercised", "retain_enforced", "strict_mqtt_utf8_enforced", "wildcard_and_shared_subscriptions_denied", "source_and_candidate_privacy_enforced", "positive_broker_ack_and_delivery_controls", "pure_oracle_equivalent"]) gate(value.matrix[key] === true, "replica_evidence_matrix");
    const sourcePayload = buildSourceInventory(sourceBytes, manifest.artifact.filename);
    exactKeys(value.retained_source, ["synthetic_publisher", "real_externaljs_path", "mqtt_payload_sha256", "source_sha256", "observer_replay_qos1_retained", "fresh_and_reconnect_privacy", "wildcard_and_shared_privacy", "raw_source_emitted", "cleared_before_restart", "absent_after_restart", "request_topics_retained_absent", "native_sentinel_replayed_after_restart_qos2", "native_sentinel_absent_after_clear_and_second_restart"], "replica_evidence_source_shape");
    gate(value.retained_source.synthetic_publisher === true && value.retained_source.real_externaljs_path === false && value.retained_source.mqtt_payload_sha256 === sha256Bytes(sourcePayload) && value.retained_source.source_sha256 === manifest.artifact.sha256, "replica_evidence_source");
    for (const key of ["observer_replay_qos1_retained", "fresh_and_reconnect_privacy", "wildcard_and_shared_privacy", "cleared_before_restart", "absent_after_restart", "request_topics_retained_absent", "native_sentinel_replayed_after_restart_qos2", "native_sentinel_absent_after_clear_and_second_restart"]) gate(value.retained_source[key] === true, "replica_evidence_source");
    gate(value.retained_source.raw_source_emitted === false, "replica_evidence_source");
    gate(same(value.limitations, {
        check_retain_source_behavior_tested: false,
        backend_fault_injection_tested: false,
        listener_fault_injection_tested: false,
        same_runner_host_isolation_proven: false,
        seccomp_isolation_boundary: false,
        permit_consumption: false,
        writer_fence: false,
        real_zigbee2mqtt_mqtt_externaljs_source_path: false,
        physical_provenance: false,
        coordinator_radio_valve_exercised: false,
    }), "replica_evidence_limitations");
    gate(same(value.security, {
        clients_nonroot: true,
        broker_nonroot: true,
        gateway_nonroot: true,
        read_only_roots: true,
        cap_drop_all: true,
        no_new_privileges: true,
        seccomp_filter_observed: true,
        bounded_resources: true,
        forbidden_host_paths_absent: true,
        exact_two_internal_networks: true,
        host_aliases_and_external_route_probed: true,
        same_runner_host_isolation_proven: false,
    }), "replica_evidence_security");
    exactKeys(value.container_image_config_digests, ["node", "mosquitto"], "replica_evidence_images");
    gate(SHA256_PREFIX_PATTERN.test(value.container_image_config_digests.node) && value.container_image_config_digests.mosquitto === manifest.images.mosquitto.oci_config_digest, "replica_evidence_images");
    gate(value.normalized_random_fields_removed_after_shape_validation === true, "replica_evidence_normalization");
}

function combineReplicas(args) {
    const [replicaOnePath, replicaTwoPath, nodeImagePath, mosquittoImagePath, manifestPath, launcherPath, runtimePath, verifierPath, workflowPath, artifactPath, preflightPath, fixturePath, preflightTestPath, commit, tree, workflowRef] = args;
    gate(args.length === 16, "combine_arguments");
    const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
    const replicaOne = canonicalFile(replicaOnePath, MAX_FINAL_BYTES, REPLICA_SCHEMA);
    const replicaTwo = canonicalFile(replicaTwoPath, MAX_FINAL_BYTES, REPLICA_SCHEMA);
    gate(replicaOne.text === replicaTwo.text, "replica_nonreproducible");
    const sourceBytes = fs.readFileSync(artifactPath);
    gate(sha256Bytes(sourceBytes) === manifest.artifact.sha256, "combine_artifact");
    validateReplicaEvidence(replicaOne.value, manifest, sourceBytes);
    validateReplicaEvidence(replicaTwo.value, manifest, sourceBytes);
    const nodeImage = validateImageInspect(readPrivateJson(nodeImagePath, "node_image_json"), "node", manifest);
    const mosquittoImage = validateImageInspect(readPrivateJson(mosquittoImagePath, "mosquitto_image_json"), "mosquitto", manifest);
    gate(replicaOne.value.container_image_config_digests?.node === nodeImage.config_digest && replicaOne.value.container_image_config_digests?.mosquitto === mosquittoImage.config_digest, "replica_image_binding");
    gate(/^[0-9a-f]{40}$/u.test(commit) && /^[0-9a-f]{40}$/u.test(tree), "git_identity");
    gate(typeof workflowRef === "string" && workflowRef.endsWith("/.github/workflows/pass-b1-broker.yaml@refs/heads/main"), "workflow_identity");
    const bindings = {
        manifest_sha256: sha256File(manifestPath),
        launcher_normalized_sha256: normalizedLauncherDigest(fs.readFileSync(launcherPath)).digest,
        runtime_harness_sha256: sha256File(runtimePath),
        verifier_sha256: sha256File(verifierPath),
        workflow_sha256: sha256File(workflowPath),
        artifact_sha256: sha256File(artifactPath),
        preflight_source_sha256: sha256File(preflightPath),
        preflight_fixture_sha256: sha256File(fixturePath),
        preflight_test_sha256: sha256File(preflightTestPath),
        broker_config_sha256: manifest.broker.config_sha256,
        broker_policy_sha256: manifest.policy.canonical_sha256,
        gateway_policy_sha256: manifest.gateway.policy_sha256,
        composite_policy_sha256: manifest.composite_policy.effective_sha256,
        expected_readback_sha256: manifest.policy.expected_readback_sha256,
        policy_matrix_sha256: sha256Bytes(Buffer.from(canonical(manifest.matrix), "utf8")),
        b0_preservation: manifest.bindings.b0_preservation,
    };
    gate(bindings.launcher_normalized_sha256 === manifest.bindings.launcher_normalized_sha256, "combine_launcher");
    gate(bindings.runtime_harness_sha256 === manifest.bindings.runtime_harness_sha256 && bindings.verifier_sha256 === manifest.bindings.verifier_sha256 && bindings.workflow_sha256 === manifest.bindings.workflow_sha256, "combine_tools");
    gate(bindings.preflight_source_sha256 === manifest.bindings.preflight_source_sha256 && bindings.preflight_fixture_sha256 === manifest.bindings.preflight_fixture_sha256 && bindings.preflight_test_sha256 === manifest.bindings.preflight_test_sha256, "combine_preflight_tools");
    return {
        schema: BASE_SCHEMA,
        result: "pass",
        pass: "B1A",
        classification: CLASSIFICATION,
        authoritative: false,
        pass_b1_complete: false,
        authorization: false,
        loose_spare_used: false,
        trust_boundary: manifest.trust_boundary,
        git: {commit, tree},
        workflow: {path: ".github/workflows/pass-b1-broker.yaml", ref: workflowRef, runner: "ubuntu-24.04", architecture: "amd64"},
        images: {
            node: {...nodeImage, index_reference_sha256: manifest.images.node.index_reference_sha256, index_used_as_runtime_identity: false},
            mosquitto: {...mosquittoImage, index_reference_sha256: manifest.images.mosquitto.index_reference_sha256, upstream_source_sha256: manifest.images.mosquitto.upstream_source_sha256, index_used_as_runtime_identity: false},
        },
        bindings,
        replica: replicaOne.value,
        replicas: {fresh_full_replicas: 2, normalized_byte_identical: true},
        claim_limits: CLAIM_LIMITS,
        cleanup_pending: true,
    };
}

function validateBaseEvidence(value, manifest) {
    exactKeys(value, ["schema", "result", "pass", "classification", "authoritative", "pass_b1_complete", "authorization", "loose_spare_used", "trust_boundary", "git", "workflow", "images", "bindings", "replica", "replicas", "claim_limits", "cleanup_pending"], "base_evidence_shape");
    gate(value.schema === BASE_SCHEMA && value.result === "pass" && value.pass === "B1A" && value.classification === CLASSIFICATION, "base_evidence_identity");
    gate(value.authoritative === false && value.pass_b1_complete === false && value.authorization === false && value.loose_spare_used === false, "base_evidence_claim");
    gate(same(value.trust_boundary, manifest.trust_boundary) && same(value.claim_limits, CLAIM_LIMITS), "base_evidence_boundary");
    gate(value.replica?.schema === REPLICA_SCHEMA && value.replica?.result === "pass", "base_evidence_replica");
    gate(same(value.replicas, {fresh_full_replicas: 2, normalized_byte_identical: true}) && value.cleanup_pending === true, "base_evidence_replicas");
}

function finalizeCleanup(input, manifest) {
    gate(Buffer.byteLength(input, "utf8") <= MAX_FINAL_BYTES && input.endsWith("\n"), "finalize_input_size");
    const base = JSON.parse(input);
    gate(input === `${canonical(base)}\n`, "finalize_input_canonical");
    validateBaseEvidence(base, manifest);
    delete base.cleanup_pending;
    base.schema = FINAL_SCHEMA;
    base.cleanup = {
        zero_labeled_containers: true,
        zero_labeled_networks: true,
        private_root_deleted: true,
        credentials_deleted: true,
        symlinks_not_followed: true,
        pass_emitted_after_cleanup: true,
    };
    base.evidence_digest = sha256Bytes(Buffer.from(canonical(base), "utf8"));
    const output = `${canonical(base)}\n`;
    gate(Buffer.byteLength(output, "utf8") <= manifest.evidence.max_final_bytes, "final_output_size");
    return output;
}

function staticSourceChecks(paths, manifest) {
    const launcher = fs.readFileSync(paths.launcher, "utf8");
    const workflow = fs.readFileSync(paths.workflow, "utf8");
    const runtime = fs.readFileSync(paths.runtime, "utf8");
    const verifier = fs.readFileSync(paths.verifier, "utf8");
    const b0Launcher = fs.readFileSync(paths.b0Launcher, "utf8");
    const b0Workflow = fs.readFileSync(paths.b0Workflow, "utf8");
    gate(!launcher.includes(manifest.images.mosquitto.tag) && !launcher.includes(manifest.images.mosquitto.index_reference_sha256), "index_reference_only");
    gate(launcher.includes(manifest.images.node.child) && launcher.includes(manifest.images.mosquitto.child), "launcher_child_images");
    gate((launcher.match(/--platform linux\/amd64/gu) ?? []).length === 5, "launcher_platform");
    gate((launcher.match(/docker_for 30 network create/gu) ?? []).length === 2 && (launcher.match(/--internal/gu) ?? []).length === 2, "launcher_network");
    gate(launcher.includes("-backend") && launcher.includes("-frontend") && launcher.includes('network connect "$backend" "$gateway_name"'), "launcher_gateway_topology");
    gate(!launcher.includes("-p 18883") && !launcher.includes("--publish") && launcher.includes("B1A_ENDPOINT_HOST") && launcher.includes("B1A_LISTEN_HOST=gateway"), "launcher_network");
    gate(!launcher.includes("/homeassistant") && !launcher.includes("/addons") && !launcher.includes("/addon_configs"), "launcher_household_paths");
    gate(!launcher.includes("mosquitto_pub") && !launcher.includes("mosquitto_sub"), "launcher_cli_trust");
    gate(launcher.includes("mosquitto_ctrl dynsec init") && launcher.includes("admin.password"), "launcher_bootstrap");
    gate(launcher.includes("--cap-drop=ALL") && launcher.includes("--security-opt=no-new-privileges") && launcher.includes("--read-only"), "launcher_container_security");
    gate(launcher.includes("--log-driver=json-file") && launcher.includes("--log-opt=max-size=1m") && launcher.includes("--log-opt=max-file=1"), "launcher_log_bounds");
    gate(launcher.includes("--ulimit=core=0:0") && launcher.includes("--ulimit=nofile=256:256"), "launcher_ulimits");
    gate(launcher.includes("--entrypoint /usr/bin/timeout") && launcher.includes("--foreground --signal=TERM --kill-after=10s"), "launcher_timeouts");
    gate(launcher.includes('DOCKER_CONFIG="$DOCKER_CONFIG_DIR"') && launcher.includes('HOME="$DOCKER_HOME"') && launcher.includes('printf \'%s\\n\' \'{}\' >"$DOCKER_CONFIG_DIR/config.json"'), "launcher_docker_environment");
    gate(launcher.includes("prepare_root_for_removal") && launcher.includes("find -P") && launcher.includes("-xdev") && !launcher.includes("find -L") && !launcher.includes("chmod -R"), "launcher_cleanup");
    gate(launcher.includes("RUN_WATCHDOG_SECONDS=1920") && launcher.includes("WORKFLOW_TIMEOUT_SECONDS=2700") && launcher.includes("LONGEST_BOUNDED_COMMAND_SECONDS=270") && launcher.includes("start_watchdog") && launcher.includes("stop_watchdog"), "launcher_watchdog");
    gate(launcher.includes("readiness_after") && launcher.includes("readiness_final") && launcher.includes("client_final"), "launcher_restart_readiness");
    gate(launcher.includes("host_for() (") && launcher.includes("docker_for() (") && (launcher.match(/exec 3>&-/gu) ?? []).length >= 3, "launcher_child_fd_closed");
    gate(launcher.includes('PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONNOUSERSITE=1') && launcher.includes('python3 "$REPO_ROOT/tests/test_physical_probe_preflight.py"'), "launcher_python_oracle");
    const normalLauncher = launcher.slice(launcher.indexOf("exec 3>&1"));
    gate(!/^\s*(?:node|git|stat|id|mkdir|chmod|sleep|cmp|find|rm|mktemp|od|tr|env|uname|dirname)\b/gmu.test(normalLauncher), "launcher_unbounded_host_command");
    const boundedCommandSeconds = [...normalLauncher.matchAll(/\b(?:host_for|docker_for)\s+([0-9]+)\b/gu)].map((match) => Number(match[1]));
    gate(boundedCommandSeconds.length > 0 && Math.max(...boundedCommandSeconds) === manifest.cleanup.longest_bounded_command_seconds, "launcher_longest_command");
    const replicaVerifyIndex = launcher.indexOf('host_for 90 node "$VERIFIER" --verify-replica');
    const gatewayStopIndex = launcher.indexOf('docker_for 30 stop --time 20 "$gateway_name"', replicaVerifyIndex);
    const brokerStopIndex = launcher.indexOf('docker_for 30 stop --time 20 "$broker_name"', gatewayStopIndex);
    const stoppedInspectIndex = launcher.indexOf('"$inspect/broker-redaction-stopped.json"', brokerStopIndex);
    const replicaScanIndex = launcher.indexOf('host_for 90 node "$VERIFIER" --scan-redaction "$ARTIFACT" "$MANIFEST" "$replica"', stoppedInspectIndex);
    const removalIndex = launcher.indexOf("docker_for 30 rm -fv", replicaScanIndex);
    const replicaScanSource = launcher.slice(replicaScanIndex, removalIndex);
    const compactReplicaScanSource = replicaScanSource.replace(/\\\s+/gu, " ").replace(/\s+/gu, " ");
    gate(replicaVerifyIndex >= 0 && gatewayStopIndex > replicaVerifyIndex && brokerStopIndex > gatewayStopIndex && stoppedInspectIndex > brokerStopIndex && replicaScanIndex > stoppedInspectIndex && removalIndex > replicaScanIndex, "launcher_scan_sequence");
    gate(compactReplicaScanSource.includes('"$replica" "$data" "$inspect/broker-redaction-stopped.json" "$logs" "$inspect" "$evidence" "$config/pass-b1a.conf" "$status" "$coord" >/dev/null') && (replicaScanSource.match(/"\$data"/gu) ?? []).length === 1 && (replicaScanSource.match(/"\$replica"/gu) ?? []).length === 1 && (launcher.match(/--scan-redaction/gu) ?? []).length === 3, "launcher_scan_explicit_roots");
    gate(!replicaScanSource.includes('"$credentials"') && !replicaScanSource.includes('"$generated"') && !replicaScanSource.includes('"$observer_after_output"'), "launcher_scan_secret_roots");
    for (const ordinal of [1, 2]) {
        const start = launcher.indexOf(`host_for 90 node "$VERIFIER" --scan-redaction "$ARTIFACT" "$MANIFEST" "$ROOT/replica-${ordinal}"`);
        const end = ordinal === 1 ? launcher.indexOf('host_for 90 node "$VERIFIER" --scan-redaction "$ARTIFACT" "$MANIFEST" "$ROOT/replica-2"', start) : launcher.indexOf('BASE_EVIDENCE="', start);
        const source = launcher.slice(start, end);
        const compact = source.replace(/\\\s+/gu, " ").replace(/\s+/gu, " ");
        gate(start >= 0 && end > start && compact.includes(`"$ROOT/replica-${ordinal}" "$ROOT/replica-${ordinal}/data" "$ROOT/replica-${ordinal}/inspect/broker-redaction-stopped.json" "$ROOT/replica-${ordinal}/logs" "$ROOT/replica-${ordinal}/inspect" "$ROOT/replica-${ordinal}/evidence" "$ROOT/replica-${ordinal}/config/pass-b1a.conf" "$ROOT/replica-${ordinal}/status" "$ROOT/replica-${ordinal}/coord" "$ROOT/base-evidence.json" "$ROOT/node-image.json" "$ROOT/mosquitto-image.json" "$ROOT/shell-self-check.json" "$ROOT/verifier-self-check.json" >/dev/null`) && (source.match(new RegExp(`"\\$ROOT/replica-${ordinal}/data"`, "gu")) ?? []).length === 1 && (source.match(new RegExp(`"\\$ROOT/replica-${ordinal}"`, "gu")) ?? []).length === 1 && !source.includes(`/replica-${ordinal}/credentials`) && !source.includes(`/replica-${ordinal}/generated`) && !source.includes(`/replica-${ordinal}/observer-after-output`), "launcher_final_scan_explicit_roots");
    }
    const failureSource = launcher.slice(launcher.indexOf("failure_exit()"), launcher.indexOf("trap failure_exit"));
    gate(failureSource.includes('if [[ -n "$ROOT" && ( -e "$ROOT" || -L "$ROOT" ) ]]') && !failureSource.includes('cleanup_queries_ok" -eq 1 &&'), "launcher_failure_root_removal");
    const stageValidatorSource = launcher.slice(launcher.indexOf("failure_stage_valid()"), launcher.indexOf("failure_stage_projection()"));
    const stageProjectionSource = launcher.slice(launcher.indexOf("failure_stage_projection()"), launcher.indexOf("set_failure_stage()"));
    const failureRecordSource = launcher.slice(launcher.indexOf("failure_record()"), launcher.indexOf("shell_self_check()"));
    gate(launcher.indexOf('FAILURE_STAGE="startup"') >= 0 && launcher.indexOf('FAILURE_STAGE="startup"') < launcher.indexOf('if [[ "${1:-}" == "--shell-self-check" ]]'), "launcher_failure_stage_default");
    gate(stageValidatorSource.includes('startup|environment|private_root|static_shell|static_verifier|static_python|pull_node|pull_mosquitto|inspect_node|inspect_mosquitto|compare|combine|final_scan_one|final_scan_two|cleanup|finalize') && stageValidatorSource.includes('install_(context|credentials|broker_connect|broker_subscribe|command_transport|command_rejected|security|unknown)') && stageValidatorSource.includes('^replica_[12]_'), "launcher_failure_stage_allowlist");
    gate(stageProjectionSource.includes('printf \'%s\' "unknown"') && failureRecordSource.includes('{"failure_code":"%s","failure_stage":"%s","result":"fail","schema":"%s"}') && !failureRecordSource.includes("status") && (launcher.match(/failure_record "\$FAILURE_STAGE"/gu) ?? []).length === 2, "launcher_failure_projection");
    const topLevelStageAssignments = [...launcher.matchAll(/^set_failure_stage "([a-z0-9_]+)"$/gmu)].map((match) => match[1]);
    const replicaStageAssignments = [...launcher.matchAll(/^\s+set_failure_stage "replica_\$\{ordinal\}_([a-z0-9_]+)"$/gmu)].map((match) => match[1]);
    gate(same(topLevelStageAssignments, LAUNCHER_TOP_LEVEL_FAILURE_STAGES.slice(1)) && same(replicaStageAssignments, LAUNCHER_REPLICA_FAILURE_PHASES), "launcher_failure_stage_coverage");
    const shellStart = launcher.indexOf('if [[ "${1:-}" == "--shell-self-check" ]]');
    const verifierStart = launcher.indexOf('if [[ "${1:-}" == "--self-check" ]]');
    const normalStart = launcher.indexOf('[[ $# -eq 0 ]]', verifierStart);
    gate(shellStart >= 0 && verifierStart > shellStart && normalStart > verifierStart, "self_check_static_shape");
    const shellSelfCheck = launcher.slice(shellStart, verifierStart);
    const verifierSelfCheck = launcher.slice(verifierStart, normalStart);
    const shellSelfCheckFunction = launcher.slice(launcher.indexOf("shell_self_check()"), shellStart);
    gate(shellSelfCheckFunction.includes("failure_stage_projection") && shellSelfCheckFunction.includes("replica_2_final_readback") && shellSelfCheckFunction.includes("replica_1_install_command_rejected") && shellSelfCheckFunction.includes("replica_1_install_control_response_error") && shellSelfCheckFunction.includes("arbitrary/path") && shellSelfCheckFunction.includes('"failure_stage":"unknown"'), "launcher_failure_shell_self_check");
    for (const source of [shellSelfCheck, verifierSelfCheck]) {
        gate(source.length > 0 && !source.includes("docker") && !source.includes("mktemp") && !source.includes("RUNNER_TEMP"), "self_check_offline");
    }
    gate(runtime.includes("command_success_from_response_not_puback: true") && runtime.includes("correlationData"), "runtime_control_response");
    const installFailureMappingSource = runtime.slice(runtime.indexOf("const INSTALL_FAILURE_CATEGORY_BY_CODE"), runtime.indexOf("export function installFailureCategoryForCode"));
    gate(installFailureMappingSource.includes('control_response_error: "command_rejected"') && installFailureMappingSource.includes('control_connect: "broker_connect"') && installFailureMappingSource.includes('control_subscribe: "broker_subscribe"') && installFailureMappingSource.includes('mqtt_timeout: "command_transport"') && installFailureMappingSource.includes('container_security: "security"') && installFailureMappingSource.includes('admin_credentials_json: "credentials"') && installFailureMappingSource.includes('runtime_environment: "context"'), "runtime_install_failure_mapping");
    gate(runtime.includes('mode === "install" && error instanceof B1AFailure') && runtime.includes('if (process.env.B1A_MODE !== "gateway") process.stdout.write(runtimeFailureRecord(runtimeFailureCategory(process.env.B1A_MODE, error)))') && !runtime.includes('failure_code: "runtime_failed"'), "runtime_failure_projection");
    const installLauncherSource = launcher.slice(launcher.indexOf('set_failure_stage "replica_${ordinal}_install"'), launcher.indexOf('set_failure_stage "replica_${ordinal}_gateway"'));
    gate(installLauncherSource.includes('if docker_for 270 start -a "$install_name"') && installLauncherSource.includes('--classify-runtime-failure install "$evidence/install.json" "$MANIFEST"') && installLauncherSource.includes('set_failure_stage "replica_${ordinal}_install_${install_failure_category}"') && installLauncherSource.includes('return "$install_status"') && !installLauncherSource.includes("printf") && !installLauncherSource.includes("cat "), "launcher_install_failure_projection");
    gate(installLauncherSource.includes('context|credentials|broker_connect|broker_subscribe|command_transport|command_rejected|security|unknown'), "launcher_install_failure_allowlist");
    const runtimeClassifierSource = verifier.slice(verifier.indexOf("function runtimeFailureCategoryFromBytes"), verifier.indexOf("function readCanonicalRuntime"));
    gate(runtimeClassifierSource.includes("contract.max_bytes") && runtimeClassifierSource.includes("runtime_failure_canonical") && runtimeClassifierSource.includes("contract.categories.includes(value.failure_category)") && verifier.includes('if (process.argv[2] !== "--classify-runtime-failure") process.stdout.write(failureToken())'), "verifier_runtime_failure_classifier");
    gate(runtime.includes("sendAndExpectClose") && runtime.includes("gateway_close_denials") && runtime.includes(".noMessage("), "runtime_gateway_denial");
    gate(runtime.includes("gatewayPolicyDigest") && runtime.includes("MqttFrameStream") && runtime.includes("broker_ack_authority: true"), "runtime_gateway_policy");
    const gatewaySource = runtime.slice(runtime.indexOf("async function runGateway"), runtime.indexOf("function encodePuback"));
    gate(gatewaySource.includes("forwardFrame(client, session.upstream, frame") && gatewaySource.includes("forwardFrame(upstream, client, brokerFrame"), "runtime_gateway_forwarding");
    gate(!gatewaySource.includes("encodePuback") && !gatewaySource.includes("encodeSuback"), "runtime_gateway_no_forged_ack");
    gate(gatewaySource.includes('server.on("error", latch)') && gatewaySource.includes("gatewayBackendDisconnectFatal") && gatewaySource.includes("gatewayUpstreamErrorFatal") && gatewaySource.includes("session.client.destroy()"), "runtime_gateway_fail_closed");
    gate(gatewaySource.includes("                            } catch {\n                                latch();\n                            }") && gatewaySource.includes("            } catch {\n                rejectSession(session);\n            }"), "runtime_malformed_scope");
    gate(gatewaySource.includes("GATEWAY_HANDSHAKE_TIMEOUT_MS") && gatewaySource.includes("GATEWAY_IDLE_TIMEOUT_MS") && gatewaySource.includes("armSessionTimer") && gatewaySource.includes("session.timer.unref()"), "runtime_gateway_timers");
    gate((runtime.match(/setTimeout\(/gu) ?? []).length === (runtime.match(/\.unref\(\)/gu) ?? []).length, "runtime_all_timers_unref");
    gate(gatewaySource.includes("gatewayConnectBatchIsIsolated") && gatewaySource.includes("gatewayBackendConnectMayForward") && gatewaySource.includes("gatewayPreConnackBufferIsEmpty"), "runtime_gateway_connect_race");
    gate(gatewaySource.includes("forwardFrame(client, upstream") && gatewaySource.includes("forwardFrame(upstream, client") && gatewaySource.includes('destination.once("drain"'), "runtime_gateway_backpressure");
    gate(runtime.includes("parsePubrec") && runtime.includes("parsePubrel") && runtime.includes("parsePubcomp") && runtime.includes("qos2State") && runtime.includes("publicationIdentityMatches") && runtime.includes("pubcomp_reason"), "runtime_gateway_qos2");
    gate(runtime.includes('!["broker_denied", "closing", "rejected", "closed"].includes(state)') && runtime.includes("broker_origin_malformed_latches_gateway: true"), "runtime_broker_malformed_scope");
    gate(runtime.includes("async function runReadiness") && runtime.includes("authenticated_mqtt_v5_ready: true") && runtime.includes("async function runClientFinal"), "runtime_restart_readiness");
    gate(runtime.includes("backend_only_application_credentials: true") && runtime.includes("retained_sentinel_replayed_after_restart_qos2") && runtime.includes("orchestrator_native_qos_retain_not_enforced"), "runtime_backend_native_probes");
    gate(runtime.includes("fs.lstatSync(file)") && runtime.includes("fs.constants.O_NOFOLLOW") && runtime.includes("fs.fstatSync(handle)"), "runtime_private_file_validation");
    gate(verifier.includes("function readPrivateBytes") && verifier.includes("fs.constants.O_NOFOLLOW") && verifier.includes("metadata.nlink === 1") && verifier.includes("metadata.uid === process.getuid()"), "verifier_private_file_validation");
    const scanRedactionSource = verifier.slice(verifier.indexOf("function scanRedaction"), verifier.indexOf("function readCanonicalRuntime"));
    gate(verifier.includes("function expectedMosquittoDatabase") && verifier.includes("scanPathIsExpectedBinary(current, expectedBinaryPath)") && verifier.includes("sanitizedBytes(bytes, sourceText, secrets)") && verifier.includes("state.binaryFiles.length === 1") && verifier.includes("scanTree(dataRoot, sourceText, secrets, expectedBinaryPath, state)") && verifier.includes("scan_secret_input_excluded"), "verifier_binary_redaction");
    gate(scanRedactionSource.includes('"/mosquitto/config/pass-b1a.conf": configPath') && scanRedactionSource.includes('"/mosquitto/data": path.resolve(dataRoot)') && !scanRedactionSource.includes('"/mosquitto/config/dynamic-security.json"') && scanRedactionSource.includes("scan_dynamic_security_containment"), "verifier_scan_mount_contract");
    const preflight = fs.readFileSync(paths.preflight, "utf8");
    gate(preflight.includes('ACL_PLAN_SCHEMA = "true-family-physical-probe-acl-plan-v2"') && preflight.includes('_ACL_DIGEST_DOMAIN = "true-family-physical-probe/acl/v2"') && preflight.includes('"topic_contract"'), "preflight_v2_contract");
    gate(runtime.includes("buildSourceInventory") && runtime.includes("retained_source_cleared_by_z2m: true"), "runtime_source_proof");
    gate(workflow.includes('runs-on: "ubuntu-24.04"') && workflow.includes('timeout-minutes: 45') && workflow.includes('if: github.ref == \'refs/heads/main\''), "workflow_runner");
    gate(workflow.includes("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020") && workflow.includes('node-version: "20.19.2"') && workflow.includes('test "$(node --version)" = "v20.19.2"'), "workflow_node");
    gate(workflow.includes("scripts/pass-b1-broker --shell-self-check") && workflow.includes("scripts/pass-b1-broker --self-check"), "workflow_self_checks");
    gate(workflow.includes("python3 -m unittest tests.test_physical_probe_preflight") && workflow.includes("python3 -m py_compile custom_components/true_family/physical_probe_preflight.py"), "workflow_python_oracle");
    const runtimeStep = workflow.slice(workflow.indexOf("Run two fresh composite-policy replicas"));
    for (const required of [
        "exec env -i", 'PATH="$PATH"', 'RUNNER_TEMP="$RUNNER_TEMP"', 'CI="true"', 'GITHUB_ACTIONS="true"',
        'GITHUB_REF="$GITHUB_REF"', 'GITHUB_SHA="$GITHUB_SHA"', 'GITHUB_WORKFLOW_REF="$GITHUB_WORKFLOW_REF"',
        'RUNNER_OS="$RUNNER_OS"', 'RUNNER_ARCH="$RUNNER_ARCH"', 'ImageOS="$ImageOS"', "scripts/pass-b1-broker",
    ]) gate(runtimeStep.includes(required), "workflow_runtime_environment");
    gate(!workflow.includes("actions/upload-artifact") && !workflow.includes("pull_request:"), "workflow_artifacts");
    gate(b0Launcher.includes("PASS B0") || b0Launcher.includes("pass-b0"), "b0_semantics");
    gate(b0Workflow.includes("Non-Authoritative PASS B0 Runtime Smoke") && b0Workflow.includes("scripts/pass-b-z2m-runtime"), "b0_semantics");
}

function selfTests(paths, manifest) {
    gate(canonical({b: 2, a: 1}) === '{"a":1,"b":2}', "canonical_self_test");
    gate(launcherFailureStageProjection() === "startup" && launcherFailureStageProjection("replica_1_restart_two") === "replica_1_restart_two" && launcherFailureStageProjection("replica_2_install_security") === "replica_2_install_security" && launcherFailureStageProjection("replica_2_install_control_response_error") === "unknown" && launcherFailureStageProjection("private/path\nvalue") === "unknown", "launcher_failure_projection_self_test");
    gate(launcherFailureRecord() === '{"failure_code":"verification_failed","failure_stage":"startup","result":"fail","schema":"true-family-pass-b1a-launcher-failure-v2"}\n' && launcherFailureRecord("private/path") === '{"failure_code":"verification_failed","failure_stage":"unknown","result":"fail","schema":"true-family-pass-b1a-launcher-failure-v2"}\n', "launcher_failure_record_self_test");
    const runtimeFailureContract = manifest.evidence.runtime_failure_record;
    for (const category of INSTALL_FAILURE_CATEGORIES) {
        const bytes = Buffer.from(`${canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_category: category})}\n`, "utf8");
        gate(runtimeFailureCategoryFromBytes(bytes, "install", runtimeFailureContract) === category, "runtime_failure_category_self_test");
    }
    for (const bytes of [
        Buffer.from(JSON.stringify({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_category: "context"}) + "\n", "utf8"),
        Buffer.from(`${canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_category: "control_response_error"})}\n`, "utf8"),
        Buffer.from(`${canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_category: "unknown", failure_code: "private/path"})}\n`, "utf8"),
        Buffer.from(`${canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_category: "unknown"})}\nextra\n`, "utf8"),
        Buffer.from([0xff, 0xfe]),
        Buffer.alloc(runtimeFailureContract.max_bytes + 1, 0x61),
    ]) {
        let rejected = false;
        try { runtimeFailureCategoryFromBytes(bytes, "install", runtimeFailureContract); } catch { rejected = true; }
        gate(rejected, "runtime_failure_adversarial_self_test");
    }
    let wrongModeRejected = false;
    try {
        runtimeFailureCategoryFromBytes(Buffer.from(`${canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_category: "unknown"})}\n`), "client_before", runtimeFailureContract);
    } catch { wrongModeRejected = true; }
    gate(wrongModeRejected, "runtime_failure_mode_self_test");
    const expectedBinaryPath = "/tmp/true-family-pass-b1a.Abcdef12/replica-1/data/mosquitto.db";
    gate(scanPathIsExpectedBinary(expectedBinaryPath, expectedBinaryPath), "binary_scan_branch_self_test");
    for (const invalid of [
        "/tmp/true-family-pass-b1a.Abcdef12/replica-1/data/other.db",
        "/tmp/true-family-pass-b1a.Abcdef12/replica-1/logs/mosquitto.db",
        "/tmp/true-family-pass-b1a.Abcdef12/replica-2/data/mosquitto.db",
    ]) gate(!scanPathIsExpectedBinary(invalid, expectedBinaryPath), "binary_scan_branch_adversarial_self_test");
    const replicaRoot = "/tmp/true-family-pass-b1a.Abcdef12/replica-1";
    gate(pathsOverlap(replicaRoot, `${replicaRoot}/credentials`) && pathsOverlap(`${replicaRoot}/generated/frontend.json`, `${replicaRoot}/generated`) && !pathsOverlap(`${replicaRoot}/logs`, `${replicaRoot}/credentials`) && !pathsOverlap(`${replicaRoot}/data`, `${replicaRoot}/observer-after-output`), "scan_root_containment_self_test");
    gate(cleanupPathAllowed("/tmp/true-family-pass-b1a.Abcdef12", "/tmp", {isDirectory: true, isSymbolicLink: false, ownerMatches: true}), "cleanup_self_test");
    for (const invalid of ["/", "/tmp", "/tmp/other.Abcdef12", "/tmp/true-family-pass-b1a.bad/slash", "/other/true-family-pass-b1a.Abcdef12"]) gate(!cleanupPathAllowed(invalid, "/tmp", {isDirectory: true, isSymbolicLink: false, ownerMatches: true}), "cleanup_adversarial_self_test");
    gate(!cleanupPathAllowed("/tmp/true-family-pass-b1a.Abcdef12", "/tmp", {isDirectory: true, isSymbolicLink: true, ownerMatches: true}), "cleanup_symlink_self_test");

    const launcher = normalizedLauncherDigest(fs.readFileSync(paths.launcher));
    gate(launcher.literal === launcher.digest && launcher.digest === manifest.bindings.launcher_normalized_sha256, "launcher_self_test");
    for (const value of [0, 127, 128, 16_383, 16_384, 268_435_455]) {
        const encoded = value < 128 ? Buffer.from([value]) : (() => {
            const bytes = [];
            let remaining = value;
            do {
                let byte = remaining % 128;
                remaining = Math.floor(remaining / 128);
                if (remaining > 0) byte |= 0x80;
                bytes.push(byte);
            } while (remaining > 0);
            return Buffer.from(bytes);
        })();
        gate(decodeVarInt(encoded).value === value, "mqtt_varint_self_test");
    }
    for (const malformed of [Buffer.from([0x80]), Buffer.from([0x80, 0]), Buffer.from([0xff, 0xff, 0xff, 0xff, 0])]) {
        let rejected = false;
        try { decodeVarInt(malformed); } catch { rejected = true; }
        gate(rejected, "mqtt_varint_adversarial_self_test");
    }
    const stream = new MqttFrameStream();
    gate(stream.push(Buffer.from([0xc0])).length === 0 && stream.push(Buffer.from([0])).length === 1, "gateway_stream_self_test");
    gate(gatewayPolicyDigest(manifest) === manifest.gateway.policy_sha256 && compositePolicyDigest(manifest) === manifest.composite_policy.effective_sha256, "gateway_digest_self_test");
    for (const depth of [0, 8, 32, 100]) {
        const prefix = depth === 0 ? "" : `${Array.from({length: depth}, () => "a").join("/")}/`;
        gate(!gatewayAllowsPublish(manifest, "z2m", {topic: `${manifest.scope.base_topic}/${prefix}bridge/request/action`, qos: 1, retain: false}), "gateway_containment_self_test");
    }
    gate(gatewayAllowsPublish(manifest, "orchestrator", {topic: manifest.topics.arm_request, qos: 1, retain: false}), "gateway_publish_self_test");
    gate(!gatewayAllowsPublish(manifest, "orchestrator", {topic: manifest.topics.arm_request, qos: 0, retain: false}), "gateway_qos_self_test");
    gate(!gatewayAllowsPublish(manifest, "orchestrator", {topic: manifest.topics.arm_request, qos: 1, retain: true}), "gateway_retain_self_test");
    for (const qos of [0, 1, 2]) {
        for (const retain of [false, true]) gate(gatewayAllowsPublish(manifest, "z2m", {topic: "outside/root", qos, retain}), "gateway_z2m_envelope_self_test");
    }
    gate(topicContractValid(`${manifest.scope.base_topic}/a//b`) && !topicContractValid(`/${manifest.scope.base_topic}`) && !topicContractValid(`${manifest.scope.base_topic}/`), "gateway_topic_self_test");
    gate(gatewayAllowsSubscribe(manifest, "z2m", `${manifest.scope.base_topic}/#`) && gatewayAllowsSubscribe(manifest, "z2m", `${manifest.scope.base_topic}/a//b`), "gateway_subscribe_self_test");
    gate(!gatewayAllowsSubscribe(manifest, "z2m", `${manifest.scope.base_topic}/+`) && !gatewayAllowsSubscribe(manifest, "collector", manifest.topics.source), "gateway_subscribe_self_test");
    gate(gatewayAllowsSubscribe(manifest, "z2m", "outside/root") && !gatewayAllowsSubscribe(manifest, "z2m", "$share/group/outside/root"), "gateway_subscribe_self_test");
    gate(gatewayBackendDisconnectFatal({state: "active", clientClosing: false, brokerClosing: false, clientDestroyed: false}) && !gatewayBackendDisconnectFatal({state: "closing", clientClosing: true, brokerClosing: false, clientDestroyed: false}), "gateway_disconnect_self_test");

    const expected = expectedReadbackFromManifest(manifest);
    gate(expectedReadbackDigest(manifest) === manifest.policy.expected_readback_sha256 && same(validateReadback(expected, expected), normalizeReadback(expected)), "readback_self_test");
    const imageFixture = (kind) => {
        const expectedImage = manifest.images[kind];
        return [{
            Id: kind === "mosquitto" ? expectedImage.oci_config_digest : `sha256:${"a".repeat(64)}`,
            Os: "linux",
            Architecture: "amd64",
            RepoDigests: [expectedImage.child],
            Config: {Env: expectedImage.expected_env, Labels: expectedImage.expected_labels, Entrypoint: expectedImage.expected_entrypoint, Cmd: expectedImage.expected_command},
        }];
    };
    validateImageInspect(imageFixture("node"), "node", manifest);
    validateImageInspect(imageFixture("mosquitto"), "mosquitto", manifest);
    for (const mutate of [(value) => { value[0].Architecture = "arm64"; }, (value) => { value[0].Config.Env.push("EXTRA=true"); }, (value) => { value[0].Config.Labels = {unexpected: "true"}; }]) {
        const fixture = structuredClone(imageFixture("mosquitto"));
        mutate(fixture);
        let rejected = false;
        try { validateImageInspect(fixture, "mosquitto", manifest); } catch { rejected = true; }
        gate(rejected, "image_adversarial_self_test");
    }
    const credential = (principal, marker) => ({username: manifest.principals[principal].username, client_id: manifest.principals[principal].client_id, password: marker.repeat(43)});
    const adminCredential = {schema: manifest.credentials.admin_schema, principal: credential("admin", "A")};
    const frontendCredential = {schema: manifest.credentials.frontend_schema, principals: {z2m: credential("z2m", "B"), orchestrator: credential("orchestrator", "C"), collector: credential("collector", "D"), other: credential("other", "E")}, wrong_password: "F".repeat(43)};
    const observerCredential = {schema: manifest.credentials.observer_schema, principal: credential("observer", "G")};
    validateAdminCredential(adminCredential, manifest);
    validateFrontendCredential(frontendCredential, manifest);
    validateObserverCredential(observerCredential, manifest);
    validateCredentialUniqueness([adminCredential, frontendCredential, observerCredential]);
    const mutations = [
        (value) => { value.gateway.generation = 2; },
        (value) => { value.composite_policy.preflight_acl_digest = "0".repeat(64); },
        (value) => { value.preflight_acl.schema = "true-family-physical-probe-acl-plan-v1"; },
        (value) => { value.preflight_acl.effective_policy.topic_contract.shared_subscriptions = true; },
        (value) => { value.topic_oracle.schema = "true-family-pass-b1a-topic-oracle-v0"; },
        (value) => { value.policy.roles.find((role) => role.rolename === value.principals.z2m.role).acls.push({acltype: "publishClientSend", topic: `${value.scope.base_topic}/bridge/request/#`, allow: false, priority: 1000}); },
        (value) => { value.matrix.publish = value.matrix.publish.filter((item) => item.topic_fixture !== "bridge_request_depth_100"); },
        (value) => { value.matrix.subscribe.find((item) => item.principal === "z2m" && item.filter === `${value.scope.base_topic}/#`).allowed = false; },
        (value) => { value.broker.config_lines.push("port 1883"); value.broker.config_sha256 = sha256Bytes(Buffer.from(`${value.broker.config_lines.join("\n")}\n`, "utf8")); },
    ];
    for (const mutate of mutations) {
        const clone = structuredClone(manifest);
        mutate(clone);
        let rejected = false;
        try { validateManifest(clone); } catch { rejected = true; }
        gate(rejected, "manifest_adversarial_self_test");
    }

    const networkFixture = (plane) => {
        const names = plane === "backend" ? ["broker", "gateway"] : ["gateway"];
        const containers = Object.fromEntries(names.map((name, index) => [String(index + 1).padStart(64, "a"), {
            Name: `tf-pass-b1a-${"a".repeat(12)}-1-${name}`,
            IPv4Address: `172.20.0.${index + 2}/16`,
            IPv6Address: "",
        }]));
        return [{
            Id: "c".repeat(64), Created: "2026-01-01T00:00:00.000000000Z", Name: `tf-pass-b1a-${"a".repeat(16)}-1-${plane}`,
            Driver: "bridge", Scope: "local", Internal: true, Attachable: false, Ingress: false, ConfigOnly: false,
            Labels: {[manifest.cleanup.label]: "a".repeat(32), [`${manifest.cleanup.label}-replica`]: "1", [`${manifest.cleanup.label}-plane`]: plane}, Containers: containers,
        }];
    };
    validateNetworkInspect(networkFixture("backend"), manifest, "backend");
    validateNetworkInspect(networkFixture("frontend"), manifest, "frontend");
    for (const mutate of [(value) => { value[0].Internal = false; }, (value) => { value[0].Labels.extra = "bad"; }, (value) => { delete value[0].Containers[Object.keys(value[0].Containers)[0]]; }, (value) => { Object.values(value[0].Containers)[0].Aliases = []; }]) {
        const fixture = networkFixture("frontend");
        mutate(fixture);
        let rejected = false;
        try { validateNetworkInspect(fixture, manifest, "frontend"); } catch { rejected = true; }
        gate(rejected, "network_adversarial_self_test");
    }
    const containerNetworkFixture = {NetworkSettings: {Networks: {backend: {Aliases: ["container-id", "broker"]}, frontend: {Aliases: ["container-id", "gateway"]}}}};
    gate(containerNetworkAliasesInclude(containerNetworkFixture, "backend", "broker") && containerNetworkAliasesInclude(containerNetworkFixture, "frontend", "gateway"), "container_alias_self_test");
    gate(!containerNetworkAliasesInclude(containerNetworkFixture, "backend", "gateway"), "container_alias_self_test");
    gate(setupUsesNetworkNone({NetworkSettings: {Networks: {none: {Aliases: null}}}}), "setup_network_none_self_test");
    gate(!setupUsesNetworkNone({NetworkSettings: {Networks: {}}}), "setup_network_none_self_test");

    const sourceText = fs.readFileSync(paths.artifact, "utf8");
    const secret = "A".repeat(43);
    sanitizedText('{"safe":true}', sourceText, [secret]);
    for (const unsafe of [sourceText, manifest.source_privacy.source_canary, secret]) {
        let rejected = false;
        try { sanitizedText(unsafe, sourceText, [secret]); } catch { rejected = true; }
        gate(rejected, "redaction_self_test");
    }
    sanitizedBytes(Buffer.from([0xff, 0xfe, 0x00, 0x80]), sourceText, [secret]);
    for (const unsafe of [sourceText, manifest.source_privacy.source_canary, secret]) {
        let rejected = false;
        try { sanitizedBytes(Buffer.from(unsafe, "utf8"), sourceText, [secret]); } catch { rejected = true; }
        gate(rejected, "binary_redaction_self_test");
    }
    const baseFixture = {schema: BASE_SCHEMA, result: "pass", pass: "B1A", classification: CLASSIFICATION, authoritative: false, pass_b1_complete: false, authorization: false, loose_spare_used: false, trust_boundary: manifest.trust_boundary, git: {}, workflow: {}, images: {}, bindings: {}, replica: {schema: REPLICA_SCHEMA, result: "pass"}, replicas: {fresh_full_replicas: 2, normalized_byte_identical: true}, claim_limits: CLAIM_LIMITS, cleanup_pending: true};
    const finalized = JSON.parse(finalizeCleanup(`${canonical(baseFixture)}\n`, manifest));
    const observedDigest = finalized.evidence_digest;
    delete finalized.evidence_digest;
    gate(finalized.schema === FINAL_SCHEMA && finalized.cleanup?.pass_emitted_after_cleanup === true && observedDigest === sha256Bytes(Buffer.from(canonical(finalized), "utf8")), "finalize_self_test");

    staticSourceChecks(paths, manifest);
    const shell = spawnSync(paths.launcher, ["--shell-self-check"], {encoding: "utf8", env: {PATH: process.env.PATH ?? "/usr/bin:/bin"}, timeout: 5_000});
    gate(shell.status === 0 && shell.stderr === "" && shell.stdout === '{"result":"pass","schema":"true-family-pass-b1a-shell-self-check-v1"}\n', "shell_self_check");
    const startupFailure = spawnSync(paths.launcher, ["--invalid-mode"], {encoding: "utf8", env: {PATH: process.env.PATH ?? "/usr/bin:/bin"}, timeout: 5_000});
    gate(startupFailure.status === 1 && startupFailure.stderr === "" && startupFailure.stdout === launcherFailureRecord("startup"), "launcher_failure_startup_self_test");
}

function pathsFromArguments(args) {
    gate(args.length === 14, "self_check_arguments");
    const [manifest, launcher, runtime, verifier, workflow, artifact, preflight, fixture, preflightTest, b0Launcher, b0Workflow, b0Manifest, b0Runtime, b0Verifier] = args;
    return {manifest, launcher, runtime, verifier, workflow, artifact, preflight, fixture, preflightTest, b0Launcher, b0Workflow, b0Manifest, b0Runtime, b0Verifier};
}

function failureToken() {
    return `${canonical({schema: FAILURE_SCHEMA, result: "fail", failure_code: "verification_failed"})}\n`;
}

async function main() {
    const [mode, ...args] = process.argv.slice(2);
    if (mode === "--self-check") {
        const paths = pathsFromArguments(args);
        const manifest = validateStaticBindings(paths);
        selfTests(paths, manifest);
        return `${canonical({
            schema: "true-family-pass-b1a-self-check-v1",
            result: "pass",
            launcher_normalized_sha256: manifest.bindings.launcher_normalized_sha256,
            runtime_harness_sha256: manifest.bindings.runtime_harness_sha256,
            verifier_sha256: manifest.bindings.verifier_sha256,
            workflow_sha256: manifest.bindings.workflow_sha256,
        })}\n`;
    }
    if (mode === "--write-broker-config") {
        gate(args.length === 2, "write_config_arguments");
        const manifest = validateManifest(readJson(args[0], "manifest_json"));
        writeExclusive(args[1], brokerConfigBytes(manifest));
        return `${canonical({schema: "true-family-pass-b1a-write-config-v1", result: "pass"})}\n`;
    }
    if (mode === "--generate-admin-credentials") {
        gate(args.length === 2, "credentials_arguments");
        generateAdminCredentials(args[0], args[1]);
        return `${canonical({schema: "true-family-pass-b1a-generate-admin-credentials-v1", result: "pass"})}\n`;
    }
    if (mode === "--verify-credential-set") {
        gate(args.length === 3 || args.length === 4, "credential_set_arguments");
        verifyCredentialSet(args[0], args[1], args[2], args[3]);
        return `${canonical({schema: "true-family-pass-b1a-verify-credential-set-v1", result: "pass"})}\n`;
    }
    if (mode === "--bind-admin-clientid") {
        gate(args.length === 2, "bind_admin_arguments");
        bindAdminClientId(args[0], args[1]);
        return `${canonical({schema: "true-family-pass-b1a-bind-admin-v1", result: "pass"})}\n`;
    }
    if (mode === "--verify-bootstrap") {
        gate(args.length === 3, "bootstrap_arguments");
        verifyBootstrap(args[0], args[1], args[2]);
        return `${canonical({schema: "true-family-pass-b1a-bootstrap-v1", result: "pass"})}\n`;
    }
    if (mode === "--validate-image-inspect") {
        gate(args.length === 3, "image_arguments");
        const manifest = validateManifest(readJson(args[2], "manifest_json"));
        validateImageInspect(readPrivateJson(args[1], "image_json"), args[0], manifest);
        return `${canonical({schema: "true-family-pass-b1a-image-inspect-v1", result: "pass"})}\n`;
    }
    if (mode === "--classify-runtime-failure") {
        gate(args.length === 3, "runtime_failure_arguments");
        const manifest = validateManifest(readJson(args[2], "manifest_json"));
        return `${classifyRuntimeFailureFile(args[0], args[1], manifest)}\n`;
    }
    if (mode === "--verify-replica") {
        const replica = verifyReplica(args);
        return `${canonical(replica)}\n`;
    }
    if (mode === "--combine-replicas") {
        const base = combineReplicas(args);
        return `${canonical(base)}\n`;
    }
    if (mode === "--scan-redaction") {
        gate(args.length >= 6, "scan_arguments");
        const sourceText = fs.readFileSync(args[0], "utf8");
        const manifestPath = args[1];
        const credentialsRoot = args[2];
        const dataRoot = args[3];
        const stoppedBrokerInspect = args[4];
        const manifest = validateManifest(readJson(manifestPath, "manifest_json"));
        gate(sourceText.includes(manifest.source_privacy.source_canary), "scan_source_binding");
        const result = scanRedaction(sourceText, manifest, credentialsRoot, dataRoot, stoppedBrokerInspect, args.slice(5));
        return `${canonical({schema: "true-family-pass-b1a-redaction-scan-v1", result: "pass", ...result})}\n`;
    }
    if (mode === "--finalize-cleanup") {
        gate(args.length === 1, "finalize_arguments");
        const manifest = validateManifest(readJson(args[0], "manifest_json"));
        let input = "";
        process.stdin.setEncoding("utf8");
        for await (const chunk of process.stdin) {
            input += chunk;
            gate(Buffer.byteLength(input, "utf8") <= MAX_FINAL_BYTES, "finalize_input_size");
        }
        return finalizeCleanup(input, manifest);
    }
    throw new VerifyFailure("mode");
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
    try {
        process.stdout.write(await main());
    } catch {
        if (process.argv[2] !== "--classify-runtime-failure") process.stdout.write(failureToken());
        process.exitCode = 1;
    }
}
