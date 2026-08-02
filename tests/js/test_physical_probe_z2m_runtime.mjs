#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import {access, chmod, link, readFile, rm, symlink, unlink, writeFile} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {constants as fsConstants} from "node:fs";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";

import {normalizedLauncherDigestBytes, runtimeHashes, treeEvidence} from "/verifier/verify_physical_probe_z2m_runtime.mjs";

const CASE_SCHEMA = "true-family-pass-b0-runtime-case-v2";
const RAW_SCHEMA = "true-family-pass-b0-runtime-raw-v2";
const FAILURE_SCHEMA = "true-family-pass-b0-runtime-failure-v2";
const FAILURE_CODE_PATTERN_TEXT = "^[a-z0-9_]{1,40}$";
const FAILURE_MAX_BYTES = 256;
const STAGE_SCHEMA = "true-family-pass-b0-runtime-stage-v2";
const MANIFEST_SCHEMA = "true-family-pass-b0-manifest-v2";
const CLASSIFICATION = "ci-only-non-authoritative-reviewed-source-smoke";
const TMPFS_TMP_BYTES = 256 * 1024 * 1024;
const PNPM_FETCH_VIRTUAL_STORE_MEASURED_BYTES = 88 * 1024 * 1024;
const ARTIFACT_NAME = "true_family_brt_probe.mjs";
const ARTIFACT_CLASS = "TrueFamilyBrtProbeExtension";
const ARTIFACT_BYTES = 164_691;
const ARTIFACT_SHA256 = "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1";
const JOURNAL_NAME = "true_family_brt_probe.state.json";
const IEEE = "0xa4c1380000000001";
const FRIENDLY_NAME = "spare-brt-100";
const CASES = Object.freeze([
    "input",
    "cold",
    "prearm",
    "armed",
    "control_rename",
    "control_group",
    "collision",
    "stop_remove",
]);
const CLAIM_LIMITS = Object.freeze([
    "same_repo_reviewed_source_trusted",
    "malicious_source_resistance_not_proven",
    "independent_attestation_not_proven",
    "branch_protection_not_proven",
    "full_controller_lifecycle_not_exercised",
    "runtime_collision_enforcement_not_proven",
    "callback_registry_cleanup_not_proven",
    "broker_not_exercised",
    "broker_delivery_not_proven",
    "acl_not_proven",
    "radio_not_exercised",
    "coordinator_not_exercised",
    "physical_provenance_not_proven",
    "actual_spare_not_exercised",
    "fetch_host_allowlist_not_enforced",
    "runtime_byte_reproducibility_not_claimed",
    "syscall_tracing_not_performed",
]);
const GUARDED_SURFACES = Object.freeze([
    "node_child_process",
    "node_dgram",
    "node_http",
    "node_https",
    "node_net",
    "node_tls",
    "mqtt_connect_subscribe_unsubscribe",
    "controller_start",
    "zigbee_start",
]);
const STATIC_NOT_USED_SURFACES = Object.freeze([
    "controller_constructor",
    "controller_full_start_stop",
    "mqtt_positive_connect_path",
    "zigbee_constructor",
    "zigbee_herdsman_controller",
    "serial_open",
]);
const CONTAINMENT_ONLY_SURFACES = Object.freeze([
    "home_assistant",
    "household_mqtt",
    "coordinator",
    "serial_usb_radio",
    "docker_socket",
    "host_devices",
]);
const TRUST_BOUNDARY = Object.freeze({
    same_repo_reviewed_source: true,
    malicious_source_resistant: false,
    independently_attested: false,
    branch_protected_evidence: false,
    cryptographically_unforgeable: false,
});
const VERIFIER_FAILURE_CODES = Object.freeze([
    "arguments",
    "mode",
    "self_check_failed",
    "classifier_failed",
    "tar_failed",
    "upstream_failed",
    "install_prepare_failed",
    "closure_normalize_failed",
    "tree_evidence_failed",
    "runtime_hashes_failed",
    "stage_write_failed",
    "stage_rehash_failed",
    "image_inspect_failed",
    "run_verification_failed",
    "final_verification_failed",
    "verifier_failed",
]);
const PNPM_PHASES = Object.freeze(["fetch", "install"]);
const PNPM_NO_CODE_SUFFIXES = Object.freeze([
    "diagnostic_empty",
    "diagnostic_oversize",
    "diagnostic_non_ndjson",
    "diagnostic_no_code",
]);
const PNPM_FIXED_FAILURE_SUFFIXES = Object.freeze(["multiple_codes", ...PNPM_NO_CODE_SUFFIXES]);
const PNPM_FIXED_STAGE_FAILURE_CODES = Object.freeze(PNPM_PHASES.flatMap((phase) => (
    PNPM_FIXED_FAILURE_SUFFIXES.map((suffix) => `pnpm_${phase}_${suffix}`)
)));
const STAGE_KEYS = Object.freeze([
    "schema",
    "manifest_sha256",
    "launcher_normalized_sha256",
    "harness_sha256",
    "verifier_sha256",
    "artifact_sha256",
    "pass_a_manifest_sha256",
    "preflight_fixture_sha256",
    "runtime_runner_sha256",
    "node_image_digest",
    "node_binary_sha256",
    "shared_library_set_sha256",
    "shared_library_count",
    "upstream_package_json_sha256",
    "pnpm_lock_sha256",
    "runtime_package_json_sha256",
    "package_dist_sha256",
    "closure_sha256",
    "closure_package_count",
]);

class SmokeFailure extends Error {
    constructor(code) {
        super(code);
        this.code = code;
    }
}

function gate(condition, code) {
    if (!condition) throw new SmokeFailure(code);
}

function exactKeys(value, keys, code) {
    gate(value !== null && typeof value === "object" && !Array.isArray(value), code);
    gate(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), code);
}

function canonical(value) {
    if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`;
    gate(value && typeof value === "object", "canonical_type");
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function same(left, right) {
    return canonical(left) === canonical(right);
}

function sha256Bytes(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(file) {
    return sha256Bytes(fs.readFileSync(file));
}

function emit(value) {
    process.stdout.write(`${canonical(value)}\n`);
}

function readJson(file, code = "json") {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        throw new SmokeFailure(code);
    }
}

function requiredEnv(name) {
    const value = process.env[name];
    gate(typeof value === "string" && value.length > 0, "environment");
    return value;
}

function checkMode(file, expected, code) {
    gate((fs.statSync(file).mode & 0o777) === expected, code);
}

function validateManifest(manifest) {
    gate(manifest.schema === MANIFEST_SCHEMA && manifest.manifest_version === 2 && manifest.pass === "B0", "manifest_identity");
    gate(manifest.classification === CLASSIFICATION && manifest.authoritative === false, "manifest_classification");
    gate(same(manifest.trust_boundary, TRUST_BOUNDARY), "manifest_trust_boundary");
    gate(manifest.container.image === "docker.io/library/node:20.19.2-bookworm-slim@sha256:ae5e29a169a6dbe7f45d552d73674001cc00913a0a8a5967c57a34f92e940ec8", "manifest_image");
    gate(manifest.container.platform === "linux/amd64" && manifest.container.fetch_host_allowlist_enforced === false, "manifest_container");
    gate(manifest.container.limits.nproc === 64, "manifest_nproc_limits");
    gate(manifest.container.limits.memory_bytes === 805306368 && manifest.container.limits.memory_swap_bytes === 805306368, "manifest_memory_limits");
    gate(manifest.container.limits.tmpfs_tmp_bytes === TMPFS_TMP_BYTES, "manifest_tmpfs_limits");
    gate(manifest.container.limits.pnpm_fetch_virtual_store_measured_bytes === PNPM_FETCH_VIRTUAL_STORE_MEASURED_BYTES && PNPM_FETCH_VIRTUAL_STORE_MEASURED_BYTES < TMPFS_TMP_BYTES, "manifest_tmpfs_capacity");
    gate(same(manifest.container.log_policy, {
        driver: "json-file",
        options: {"max-file": "1", "max-size": "1m"},
        attach_required: true,
        transient: true,
        stdout_stderr_privately_captured: true,
        uploaded_artifacts: false,
        containers_removed_before_pass: true,
        cleanup_verified_before_pass: true,
    }), "manifest_log_policy");
    gate(same(manifest.container.cleanup_policy, {
        root_pattern: "$RUNNER_TEMP/true-family-pass-b0.*",
        directory_prepare_command: "find -P <root> -xdev -type d -exec chmod 0700 {} +",
        files_chmodded: false,
        symlinks_followed: false,
        trap_prepare_best_effort: true,
        final_prepare_after_zero_containers_networks: true,
        immutable_until_final_validations: true,
        evidence_emitted_after_root_deletion_verified: true,
        failure_codes: ["cleanup_prepare_failed", "cleanup_remove_failed", "cleanup_root_remained"],
    }), "manifest_cleanup_policy");
    gate(same(manifest.container.package_download_policy, {
        implementation: "node:https",
        method: "GET",
        hostname: "registry.npmjs.org",
        port: 443,
        timeout_ms: 45000,
        redirects_allowed: false,
        proxy_environment_used: false,
        exclusive_output: true,
        output_mode: "0600",
        file_fsync: true,
        partial_removed_on_failure: true,
        success_schema: "true-family-pass-b0-package-download-v1",
        failure_schema: "true-family-pass-b0-package-download-failure-v1",
    }), "manifest_package_download_policy");
    gate(same(manifest.container.pnpm_diagnostic_policy, {
        schema: "true-family-pass-b0-pnpm-failure-v1",
        phases: PNPM_PHASES,
        reporter: "ndjson",
        max_file_bytes: 1048576,
        max_line_bytes: 65536,
        regular_files_only: true,
        noninteractive_ci: true,
        original_exit_status_preserved: true,
        raw_output_emitted: false,
        canonical_code_fields: ["code", "err.code"],
        identifier_pattern: "^ERR_PNPM_[A-Z0-9_]{1,40}$",
        failure_code_pattern: "^pnpm_(fetch|install)_[a-z0-9_]{1,40}$",
        raw_scan_on_structural_failure: true,
        raw_scan_ascii_boundaries: true,
        fixed_no_code_suffixes: PNPM_NO_CODE_SUFFIXES,
        multiple_code_suffix: "multiple_codes",
        failure_code_max_bytes: 64,
    }), "manifest_pnpm_diagnostic_policy");
    gate(same(manifest.container.start_diagnostics, {
        stages: ["package_fetch", "fetch", "install", "runtime", "verifier"],
        state_inspected_before_removal: true,
        state_inspect_seconds: 10,
        classifier_seconds: 5,
        state_error_categories: ["rlimit", "mount", "permission", "invalid_argument", "exec", "no_such_file", "not_directory", "readonly", "cgroup", "security", "unknown"],
        runtime_failure_policy: {
            schema: FAILURE_SCHEMA,
            exact_keys: ["failure_code", "result", "schema"],
            failure_code_pattern: FAILURE_CODE_PATTERN_TEXT,
            max_bytes: FAILURE_MAX_BYTES,
            byte_exact_canonical_token: true,
            trailing_newline_required: true,
            classification_prefix: "runtime_",
            classification_max_bytes: 64,
            internal_failure_code: "internal_failure",
            synthetic_failure_code: "case_failed",
            source_smoke_failure_codes_verified: true,
        },
        known_process_failure_codes: [
            "package_fetch_download_arguments",
            "package_fetch_download_kind",
            "package_fetch_download_contract",
            "package_fetch_download_url",
            "package_fetch_download_destination",
            "package_fetch_download_destination_exists",
            "package_fetch_download_request",
            "package_fetch_download_timeout",
            "package_fetch_download_redirect",
            "package_fetch_download_status",
            "package_fetch_download_length",
            "package_fetch_download_overrun",
            "package_fetch_download_truncated",
            "package_fetch_download_integrity",
            "package_fetch_download_response",
            "package_fetch_download_write",
            "package_fetch_download_sync",
            "package_fetch_download_cleanup",
            "package_fetch_download_failed",
            ...VERIFIER_FAILURE_CODES.map((code) => `verifier_${code}`),
            ...PNPM_FIXED_STAGE_FAILURE_CODES,
            "runtime_case_failed",
        ],
        unknown_process_output_code: "<stage>_process_exit",
        raw_output_emitted: false,
    }), "manifest_start_diagnostics");
    gate(manifest.verifier.failure_schema === "true-family-pass-b0-verifier-failure-v1", "manifest_verifier_failure");
    gate(manifest.verifier.failure_max_bytes === 256 && same(manifest.verifier.failure_codes, VERIFIER_FAILURE_CODES), "manifest_verifier_failure");
    gate(manifest.runtime.node.version === "20.19.2", "manifest_runtime");
    gate(same(manifest.runtime.zigbee2mqtt, {
        version: "2.12.1",
        tarball_url: "https://registry.npmjs.org/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz",
        filename: "zigbee2mqtt-2.12.1.tgz",
        sha512_sri: "sha512-OucrVP2raFmMEKK+4r7qHOSamAmaM4WI0WYLbLRhZ1s73frVDcppzD/6BHGPWFIalJrxGrdKHYSbRmpQqLUt5w==",
        compressed_size: 349915,
        max_bytes: 524288,
    }), "manifest_runtime");
    gate(same(manifest.runtime.zigbee_herdsman, {
        version: "10.6.1",
        tarball_url: "https://registry.npmjs.org/zigbee-herdsman/-/zigbee-herdsman-10.6.1.tgz",
        filename: "zigbee-herdsman-10.6.1.tgz",
        sha512_sri: "sha512-BXy2jai1R6OkJ7gWFwS8J6vKJ7Mm+vfReDcuN+IPCmHdT65oiaZ6oZDY/thjG7ePMHD2m0YD8AZvi7o5LBNPpQ==",
        compressed_size: 1193873,
        max_bytes: 2097152,
    }), "manifest_runtime");
    gate(same(manifest.runtime.zigbee_herdsman_converters, {
        version: "26.76.0",
        tarball_url: "https://registry.npmjs.org/zigbee-herdsman-converters/-/zigbee-herdsman-converters-26.76.0.tgz",
        filename: "zigbee-herdsman-converters-26.76.0.tgz",
        sha512_sri: "sha512-JSgW/9Yn5xdfUHvyXunKSqoPk7w6wY+0OEzOiqBs/hr67o9YSXKc4joUr/dbRMXJcv7fNlDNDRvIDS41b2758Q==",
        compressed_size: 2752484,
        max_bytes: 4194304,
    }), "manifest_runtime");
    gate(same(manifest.runtime.pnpm, {
        version: "10.18.3",
        tarball_url: "https://registry.npmjs.org/pnpm/-/pnpm-10.18.3.tgz",
        filename: "pnpm-10.18.3.tgz",
        sha512_sri: "sha512-u9FubXKG/X4B9rPAs8kyzaKWXAapCDKPdGY/EKmupR8RKe6mFRNL+ZKDGwCeq+Fn7LcAi1l/QP+bx1lGqt+wjQ==",
        compressed_size: 4155290,
        max_bytes: 5242880,
    }), "manifest_runtime");
    gate(manifest.expected.closure_package_count === 148, "manifest_closure");
    gate(manifest.expected.closure_sha256 === "de77c8dea2c3a531c3af9331147426d708ad83435072aa4aec228cdcf10c9e52", "manifest_closure");
    gate(manifest.expected.dist_sha256 === "b69100d9ec7992eb47ee756d4cbaf540996e30e12b24b8dbb348c05356c72ff2", "manifest_dist");
    gate(manifest.artifact.filename === ARTIFACT_NAME && manifest.artifact.class_name === ARTIFACT_CLASS, "manifest_artifact");
    gate(manifest.artifact.byte_length === ARTIFACT_BYTES && manifest.artifact.sha256 === ARTIFACT_SHA256, "manifest_artifact");
    gate(same(manifest.test_scope.cases, CASES) && manifest.test_scope.malicious_source_resistant === false, "manifest_scope");
    gate(same(manifest.evidence.claim_limits, CLAIM_LIMITS), "manifest_claims");
    gate(manifest.evidence.raw_source_seen_in_process_retained_inventory === true, "manifest_claims");
    gate(manifest.evidence.raw_source_emitted_to_ci_evidence === false && manifest.evidence.broker_delivery_exercised === false, "manifest_claims");
    const externalJsPolicy = manifest.evidence.external_js_node_modules_policy;
    gate(manifest.evidence.comparison_scope === "normalized-verifier-output-only" && manifest.evidence.raw_runtime_bytes_reproducible === false
        && manifest.evidence.immutable_trees_unsealed_only_for_deletion === true
        && manifest.evidence.cleanup_unseal_after_final_validations_and_zero_resources === true
        && manifest.evidence.pass_evidence_emitted_after_root_deletion_verified === true
        && same(externalJsPolicy, {
        pinned_dist_sha256: "b69100d9ec7992eb47ee756d4cbaf540996e30e12b24b8dbb348c05356c72ff2",
        creation: "lazy-inside-loadFiles-loop",
        positive_source_target: "/z2m/node_modules",
        source_free_restart_entries: 0,
        source_free_restart_node_modules_alias: false,
    }), "manifest_claims");
    gate(same(manifest.prohibited.guarded_surfaces, GUARDED_SURFACES), "manifest_prohibited");
    gate(same(manifest.prohibited.static_not_used_surfaces, STATIC_NOT_USED_SURFACES), "manifest_prohibited");
    gate(same(manifest.prohibited.containment_only_surfaces, CONTAINMENT_ONLY_SURFACES), "manifest_prohibited");
}

function validateStage(stage, manifest) {
    exactKeys(stage, STAGE_KEYS, "stage_shape");
    gate(stage.schema === STAGE_SCHEMA, "stage_schema");
    for (const key of STAGE_KEYS.filter((key) => key.endsWith("sha256"))) gate(/^[0-9a-f]{64}$/u.test(stage[key]), "stage_digest");
    gate(stage.manifest_sha256 === sha256File("/input/physical_probe_pass_b_manifest.json"), "stage_manifest");
    gate(stage.launcher_normalized_sha256 === normalizedLauncherDigestBytes(fs.readFileSync("/launcher/pass-b-z2m-runtime")).digest, "stage_launcher");
    gate(stage.launcher_normalized_sha256 === manifest.verifier.launcher_normalized_sha256, "stage_launcher");
    gate(stage.harness_sha256 === sha256File("/harness/test_physical_probe_z2m_runtime.mjs"), "stage_harness");
    gate(stage.verifier_sha256 === sha256File("/verifier/verify_physical_probe_z2m_runtime.mjs"), "stage_verifier");
    gate(stage.artifact_sha256 === sha256File(`/input/${ARTIFACT_NAME}`), "stage_artifact");
    gate(stage.pass_a_manifest_sha256 === sha256File("/input/true_family_brt_probe.manifest.json"), "stage_pass_a");
    gate(stage.preflight_fixture_sha256 === sha256File("/input/physical_probe_preflight_vectors.json"), "stage_fixture");
    gate(stage.runtime_runner_sha256 === sha256File("/runtime/run.sh"), "stage_runner");
    gate(stage.upstream_package_json_sha256 === sha256File("/upstream/package.json"), "stage_upstream");
    gate(stage.pnpm_lock_sha256 === sha256File("/upstream/pnpm-lock.yaml"), "stage_upstream");
    gate(stage.runtime_package_json_sha256 === sha256File("/z2m/package.json"), "stage_runtime_package");
    const dist = treeEvidence("/z2m/dist", false);
    const closure = treeEvidence("/z2m/node_modules", true);
    gate(stage.package_dist_sha256 === dist.digest && stage.package_dist_sha256 === manifest.expected.dist_sha256, "stage_dist");
    gate(stage.closure_sha256 === closure.digest && stage.closure_sha256 === manifest.expected.closure_sha256, "stage_closure");
    gate(stage.closure_package_count === closure.count && stage.closure_package_count === 148, "stage_closure");
    gate(stage.node_image_digest === manifest.container.image.split("@")[1], "stage_image");
    const runtime = runtimeHashes();
    gate(stage.node_binary_sha256 === runtime.node_binary_sha256, "stage_node_binary");
    gate(stage.shared_library_set_sha256 === runtime.shared_library_set_sha256, "stage_libraries");
    gate(stage.shared_library_count === runtime.shared_library_count && stage.shared_library_count > 0, "stage_libraries");
}

function validateEnvironment() {
    const allowed = new Set([
        "HOME",
        "LANG",
        "LC_ALL",
        "NODE_VERSION",
        "PASS_B_BASE_TOPIC",
        "PASS_B_CASE",
        "PASS_B_CASES_ROOT",
        "PASS_B_DATA_ROOT",
        "PASS_B_INPUT_ROOT",
        "PASS_B_RESULTS_ROOT",
        "PASS_B_RUNTIME_ROOT",
        "PASS_B_Z2M_ROOT",
        "PATH",
        "TMPDIR",
        "TZ",
        "YARN_VERSION",
        "ZIGBEE2MQTT_DATA",
    ]);
    for (const name of Object.keys(process.env)) gate(allowed.has(name), "environment_allowlist");
}

function validateBaseTopic(value) {
    gate(/^tf_pass_b\/[0-9a-f]{32}$/u.test(value), "base_topic");
    gate(value !== "zigbee2mqtt" && !value.startsWith("zigbee2mqtt/"), "base_topic");
}

function procStatus() {
    const values = {};
    for (const line of fs.readFileSync("/proc/self/status", "utf8").split("\n")) {
        const index = line.indexOf(":");
        if (index > 0) values[line.slice(0, index)] = line.slice(index + 1).trim();
    }
    return values;
}

function externalRouteAbsent() {
    for (const file of ["/proc/net/route", "/proc/net/ipv6_route"]) {
        if (!fs.existsSync(file)) continue;
        const lines = fs.readFileSync(file, "utf8").trim().split("\n");
        for (const line of lines) {
            if (!line || line.startsWith("Iface")) continue;
            const fields = line.trim().split(/\s+/u);
            const iface = file.endsWith("ipv6_route") ? fields.at(-1) : fields[0];
            if (iface && iface !== "lo") return false;
        }
    }
    return true;
}

function mountReadOnly(mountPoint) {
    for (const line of fs.readFileSync("/proc/self/mountinfo", "utf8").split("\n")) {
        if (!line) continue;
        const fields = line.split(" ");
        if (fields[4] === mountPoint) return fields[5].split(",").includes("ro");
    }
    return false;
}

async function writeBlocked(root) {
    const candidate = path.join(root, ".pass-b0-write-test");
    let blocked = false;
    try {
        await writeFile(candidate, "blocked", {flag: "wx"});
    } catch (error) {
        blocked = ["EACCES", "EPERM", "EROFS"].includes(error?.code);
    }
    await unlink(candidate).catch(() => undefined);
    return blocked;
}

async function securityChecks() {
    const status = procStatus();
    const uid = Number.parseInt(status.Uid.split(/\s+/u)[0], 10);
    const capabilitySetsZero = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"].every((key) => /^0+$/u.test(status[key]));
    const interfaces = os.networkInterfaces();
    const loopbackOnly = Object.entries(interfaces).every(([name, entries]) => name === "lo" && (entries ?? []).every((entry) => entry.internal));
    const immutableWriteAttemptsBlocked = (await Promise.all([
        "/input",
        "/z2m",
        "/harness",
        "/verifier",
        "/launcher",
        "/upstream",
        "/runtime",
        "/",
    ].map((root) => writeBlocked(root)))).every(Boolean);
    const immutableMountsReadOnly = ["/input", "/z2m", "/harness", "/verifier", "/launcher", "/upstream", "/runtime"]
        .every((root) => mountReadOnly(root));
    const absent = [
        "/homeassistant",
        "/addons",
        "/addon_configs",
        "/github/workspace",
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/dev/ttyUSB0",
        "/dev/ttyACM0",
        "/dev/serial",
    ].every((item) => !fs.existsSync(item));
    let rootInaccessible = false;
    try {
        await access("/root", fsConstants.R_OK);
    } catch {
        rootInaccessible = true;
    }
    const result = {
        uid_nonzero: Number.isSafeInteger(uid) && uid > 0,
        no_new_privs: status.NoNewPrivs === "1",
        capability_sets_zero: capabilitySetsZero,
        seccomp_filtering: status.Seccomp === "2",
        read_only_root: mountReadOnly("/") && await writeBlocked("/"),
        immutable_write_attempts_blocked: immutableWriteAttemptsBlocked && immutableMountsReadOnly,
        loopback_only: loopbackOnly,
        external_route_absent: externalRouteAbsent(),
        forbidden_host_paths_unavailable: absent && rootInaccessible,
    };
    gate(Object.values(result).every(Boolean), "container_security");
    return result;
}

function extensionInventory(dataRoot, phase, sourceCount = 1) {
    gate(Number.isSafeInteger(sourceCount) && sourceCount >= 0, "source_count_invalid");
    const root = path.join(dataRoot, "external_extensions");
    checkMode(root, 0o700, "extension_root_mode");
    const entries = fs.readdirSync(root, {withFileTypes: true}).sort((left, right) => left.name.localeCompare(right.name));
    if (phase === "pre") {
        gate(entries.length === sourceCount, "source_inventory_pre");
        const sources = entries.filter((entry) => /\.(?:cjs|mjs|js)$/u.test(entry.name));
        gate(sources.length === sourceCount, "source_inventory_pre");
        for (const entry of sources) {
            const metadata = fs.lstatSync(path.join(root, entry.name));
            gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1, "source_inventory_pre");
        }
    } else {
        if (sourceCount === 0) {
            gate(!entries.some((entry) => entry.name === "node_modules"), "source_post_empty_symlink");
            gate(entries.length === 0, "source_post_empty_count");
            return 0;
        }
        gate(entries.length === sourceCount + 1 && entries.some((entry) => entry.name === "node_modules"), "source_post_entry_count");
        const sources = entries.filter((entry) => /\.(?:cjs|mjs|js)$/u.test(entry.name));
        gate(sources.length === sourceCount, "source_post_source_count");
        for (const entry of sources) {
            const source = fs.lstatSync(path.join(root, entry.name));
            gate(source.isFile() && !source.isSymbolicLink() && source.nlink === 1, "source_post_source_metadata");
        }
        const modulesPath = path.join(root, "node_modules");
        const modules = fs.lstatSync(modulesPath);
        gate(modules.isSymbolicLink(), "source_post_modules_symlink");
        gate(fs.realpathSync(modulesPath) === fs.realpathSync("/z2m/node_modules"), "source_post_modules_target");
    }
    return entries.length;
}

function freshInventory(dataRoot, {allowMissingSource = false} = {}) {
    checkMode(dataRoot, 0o700, "data_root_mode");
    const root = path.join(dataRoot, "external_extensions");
    const entries = fs.readdirSync(root, {withFileTypes: true});
    const sources = entries.filter((entry) => /\.(?:cjs|mjs|js)$/u.test(entry.name));
    if (allowMissingSource) gate(sources.length === 0, "fresh_source_inventory");
    else gate(sources.length === 1 && sources[0].name === ARTIFACT_NAME, "fresh_source_inventory");
    for (const entry of entries) {
        gate(!entry.isSymbolicLink(), "fresh_alias");
        gate(!entry.name.endsWith(".invalid") && !entry.name.startsWith(".tmp-"), "fresh_alias");
        if (/\.(?:cjs|mjs|js)$/u.test(entry.name)) gate(entry.name === ARTIFACT_NAME, "fresh_collision");
    }
    const dataEntries = fs.readdirSync(dataRoot);
    gate(!dataEntries.includes(JOURNAL_NAME), "fresh_journal");
    gate(!dataEntries.some((name) => name.startsWith(".true_family_brt_probe.") || name.endsWith(".tmp")), "fresh_temp");
}

function noJournal(dataRoot) {
    gate(!fs.existsSync(path.join(dataRoot, JOURNAL_NAME)), "unexpected_journal");
    gate(!fs.readdirSync(dataRoot).some((name) => name.startsWith(".true_family_brt_probe.") || name.endsWith(".tmp")), "unexpected_journal_temp");
}

function installGuards(require) {
    let calls = 0;
    const forbidden = () => {
        calls += 1;
        throw new SmokeFailure("prohibited_api");
    };
    for (const [module, methods] of [
        [require("node:net"), ["connect", "createConnection"]],
        [require("node:tls"), ["connect"]],
        [require("node:http"), ["request", "get"]],
        [require("node:https"), ["request", "get"]],
        [require("node:dgram"), ["createSocket"]],
        [require("node:child_process"), ["exec", "execFile", "execFileSync", "execSync", "fork", "spawn", "spawnSync"]],
    ]) {
        for (const method of methods) module[method] = forbidden;
    }
    return {forbidden, count: () => calls};
}

function staticChecks() {
    const harness = fs.readFileSync("/harness/test_physical_probe_z2m_runtime.mjs", "utf8");
    const source = fs.readFileSync(`/input/${ARTIFACT_NAME}`, "utf8");
    for (const pattern of [
        /new\s+(?:runtime\.)?Controller\s*\(/u,
        /new\s+(?:runtime\.)?Zigbee\s*\(/u,
        /controller\.start\s*\(/u,
        /controller\.stop\s*\(/u,
        /mqtt\.connect\s*\(/u,
        /zigbee\.start\s*\(/u,
    ]) gate(!pattern.test(harness), "static_positive_path");
    for (const pattern of [/new\s+Controller\s*\(/u, /new\s+Zigbee\s*\(/u, /mqtt\.connect\s*\(/u]) {
        gate(!pattern.test(source), "static_probe_positive_path");
    }
}

function loadPublishedRuntime() {
    const require = createRequire(import.meta.url);
    const guards = installGuards(require);
    const logger = require("/z2m/dist/util/logger.js").default;
    const errors = [];
    logger.debug = () => undefined;
    logger.info = () => undefined;
    logger.warning = () => undefined;
    logger.error = () => errors.push("error");
    const EventBus = require("/z2m/dist/eventBus.js").default;
    const Mqtt = require("/z2m/dist/mqtt.js").default;
    const ExternalJS = require("/z2m/dist/extension/externalJS.js").default;
    const ExternalExtensions = require("/z2m/dist/extension/externalExtensions.js").default;
    const {Controller} = require("/z2m/dist/controller.js");
    const Zigbee = require("/z2m/dist/zigbee.js").default;
    Mqtt.prototype.connect = guards.forbidden;
    Mqtt.prototype.subscribe = guards.forbidden;
    Mqtt.prototype.unsubscribe = guards.forbidden;
    Controller.prototype.start = guards.forbidden;
    Zigbee.prototype.start = guards.forbidden;
    gate(EventBus.name === "EventBus" && Mqtt.name === "Mqtt" && ExternalJS.name === "ExternalJSExtension", "published_runtime");
    gate(ExternalExtensions.name === "ExternalExtensions" && Controller.name === "Controller", "published_runtime");
    return {Controller, EventBus, ExternalExtensions, ExternalJS, Mqtt, guards, errors};
}

function strictProxy(target, allowed, code) {
    return new Proxy(target, {
        get(object, property, receiver) {
            if (typeof property === "symbol" || allowed.has(property)) return Reflect.get(object, property, receiver);
            throw new SmokeFailure(code);
        },
        set() {
            throw new SmokeFailure(code);
        },
    });
}

function createZigbeeDouble(commands) {
    const endpointTarget = {
        ID: 1,
        deviceIeeeAddress: IEEE,
        hasPendingRequests: () => false,
        supportsInputCluster: (cluster) => cluster === "manuSpecificTuya" || cluster === 0xef00,
        command: async (...args) => commands.push(args),
    };
    const endpoint = strictProxy(endpointTarget, new Set(Object.keys(endpointTarget)), "endpoint_api");
    const zh = {
        ieeeAddr: IEEE,
        modelID: "TS0601",
        manufacturerName: "_TZE200_b6wax7g0",
        endpoints: [endpoint],
        getEndpoint: (id) => id === 1 ? endpoint : undefined,
    };
    const deviceTarget = {
        ieeeAddr: IEEE,
        ID: IEEE,
        name: FRIENDLY_NAME,
        isDevice: () => true,
        definition: {model: "BRT-100-TRV", vendor: "Moes"},
        zh,
        endpoint: (id) => id === 1 ? endpoint : undefined,
    };
    const device = strictProxy(deviceTarget, new Set(Object.keys(deviceTarget)), "device_api");
    const zigbee = strictProxy({resolveEntity: (identity) => identity === IEEE ? device : undefined}, new Set(["resolveEntity"]), "zigbee_api");
    return {device, endpoint, zigbee};
}

async function settle() {
    await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
    await Promise.resolve();
}

async function bounded(promise, code, milliseconds = 12_000) {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new SmokeFailure(code)), milliseconds);
    });
    try {
        return await Promise.race([promise, timeout]);
    } finally {
        clearTimeout(timer);
    }
}

const RELEVANT_EVENTS = Object.freeze(["deviceMessage", "entityRenamed", "groupMembersChanged", "mqttMessage", "mqttMessagePublished"]);

function eventFunctionCounts(eventBus) {
    return Object.fromEntries(RELEVANT_EVENTS.map((event) => [event, eventBus.emitter.listeners(event).length]));
}

function relevantListenerCount(eventBus) {
    return Object.values(eventFunctionCounts(eventBus)).reduce((count, value) => count + value, 0);
}

function capturedProbeFunctions(eventBus) {
    const entries = eventBus.callbacksByExtension.get(ARTIFACT_CLASS) ?? [];
    return entries.map((item) => ({event: item.event, callback: item.callback}));
}

function capturedFunctionsRemoved(eventBus, captured) {
    return captured.every((item) => !eventBus.emitter.listeners(item.event).includes(item.callback));
}

async function createRuntime(context, {expectProbe = true, validateFresh = true, sourceCount = expectProbe ? 1 : 0} = {}) {
    if (validateFresh) freshInventory(context.dataRoot, {allowMissingSource: !expectProbe});
    extensionInventory(context.dataRoot, "pre", sourceCount);
    const runtime = loadPublishedRuntime();
    const commands = [];
    const {device, endpoint, zigbee} = createZigbeeDouble(commands);
    const eventBus = new runtime.EventBus();
    const mqtt = new runtime.Mqtt(eventBus);
    mqtt.connect = runtime.guards.forbidden;
    mqtt.subscribe = runtime.guards.forbidden;
    mqtt.unsubscribe = runtime.guards.forbidden;
    const published = [];
    class PassBPublishedAudit {}
    const audit = new PassBPublishedAudit();
    eventBus.onMQTTMessagePublished(audit, (data) => published.push(data));
    const controller = Object.create(runtime.Controller.prototype);
    controller.extensions = new Set();
    controller.eventBus = eventBus;
    controller.zigbee = zigbee;
    controller.mqtt = mqtt;
    controller.state = strictProxy({}, new Set(), "state_api");
    const publishEntityState = () => runtime.guards.forbidden();
    const restartCallback = () => runtime.guards.forbidden();
    const loader = new runtime.ExternalExtensions(
        zigbee,
        mqtt,
        controller.state,
        publishEntityState,
        eventBus,
        controller.enableDisableExtension,
        restartCallback,
        controller.addExtension,
    );
    gate(loader instanceof runtime.ExternalJS, "external_js_runtime");
    controller.extensions.add(loader);
    await bounded(loader.start(), "loader_start_timeout");
    await settle();
    const postInventoryCount = extensionInventory(context.dataRoot, "post", sourceCount);
    const probe = controller.getExtension(ARTIFACT_CLASS);
    if (expectProbe) gate(probe?.constructor.name === ARTIFACT_CLASS, "probe_loader");
    else gate(probe === undefined, "probe_loader");
    gate(runtime.errors.length === 0 && runtime.guards.count() === 0, "runtime_side_effect");
    return {...runtime, audit, commands, controller, device, endpoint, eventBus, loader, mqtt, postInventoryCount, probe, published};
}

async function removeProbe(runtime) {
    if (runtime.probe && runtime.controller.extensions.has(runtime.probe)) {
        await bounded(runtime.controller.removeExtension(runtime.probe), "probe_stop_timeout");
    }
}

async function stopRuntime(runtime) {
    await removeProbe(runtime);
    if (runtime.controller.extensions.has(runtime.loader)) await bounded(runtime.controller.removeExtension(runtime.loader), "loader_stop_timeout");
    runtime.eventBus.removeListeners(runtime.audit);
    await settle();
    gate(runtime.guards.count() === 0 && runtime.errors.length === 0, "runtime_side_effect");
}

async function drainProbe(runtime) {
    await settle();
    if (runtime.probe) await runtime.probe.core.queue.drain();
    await settle();
    if (runtime.probe) await runtime.probe.core.queue.drain();
}

function sourceInventory(runtime, context) {
    const topic = `${context.baseTopic}/bridge/extensions`;
    const retained = runtime.mqtt.retainedMessages[topic];
    gate(retained && retained.topic === "bridge/extensions", "retained_inventory");
    gate(retained.options.clientOptions.retain === true && retained.options.skipLog === true, "retained_inventory");
    const inventory = JSON.parse(retained.payload);
    gate(Array.isArray(inventory), "retained_inventory");
    return inventory;
}

async function probeApi(context) {
    return import(`${pathToFileURL(path.join(context.dataRoot, "external_extensions", ARTIFACT_NAME)).href}?pass_b=${crypto.randomBytes(8).toString("hex")}`);
}

function buildArmRequest(api, runtime, fixture) {
    const request = structuredClone(fixture.arm_request);
    const now = Date.now();
    request.boot_id = runtime.probe.core.bootId;
    request.request_id = `tfpp-req-${"2".repeat(24)}`;
    request.operation_id = `tfpp-op-${"3".repeat(24)}`;
    request.nonce = `tfpp-nonce-${"4".repeat(32)}`;
    request.request_deadline_ms = now + 6_000;
    request.operation_deadline_ms = now + 120_000;
    gate(request.action === "arm" && request.phase === "quiescent" && request.generation === 0, "arm_fixture");
    gate(request.protocol_id === api.PROTOCOL_ID && request.protocol_version === api.PROTOCOL_VERSION && request.build_id === api.BUILD_ID, "arm_fixture");
    return request;
}

function physicalFrame(api, target, sequence) {
    const command = api.buildTuyaCommand(0, target);
    return {
        type: api.FRAME_KINDS.response,
        device: {ieeeAddr: IEEE},
        endpoint: {ID: 1, deviceIeeeAddress: IEEE},
        groupID: 0,
        cluster: "manuSpecificTuya",
        data: {seq: sequence, dpValues: command.payload.dpValues},
    };
}

async function arm(runtime, context, api, fixture) {
    const request = buildArmRequest(api, runtime, fixture);
    const wire = api.canonicalJson(request);
    gate(wire === api.canonicalJson(JSON.parse(wire)), "arm_canonical");
    runtime.eventBus.emitMQTTMessage({topic: `${context.baseTopic}/${api.TOPICS.request}`, message: wire});
    await drainProbe(runtime);
    const response = runtime.published.filter((item) => item.topic === `${context.baseTopic}/${api.TOPICS.response}`).at(-1);
    gate(response && JSON.parse(response.payload).accepted === true, "arm_rejected");
    gate(runtime.probe.core.record?.phase === api.PHASES.physical1, "arm_phase");
}

function observeDurablePhaseHistory(runtime) {
    const journal = runtime.probe.core.journal;
    const originalWrite = journal.write;
    const phases = [];
    const wrappedWrite = async (...args) => {
        const committed = await Reflect.apply(originalWrite, journal, args);
        phases.push(committed.phase);
        return committed;
    };
    journal.write = wrappedWrite;
    return {
        phases,
        restore() {
            gate(journal.write === wrappedWrite, "durable_phase_observer");
            journal.write = originalWrite;
        },
    };
}

function measureJournal(context, api, record) {
    const file = path.join(context.dataRoot, JOURNAL_NAME);
    const metadata = fs.lstatSync(file);
    const text = fs.readFileSync(file, "utf8");
    const expected = api.canonicalJson(record);
    const tempCount = fs.readdirSync(context.dataRoot).filter((name) => name.startsWith(".true_family_brt_probe.") || name.endsWith(".tmp")).length;
    const matchingFiles = fs.readdirSync(context.dataRoot).filter((name) => name === JOURNAL_NAME).length;
    return {
        file_count: matchingFiles,
        regular_file: metadata.isFile() && !metadata.isSymbolicLink(),
        nlink_one: metadata.nlink === 1,
        mode_0600: (metadata.mode & 0o777) === 0o600,
        exact_data_root_location: fs.realpathSync(file) === path.join(fs.realpathSync(context.dataRoot), JOURNAL_NAME),
        namespace_uid_zero: process.getuid() === 0,
        canonical_readback_match: text === expected,
        canonical_sha256: sha256Bytes(text),
        temp_file_count: tempCount,
    };
}

function validateMeasuredJournal(value) {
    gate(value.file_count === 1 && value.regular_file && value.nlink_one && value.mode_0600, "journal_measurement");
    gate(value.exact_data_root_location && value.namespace_uid_zero === false && value.canonical_readback_match, "journal_measurement");
    gate(/^[0-9a-f]{64}$/u.test(value.canonical_sha256) && value.temp_file_count === 0, "journal_measurement");
}

async function journalDetectorSelfTests(context) {
    const root = path.join(context.dataRoot, "journal-detector-tests");
    fs.mkdirSync(root, {mode: 0o700});
    const canonicalFile = path.join(root, "canonical");
    const noncanonical = path.join(root, "noncanonical");
    const linked = path.join(root, "linked");
    const wrongMode = path.join(root, "mode");
    fs.writeFileSync(canonicalFile, '{"a":1,"b":2}', {mode: 0o600});
    fs.writeFileSync(noncanonical, '{"b":2,"a":1}', {mode: 0o600});
    await link(canonicalFile, linked);
    fs.writeFileSync(wrongMode, '{"a":1,"b":2}', {mode: 0o644});
    fs.chmodSync(wrongMode, 0o644);
    gate((fs.lstatSync(wrongMode).mode & 0o777) === 0o644, "journal_mode_fixture");
    const accepts = (file) => {
        const metadata = fs.lstatSync(file);
        const text = fs.readFileSync(file, "utf8");
        return metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1 && (metadata.mode & 0o777) === 0o600 && text === canonical(JSON.parse(text));
    };
    const result = {
        journal_noncanonical_rejected: !accepts(noncanonical),
        journal_link_rejected: !accepts(linked),
        journal_mode_rejected: !accepts(wrongMode),
    };
    await rm(root, {recursive: true, force: true});
    gate(result.journal_noncanonical_rejected, "journal_noncanonical_detector");
    gate(result.journal_link_rejected, "journal_link_detector");
    gate(result.journal_mode_rejected, "journal_mode_detector");
    return result;
}

async function expectFreshReject(context, prepare, clean) {
    await prepare();
    let rejected = false;
    try {
        freshInventory(context.dataRoot);
    } catch (error) {
        rejected = error instanceof SmokeFailure;
    }
    await clean();
    gate(rejected, "fresh_rejection");
}

async function caseInput(context) {
    validateEnvironment();
    validateBaseTopic(context.baseTopic);
    validateManifest(context.manifest);
    validateStage(context.stage, context.manifest);
    staticChecks();
    const security = await securityChecks();
    extensionInventory(context.dataRoot, "pre");
    const source = path.join(context.dataRoot, "external_extensions", ARTIFACT_NAME);
    gate(fs.statSync(source).size === ARTIFACT_BYTES && sha256File(source) === ARTIFACT_SHA256, "artifact_identity");
    const runtime = loadPublishedRuntime();
    gate(typeof runtime.Controller.prototype.addExtension === "function", "controller_api");
    gate(typeof runtime.Controller.prototype.removeExtension === "function", "controller_api");
    gate(typeof runtime.Controller.prototype.getExtension === "function", "controller_api");
    gate(typeof runtime.Controller.prototype.enableDisableExtension === "function", "controller_api");
    gate(runtime.guards.count() === 0 && runtime.errors.length === 0, "runtime_side_effect");
    const journalTests = await journalDetectorSelfTests(context);
    const listenerLeakRejected = (() => {
        const marker = () => undefined;
        const fake = {emitter: {listeners: () => [marker]}};
        return !capturedFunctionsRemoved(fake, [{event: "deviceMessage", callback: marker}]);
    })();
    gate(listenerLeakRejected, "listener_detector_self_test");
    return {security, journalTests, listenerLeakRejected, sourceInventorySha256: sha256File(source)};
}

async function caseCold(context) {
    const runtime = await createRuntime(context);
    const captured = capturedProbeFunctions(runtime.eventBus);
    gate(captured.length === 4, "probe_listener_count");
    const emitterCountsBefore = eventFunctionCounts(runtime.eventBus);
    const relevantBefore = Object.values(emitterCountsBefore).reduce((count, value) => count + value, 0);
    gate(relevantBefore === 6, "relevant_listener_count");
    gate(same(emitterCountsBefore, {deviceMessage: 1, entityRenamed: 1, groupMembersChanged: 1, mqttMessage: 2, mqttMessagePublished: 1}), "relevant_listener_count");
    const registryBefore = (runtime.eventBus.callbacksByExtension.get(ARTIFACT_CLASS) ?? []).length;
    gate(registryBefore === 4, "callback_registry_count");
    try {
        gate(same([...runtime.controller.extensions].map((item) => item.constructor.name), ["ExternalExtensions", ARTIFACT_CLASS]), "loader_count");
        const inventory = sourceInventory(runtime, context);
        gate(inventory.length === 1 && inventory[0].name === ARTIFACT_NAME, "retained_inventory");
        gate(Buffer.byteLength(inventory[0].code) === ARTIFACT_BYTES && sha256Bytes(inventory[0].code) === ARTIFACT_SHA256, "retained_inventory");
        gate(runtime.commands.length === 0, "command_before_arm");
        noJournal(context.dataRoot);
        await removeProbe(runtime);
        await settle();
        gate(capturedFunctionsRemoved(runtime.eventBus, captured), "probe_listener_leak");
        const probeAfter = captured.filter((item) => runtime.eventBus.emitter.listeners(item.event).includes(item.callback)).length;
        gate(probeAfter === 0, "probe_listener_leak");
        const emitterCountsAfterProbeStop = eventFunctionCounts(runtime.eventBus);
        gate(same(emitterCountsAfterProbeStop, {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 1, mqttMessagePublished: 1}), "relevant_listener_count");
        const registryAfter = (runtime.eventBus.callbacksByExtension.get(ARTIFACT_CLASS) ?? []).length;
        gate(registryAfter === 4, "callback_registry_count");
        await stopRuntime(runtime);
        const emitterCountsAfterFullStop = eventFunctionCounts(runtime.eventBus);
        gate(relevantListenerCount(runtime.eventBus) === 0 && Object.values(emitterCountsAfterFullStop).every((value) => value === 0), "listener_leak");
        return {
            loaderCount: 1,
            sourceInventorySha256: sha256Bytes(inventory[0].code),
            probeBefore: captured.length,
            relevantBefore,
            probeAfter,
            relevantAfterFullStop: 0,
            actualFunctionsRemoved: true,
            emitterCountsBefore,
            emitterCountsAfterProbeStop,
            emitterCountsAfterFullStop,
            registryBefore,
            registryAfter,
        };
    } finally {
        await stopRuntime(runtime);
    }
}

async function casePrearm(context) {
    const runtime = await createRuntime(context);
    const api = await probeApi(context);
    const fixture = readJson("/input/physical_probe_preflight_vectors.json", "fixture");
    try {
        const wrongBoot = buildArmRequest(api, runtime, fixture);
        wrongBoot.boot_id = `tfpp-boot-${"9".repeat(32)}`;
        const requestTopic = `${context.baseTopic}/${api.TOPICS.request}`;
        runtime.eventBus.emitMQTTMessage({topic: requestTopic, message: "{"});
        runtime.eventBus.emitMQTTMessage({topic: requestTopic, message: JSON.stringify(wrongBoot)});
        runtime.eventBus.emitMQTTMessage({topic: requestTopic, message: api.canonicalJson(wrongBoot)});
        runtime.eventBus.emitMQTTMessage({topic: requestTopic, message: "retained-invalid", retain: true});
        runtime.eventBus.emitDeviceMessage(physicalFrame(api, 18, 500));
        runtime.eventBus.emitDeviceMessage(physicalFrame(api, 21, 501));
        runtime.eventBus.emitEntityRenamed({entity: runtime.device, from: FRIENDLY_NAME, to: "synthetic-renamed"});
        runtime.eventBus.emitGroupMembersChanged({group: {}, action: "add", endpoint: runtime.endpoint});
        await drainProbe(runtime);
        gate(runtime.commands.length === 0 && runtime.probe.core.record === null, "prearm_command");
        noJournal(context.dataRoot);
        return {commandCount: 0, journalFileCount: 0};
    } finally {
        await stopRuntime(runtime);
    }
}

async function caseArmed(context) {
    const runtime = await createRuntime(context);
    const api = await probeApi(context);
    const fixture = readJson("/input/physical_probe_preflight_vectors.json", "fixture");
    const durableHistory = observeDurablePhaseHistory(runtime);
    try {
        await arm(runtime, context, api, fixture);
        gate(runtime.commands.length === 0, "arm_immediate_command");
        gate(same(durableHistory.phases, [api.PHASES.physical1]), "durable_phase_history");
        const armJournal = measureJournal(context, api, runtime.probe.core.record);
        validateMeasuredJournal(armJournal);
        gate(armJournal.canonical_readback_match && runtime.probe.core.record.phase === api.PHASES.physical1, "arm_journal");
        runtime.eventBus.emitDeviceMessage(physicalFrame(api, 18, 500));
        await drainProbe(runtime);
        gate(runtime.commands.length === 0, "early_physical_command");
        gate(runtime.probe.core.record.phase === api.PHASES.physical2, "physical_phase");
        gate(same(durableHistory.phases, [api.PHASES.physical1, api.PHASES.physical2]), "durable_phase_history");
        runtime.eventBus.emitDeviceMessage(physicalFrame(api, 21, 501));
        await drainProbe(runtime);
        gate(runtime.commands.length === 1, "physical_command_count");
        gate(runtime.commands[0].length === 4, "noop_shape");
        const [cluster, command, payload, options] = runtime.commands[0];
        gate(cluster === "manuSpecificTuya" && command === "dataRequest", "noop_shape");
        exactKeys(payload, ["seq", "dpValues"], "noop_shape");
        gate(Number.isInteger(payload.seq) && payload.seq >= 0 && payload.seq <= 65_534, "noop_shape");
        const noopRecord = runtime.probe.core.record;
        gate(noopRecord.phase === api.PHASES.noop, "challenge_boundary");
        gate(payload.seq === noopRecord.expected_proof.sequence, "noop_expected_sequence");
        gate(Array.isArray(payload.dpValues) && payload.dpValues.length === 1, "noop_shape");
        const datapoint = payload.dpValues[0];
        exactKeys(datapoint, ["dp", "datatype", "data"], "noop_shape");
        gate(datapoint.dp === 2 && datapoint.datatype === 2 && Buffer.isBuffer(datapoint.data), "noop_shape");
        gate(same([...datapoint.data], [0, 0, 0, 21]), "noop_shape");
        gate(same(options, {disableDefaultResponse: true, sendPolicy: "immediate", disableRecovery: true, timeout: 5_000}), "noop_shape");
        await drainProbe(runtime);
        gate(runtime.commands.length === 1, "physical_command_count");
        const durablePhaseHistory = [...durableHistory.phases];
        gate(same(durablePhaseHistory, [api.PHASES.physical1, api.PHASES.physical2, api.PHASES.noop]), "durable_phase_history");
        const challengePhaseAbsent = !durablePhaseHistory.includes(api.PHASES.challenge);
        gate(challengePhaseAbsent, "challenge_boundary");
        const journal = measureJournal(context, api, runtime.probe.core.record);
        validateMeasuredJournal(journal);
        return {
            armImmediate: 0,
            commandCount: 1,
            exactNoop: true,
            exactExpectedNoopSequence: true,
            completeDurablePhaseHistoryObserved: true,
            challengePhaseAbsent,
            durablePhaseHistory,
            armJournalCanonicalMatch: armJournal.canonical_readback_match,
            armJournalPhasePhysical1: durablePhaseHistory[0] === api.PHASES.physical1,
            armJournalFileCount: armJournal.file_count,
            journal,
        };
    } finally {
        durableHistory.restore();
        await stopRuntime(runtime);
    }
}

async function caseControl(context, kind) {
    const runtime = await createRuntime(context);
    const api = await probeApi(context);
    const fixture = readJson("/input/physical_probe_preflight_vectors.json", "fixture");
    try {
        await arm(runtime, context, api, fixture);
        if (kind === "rename") runtime.eventBus.emitEntityRenamed({entity: runtime.device, from: FRIENDLY_NAME, to: "synthetic-renamed"});
        else runtime.eventBus.emitGroupMembersChanged({group: {}, action: "add", endpoint: runtime.endpoint});
        await drainProbe(runtime);
        gate(runtime.commands.length === 0, "control_drift_command");
        gate(runtime.probe.core.record?.outcome === api.OUTCOMES.failedSafe && runtime.probe.core.record?.failure_code === "control_drift", "control_drift_state");
        return {kind, failedSafe: true, commandCount: 0};
    } finally {
        await stopRuntime(runtime);
    }
}

async function caseCollision(context) {
    const extensionRoot = path.join(context.dataRoot, "external_extensions");
    const source = path.join(extensionRoot, ARTIFACT_NAME);
    const journal = path.join(context.dataRoot, JOURNAL_NAME);
    const temporary = path.join(context.dataRoot, `.true_family_brt_probe.1.${"a".repeat(24)}.tmp`);
    const alias = path.join(extensionRoot, "probe-alias");
    const collision = path.join(extensionRoot, `collision_${ARTIFACT_NAME}`);
    await expectFreshReject(context, () => writeFile(journal, "blocked"), () => unlink(journal));
    await expectFreshReject(context, () => writeFile(temporary, "blocked"), () => unlink(temporary));
    await expectFreshReject(context, () => symlink(ARTIFACT_NAME, alias), () => unlink(alias));
    await expectFreshReject(context, async () => fs.copyFileSync(source, collision), () => unlink(collision));
    fs.copyFileSync(source, collision);
    let preflightRejected = false;
    try {
        freshInventory(context.dataRoot);
    } catch (error) {
        preflightRejected = error instanceof SmokeFailure;
    }
    gate(preflightRejected, "collision_preflight");
    const runtime = await createRuntime(context, {validateFresh: false, sourceCount: 2});
    try {
        const probes = [...runtime.controller.extensions].filter((item) => item.constructor.name === ARTIFACT_CLASS);
        gate(probes.length === 1 && runtime.commands.length === 0, "collision_replacement");
        const inventory = sourceInventory(runtime, context);
        gate(inventory.length === 2, "collision_inventory");
        const callbacks = runtime.eventBus.callbacksByExtension.get(ARTIFACT_CLASS);
        gate(Array.isArray(callbacks) && callbacks.length === 8, "collision_class_key");
        gate(runtime.commands.length === 0 && runtime.probe.core.record === null, "collision_no_authority");
        return {
            testPreflightByteIdenticalRejected: true,
            realLoaderSequentialSameClassReplaced: true,
            enforcementProven: false,
            authorityGranted: false,
            classKeyRegistryEntries: callbacks.length,
            existingJournalRejected: true,
            existingTempRejected: true,
            existingSymlinkRejected: true,
            duplicateSourceRejected: true,
        };
    } finally {
        await stopRuntime(runtime);
        await unlink(collision).catch(() => undefined);
    }
}

async function caseStopRemove(context) {
    const runtime = await createRuntime(context);
    const source = path.join(context.dataRoot, "external_extensions", ARTIFACT_NAME);
    const captured = capturedProbeFunctions(runtime.eventBus);
    try {
        await removeProbe(runtime);
        await settle();
        gate(capturedFunctionsRemoved(runtime.eventBus, captured), "stop_listener_leak");
        gate(fs.existsSync(source), "stop_before_delete");
        await bounded(runtime.controller.removeExtension(runtime.loader), "loader_stop_timeout");
        runtime.eventBus.removeListeners(runtime.audit);
        await settle();
        gate(relevantListenerCount(runtime.eventBus) === 0, "stop_listener_leak");
        await unlink(source);
        freshInventory(context.dataRoot, {allowMissingSource: true});
        const fresh = await createRuntime(context, {expectProbe: false});
        const sourceFreeRestartEntries = fresh.postInventoryCount;
        const sourceFreeRestartNodeModulesAlias = fs.existsSync(path.join(context.dataRoot, "external_extensions", "node_modules"));
        try {
            gate(sourceInventory(fresh, context).length === 0, "empty_inventory");
        } finally {
            await stopRuntime(fresh);
        }
        return {
            boundedStop: true,
            listenersBeforeDelete: true,
            outOfBandDelete: true,
            retainedEmpty: true,
            sourceFreeRestartEntries,
            sourceFreeRestartNodeModulesAlias,
        };
    } finally {
        await stopRuntime(runtime);
    }
}

async function runCase(caseName, context) {
    const handlers = {
        input: () => caseInput(context),
        cold: () => caseCold(context),
        prearm: () => casePrearm(context),
        armed: () => caseArmed(context),
        control_rename: () => caseControl(context, "rename"),
        control_group: () => caseControl(context, "group"),
        collision: () => caseCollision(context),
        stop_remove: () => caseStopRemove(context),
    };
    gate(Object.hasOwn(handlers, caseName), "case_name");
    return {schema: CASE_SCHEMA, result: "pass", case: caseName, evidence: await handlers[caseName]()};
}

function aggregate(context) {
    const results = {};
    const evidenceKeys = {
        input: ["security", "journalTests", "listenerLeakRejected", "sourceInventorySha256"],
        cold: ["loaderCount", "sourceInventorySha256", "probeBefore", "relevantBefore", "probeAfter", "relevantAfterFullStop", "actualFunctionsRemoved", "emitterCountsBefore", "emitterCountsAfterProbeStop", "emitterCountsAfterFullStop", "registryBefore", "registryAfter"],
        prearm: ["commandCount", "journalFileCount"],
        armed: ["armImmediate", "commandCount", "exactNoop", "exactExpectedNoopSequence", "completeDurablePhaseHistoryObserved", "challengePhaseAbsent", "durablePhaseHistory", "armJournalCanonicalMatch", "armJournalPhasePhysical1", "armJournalFileCount", "journal"],
        control_rename: ["kind", "failedSafe", "commandCount"],
        control_group: ["kind", "failedSafe", "commandCount"],
        collision: ["testPreflightByteIdenticalRejected", "realLoaderSequentialSameClassReplaced", "enforcementProven", "authorityGranted", "classKeyRegistryEntries", "existingJournalRejected", "existingTempRejected", "existingSymlinkRejected", "duplicateSourceRejected"],
        stop_remove: ["boundedStop", "listenersBeforeDelete", "outOfBandDelete", "retainedEmpty", "sourceFreeRestartEntries", "sourceFreeRestartNodeModulesAlias"],
    };
    for (const caseName of CASES) {
        const value = readJson(path.join(context.resultsRoot, `${caseName}.json`), "case_result");
        exactKeys(value, ["schema", "result", "case", "evidence"], "case_result_shape");
        gate(value.schema === CASE_SCHEMA && value.result === "pass" && value.case === caseName, "case_result_identity");
        exactKeys(value.evidence, evidenceKeys[caseName], "case_evidence_shape");
        results[caseName] = value.evidence;
    }
    gate(fs.readdirSync(context.casesRoot).length === 0, "case_cleanup");
    gate(results.input.sourceInventorySha256 === ARTIFACT_SHA256 && results.cold.sourceInventorySha256 === ARTIFACT_SHA256, "source_inventory_digest");
    const bindings = {...context.stage};
    delete bindings.schema;
    const journal = results.armed.journal;
    return {
        schema: RAW_SCHEMA,
        result: "pass",
        pass: "B0",
        classification: CLASSIFICATION,
        authoritative: false,
        trust_boundary: TRUST_BOUNDARY,
        runtime: {
            node: "20.19.2",
            zigbee2mqtt: "2.12.1",
            zigbee_herdsman: "10.6.1",
            zigbee_herdsman_converters: "26.76.0",
            real_event_bus: true,
            disconnected_real_mqtt: true,
            real_external_extensions: true,
            real_external_js: true,
            controller_api_shell: true,
            controller_full_lifecycle_exercised: false,
        },
        bindings,
        security: results.input.security,
        counts: {
            cases: CASES.length,
            closure_packages: context.stage.closure_package_count,
            loaders: results.cold.loaderCount,
            journal_file_count: journal.file_count,
            probe_listener_functions_before_stop: results.cold.probeBefore,
            relevant_listener_functions_before_stop: results.cold.relevantBefore,
            probe_listener_functions_after_probe_stop: results.cold.probeAfter,
            relevant_listener_functions_after_full_stop: results.cold.relevantAfterFullStop,
        },
        behavior: {
            prearm: {command_count: results.prearm.commandCount, journal_file_count: results.prearm.journalFileCount},
            armed: {
                arm_immediate_command_count: results.armed.armImmediate,
                command_count_after_two_physical_frames: results.armed.commandCount,
                exact_tuya_noop: results.armed.exactNoop,
                exact_expected_noop_sequence: results.armed.exactExpectedNoopSequence,
                complete_durable_phase_history_observed: results.armed.completeDurablePhaseHistoryObserved,
                challenge_phase_absent: results.armed.challengePhaseAbsent,
                durable_phase_history: results.armed.durablePhaseHistory,
                arm_journal_canonical_match: results.armed.armJournalCanonicalMatch,
                arm_journal_phase_physical1: results.armed.armJournalPhasePhysical1,
                arm_journal_file_count: results.armed.armJournalFileCount,
            },
            journal,
            listeners: {
                emitter_counts_before_stop: results.cold.emitterCountsBefore,
                emitter_counts_after_probe_stop: results.cold.emitterCountsAfterProbeStop,
                emitter_counts_after_full_stop: results.cold.emitterCountsAfterFullStop,
                emitter_callbacks_removed: results.cold.actualFunctionsRemoved,
                class_key_registry_entries_before_stop: results.cold.registryBefore,
                class_key_registry_entries_after_stop: results.cold.registryAfter,
                class_key_bookkeeping_retained: results.cold.registryAfter === results.cold.registryBefore,
                collision_class_key_registry_entries: results.collision.classKeyRegistryEntries,
                callback_registry_cleanup_proven: false,
            },
            collision: {
                test_preflight_byte_identical_collision_rejected: results.collision.testPreflightByteIdenticalRejected,
                real_loader_sequential_same_class_replaced: results.collision.realLoaderSequentialSameClassReplaced,
                runtime_collision_enforcement_proven: results.collision.enforcementProven,
                authority_granted: results.collision.authorityGranted,
            },
            stop_remove: {
                bounded_stop: results.stop_remove.boundedStop,
                listeners_removed_before_delete: results.stop_remove.listenersBeforeDelete,
                out_of_band_delete: results.stop_remove.outOfBandDelete,
                dynamic_mqtt_save_remove_used: false,
                retained_empty_array: results.stop_remove.retainedEmpty,
                source_free_restart_entries: results.stop_remove.sourceFreeRestartEntries,
                source_free_restart_node_modules_alias: results.stop_remove.sourceFreeRestartNodeModulesAlias,
            },
            adversarial: {
                existing_journal_rejected: results.collision.existingJournalRejected,
                existing_temp_rejected: results.collision.existingTempRejected,
                existing_symlink_rejected: results.collision.existingSymlinkRejected,
                duplicate_source_rejected: results.collision.duplicateSourceRejected,
                journal_noncanonical_rejected: results.input.journalTests.journal_noncanonical_rejected,
                journal_link_rejected: results.input.journalTests.journal_link_rejected,
                journal_mode_rejected: results.input.journalTests.journal_mode_rejected,
                listener_leak_rejected: results.input.listenerLeakRejected,
            },
        },
        prohibited: {
            guarded_surfaces: GUARDED_SURFACES,
            static_not_used_surfaces: STATIC_NOT_USED_SURFACES,
            containment_only_surfaces: CONTAINMENT_ONLY_SURFACES,
            syscall_tracing_performed: false,
        },
        raw_source_seen_in_process_retained_inventory: true,
        raw_source_emitted_to_ci_evidence: false,
        broker_delivery_exercised: false,
        reproducibility: {
            comparison_scope: "normalized-verifier-output-only",
            raw_runtime_bytes_reproducible: false,
            raw_journal_bytes_reproducible: false,
            boot_ids_reproducible: false,
            command_sequences_reproducible: false,
        },
        claim_limits: CLAIM_LIMITS,
    };
}

function contextFromEnvironment() {
    const inputRoot = requiredEnv("PASS_B_INPUT_ROOT");
    const manifest = readJson(path.join(inputRoot, "physical_probe_pass_b_manifest.json"), "manifest");
    const stage = readJson(path.join(inputRoot, "runtime_stage.json"), "stage");
    validateManifest(manifest);
    return {
        runtimeRoot: requiredEnv("PASS_B_RUNTIME_ROOT"),
        inputRoot,
        manifest,
        stage,
        z2mRoot: requiredEnv("PASS_B_Z2M_ROOT"),
        dataRoot: process.env.PASS_B_DATA_ROOT,
        baseTopic: process.env.PASS_B_BASE_TOPIC,
        resultsRoot: process.env.PASS_B_RESULTS_ROOT,
        casesRoot: process.env.PASS_B_CASES_ROOT,
    };
}

async function main() {
    const caseName = requiredEnv("PASS_B_CASE");
    const context = contextFromEnvironment();
    if (caseName === "aggregate") {
        gate(context.resultsRoot && context.casesRoot, "aggregate_environment");
        return aggregate(context);
    }
    gate(context.dataRoot && context.baseTopic, "case_environment");
    validateBaseTopic(context.baseTopic);
    gate(path.resolve(context.dataRoot).startsWith(`${path.resolve(context.runtimeRoot)}${path.sep}`), "data_root_scope");
    return runCase(caseName, context);
}

try {
    emit(await main());
} catch (error) {
    emit({schema: FAILURE_SCHEMA, result: "fail", failure_code: error instanceof SmokeFailure ? error.code : "internal_failure"});
    process.exitCode = 1;
}
