#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import zlib from "node:zlib";
import {spawnSync} from "node:child_process";
import {fileURLToPath, pathToFileURL} from "node:url";

const MANIFEST_SCHEMA = "true-family-pass-b0-manifest-v2";
const RAW_SCHEMA = "true-family-pass-b0-runtime-raw-v2";
const FINAL_SCHEMA = "true-family-pass-b0-smoke-v2";
const FAILURE_SCHEMA = "true-family-pass-b0-launcher-failure-v2";
const STAGE_SCHEMA = "true-family-pass-b0-runtime-stage-v2";
const CLASSIFICATION = "ci-only-non-authoritative-reviewed-source-smoke";
const IMAGE = "docker.io/library/node:20.19.2-bookworm-slim@sha256:ae5e29a169a6dbe7f45d552d73674001cc00913a0a8a5967c57a34f92e940ec8";
const IMAGE_INDEX = "sha256:7cd3fbc830c75c92256fe1122002add9a1c025831af8770cd0bf8e45688ef661";
const ARTIFACT_SHA256 = "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1";
const PACKAGE_JSON_SHA256 = "c9b0593136090da7aad27aeea97afbffc11de0c23f8717281ced2d9f95045323";
const PNPM_LOCK_SHA256 = "b432429b5c07e0824e52d23b3186c181f4904ec6a288232b71a07c20446a32f6";
const DIST_SHA256 = "b69100d9ec7992eb47ee756d4cbaf540996e30e12b24b8dbb348c05356c72ff2";
const CLOSURE_SHA256 = "de77c8dea2c3a531c3af9331147426d708ad83435072aa4aec228cdcf10c9e52";
const CLOSURE_COUNT = 148;
const MAX_RAW_BYTES = 32 * 1024;
const MAX_FINAL_BYTES = 32 * 1024;
const TMPFS_TMP_BYTES = 256 * 1024 * 1024;
const PNPM_FETCH_VIRTUAL_STORE_MEASURED_BYTES = 88 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const FAILURE_CODE_PATTERN = /^[a-z0-9_]{1,64}$/u;
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
const PACKAGE_DOWNLOAD_SCHEMA = "true-family-pass-b0-package-download-v1";
const PACKAGE_DOWNLOAD_FAILURE_SCHEMA = "true-family-pass-b0-package-download-failure-v1";
const PACKAGE_DOWNLOAD_TIMEOUT_MS = 45000;
const VERIFIER_FAILURE_SCHEMA = "true-family-pass-b0-verifier-failure-v1";
const VERIFIER_FAILURE_MAX_BYTES = 256;
const RUNTIME_FAILURE_SCHEMA = "true-family-pass-b0-runtime-failure-v2";
const RUNTIME_FAILURE_MAX_BYTES = 256;
const RUNTIME_FAILURE_CODE_PATTERN_TEXT = "^[a-z0-9_]{1,40}$";
const RUNTIME_FAILURE_CODE_PATTERN = /^[a-z0-9_]{1,40}$/u;
const PNPM_FAILURE_SCHEMA = "true-family-pass-b0-pnpm-failure-v1";
const PNPM_DIAGNOSTIC_MAX_BYTES = 1024 * 1024;
const PNPM_DIAGNOSTIC_LINE_MAX_BYTES = 64 * 1024;
const PNPM_ERROR_IDENTIFIER_PATTERN_TEXT = "^ERR_PNPM_[A-Z0-9_]{1,40}$";
const PNPM_ERROR_IDENTIFIER_PATTERN = /^ERR_PNPM_[A-Z0-9_]{1,40}$/u;
const PNPM_FAILURE_CODE_PATTERN_TEXT = "^pnpm_(fetch|install)_[a-z0-9_]{1,40}$";
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
const VERIFIER_FAILURE_CODE_PATTERN = /^[a-z][a-z0-9_]{0,54}$/u;
const VERIFIER_MODE_FAILURE_CODES = Object.freeze({
    "--self-check": "self_check_failed",
    "--classify-container-start": "classifier_failed",
    "--validate-tar": "tar_failed",
    "--extract-tar": "tar_failed",
    "--verify-upstream": "upstream_failed",
    "--prepare-install": "install_prepare_failed",
    "--normalize-closure": "closure_normalize_failed",
    "--tree-evidence": "tree_evidence_failed",
    "--runtime-hashes": "runtime_hashes_failed",
    "--write-stage": "stage_write_failed",
    "--rehash-stage": "stage_rehash_failed",
    "--validate-image-inspect": "image_inspect_failed",
    "--verify-run": "run_verification_failed",
    "--validate-final": "final_verification_failed",
});
const VERIFIER_FAILURE_CODES = Object.freeze([
    "arguments",
    "mode",
    ...new Set(Object.values(VERIFIER_MODE_FAILURE_CODES)),
    "verifier_failed",
]);
const PACKAGE_DOWNLOAD_FAILURE_CODES = Object.freeze([
    "download_arguments",
    "download_kind",
    "download_contract",
    "download_url",
    "download_destination",
    "download_destination_exists",
    "download_request",
    "download_timeout",
    "download_redirect",
    "download_status",
    "download_length",
    "download_overrun",
    "download_truncated",
    "download_integrity",
    "download_response",
    "download_write",
    "download_sync",
    "download_cleanup",
    "download_failed",
]);
const PACKAGE_DOWNLOAD_SPECS = Object.freeze({
    z2m: Object.freeze({
        runtime_key: "zigbee2mqtt",
        version: "2.12.1",
        tarball_url: "https://registry.npmjs.org/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz",
        filename: "zigbee2mqtt-2.12.1.tgz",
        sha512_sri: "sha512-OucrVP2raFmMEKK+4r7qHOSamAmaM4WI0WYLbLRhZ1s73frVDcppzD/6BHGPWFIalJrxGrdKHYSbRmpQqLUt5w==",
        compressed_size: 349915,
        max_bytes: 524288,
    }),
    herdsman: Object.freeze({
        runtime_key: "zigbee_herdsman",
        version: "10.6.1",
        tarball_url: "https://registry.npmjs.org/zigbee-herdsman/-/zigbee-herdsman-10.6.1.tgz",
        filename: "zigbee-herdsman-10.6.1.tgz",
        sha512_sri: "sha512-BXy2jai1R6OkJ7gWFwS8J6vKJ7Mm+vfReDcuN+IPCmHdT65oiaZ6oZDY/thjG7ePMHD2m0YD8AZvi7o5LBNPpQ==",
        compressed_size: 1193873,
        max_bytes: 2097152,
    }),
    converters: Object.freeze({
        runtime_key: "zigbee_herdsman_converters",
        version: "26.76.0",
        tarball_url: "https://registry.npmjs.org/zigbee-herdsman-converters/-/zigbee-herdsman-converters-26.76.0.tgz",
        filename: "zigbee-herdsman-converters-26.76.0.tgz",
        sha512_sri: "sha512-JSgW/9Yn5xdfUHvyXunKSqoPk7w6wY+0OEzOiqBs/hr67o9YSXKc4joUr/dbRMXJcv7fNlDNDRvIDS41b2758Q==",
        compressed_size: 2752484,
        max_bytes: 4194304,
    }),
    pnpm: Object.freeze({
        runtime_key: "pnpm",
        version: "10.18.3",
        tarball_url: "https://registry.npmjs.org/pnpm/-/pnpm-10.18.3.tgz",
        filename: "pnpm-10.18.3.tgz",
        sha512_sri: "sha512-u9FubXKG/X4B9rPAs8kyzaKWXAapCDKPdGY/EKmupR8RKe6mFRNL+ZKDGwCeq+Fn7LcAi1l/QP+bx1lGqt+wjQ==",
        compressed_size: 4155290,
        max_bytes: 5242880,
    }),
});

class VerifyError extends Error {
    constructor(code) {
        super(code);
        this.code = code;
    }
}

function gate(condition, code) {
    if (!condition) throw new VerifyError(code);
}

function exactKeys(value, keys, code) {
    gate(value !== null && typeof value === "object" && !Array.isArray(value), code);
    gate(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), code);
}

function canonical(value) {
    if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`;
    gate(value && typeof value === "object", "canonical_type");
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function same(left, right) {
    return canonical(left) === canonical(right);
}

function harnessSmokeFailureCodes(source) {
    const helperNames = ["gate", "exactKeys", "readJson", "checkMode", "strictProxy", "bounded"];
    const expectedLiteralCalls = {gate: 157, exactKeys: 5, readJson: 6, checkMode: 2, strictProxy: 4, bounded: 4};
    const masked = source.replace(/(?:async\s+)?function\s+(?:gate|exactKeys|readJson|checkMode|strictProxy|bounded)\s*\([^)]*\)\s*\{/gu, "");
    const codes = [];
    for (const name of helperNames) {
        const pattern = new RegExp(`\\b${name}\\([\\s\\S]*?,\\s*"((?:\\\\.|[^"\\\\])*)"\\s*(?:,\\s*[^)]*)?\\);`, "gu");
        const matches = [...masked.matchAll(pattern)];
        gate(matches.length === expectedLiteralCalls[name], "runtime_failure_source");
        const totalCalls = (source.match(new RegExp(`\\b${name}\\(`, "gu")) ?? []).length - 1;
        gate(matches.length + (name === "gate" ? 3 : 0) === totalCalls, "runtime_failure_source");
        for (const match of matches) codes.push(JSON.parse(`"${match[1]}"`));
    }
    const direct = [...source.matchAll(/new\s+SmokeFailure\(\s*"((?:\\.|[^"\\])*)"\s*\)/gu)];
    const forwarded = (source.match(/new\s+SmokeFailure\(code\)/gu) ?? []).length;
    const constructors = (source.match(/new\s+SmokeFailure\(/gu) ?? []).length;
    gate(direct.length === 1 && forwarded === 5 && direct.length + forwarded === constructors, "runtime_failure_source");
    for (const match of direct) codes.push(JSON.parse(`"${match[1]}"`));
    gate(source.includes('error instanceof SmokeFailure ? error.code : "internal_failure"'), "runtime_failure_source");
    const unique = [...new Set(codes)].sort();
    gate(unique.length > 0 && unique.every((code) => RUNTIME_FAILURE_CODE_PATTERN.test(code)), "runtime_failure_source");
    return unique;
}

function allowedVerifierFailureCode(code) {
    return typeof code === "string"
        && VERIFIER_FAILURE_CODE_PATTERN.test(code)
        && VERIFIER_FAILURE_CODES.includes(code)
        && `verifier_${code}`.length <= 64;
}

function publicVerifierFailureCode(error, mode) {
    if (!(error instanceof VerifyError) || typeof error.code !== "string" || !FAILURE_CODE_PATTERN.test(error.code)) return "verifier_failed";
    let code;
    if (error.code === "arguments" || error.code === "mode") code = error.code;
    else code = VERIFIER_MODE_FAILURE_CODES[mode] ?? "verifier_failed";
    return allowedVerifierFailureCode(code) ? code : "verifier_failed";
}

function verifierFailureToken(code) {
    const safe = allowedVerifierFailureCode(code) ? code : "verifier_failed";
    const token = `${canonical({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: safe})}\n`;
    gate(Buffer.byteLength(token, "utf8") <= VERIFIER_FAILURE_MAX_BYTES, "verifier_failure_token");
    return token;
}

function allowedPnpmFailureCode(code, phase) {
    if (typeof code !== "string" || code.length > 64) return false;
    const match = /^pnpm_(fetch|install)_([a-z0-9_]{1,40})$/u.exec(code);
    if (match === null || (phase !== undefined && match[1] !== phase)) return false;
    return PNPM_FIXED_FAILURE_SUFFIXES.includes(match[2])
        || PNPM_ERROR_IDENTIFIER_PATTERN.test(`ERR_PNPM_${match[2].toUpperCase()}`);
}

function pnpmFailureCode(phase, suffix) {
    const code = `pnpm_${phase}_${suffix}`;
    return allowedPnpmFailureCode(code, phase) ? code : "pnpm_fetch_diagnostic_non_ndjson";
}

function pnpmFailureToken(code) {
    const safe = allowedPnpmFailureCode(code) ? code : "pnpm_fetch_diagnostic_non_ndjson";
    return `${canonical({schema: PNPM_FAILURE_SCHEMA, result: "fail", failure_code: safe})}\n`;
}

function parsePnpmNdjson(text, seenLines) {
    if (typeof text !== "string") return {status: "non_ndjson", codes: []};
    if (Buffer.byteLength(text, "utf8") > PNPM_DIAGNOSTIC_MAX_BYTES) return {status: "oversize", codes: []};
    if (text === "") return {status: "ok", codes: []};
    if (text.includes("\r") || !text.endsWith("\n")) return {status: "non_ndjson", codes: []};
    const codes = [];
    for (const line of text.slice(0, -1).split("\n")) {
        if (line === "") return {status: "non_ndjson", codes: []};
        if (Buffer.byteLength(line, "utf8") > PNPM_DIAGNOSTIC_LINE_MAX_BYTES) return {status: "oversize", codes: []};
        if (seenLines.has(line)) return {status: "non_ndjson", codes: []};
        seenLines.add(line);
        let value;
        try {
            value = JSON.parse(line);
        } catch {
            return {status: "non_ndjson", codes: []};
        }
        if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(value) !== line) return {status: "non_ndjson", codes: []};
        if (Object.hasOwn(value, "code")) {
            if (typeof value.code !== "string") return {status: "non_ndjson", codes: []};
            if (PNPM_ERROR_IDENTIFIER_PATTERN.test(value.code)) codes.push(value.code);
        }
        if (Object.hasOwn(value, "err") && value.err !== null) {
            if (typeof value.err !== "object" || Array.isArray(value.err)) return {status: "non_ndjson", codes: []};
            if (Object.hasOwn(value.err, "code")) {
                if (typeof value.err.code !== "string") return {status: "non_ndjson", codes: []};
                if (PNPM_ERROR_IDENTIFIER_PATTERN.test(value.err.code)) codes.push(value.err.code);
            }
        }
    }
    return {status: "ok", codes};
}

function scanPnpmIdentifiers(text) {
    const codes = [];
    const pattern = /ERR_PNPM_[A-Z0-9_]{1,40}/gu;
    const asciiWord = /[A-Za-z0-9_]/u;
    for (const match of text.matchAll(pattern)) {
        const before = match.index === 0 ? "" : text[match.index - 1];
        const afterIndex = match.index + match[0].length;
        const after = afterIndex === text.length ? "" : text[afterIndex];
        if ((before !== "" && asciiWord.test(before)) || (after !== "" && asciiWord.test(after))) continue;
        codes.push(match[0]);
    }
    return codes;
}

function classifyPnpmIdentifiers(phase, codes, emptySuffix) {
    const unique = [...new Set(codes)];
    if (unique.length > 1) return pnpmFailureCode(phase, "multiple_codes");
    if (unique.length === 1) return pnpmFailureCode(phase, unique[0].slice("ERR_PNPM_".length).toLowerCase());
    return pnpmFailureCode(phase, emptySuffix);
}

function classifyPnpmText(phase, stdoutText, stderrText) {
    if (!PNPM_PHASES.includes(phase)) return "pnpm_fetch_diagnostic_non_ndjson";
    if (typeof stdoutText !== "string" || typeof stderrText !== "string") return pnpmFailureCode(phase, "diagnostic_non_ndjson");
    if (Buffer.byteLength(stdoutText, "utf8") > PNPM_DIAGNOSTIC_MAX_BYTES || Buffer.byteLength(stderrText, "utf8") > PNPM_DIAGNOSTIC_MAX_BYTES) {
        return pnpmFailureCode(phase, "diagnostic_oversize");
    }
    if (stdoutText === "" && stderrText === "") return pnpmFailureCode(phase, "diagnostic_empty");
    const seenLines = new Set();
    const stdout = parsePnpmNdjson(stdoutText, seenLines);
    const stderr = parsePnpmNdjson(stderrText, seenLines);
    if (stdout.status === "ok" && stderr.status === "ok") {
        return classifyPnpmIdentifiers(phase, [...stdout.codes, ...stderr.codes], "diagnostic_no_code");
    }
    const rawCodes = [...scanPnpmIdentifiers(stdoutText), ...scanPnpmIdentifiers(stderrText)];
    if (rawCodes.length > 0) return classifyPnpmIdentifiers(phase, rawCodes, "diagnostic_non_ndjson");
    const suffix = stdout.status === "oversize" || stderr.status === "oversize"
        ? "diagnostic_oversize"
        : "diagnostic_non_ndjson";
    return pnpmFailureCode(phase, suffix);
}

function readPnpmDiagnosticFile(filePath, dependencies = {}) {
    const lstat = dependencies.lstatSync ?? fs.lstatSync;
    const readFile = dependencies.readFileSync ?? fs.readFileSync;
    try {
        const metadata = lstat(filePath);
        if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || !Number.isSafeInteger(metadata.size) || metadata.size < 0) {
            return {status: "non_ndjson", text: ""};
        }
        if (metadata.size > PNPM_DIAGNOSTIC_MAX_BYTES) return {status: "oversize", text: ""};
        const bytes = readFile(filePath);
        if (!Buffer.isBuffer(bytes) || bytes.length !== metadata.size) return {status: "non_ndjson", text: ""};
        if (bytes.length > PNPM_DIAGNOSTIC_MAX_BYTES) return {status: "oversize", text: ""};
        const text = bytes.toString("utf8");
        if (!Buffer.from(text, "utf8").equals(bytes)) return {status: "non_ndjson", text: ""};
        return {status: "ok", text};
    } catch {
        return {status: "non_ndjson", text: ""};
    }
}

function classifyPnpmFiles(phase, stdoutPath, stderrPath, dependencies = {}) {
    if (!PNPM_PHASES.includes(phase)) return "pnpm_fetch_diagnostic_non_ndjson";
    const stdout = readPnpmDiagnosticFile(stdoutPath, dependencies);
    const stderr = readPnpmDiagnosticFile(stderrPath, dependencies);
    if (stdout.status !== "ok" || stderr.status !== "ok") {
        const suffix = stdout.status === "oversize" || stderr.status === "oversize"
            ? "diagnostic_oversize"
            : "diagnostic_non_ndjson";
        return pnpmFailureCode(phase, suffix);
    }
    return classifyPnpmText(phase, stdout.text, stderr.text);
}

function sha256Bytes(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function sha512Sri(value) {
    return `sha512-${crypto.createHash("sha512").update(value).digest("base64")}`;
}

function sha256File(file) {
    return sha256Bytes(fs.readFileSync(file));
}

function readJson(file, code = "json") {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        throw new VerifyError(code);
    }
}

function writeCanonical(file, value) {
    fs.writeFileSync(file, `${canonical(value)}\n`, {mode: 0o600, flag: "wx"});
}

export function normalizedLauncherDigestBytes(bytes) {
    const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
    const pattern = /EXPECTED_LAUNCHER_SHA256="([0-9a-f]{64})"/gu;
    const matches = [...text.matchAll(pattern)];
    gate(matches.length === 1, "launcher_normalization");
    const normalized = text.replace(pattern, `EXPECTED_LAUNCHER_SHA256="${"0".repeat(64)}"`);
    return {
        digest: sha256Bytes(Buffer.from(normalized, "utf8")),
        literal: matches[0][1],
    };
}

export function treeEvidence(root, packageCount = false) {
    const resolvedRoot = path.resolve(root);
    const records = [];
    const pending = [resolvedRoot];
    while (pending.length) {
        const current = pending.pop();
        const entries = fs.readdirSync(current, {withFileTypes: true}).sort((left, right) => left.name.localeCompare(right.name));
        for (const entry of entries) {
            const file = path.join(current, entry.name);
            const relative = path.relative(resolvedRoot, file).split(path.sep).join("/");
            const metadata = fs.lstatSync(file);
            if (metadata.isSymbolicLink()) {
                const target = fs.readlinkSync(file);
                gate(!path.isAbsolute(target), "tree_absolute_link");
                const resolved = path.resolve(path.dirname(file), target);
                gate(resolved === resolvedRoot || resolved.startsWith(`${resolvedRoot}${path.sep}`), "tree_escaping_link");
                records.push([relative, "l", target]);
            } else if (metadata.isDirectory()) {
                records.push([relative, "d", ""]);
                pending.push(file);
            } else if (metadata.isFile()) {
                records.push([relative, "f", sha256File(file)]);
            } else {
                throw new VerifyError("tree_special_file");
            }
        }
    }
    records.sort((left, right) => left[0].localeCompare(right[0]));
    let count = 0;
    if (packageCount) {
        const virtualStore = path.join(resolvedRoot, ".pnpm");
        count = fs.readdirSync(virtualStore, {withFileTypes: true})
            .filter((entry) => entry.isDirectory() && entry.name !== "node_modules").length;
    }
    return {digest: sha256Bytes(Buffer.from(canonical(records), "utf8")), count};
}

function validateManifest(manifest) {
    exactKeys(manifest, [
        "schema",
        "manifest_version",
        "pass",
        "classification",
        "authoritative",
        "trust_boundary",
        "container",
        "runtime",
        "upstream",
        "artifact",
        "expected",
        "verifier",
        "test_scope",
        "prohibited",
        "evidence",
    ], "manifest_shape");
    gate(manifest.schema === MANIFEST_SCHEMA && manifest.manifest_version === 2 && manifest.pass === "B0", "manifest_identity");
    gate(manifest.classification === CLASSIFICATION && manifest.authoritative === false, "manifest_classification");
    gate(same(manifest.trust_boundary, TRUST_BOUNDARY), "manifest_trust_boundary");
    exactKeys(manifest.container, [
        "image",
        "index_reference_sha256",
        "platform",
        "producer_user",
        "runtime_user",
        "log_policy",
        "package_download_policy",
        "pnpm_diagnostic_policy",
        "start_diagnostics",
        "fetch_host_allowlist_enforced",
        "explicit_fetch_targets",
        "limits",
    ], "manifest_container_shape");
    gate(manifest.container.image === IMAGE && manifest.container.index_reference_sha256 === IMAGE_INDEX, "manifest_image");
    gate(manifest.container.platform === "linux/amd64" && manifest.container.fetch_host_allowlist_enforced === false, "manifest_platform");
    gate(manifest.container.producer_user === "host-runner-numeric-nonroot" && manifest.container.runtime_user === "65532:65532", "manifest_users");
    gate(manifest.container.limits.nproc === 64, "manifest_nproc_limits");
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
    gate(same(manifest.container.package_download_policy, {
        implementation: "node:https",
        method: "GET",
        hostname: "registry.npmjs.org",
        port: 443,
        timeout_ms: PACKAGE_DOWNLOAD_TIMEOUT_MS,
        redirects_allowed: false,
        proxy_environment_used: false,
        exclusive_output: true,
        output_mode: "0600",
        file_fsync: true,
        partial_removed_on_failure: true,
        success_schema: PACKAGE_DOWNLOAD_SCHEMA,
        failure_schema: PACKAGE_DOWNLOAD_FAILURE_SCHEMA,
    }), "manifest_package_download_policy");
    gate(same(manifest.container.pnpm_diagnostic_policy, {
        schema: PNPM_FAILURE_SCHEMA,
        phases: PNPM_PHASES,
        reporter: "ndjson",
        max_file_bytes: PNPM_DIAGNOSTIC_MAX_BYTES,
        max_line_bytes: PNPM_DIAGNOSTIC_LINE_MAX_BYTES,
        regular_files_only: true,
        noninteractive_ci: true,
        original_exit_status_preserved: true,
        raw_output_emitted: false,
        canonical_code_fields: ["code", "err.code"],
        identifier_pattern: PNPM_ERROR_IDENTIFIER_PATTERN_TEXT,
        failure_code_pattern: PNPM_FAILURE_CODE_PATTERN_TEXT,
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
            schema: RUNTIME_FAILURE_SCHEMA,
            exact_keys: ["failure_code", "result", "schema"],
            failure_code_pattern: RUNTIME_FAILURE_CODE_PATTERN_TEXT,
            max_bytes: RUNTIME_FAILURE_MAX_BYTES,
            byte_exact_canonical_token: true,
            trailing_newline_required: true,
            classification_prefix: "runtime_",
            classification_max_bytes: 64,
            internal_failure_code: "internal_failure",
            synthetic_failure_code: "case_failed",
            source_smoke_failure_codes_verified: true,
        },
        known_process_failure_codes: [
            ...PACKAGE_DOWNLOAD_FAILURE_CODES.map((code) => `package_fetch_${code}`),
            ...VERIFIER_FAILURE_CODES.map((code) => `verifier_${code}`),
            ...PNPM_FIXED_STAGE_FAILURE_CODES,
            "runtime_case_failed",
        ],
        unknown_process_output_code: "<stage>_process_exit",
        raw_output_emitted: false,
    }), "manifest_start_diagnostics");
    gate(same(manifest.container.explicit_fetch_targets, ["registry.npmjs.org", "github.com"]), "manifest_fetch_targets");
    gate(same(manifest.container.limits, {
        memory_bytes: 805306368,
        memory_swap_bytes: 805306368,
        nano_cpus: 1000000000,
        pids: 64,
        nofile: 1024,
        nproc: 64,
        fsize_bytes: 268435456,
        tmpfs_tmp_bytes: TMPFS_TMP_BYTES,
        pnpm_fetch_virtual_store_measured_bytes: PNPM_FETCH_VIRTUAL_STORE_MEASURED_BYTES,
        full_run_seconds: 2040,
        workflow_timeout_minutes: 45,
        runtime_seconds: 240,
        raw_output_bytes: MAX_RAW_BYTES,
    }), "manifest_limits");
    gate(PNPM_FETCH_VIRTUAL_STORE_MEASURED_BYTES < TMPFS_TMP_BYTES, "manifest_tmpfs_capacity");
    exactKeys(manifest.runtime, ["node", "zigbee2mqtt", "zigbee_herdsman", "zigbee_herdsman_converters", "pnpm"], "manifest_runtime_shape");
    gate(same(manifest.runtime.node, {version: "20.19.2"}), "manifest_node");
    for (const [kind, spec] of Object.entries(PACKAGE_DOWNLOAD_SPECS)) {
        const {runtime_key: runtimeKey, ...expected} = spec;
        gate(same(manifest.runtime[runtimeKey], expected), `manifest_${kind}`);
    }
    gate(same(manifest.upstream, {
        repository: "Koenkk/zigbee2mqtt",
        commit: "aa909a8a62f76e2dd98ace3a172bca88ee56f5fe",
        tree: "fd134890cc89e628caa48f6f235862b0bfe40c45",
        package_json_sha256: PACKAGE_JSON_SHA256,
        pnpm_lock_sha256: PNPM_LOCK_SHA256,
        identity_claim: "exact-content-only-not-signature-or-provenance",
    }), "manifest_upstream");
    gate(same(manifest.artifact, {
        filename: "true_family_brt_probe.mjs",
        class_name: "TrueFamilyBrtProbeExtension",
        byte_length: 164691,
        sha256: ARTIFACT_SHA256,
    }), "manifest_artifact");
    gate(same(manifest.expected, {
        closure_package_count: CLOSURE_COUNT,
        closure_sha256: CLOSURE_SHA256,
        dist_sha256: DIST_SHA256,
    }), "manifest_expected");
    exactKeys(manifest.verifier, [
        "launcher_normalization",
        "failure_schema",
        "failure_max_bytes",
        "failure_codes",
        "launcher_normalized_sha256",
        "harness_sha256",
        "verifier_sha256",
    ], "manifest_verifier_shape");
    gate(manifest.verifier.launcher_normalization === "sha256 of launcher UTF-8 bytes after replacing only EXPECTED_LAUNCHER_SHA256=\"<64 lowercase hex>\" with the same assignment containing 64 zeroes", "manifest_launcher_rule");
    gate(manifest.verifier.failure_schema === VERIFIER_FAILURE_SCHEMA && manifest.verifier.failure_max_bytes === VERIFIER_FAILURE_MAX_BYTES, "manifest_verifier_failure");
    gate(same(manifest.verifier.failure_codes, VERIFIER_FAILURE_CODES), "manifest_verifier_failure");
    for (const key of ["launcher_normalized_sha256", "harness_sha256", "verifier_sha256"]) {
        gate(SHA256_PATTERN.test(manifest.verifier[key]), "manifest_verifier_digest");
    }
    gate(same(manifest.test_scope, {
        cases: CASES,
        same_repo_reviewed_source_trusted: true,
        malicious_source_resistant: false,
        full_controller_lifecycle: false,
        fetch_host_allowlist_enforced: false,
    }), "manifest_scope");
    gate(same(manifest.prohibited, {
        guarded_surfaces: GUARDED_SURFACES,
        static_not_used_surfaces: STATIC_NOT_USED_SURFACES,
        containment_only_surfaces: CONTAINMENT_ONLY_SURFACES,
    }), "manifest_prohibited");
    gate(same(manifest.evidence, {
        raw_schema: RAW_SCHEMA,
        final_schema: FINAL_SCHEMA,
        failure_schema: FAILURE_SCHEMA,
        max_raw_bytes: MAX_RAW_BYTES,
        raw_source_seen_in_process_retained_inventory: true,
        raw_source_emitted_to_ci_evidence: false,
        broker_delivery_exercised: false,
        comparison_scope: "normalized-verifier-output-only",
        raw_runtime_bytes_reproducible: false,
        claim_limits: CLAIM_LIMITS,
    }), "manifest_evidence");
}

function validateStaticBindings(manifestPath, launcherPath, harnessPath, verifierPath, artifactPath) {
    const manifest = readJson(manifestPath, "manifest_json");
    validateManifest(manifest);
    const launcher = normalizedLauncherDigestBytes(fs.readFileSync(launcherPath));
    gate(launcher.digest === manifest.verifier.launcher_normalized_sha256, "launcher_digest");
    gate(launcher.literal === manifest.verifier.launcher_normalized_sha256, "launcher_literal");
    gate(sha256File(harnessPath) === manifest.verifier.harness_sha256, "harness_digest");
    gate(sha256File(verifierPath) === manifest.verifier.verifier_sha256, "verifier_digest");
    gate(sha256File(artifactPath) === manifest.artifact.sha256, "artifact_digest");
    gate(fs.statSync(artifactPath).size === manifest.artifact.byte_length, "artifact_size");
    return manifest;
}

function parseOctal(field, code) {
    gate((field[0] & 0x80) === 0, code);
    const text = field.toString("ascii").replace(/\0.*$/u, "").trim();
    if (text === "") return 0;
    gate(/^[0-7]+$/u.test(text), code);
    const value = Number.parseInt(text, 8);
    gate(Number.isSafeInteger(value) && value >= 0, code);
    return value;
}

function tarString(field, code) {
    const nul = field.indexOf(0);
    const bytes = nul === -1 ? field : field.subarray(0, nul);
    gate(!bytes.includes(0), code);
    const text = bytes.toString("utf8");
    gate(Buffer.from(text, "utf8").equals(bytes), code);
    gate(!/[\x00-\x1f\x7f\\]/u.test(text), code);
    return text;
}

function validateTarPath(rawName, type) {
    gate(rawName.length > 0 && Buffer.byteLength(rawName, "utf8") <= 512, "tar_path");
    gate(!rawName.startsWith("/") && !rawName.includes("\\"), "tar_path");
    const directory = type === "5";
    const name = directory && rawName.endsWith("/") ? rawName.slice(0, -1) : rawName;
    gate(name.length > 0 && !name.includes("//"), "tar_path");
    const parts = name.split("/");
    gate(parts.length <= 32 && parts.every((part) => part !== "" && part !== "." && part !== ".."), "tar_path");
    gate(path.posix.normalize(name) === name, "tar_path");
    return name;
}

export function parseStrictTarGzip(compressed, options = {}) {
    const maxCompressed = options.maxCompressed ?? 8 * 1024 * 1024;
    const maxEntries = options.maxEntries ?? 10000;
    const maxUnpacked = options.maxUnpacked ?? 256 * 1024 * 1024;
    const maxMember = options.maxMember ?? 64 * 1024 * 1024;
    gate(Buffer.isBuffer(compressed) && compressed.length > 0 && compressed.length <= maxCompressed, "tar_compressed_size");
    let archive;
    try {
        archive = zlib.gunzipSync(compressed, {maxOutputLength: maxUnpacked + 1024});
    } catch {
        throw new VerifyError("tar_gzip");
    }
    gate(archive.length % 512 === 0 && archive.length <= maxUnpacked, "tar_truncated");
    const entries = [];
    const names = new Set();
    let offset = 0;
    let zeroBlocks = 0;
    let unpacked = 0;
    while (offset < archive.length) {
        const header = archive.subarray(offset, offset + 512);
        gate(header.length === 512, "tar_truncated");
        if (header.every((byte) => byte === 0)) {
            zeroBlocks += 1;
            offset += 512;
            if (zeroBlocks === 2) break;
            continue;
        }
        gate(zeroBlocks === 0, "tar_trailing_nonzero");
        const expectedChecksum = parseOctal(header.subarray(148, 156), "tar_checksum");
        let actualChecksum = 0;
        for (let index = 0; index < 512; index += 1) {
            actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
        }
        gate(actualChecksum === expectedChecksum, "tar_checksum");
        const typeByte = header[156];
        const type = typeByte === 0 ? "0" : String.fromCharCode(typeByte);
        gate(type === "0" || type === "5", "tar_entry_type");
        gate(header.subarray(157, 257).every((byte) => byte === 0), "tar_link_target");
        const mode = parseOctal(header.subarray(100, 108), "tar_mode");
        gate((mode & 0o6000) === 0, "tar_mode");
        gate(parseOctal(header.subarray(329, 337), "tar_device") === 0, "tar_device");
        gate(parseOctal(header.subarray(337, 345), "tar_device") === 0, "tar_device");
        const magic = header.subarray(257, 263).toString("ascii");
        gate(magic === "ustar\0" || magic === "ustar ", "tar_format");
        const namePart = tarString(header.subarray(0, 100), "tar_path");
        const prefix = tarString(header.subarray(345, 500), "tar_path");
        const rawName = prefix ? `${prefix}/${namePart}` : namePart;
        const name = validateTarPath(rawName, type);
        gate(!names.has(name), "tar_duplicate");
        names.add(name);
        const size = parseOctal(header.subarray(124, 136), "tar_size");
        gate(size <= maxMember && (type === "0" || size === 0), "tar_member_size");
        unpacked += size;
        gate(unpacked <= maxUnpacked, "tar_unpacked_size");
        const bodyStart = offset + 512;
        const padded = Math.ceil(size / 512) * 512;
        gate(bodyStart + padded <= archive.length, "tar_truncated");
        entries.push({name, type, mode, data: archive.subarray(bodyStart, bodyStart + size)});
        gate(entries.length <= maxEntries, "tar_entry_count");
        offset = bodyStart + padded;
    }
    gate(zeroBlocks >= 2, "tar_end_markers");
    gate(archive.subarray(offset).every((byte) => byte === 0), "tar_trailing_nonzero");
    return entries;
}

function packageTarContract(manifest, kind) {
    const contracts = {
        z2m: manifest.runtime.zigbee2mqtt,
        herdsman: manifest.runtime.zigbee_herdsman,
        converters: manifest.runtime.zigbee_herdsman_converters,
        pnpm: manifest.runtime.pnpm,
    };
    gate(Object.hasOwn(contracts, kind), "tar_kind");
    return contracts[kind];
}

function packageDownloadSpec(kind) {
    gate(Object.hasOwn(PACKAGE_DOWNLOAD_SPECS, kind), "download_kind");
    return PACKAGE_DOWNLOAD_SPECS[kind];
}

function packageDownloadContract(manifest, kind) {
    const spec = packageDownloadSpec(kind);
    const {runtime_key: runtimeKey, ...expected} = spec;
    gate(same(manifest.runtime?.[runtimeKey], expected), "download_contract");
    return expected;
}

function packageDownloadRequestOptions(kind, contract) {
    const spec = packageDownloadSpec(kind);
    const expected = {...spec};
    delete expected.runtime_key;
    let parsed;
    try {
        parsed = new URL(contract.tarball_url);
    } catch {
        throw new VerifyError("download_url");
    }
    gate(parsed.href === contract.tarball_url, "download_url");
    gate(parsed.protocol === "https:" && parsed.hostname === "registry.npmjs.org" && parsed.port === "", "download_url");
    gate(parsed.username === "" && parsed.password === "" && parsed.search === "" && parsed.hash === "", "download_url");
    gate(parsed.pathname === new URL(spec.tarball_url).pathname, "download_url");
    gate(same(contract, expected), "download_contract");
    return {
        protocol: "https:",
        hostname: "registry.npmjs.org",
        port: 443,
        method: "GET",
        path: parsed.pathname,
        headers: {
            accept: "application/octet-stream",
            "accept-encoding": "identity",
            "user-agent": "true-family-pass-b0-package-fetch/1",
        },
        agent: false,
    };
}

function packageDownloadFailureToken(code) {
    const safe = PACKAGE_DOWNLOAD_FAILURE_CODES.includes(code) ? code : "download_failed";
    return `${canonical({schema: PACKAGE_DOWNLOAD_FAILURE_SCHEMA, result: "fail", failure_code: safe})}\n`;
}

const PACKAGE_DOWNLOAD_SUCCESS_TOKEN = `${canonical({schema: PACKAGE_DOWNLOAD_SCHEMA, result: "pass"})}\n`;

function validatePackageResponseMetadata(response, contract) {
    gate(response && typeof response === "object" && response.headers && typeof response.headers === "object", "download_response");
    gate(Number.isInteger(response.statusCode), "download_response");
    if (response.statusCode >= 300 && response.statusCode <= 399) throw new VerifyError("download_redirect");
    gate(response.statusCode === 200, "download_status");
    const contentLength = response.headers["content-length"];
    if (contentLength !== undefined) {
        gate(typeof contentLength === "string" && /^[1-9][0-9]*$/u.test(contentLength), "download_length");
        gate(Number(contentLength) === contract.compressed_size, "download_length");
    }
}

async function consumePackageResponse(response, contract, sink) {
    validatePackageResponseMetadata(response, contract);
    gate(response[Symbol.asyncIterator] && typeof sink?.write === "function" && typeof sink?.sync === "function", "download_response");
    const digest = crypto.createHash("sha512");
    let total = 0;
    try {
        for await (const chunk of response) {
            gate(Buffer.isBuffer(chunk) || chunk instanceof Uint8Array, "download_response");
            const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            total += bytes.length;
            gate(total <= contract.max_bytes && total <= contract.compressed_size, "download_overrun");
            digest.update(bytes);
            try {
                await sink.write(bytes);
            } catch {
                throw new VerifyError("download_write");
            }
        }
    } catch (error) {
        if (error instanceof VerifyError) throw error;
        throw new VerifyError("download_response");
    }
    gate(total === contract.compressed_size, "download_truncated");
    gate(`sha512-${digest.digest("base64")}` === contract.sha512_sri, "download_integrity");
    try {
        await sink.sync();
    } catch {
        throw new VerifyError("download_sync");
    }
}

function fileDownloadSink(handle) {
    return {
        async write(bytes) {
            let offset = 0;
            while (offset < bytes.length) {
                const result = await handle.write(bytes, offset, bytes.length - offset, null);
                gate(Number.isInteger(result?.bytesWritten) && result.bytesWritten > 0 && result.bytesWritten <= bytes.length - offset, "download_write");
                offset += result.bytesWritten;
            }
        },
        async sync() {
            await handle.sync();
        },
    };
}

async function transferPackage(kind, contract, sink, dependencies = {}) {
    const requestOptions = packageDownloadRequestOptions(kind, contract);
    const requestImpl = dependencies.request ?? https.request;
    const setTimer = dependencies.setTimeout ?? globalThis.setTimeout;
    const clearTimer = dependencies.clearTimeout ?? globalThis.clearTimeout;
    let request;
    let response;
    let timer;
    let timedOut = false;
    let completed = false;
    const responsePromise = new Promise((resolve, reject) => {
        try {
            request = requestImpl(requestOptions, (incoming) => {
                response = incoming;
                resolve(incoming);
            });
            request.once("error", () => reject(new VerifyError(timedOut ? "download_timeout" : "download_request")));
            request.end();
        } catch {
            reject(new VerifyError("download_request"));
        }
    });
    const timeoutPromise = new Promise((resolve, reject) => {
        timer = setTimer(() => {
            timedOut = true;
            request?.destroy();
            response?.destroy?.();
            reject(new VerifyError("download_timeout"));
        }, PACKAGE_DOWNLOAD_TIMEOUT_MS);
    });
    try {
        response = await Promise.race([responsePromise, timeoutPromise]);
        await Promise.race([consumePackageResponse(response, contract, sink), timeoutPromise]);
        completed = true;
    } catch (error) {
        if (timedOut) throw new VerifyError("download_timeout");
        if (error instanceof VerifyError) throw error;
        throw new VerifyError("download_response");
    } finally {
        clearTimer(timer);
        if (!completed) response?.destroy?.();
    }
}

async function downloadPackageToPath(manifest, kind, outputPath, dependencies = {}) {
    const contract = packageDownloadContract(manifest, kind);
    packageDownloadRequestOptions(kind, contract);
    gate(outputPath === `/out/${contract.filename}`, "download_destination");
    const openOutput = dependencies.openOutput ?? fs.promises.open;
    const unlinkOutput = dependencies.unlinkOutput ?? fs.promises.unlink;
    const transfer = dependencies.transfer ?? transferPackage;
    let handle;
    let created = false;
    try {
        try {
            handle = await openOutput(outputPath, "wx", 0o600);
            created = true;
        } catch (error) {
            throw new VerifyError(error?.code === "EEXIST" ? "download_destination_exists" : "download_destination");
        }
        try {
            await handle.chmod(0o600);
        } catch {
            throw new VerifyError("download_destination");
        }
        await transfer(kind, contract, fileDownloadSink(handle), dependencies);
        await handle.close();
        handle = undefined;
    } catch (error) {
        let cleanupFailed = false;
        if (handle) {
            try {
                await handle.close();
            } catch {
                cleanupFailed = true;
            }
        }
        if (created) {
            try {
                await unlinkOutput(outputPath);
            } catch {
                cleanupFailed = true;
            }
        }
        if (cleanupFailed) throw new VerifyError("download_cleanup");
        if (error instanceof VerifyError && PACKAGE_DOWNLOAD_FAILURE_CODES.includes(error.code)) throw error;
        throw new VerifyError("download_failed");
    }
}

async function downloadPackageFile(kind, outputPath, manifestPath, dependencies = {}) {
    let manifest;
    try {
        manifest = readJson(manifestPath, "download_contract");
        validateManifest(manifest);
    } catch {
        throw new VerifyError("download_contract");
    }
    await downloadPackageToPath(manifest, kind, outputPath, dependencies);
}

function validateTarFile(kind, archivePath, manifestPath) {
    const manifest = readJson(manifestPath, "manifest_json");
    validateManifest(manifest);
    const contract = packageTarContract(manifest, kind);
    const compressed = fs.readFileSync(archivePath);
    gate(sha512Sri(compressed) === contract.sha512_sri, "tar_integrity");
    gate(compressed.length === contract.compressed_size && compressed.length <= contract.max_bytes, "tar_compressed_size");
    const entries = parseStrictTarGzip(compressed);
    gate(entries.length > 0 && entries.every((entry) => entry.name === "package" || entry.name.startsWith("package/")), "tar_package_root");
    return {manifest, entries};
}

function extractTar(kind, archivePath, destination, manifestPath) {
    const {entries} = validateTarFile(kind, archivePath, manifestPath);
    gate(fs.readdirSync(destination).length === 0, "extract_destination");
    for (const entry of entries) {
        const relative = entry.name === "package" ? "" : entry.name.slice("package/".length);
        if (relative === "") continue;
        const target = path.join(destination, ...relative.split("/"));
        const root = path.resolve(destination);
        const resolved = path.resolve(target);
        gate(resolved.startsWith(`${root}${path.sep}`), "extract_path");
        if (entry.type === "5") {
            fs.mkdirSync(target, {recursive: true, mode: 0o755});
        } else {
            fs.mkdirSync(path.dirname(target), {recursive: true, mode: 0o755});
            fs.writeFileSync(target, entry.data, {flag: "wx", mode: (entry.mode & 0o111) ? 0o755 : 0o644});
        }
    }
}

const PROHIBITED_RESOLUTION_KEYS = Object.freeze(new Set(["tarball", "repo", "directory", "path"]));
const EXTERNAL_RESOLUTION_PROTOCOL = /(?:^|[\s{,])(?:["'])?(?:https?:\/\/|git\+|file:|link:|workspace:)/iu;

function yamlMappingLine(line) {
    const match = line.match(/^(\s*)(?:(?:"([a-z_]+)")|(?:'([a-z_]+)')|([a-z_]+)):\s*(.*)$/iu);
    if (!match) return null;
    return {
        indent: match[1].length,
        key: (match[2] ?? match[3] ?? match[4]).toLowerCase(),
        value: match[5],
    };
}

function externalResolutionValue(value) {
    if (EXTERNAL_RESOLUTION_PROTOCOL.test(value)) return true;
    if (/(?:^|[{,]\s*)(?:["']?(?:tarball|repo|directory|path)["']?)\s*:/iu.test(value)) return true;
    return /(?:^|[{,]\s*)[^,{}:]+:\s*(?:["'])?(?:https?:\/\/|git\+|file:|link:|workspace:)/iu.test(value);
}

export function validatePackageResolutions(packages) {
    gate(packages.startsWith("packages:\n"), "lock_packages_section");
    let inPackage = false;
    let resolutionIndent = -1;
    let resolutionCount = 0;
    for (const line of packages.split("\n").slice(1)) {
        if (line === "" || /^\s+#/u.test(line)) continue;
        if (/^  \S.*:\s*$/u.test(line) && !line.startsWith("    ")) {
            inPackage = true;
            resolutionIndent = -1;
            continue;
        }
        const mapping = yamlMappingLine(line);
        if (!inPackage || mapping === null) continue;
        if (resolutionIndent >= 0 && mapping.indent <= resolutionIndent && mapping.key !== "resolution") resolutionIndent = -1;
        if (mapping.indent >= 4 && PROHIBITED_RESOLUTION_KEYS.has(mapping.key)) throw new VerifyError("lock_external_resolution");
        if (mapping.indent === 4 && mapping.key === "resolution") {
            if (externalResolutionValue(mapping.value)) throw new VerifyError("lock_external_resolution");
            gate(/^    resolution: \{integrity: sha512-[A-Za-z0-9+/=]+\}$/u.test(line), "lock_resolution_shape");
            resolutionIndent = mapping.indent;
            resolutionCount += 1;
            continue;
        }
        if (resolutionIndent >= 0 && mapping.indent > resolutionIndent) {
            if (PROHIBITED_RESOLUTION_KEYS.has(mapping.key) || externalResolutionValue(mapping.value)) throw new VerifyError("lock_external_resolution");
        }
    }
    gate(resolutionCount > 0, "lock_resolution_shape");
}

function verifyUpstream(manifestPath, packagePath, lockPath, z2mPackagePath) {
    const manifest = readJson(manifestPath, "manifest_json");
    validateManifest(manifest);
    gate(sha256File(packagePath) === manifest.upstream.package_json_sha256, "upstream_package_digest");
    gate(sha256File(lockPath) === manifest.upstream.pnpm_lock_sha256, "upstream_lock_digest");
    const pkg = readJson(packagePath, "upstream_package_json");
    gate(pkg.name === "zigbee2mqtt" && pkg.version === "2.12.1" && pkg.packageManager === "pnpm@10.18.3", "upstream_package_identity");
    gate(pkg.dependencies?.["zigbee-herdsman"] === "10.6.1", "upstream_herdsman_direct");
    gate(pkg.dependencies?.["zigbee-herdsman-converters"] === "26.76.0", "upstream_converters_direct");
    const lock = fs.readFileSync(lockPath, "utf8");
    gate(lock.startsWith("lockfileVersion: '9.0'\n"), "lock_version");
    const importerStart = lock.indexOf("  .:\n");
    const importerEnd = lock.indexOf("    devDependencies:\n");
    const packagesStart = lock.indexOf("packages:\n");
    const snapshotsStart = lock.indexOf("snapshots:\n");
    gate(importerStart >= 0 && importerEnd > importerStart && packagesStart > importerEnd && snapshotsStart > packagesStart, "lock_sections");
    const importer = lock.slice(importerStart, importerEnd);
    gate((importer.match(/      zigbee-herdsman:\n        specifier: 10\.6\.1\n        version: 10\.6\.1\n/gu) ?? []).length === 1, "lock_herdsman_importer");
    gate((importer.match(/      zigbee-herdsman-converters:\n        specifier: 26\.76\.0\n        version: 26\.76\.0\n/gu) ?? []).length === 1, "lock_converters_importer");
    const packages = lock.slice(packagesStart, snapshotsStart);
    validatePackageResolutions(packages);
    const herdsman = /^  zigbee-herdsman@10\.6\.1:\n    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$/gmu;
    const converters = /^  zigbee-herdsman-converters@26\.76\.0:\n    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$/gmu;
    const herdsmanMatches = [...packages.matchAll(herdsman)];
    const converterMatches = [...packages.matchAll(converters)];
    gate(herdsmanMatches.length === 1 && herdsmanMatches[0][1] === manifest.runtime.zigbee_herdsman.sha512_sri, "lock_herdsman_integrity");
    gate(converterMatches.length === 1 && converterMatches[0][1] === manifest.runtime.zigbee_herdsman_converters.sha512_sri, "lock_converters_integrity");
    const published = readJson(z2mPackagePath, "published_package_json");
    gate(published.name === "zigbee2mqtt" && published.version === "2.12.1", "published_package_identity");
}

function permissionSnapshot(root) {
    const absoluteRoot = path.resolve(root);
    const pending = [[".", absoluteRoot]];
    const records = [];
    while (pending.length) {
        const [relative, current] = pending.pop();
        const metadata = fs.lstatSync(current);
        gate(!metadata.isSymbolicLink(), "install_source");
        if (metadata.isDirectory()) {
            records.push([relative, "directory", metadata.mode & 0o777]);
            const entries = fs.readdirSync(current).sort().reverse();
            for (const name of entries) pending.push([relative === "." ? name : `${relative}/${name}`, path.join(current, name)]);
        } else {
            gate(metadata.isFile() && metadata.nlink === 1, "install_source");
            records.push([relative, "file", metadata.mode & 0o777, metadata.size, sha256File(current)]);
        }
    }
    return records.sort((left, right) => left[0].localeCompare(right[0]));
}

function normalizeWritableTree(root) {
    const pending = [path.resolve(root)];
    while (pending.length) {
        const current = pending.pop();
        const metadata = fs.lstatSync(current);
        gate(!metadata.isSymbolicLink(), "install_work_tree");
        if (metadata.isDirectory()) {
            fs.chmodSync(current, 0o700);
            for (const name of fs.readdirSync(current)) pending.push(path.join(current, name));
        } else {
            gate(metadata.isFile() && metadata.nlink === 1, "install_work_tree");
            fs.chmodSync(current, 0o600);
        }
    }
}

function prepareInstall(source, destination) {
    const sourceBefore = permissionSnapshot(source);
    gate(fs.readdirSync(destination).length === 0, "install_destination");
    const allowed = new Set(["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"]);
    const names = fs.readdirSync(source).sort();
    gate(names.includes("package.json") && names.includes("pnpm-lock.yaml") && names.every((name) => allowed.has(name)), "install_source");
    for (const name of names) {
        const input = path.join(source, name);
        const metadata = fs.lstatSync(input);
        gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1, "install_source");
        fs.copyFileSync(input, path.join(destination, name), fs.constants.COPYFILE_EXCL);
    }
    normalizeWritableTree(destination);
    const packagePath = path.join(destination, "package.json");
    const writable = fs.openSync(packagePath, "r+");
    fs.closeSync(writable);
    const pkg = readJson(packagePath, "install_package_json");
    pkg.scripts = {
        ...pkg.scripts,
        preinstall: "node -e \"require('node:fs').writeFileSync('/work/lifecycle-canary', 'executed')\"",
    };
    fs.writeFileSync(packagePath, `${JSON.stringify(pkg, null, 4)}\n`, {mode: 0o600});
    gate((fs.lstatSync(destination).mode & 0o777) === 0o700 && (fs.lstatSync(packagePath).mode & 0o777) === 0o600, "install_work_mode");
    gate(same(permissionSnapshot(source), sourceBefore), "install_source_changed");
}

function normalizeClosure(root) {
    const pending = [path.resolve(root)];
    while (pending.length) {
        const current = pending.pop();
        for (const entry of fs.readdirSync(current, {withFileTypes: true})) {
            const file = path.join(current, entry.name);
            if (entry.name === ".bin" && entry.isDirectory()) {
                fs.rmSync(file, {recursive: true, force: true});
            } else if (entry.isDirectory() && !entry.isSymbolicLink()) {
                pending.push(file);
            }
        }
    }
    for (const name of [".modules.yaml", ".pnpm-workspace-state-v1.json"]) fs.rmSync(path.join(root, name), {force: true});
}

export function runtimeHashes() {
    const executable = fs.realpathSync(process.execPath);
    const libraries = new Set();
    for (const line of fs.readFileSync("/proc/self/maps", "utf8").split("\n")) {
        const match = line.match(/\s(\/[^\s]+)$/u);
        if (!match) continue;
        const file = match[1].replace(/ \(deleted\)$/u, "");
        if (file === executable || !fs.existsSync(file)) continue;
        const metadata = fs.statSync(file);
        if (metadata.isFile() && (file.includes(".so") || /\/ld-linux[^/]*$/u.test(file))) libraries.add(file);
    }
    const records = [...libraries].sort().map((file) => [file, sha256File(file)]);
    gate(records.length > 0, "runtime_library_set");
    return {
        node_binary_sha256: sha256File(executable),
        shared_library_set_sha256: sha256Bytes(Buffer.from(canonical(records), "utf8")),
        shared_library_count: records.length,
    };
}

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

function validateStageShape(stage, manifest) {
    exactKeys(stage, STAGE_KEYS, "stage_shape");
    gate(stage.schema === STAGE_SCHEMA, "stage_schema");
    for (const key of STAGE_KEYS.filter((key) => key.endsWith("sha256"))) gate(SHA256_PATTERN.test(stage[key]), "stage_digest");
    gate(stage.node_image_digest === manifest.container.image.split("@")[1], "stage_image");
    gate(Number.isSafeInteger(stage.shared_library_count) && stage.shared_library_count > 0, "stage_library_count");
    gate(stage.closure_package_count === CLOSURE_COUNT, "stage_closure_count");
    gate(stage.launcher_normalized_sha256 === manifest.verifier.launcher_normalized_sha256, "stage_launcher");
    gate(stage.harness_sha256 === manifest.verifier.harness_sha256 && stage.verifier_sha256 === manifest.verifier.verifier_sha256, "stage_verifiers");
    gate(stage.artifact_sha256 === manifest.artifact.sha256, "stage_artifact");
    gate(stage.upstream_package_json_sha256 === manifest.upstream.package_json_sha256 && stage.pnpm_lock_sha256 === manifest.upstream.pnpm_lock_sha256, "stage_upstream");
    gate(stage.package_dist_sha256 === manifest.expected.dist_sha256 && stage.closure_sha256 === manifest.expected.closure_sha256, "stage_package");
}

function makeStage(args) {
    const [manifestPath, launcherPath, harnessPath, verifierPath, artifactPath, passAPath, fixturePath, runnerPath, runtimeHashesPath, upstreamPackagePath, lockPath, runtimePackagePath, distRoot, closureRoot] = args;
    const manifest = validateStaticBindings(manifestPath, launcherPath, harnessPath, verifierPath, artifactPath);
    const runtime = readJson(runtimeHashesPath, "runtime_hashes");
    exactKeys(runtime, ["node_binary_sha256", "shared_library_set_sha256", "shared_library_count"], "runtime_hashes_shape");
    const dist = treeEvidence(distRoot, false);
    const closure = treeEvidence(closureRoot, true);
    const stage = {
        schema: STAGE_SCHEMA,
        manifest_sha256: sha256File(manifestPath),
        launcher_normalized_sha256: manifest.verifier.launcher_normalized_sha256,
        harness_sha256: manifest.verifier.harness_sha256,
        verifier_sha256: manifest.verifier.verifier_sha256,
        artifact_sha256: manifest.artifact.sha256,
        pass_a_manifest_sha256: sha256File(passAPath),
        preflight_fixture_sha256: sha256File(fixturePath),
        runtime_runner_sha256: sha256File(runnerPath),
        node_image_digest: manifest.container.image.split("@")[1],
        node_binary_sha256: runtime.node_binary_sha256,
        shared_library_set_sha256: runtime.shared_library_set_sha256,
        shared_library_count: runtime.shared_library_count,
        upstream_package_json_sha256: sha256File(upstreamPackagePath),
        pnpm_lock_sha256: sha256File(lockPath),
        runtime_package_json_sha256: sha256File(runtimePackagePath),
        package_dist_sha256: dist.digest,
        closure_sha256: closure.digest,
        closure_package_count: closure.count,
    };
    validateStageShape(stage, manifest);
    return stage;
}

function rehashStage(stagePath, args) {
    const expected = makeStage(args);
    const actual = readJson(stagePath, "stage_json");
    gate(same(actual, expected), "stage_rehash");
}

function scanSanitizedText(text, sourceText) {
    gate(Buffer.byteLength(text, "utf8") <= MAX_RAW_BYTES, "output_oversized");
    gate(!text.includes("0xa4c1380000000001"), "output_ieee");
    gate(!text.includes("::") && !text.includes("\u001b"), "output_workflow_control");
    gate(!/https?:\/\//iu.test(text), "output_url");
    gate(!/"\/(?:[^"\\]|\\.)*"/u.test(text), "output_absolute_path");
    gate(!/(?:\/home\/runner|\/homeassistant|\/github\/workspace|\/data\/.cache|\/root\/|\/run\/docker|\/var\/run\/docker|RUNNER_TEMP)/u.test(text), "output_host_path");
    gate(!/(?:password|credential|access[_-]?token|api[_-]?key|github[_-]?token|authorization)/iu.test(text), "output_credential");
    const fragmentLength = 64;
    if (text.length >= fragmentLength) {
        const outputFragments = new Set();
        for (let index = 0; index + fragmentLength <= text.length; index += 1) {
            outputFragments.add(text.slice(index, index + fragmentLength));
        }
        for (let index = 0; index + fragmentLength <= sourceText.length; index += 1) {
            gate(!outputFragments.has(sourceText.slice(index, index + fragmentLength)), "output_source");
        }
    }
    for (const character of text) {
        const code = character.codePointAt(0);
        gate(code === 0x0a || code === 0x0d || code === 0x09 || code >= 0x20, "output_control_character");
    }
}

function scanObjectKeys(value) {
    if (Array.isArray(value)) {
        value.forEach(scanObjectKeys);
        return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, item] of Object.entries(value)) {
        gate(!/^(?:payload|raw|source|source_text|code|arm_request|journal_text|journal_bytes|ieee|token|credential|password)$/iu.test(key), "output_field");
        scanObjectKeys(item);
    }
}

function validateFailureObject(value) {
    exactKeys(value, ["schema", "result", "failure_code"], "failure_shape");
    gate(value.schema === FAILURE_SCHEMA && value.result === "fail" && FAILURE_CODE_PATTERN.test(value.failure_code), "failure_identity");
}

function exactBooleanMap(value, keys, code) {
    exactKeys(value, keys, code);
    for (const key of keys) gate(typeof value[key] === "boolean", code);
}

function validateRaw(raw, manifest, stage) {
    exactKeys(raw, [
        "schema",
        "result",
        "pass",
        "classification",
        "authoritative",
        "trust_boundary",
        "runtime",
        "bindings",
        "security",
        "counts",
        "behavior",
        "prohibited",
        "raw_source_seen_in_process_retained_inventory",
        "raw_source_emitted_to_ci_evidence",
        "broker_delivery_exercised",
        "reproducibility",
        "claim_limits",
    ], "raw_shape");
    gate(raw.schema === RAW_SCHEMA && raw.result === "pass" && raw.pass === "B0", "raw_identity");
    gate(raw.classification === CLASSIFICATION && raw.authoritative === false, "raw_classification");
    gate(raw.raw_source_seen_in_process_retained_inventory === true && raw.raw_source_emitted_to_ci_evidence === false, "raw_source_claim");
    gate(raw.broker_delivery_exercised === false, "raw_source_claim");
    gate(same(raw.reproducibility, {
        comparison_scope: "normalized-verifier-output-only",
        raw_runtime_bytes_reproducible: false,
        raw_journal_bytes_reproducible: false,
        boot_ids_reproducible: false,
        command_sequences_reproducible: false,
    }), "raw_reproducibility");
    gate(same(raw.trust_boundary, TRUST_BOUNDARY), "raw_trust_boundary");
    exactKeys(raw.runtime, [
        "node",
        "zigbee2mqtt",
        "zigbee_herdsman",
        "zigbee_herdsman_converters",
        "real_event_bus",
        "disconnected_real_mqtt",
        "real_external_extensions",
        "real_external_js",
        "controller_api_shell",
        "controller_full_lifecycle_exercised",
    ], "raw_runtime_shape");
    gate(same(raw.runtime, {
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
    }), "raw_runtime");
    exactKeys(raw.bindings, STAGE_KEYS.filter((key) => key !== "schema"), "raw_bindings_shape");
    const expectedBindings = {...stage};
    delete expectedBindings.schema;
    gate(same(raw.bindings, expectedBindings), "raw_bindings");
    exactBooleanMap(raw.security, [
        "uid_nonzero",
        "no_new_privs",
        "capability_sets_zero",
        "seccomp_filtering",
        "read_only_root",
        "immutable_write_attempts_blocked",
        "loopback_only",
        "external_route_absent",
        "forbidden_host_paths_unavailable",
    ], "raw_security_shape");
    gate(Object.values(raw.security).every(Boolean), "raw_security");
    exactKeys(raw.counts, [
        "cases",
        "closure_packages",
        "loaders",
        "journal_file_count",
        "probe_listener_functions_before_stop",
        "relevant_listener_functions_before_stop",
        "probe_listener_functions_after_probe_stop",
        "relevant_listener_functions_after_full_stop",
    ], "raw_counts_shape");
    for (const value of Object.values(raw.counts)) gate(Number.isSafeInteger(value) && value >= 0, "raw_count");
    gate(raw.counts.cases === CASES.length && raw.counts.closure_packages === CLOSURE_COUNT && raw.counts.loaders === 1, "raw_counts");
    gate(raw.counts.journal_file_count === 1 && raw.counts.probe_listener_functions_before_stop === 4, "raw_counts");
    gate(raw.counts.relevant_listener_functions_before_stop === 6 && raw.counts.probe_listener_functions_after_probe_stop === 0 && raw.counts.relevant_listener_functions_after_full_stop === 0, "raw_counts");
    exactKeys(raw.behavior, ["prearm", "armed", "journal", "listeners", "collision", "stop_remove", "adversarial"], "raw_behavior_shape");
    gate(same(raw.behavior.prearm, {command_count: 0, journal_file_count: 0}), "raw_prearm");
    gate(same(raw.behavior.armed, {
        arm_immediate_command_count: 0,
        command_count_after_two_physical_frames: 1,
        exact_tuya_noop: true,
        exact_expected_noop_sequence: true,
        complete_durable_phase_history_observed: true,
        challenge_phase_absent: true,
        durable_phase_history: ["awaiting_physical_target_1", "awaiting_physical_target_2", "awaiting_noop_response"],
        arm_journal_canonical_match: true,
        arm_journal_phase_physical1: true,
        arm_journal_file_count: 1,
    }), "raw_armed");
    exactKeys(raw.behavior.journal, [
        "file_count",
        "regular_file",
        "nlink_one",
        "mode_0600",
        "exact_data_root_location",
        "namespace_uid_zero",
        "canonical_readback_match",
        "canonical_sha256",
        "temp_file_count",
    ], "raw_journal_shape");
    gate(raw.behavior.journal.file_count === 1 && raw.behavior.journal.regular_file === true && raw.behavior.journal.nlink_one === true, "raw_journal");
    gate(raw.behavior.journal.mode_0600 === true && raw.behavior.journal.exact_data_root_location === true, "raw_journal");
    gate(raw.behavior.journal.namespace_uid_zero === false && raw.behavior.journal.canonical_readback_match === true, "raw_journal");
    gate(SHA256_PATTERN.test(raw.behavior.journal.canonical_sha256) && raw.behavior.journal.temp_file_count === 0, "raw_journal");
    gate(same(raw.behavior.listeners, {
        emitter_counts_before_stop: {deviceMessage: 1, entityRenamed: 1, groupMembersChanged: 1, mqttMessage: 2, mqttMessagePublished: 1},
        emitter_counts_after_probe_stop: {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 1, mqttMessagePublished: 1},
        emitter_counts_after_full_stop: {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 0, mqttMessagePublished: 0},
        emitter_callbacks_removed: true,
        class_key_registry_entries_before_stop: 4,
        class_key_registry_entries_after_stop: 4,
        class_key_bookkeeping_retained: true,
        collision_class_key_registry_entries: 8,
        callback_registry_cleanup_proven: false,
    }), "raw_listeners");
    gate(same(raw.behavior.collision, {
        test_preflight_byte_identical_collision_rejected: true,
        real_loader_sequential_same_class_replaced: true,
        runtime_collision_enforcement_proven: false,
        authority_granted: false,
    }), "raw_collision");
    gate(same(raw.behavior.stop_remove, {
        bounded_stop: true,
        listeners_removed_before_delete: true,
        out_of_band_delete: true,
        dynamic_mqtt_save_remove_used: false,
        retained_empty_array: true,
    }), "raw_stop_remove");
    exactBooleanMap(raw.behavior.adversarial, [
        "existing_journal_rejected",
        "existing_temp_rejected",
        "existing_symlink_rejected",
        "duplicate_source_rejected",
        "journal_noncanonical_rejected",
        "journal_link_rejected",
        "journal_mode_rejected",
        "listener_leak_rejected",
    ], "raw_adversarial_shape");
    gate(Object.values(raw.behavior.adversarial).every(Boolean), "raw_adversarial");
    gate(same(raw.prohibited, {
        guarded_surfaces: GUARDED_SURFACES,
        static_not_used_surfaces: STATIC_NOT_USED_SURFACES,
        containment_only_surfaces: CONTAINMENT_ONLY_SURFACES,
        syscall_tracing_performed: false,
    }), "raw_prohibited");
    gate(same(raw.claim_limits, CLAIM_LIMITS) && same(raw.claim_limits, manifest.evidence.claim_limits), "raw_claim_limits");
}

function validateAttachLogConfig(logConfig) {
    gate(same(logConfig, {
        Type: "json-file",
        Config: {"max-file": "1", "max-size": "1m"},
    }), "inspect_log_policy");
}

const START_STAGES = Object.freeze(["package_fetch", "fetch", "install", "runtime", "verifier"]);

function runtimeFailureToken(code) {
    gate(typeof code === "string" && RUNTIME_FAILURE_CODE_PATTERN.test(code), "runtime_failure_token");
    return `${canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: code})}\n`;
}

function runtimeFailureClassification(output) {
    if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > RUNTIME_FAILURE_MAX_BYTES) return null;
    let value;
    try {
        value = JSON.parse(output);
    } catch {
        return null;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if (!same(Object.keys(value).sort(), ["failure_code", "result", "schema"])) return null;
    if (value.schema !== RUNTIME_FAILURE_SCHEMA || value.result !== "fail" || typeof value.failure_code !== "string") return null;
    if (!RUNTIME_FAILURE_CODE_PATTERN.test(value.failure_code) || output !== runtimeFailureToken(value.failure_code)) return null;
    const classification = `runtime_${value.failure_code}`;
    return classification.length <= 64 ? classification : null;
}

function packageFetchFailureClassification(output) {
    for (const code of PACKAGE_DOWNLOAD_FAILURE_CODES) {
        if (output === packageDownloadFailureToken(code)) return `package_fetch_${code}`;
    }
    return null;
}

function verifierFailureClassification(output) {
    if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > VERIFIER_FAILURE_MAX_BYTES) return null;
    let value;
    try {
        value = JSON.parse(output);
    } catch {
        return null;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if (!same(Object.keys(value).sort(), ["failure_code", "result", "schema"])) return null;
    if (value.schema !== VERIFIER_FAILURE_SCHEMA || value.result !== "fail" || !allowedVerifierFailureCode(value.failure_code)) return null;
    if (output !== verifierFailureToken(value.failure_code)) return null;
    const classification = `verifier_${value.failure_code}`;
    return classification.length <= 64 ? classification : null;
}

function pnpmFailureClassification(stage, output) {
    if (!PNPM_PHASES.includes(stage) || typeof output !== "string" || Buffer.byteLength(output, "utf8") > 256) return null;
    let value;
    try {
        value = JSON.parse(output);
    } catch {
        return null;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if (!same(Object.keys(value).sort(), ["failure_code", "result", "schema"])) return null;
    if (value.schema !== PNPM_FAILURE_SCHEMA || value.result !== "fail") return null;
    if (!allowedPnpmFailureCode(value.failure_code, stage)) return null;
    return output === pnpmFailureToken(value.failure_code) ? value.failure_code : null;
}

function stageStateErrorCategory(value) {
    const normalized = value.toLowerCase();
    if (/no such file or directory|\benoent\b/u.test(normalized)) return "no_such_file";
    if (/not a directory|\benotdir\b/u.test(normalized)) return "not_directory";
    if (/read-only file system|\berofs\b|\breadonly\b|\bread only\b/u.test(normalized)) return "readonly";
    if (/\b(?:rlimits?|ulimit|setrlimit)\b|resource limit/u.test(normalized)) return "rlimit";
    if (/\bcgroups?\b|\/sys\/fs\/cgroup/u.test(normalized)) return "cgroup";
    if (/\b(?:apparmor|seccomp|selinux|landlock)\b|no[- ]new[- ]privileges|security (?:option|profile)/u.test(normalized)) return "security";
    if (/\bmount(?:ed|ing)?\b|\bbind\b|\bvolume\b/u.test(normalized)) return "mount";
    if (/permission denied|operation not permitted|access denied|\beacces\b|\beperm\b/u.test(normalized)) return "permission";
    if (/invalid argument|\beinval\b/u.test(normalized)) return "invalid_argument";
    if (/\bexec\b|executable|entrypoint/u.test(normalized)) return "exec";
    return "unknown";
}

function classifyStageStart(stage, startStatus, inspectStatus, output, stateText) {
    if (!START_STAGES.includes(stage)) return "verifier_unknown";
    if (!Number.isInteger(startStatus) || startStatus < 0 || startStatus > 255 || !Number.isInteger(inspectStatus) || inspectStatus < 0 || inspectStatus > 255) return `${stage}_unknown`;
    if ([124, 137].includes(inspectStatus)) return `${stage}_inspect_timeout`;
    if (inspectStatus !== 0) return `${stage}_inspect_failed`;
    let state;
    try {
        state = JSON.parse(stateText);
    } catch {
        return `${stage}_inspect_malformed`;
    }
    if (!state || typeof state !== "object" || Array.isArray(state)) return `${stage}_inspect_malformed`;
    if (typeof state.OOMKilled !== "boolean" || typeof state.Error !== "string" || !Number.isInteger(state.ExitCode)) return `${stage}_inspect_malformed`;
    if (typeof state.Status !== "string" || typeof state.Running !== "boolean") return `${stage}_inspect_malformed`;
    if (state.OOMKilled) return `${stage}_oom`;
    if (state.Error !== "") return `${stage}_state_error_${stageStateErrorCategory(state.Error)}`;
    if ([124, 137].includes(startStatus) && (state.Status !== "exited" || state.Running || state.ExitCode !== startStatus)) return `${stage}_start_timeout`;
    if (startStatus !== 0 || state.ExitCode !== 0) {
        if (stage === "package_fetch") {
            const classification = packageFetchFailureClassification(output);
            if (classification !== null) return classification;
        }
        if (stage === "verifier") {
            const classification = verifierFailureClassification(output);
            if (classification !== null) return classification;
        }
        if (stage === "fetch" || stage === "install") {
            const classification = pnpmFailureClassification(stage, output);
            if (classification !== null) return classification;
        }
        if (stage === "runtime") {
            const classification = runtimeFailureClassification(output);
            if (classification !== null) return classification;
        }
        return `${stage}_process_exit`;
    }
    if (state.Status !== "exited" || state.Running) return `${stage}_unknown`;
    return "pass";
}

function readStartDiagnostic(filePath, maximumBytes) {
    try {
        const metadata = fs.lstatSync(filePath);
        if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size > maximumBytes) return null;
        const bytes = fs.readFileSync(filePath);
        const text = bytes.toString("utf8");
        return Buffer.from(text, "utf8").equals(bytes) ? text : null;
    } catch {
        return null;
    }
}

function classifyStageStartFiles(stage, startStatusText, inspectStatusText, outputPath, statePath) {
    const parseStatus = (value) => /^(?:0|[1-9][0-9]{0,2})$/u.test(value) ? Number(value) : -1;
    return classifyStageStart(
        stage,
        parseStatus(startStatusText),
        parseStatus(inspectStatusText),
        readStartDiagnostic(outputPath, 32768),
        readStartDiagnostic(statePath, 4096),
    );
}

function validateTmpfsTmp(value, uid, gid) {
    gate(value === `rw,noexec,nosuid,nodev,size=${TMPFS_TMP_BYTES},mode=1777,uid=${uid},gid=${gid}`, "inspect_tmpfs");
}

function validateInspect(inspect, manifest) {
    gate(Array.isArray(inspect) && inspect.length === 1, "inspect_shape");
    const item = inspect[0];
    gate(item.Config?.Image === manifest.container.image && item.Config?.User === "65532:65532", "inspect_image_user");
    exactKeys(item.Config?.Labels ?? {}, ["true-family-pass-b0"], "inspect_labels");
    gate(/^[0-9a-f]{32}$/u.test(item.Config.Labels["true-family-pass-b0"]), "inspect_labels");
    gate(same(item.Config?.Entrypoint, ["/usr/bin/timeout"]), "inspect_command");
    gate(same(item.Config?.Cmd, ["--foreground", "--signal=TERM", "--kill-after=10s", "240s", "/runtime/run.sh"]), "inspect_command");
    const host = item.HostConfig;
    gate(host && host.ReadonlyRootfs === true && host.Privileged === false, "inspect_root");
    gate(host.NetworkMode === "none" && host.IpcMode === "private" && host.CgroupnsMode === "private", "inspect_namespaces");
    gate(host.PidMode === "" && host.UTSMode === "" && host.UsernsMode === "", "inspect_host_namespaces");
    gate(host.PidsLimit === 64 && host.Memory === 805306368 && host.MemorySwap === 805306368 && host.NanoCpus === 1000000000, "inspect_limits");
    const ulimits = Object.fromEntries((host.Ulimits ?? []).map((item) => [item.Name, [item.Soft, item.Hard]]));
    gate(same(ulimits, {core: [0, 0], fsize: [268435456, 268435456], nofile: [1024, 1024], nproc: [64, 64]}), "inspect_ulimits");
    gate(host.Init === true, "inspect_process");
    validateAttachLogConfig(host.LogConfig);
    gate(Array.isArray(host.CapDrop) && host.CapDrop.map((item) => item.toUpperCase()).includes("ALL"), "inspect_caps");
    gate(!host.CapAdd || host.CapAdd.length === 0, "inspect_caps");
    gate(Array.isArray(host.SecurityOpt) && host.SecurityOpt.some((item) => item === "no-new-privileges" || item === "no-new-privileges:true"), "inspect_nnp");
    gate(!host.Devices || host.Devices.length === 0, "inspect_devices");
    gate(!host.DeviceRequests || host.DeviceRequests.length === 0, "inspect_devices");
    gate(!host.PortBindings || Object.keys(host.PortBindings).length === 0, "inspect_ports");
    gate(host.PublishAllPorts === false && host.AutoRemove === false, "inspect_ports");
    gate(host.RestartPolicy?.Name === "no" && host.RestartPolicy?.MaximumRetryCount === 0, "inspect_restart");
    gate(!item.Config?.ExposedPorts || Object.keys(item.Config.ExposedPorts).length === 0, "inspect_ports");
    gate(item.State?.ExitCode === 0 && item.State?.OOMKilled === false && item.RestartCount === 0, "inspect_state");
    const expectedMounts = ["/harness", "/input", "/launcher", "/runtime", "/upstream", "/verifier", "/z2m"];
    const mounts = (item.Mounts ?? []).map((mount) => ({destination: mount.Destination, type: mount.Type, rw: mount.RW})).sort((left, right) => left.destination.localeCompare(right.destination));
    gate(same(mounts, expectedMounts.map((destination) => ({destination, type: "bind", rw: false}))), "inspect_mounts");
    const tmpfs = host.Tmpfs ?? {};
    exactKeys(tmpfs, ["/data", "/tmp"], "inspect_tmpfs");
    gate(tmpfs["/data"] === "rw,nosuid,nodev,size=268435456,mode=0700,uid=65532,gid=65532", "inspect_tmpfs");
    validateTmpfsTmp(tmpfs["/tmp"], "65532", "65532");
    gate(!mounts.some((mount) => mount.destination.includes("docker.sock")), "inspect_docker_socket");
    const environmentEntries = item.Config?.Env ?? [];
    gate(environmentEntries.length === 4, "inspect_environment");
    const environment = Object.fromEntries(environmentEntries.map((entry) => {
        const index = entry.indexOf("=");
        gate(index > 0, "inspect_environment");
        return [entry.slice(0, index), entry.slice(index + 1)];
    }));
    exactKeys(environment, ["PATH", "NODE_VERSION", "YARN_VERSION", "PASS_B_BASE_TOPIC"], "inspect_environment");
    gate(environment.PATH === "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "inspect_environment");
    gate(environment.NODE_VERSION === "20.19.2" && environment.YARN_VERSION === "1.22.22", "inspect_environment");
    gate(/^tf_pass_b\/[0-9a-f]{32}$/u.test(environment.PASS_B_BASE_TOPIC), "inspect_environment");
}

function validateImageInspect(inspect, manifest) {
    gate(Array.isArray(inspect) && inspect.length === 1, "image_inspect_shape");
    const item = inspect[0];
    gate(item.Os === "linux" && item.Architecture === "amd64", "image_platform");
    const digest = manifest.container.image.split("@")[1];
    const accepted = new Set([manifest.container.image, `node@${digest}`, `docker.io/library/node@${digest}`]);
    gate(Array.isArray(item.RepoDigests) && item.RepoDigests.some((value) => accepted.has(value)), "image_repo_digest");
}

function finalFromRaw(raw, manifest, stage) {
    const final = {
        schema: FINAL_SCHEMA,
        result: "pass",
        pass: "B0",
        classification: CLASSIFICATION,
        authoritative: false,
        trust_boundary: {...TRUST_BOUNDARY},
        runtime: {
            image: manifest.container.image,
            platform: manifest.container.platform,
            node: raw.runtime.node,
            zigbee2mqtt: raw.runtime.zigbee2mqtt,
            zigbee_herdsman: raw.runtime.zigbee_herdsman,
            zigbee_herdsman_converters: raw.runtime.zigbee_herdsman_converters,
            controller_full_lifecycle_exercised: false,
        },
        bindings: {...raw.bindings},
        counts: {...raw.counts},
        security: {...raw.security},
        behavior: {
            prearm: {...raw.behavior.prearm},
            armed: {...raw.behavior.armed},
            journal: {
                file_count: raw.behavior.journal.file_count,
                regular_file: raw.behavior.journal.regular_file,
                nlink_one: raw.behavior.journal.nlink_one,
                mode_0600: raw.behavior.journal.mode_0600,
                exact_data_root_location: raw.behavior.journal.exact_data_root_location,
                namespace_uid_zero: raw.behavior.journal.namespace_uid_zero,
                canonical_readback_match: raw.behavior.journal.canonical_readback_match,
                temp_file_count: raw.behavior.journal.temp_file_count,
            },
            listeners: {...raw.behavior.listeners},
            collision: {...raw.behavior.collision},
            stop_remove: {...raw.behavior.stop_remove},
            adversarial: {...raw.behavior.adversarial},
        },
        prohibited: {...raw.prohibited},
        fetch_host_allowlist_enforced: false,
        raw_source_seen_in_process_retained_inventory: true,
        raw_source_emitted_to_ci_evidence: false,
        broker_delivery_exercised: false,
        reproducibility: {...raw.reproducibility},
        claim_limits: [...CLAIM_LIMITS],
    };
    gate(same(final.bindings, Object.fromEntries(STAGE_KEYS.filter((key) => key !== "schema").map((key) => [key, stage[key]]))), "final_bindings");
    final.evidence_digest = sha256Bytes(Buffer.from(canonical(final), "utf8"));
    return final;
}

const FINAL_KEYS = Object.freeze([
    "schema",
    "result",
    "pass",
    "classification",
    "authoritative",
    "trust_boundary",
    "runtime",
    "bindings",
    "counts",
    "security",
    "behavior",
    "prohibited",
    "fetch_host_allowlist_enforced",
    "raw_source_seen_in_process_retained_inventory",
    "raw_source_emitted_to_ci_evidence",
    "broker_delivery_exercised",
    "reproducibility",
    "claim_limits",
    "evidence_digest",
]);

function validateFinal(final, manifest, manifestDigest, expectedBindings) {
    exactKeys(final, FINAL_KEYS, "final_shape");
    gate(final.schema === FINAL_SCHEMA && final.result === "pass" && final.pass === "B0", "final_identity");
    gate(final.classification === CLASSIFICATION && final.authoritative === false, "final_classification");
    gate(same(final.trust_boundary, TRUST_BOUNDARY), "final_trust_boundary");
    exactKeys(final.runtime, ["image", "platform", "node", "zigbee2mqtt", "zigbee_herdsman", "zigbee_herdsman_converters", "controller_full_lifecycle_exercised"], "final_runtime_shape");
    gate(same(final.runtime, {
        image: manifest.container.image,
        platform: "linux/amd64",
        node: "20.19.2",
        zigbee2mqtt: "2.12.1",
        zigbee_herdsman: "10.6.1",
        zigbee_herdsman_converters: "26.76.0",
        controller_full_lifecycle_exercised: false,
    }), "final_runtime");
    exactKeys(final.bindings, STAGE_KEYS.filter((key) => key !== "schema"), "final_bindings_shape");
    gate(same(final.bindings, expectedBindings), "final_bindings");
    for (const key of Object.keys(final.bindings).filter((key) => key.endsWith("sha256"))) gate(SHA256_PATTERN.test(final.bindings[key]), "final_binding_digest");
    gate(final.bindings.manifest_sha256 === manifestDigest, "final_manifest_binding");
    gate(final.bindings.launcher_normalized_sha256 === manifest.verifier.launcher_normalized_sha256, "final_verifier_binding");
    gate(final.bindings.harness_sha256 === manifest.verifier.harness_sha256 && final.bindings.verifier_sha256 === manifest.verifier.verifier_sha256, "final_verifier_binding");
    gate(final.bindings.artifact_sha256 === manifest.artifact.sha256, "final_artifact_binding");
    gate(final.bindings.node_image_digest === manifest.container.image.split("@")[1], "final_image_binding");
    gate(final.bindings.upstream_package_json_sha256 === manifest.upstream.package_json_sha256 && final.bindings.pnpm_lock_sha256 === manifest.upstream.pnpm_lock_sha256, "final_upstream_binding");
    gate(final.bindings.package_dist_sha256 === manifest.expected.dist_sha256 && final.bindings.closure_sha256 === manifest.expected.closure_sha256, "final_package_binding");
    gate(final.bindings.closure_package_count === CLOSURE_COUNT, "final_package_binding");
    gate(Number.isSafeInteger(final.bindings.shared_library_count) && final.bindings.shared_library_count > 0, "final_library_binding");
    exactKeys(final.counts, ["cases", "closure_packages", "loaders", "journal_file_count", "probe_listener_functions_before_stop", "relevant_listener_functions_before_stop", "probe_listener_functions_after_probe_stop", "relevant_listener_functions_after_full_stop"], "final_counts_shape");
    gate(same(final.counts, {
        cases: 8,
        closure_packages: 148,
        loaders: 1,
        journal_file_count: 1,
        probe_listener_functions_before_stop: 4,
        relevant_listener_functions_before_stop: 6,
        probe_listener_functions_after_probe_stop: 0,
        relevant_listener_functions_after_full_stop: 0,
    }), "final_counts");
    exactBooleanMap(final.security, ["uid_nonzero", "no_new_privs", "capability_sets_zero", "seccomp_filtering", "read_only_root", "immutable_write_attempts_blocked", "loopback_only", "external_route_absent", "forbidden_host_paths_unavailable"], "final_security_shape");
    gate(Object.values(final.security).every((value) => value === true), "final_security");
    exactKeys(final.behavior, ["prearm", "armed", "journal", "listeners", "collision", "stop_remove", "adversarial"], "final_behavior_shape");
    gate(same(final.behavior.prearm, {command_count: 0, journal_file_count: 0}), "final_prearm");
    gate(same(final.behavior.armed, {
        arm_immediate_command_count: 0,
        command_count_after_two_physical_frames: 1,
        exact_tuya_noop: true,
        exact_expected_noop_sequence: true,
        complete_durable_phase_history_observed: true,
        challenge_phase_absent: true,
        durable_phase_history: ["awaiting_physical_target_1", "awaiting_physical_target_2", "awaiting_noop_response"],
        arm_journal_canonical_match: true,
        arm_journal_phase_physical1: true,
        arm_journal_file_count: 1,
    }), "final_armed");
    gate(same(final.behavior.journal, {
        file_count: 1,
        regular_file: true,
        nlink_one: true,
        mode_0600: true,
        exact_data_root_location: true,
        namespace_uid_zero: false,
        canonical_readback_match: true,
        temp_file_count: 0,
    }), "final_journal");
    gate(same(final.behavior.listeners, {
        emitter_counts_before_stop: {deviceMessage: 1, entityRenamed: 1, groupMembersChanged: 1, mqttMessage: 2, mqttMessagePublished: 1},
        emitter_counts_after_probe_stop: {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 1, mqttMessagePublished: 1},
        emitter_counts_after_full_stop: {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 0, mqttMessagePublished: 0},
        emitter_callbacks_removed: true,
        class_key_registry_entries_before_stop: 4,
        class_key_registry_entries_after_stop: 4,
        class_key_bookkeeping_retained: true,
        collision_class_key_registry_entries: 8,
        callback_registry_cleanup_proven: false,
    }), "final_listeners");
    gate(same(final.behavior.collision, {
        test_preflight_byte_identical_collision_rejected: true,
        real_loader_sequential_same_class_replaced: true,
        runtime_collision_enforcement_proven: false,
        authority_granted: false,
    }), "final_collision");
    gate(same(final.behavior.stop_remove, {
        bounded_stop: true,
        listeners_removed_before_delete: true,
        out_of_band_delete: true,
        dynamic_mqtt_save_remove_used: false,
        retained_empty_array: true,
    }), "final_stop_remove");
    exactBooleanMap(final.behavior.adversarial, ["existing_journal_rejected", "existing_temp_rejected", "existing_symlink_rejected", "duplicate_source_rejected", "journal_noncanonical_rejected", "journal_link_rejected", "journal_mode_rejected", "listener_leak_rejected"], "final_adversarial_shape");
    gate(Object.values(final.behavior.adversarial).every((value) => value === true), "final_adversarial");
    gate(same(final.prohibited, {
        guarded_surfaces: GUARDED_SURFACES,
        static_not_used_surfaces: STATIC_NOT_USED_SURFACES,
        containment_only_surfaces: CONTAINMENT_ONLY_SURFACES,
        syscall_tracing_performed: false,
    }), "final_prohibited");
    gate(final.fetch_host_allowlist_enforced === false, "final_claims");
    gate(final.raw_source_seen_in_process_retained_inventory === true && final.raw_source_emitted_to_ci_evidence === false, "final_source_claims");
    gate(final.broker_delivery_exercised === false, "final_source_claims");
    gate(same(final.reproducibility, {
        comparison_scope: "normalized-verifier-output-only",
        raw_runtime_bytes_reproducible: false,
        raw_journal_bytes_reproducible: false,
        boot_ids_reproducible: false,
        command_sequences_reproducible: false,
    }), "final_reproducibility");
    gate(same(final.claim_limits, CLAIM_LIMITS), "final_claim_limits");
    gate(SHA256_PATTERN.test(final.evidence_digest), "final_digest");
    const copy = structuredClone(final);
    delete copy.evidence_digest;
    gate(final.evidence_digest === sha256Bytes(Buffer.from(canonical(copy), "utf8")), "final_digest");
}

function verifyRun(rawPath, inspectPath, manifestPath, stagePath, launcherPath, harnessPath, verifierPath, artifactPath, passAPath, fixturePath, runnerPath, runtimeHashesPath, upstreamPackagePath, lockPath, runtimePackagePath, distRoot, closureRoot) {
    const manifest = validateStaticBindings(manifestPath, launcherPath, harnessPath, verifierPath, artifactPath);
    const stage = readJson(stagePath, "stage_json");
    validateStageShape(stage, manifest);
    gate(stage.manifest_sha256 === sha256File(manifestPath), "stage_manifest_digest");
    rehashStage(stagePath, [
        manifestPath,
        launcherPath,
        harnessPath,
        verifierPath,
        artifactPath,
        passAPath,
        fixturePath,
        runnerPath,
        runtimeHashesPath,
        upstreamPackagePath,
        lockPath,
        runtimePackagePath,
        distRoot,
        closureRoot,
    ]);
    const rawBytes = fs.readFileSync(rawPath);
    gate(rawBytes.length > 0 && rawBytes.length <= MAX_RAW_BYTES, "raw_size");
    const rawText = rawBytes.toString("utf8");
    gate(Buffer.from(rawText, "utf8").equals(rawBytes), "raw_utf8");
    const sourceText = fs.readFileSync(artifactPath, "utf8");
    scanSanitizedText(rawText, sourceText);
    let raw;
    try {
        raw = JSON.parse(rawText);
    } catch {
        throw new VerifyError("raw_json");
    }
    scanObjectKeys(raw);
    validateRaw(raw, manifest, stage);
    validateInspect(readJson(inspectPath, "inspect_json"), manifest);
    const final = finalFromRaw(raw, manifest, stage);
    const finalText = canonical(final);
    gate(Buffer.byteLength(finalText, "utf8") <= MAX_FINAL_BYTES, "final_size");
    scanSanitizedText(finalText, sourceText);
    const expectedBindings = {...stage};
    delete expectedBindings.schema;
    validateFinal(final, manifest, sha256File(manifestPath), expectedBindings);
    return finalText;
}

function tarHeader(name, type = "0", content = Buffer.alloc(0), mode = 0o644, link = "") {
    const header = Buffer.alloc(512);
    const writeString = (value, start, length) => Buffer.from(value).copy(header, start, 0, length);
    const writeOctal = (value, start, length) => writeString(value.toString(8).padStart(length - 1, "0") + "\0", start, length);
    writeString(name, 0, 100);
    writeOctal(mode, 100, 8);
    writeOctal(0, 108, 8);
    writeOctal(0, 116, 8);
    writeOctal(content.length, 124, 12);
    writeOctal(0, 136, 12);
    header.fill(0x20, 148, 156);
    header[156] = type.charCodeAt(0);
    writeString(link, 157, 100);
    writeString("ustar\0", 257, 6);
    writeString("00", 263, 2);
    writeOctal(0, 329, 8);
    writeOctal(0, 337, 8);
    let checksum = 0;
    for (const byte of header) checksum += byte;
    writeString(checksum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
    const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512);
    content.copy(padded);
    return Buffer.concat([header, padded]);
}

function tarFixture(entries, trailing = Buffer.alloc(0)) {
    return zlib.gzipSync(Buffer.concat([...entries, Buffer.alloc(1024), trailing]), {mtime: 0});
}

function validateFinalBytes(bytes, manifest, sourceText, manifestDigest, expectedBindings) {
    gate(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_FINAL_BYTES, "final_size");
    const text = bytes.toString("utf8");
    gate(Buffer.from(text, "utf8").equals(bytes), "final_utf8");
    scanSanitizedText(text, sourceText);
    let final;
    try {
        final = JSON.parse(text);
    } catch {
        throw new VerifyError("final_json");
    }
    gate(text === canonical(final), "final_canonical");
    scanObjectKeys(final);
    validateFinal(final, manifest, manifestDigest, expectedBindings);
    return final;
}

function finalSelfTestFixture(manifest, manifestDigest) {
    const digest = (character) => character.repeat(64);
    const bindings = {
        manifest_sha256: manifestDigest,
        launcher_normalized_sha256: manifest.verifier.launcher_normalized_sha256,
        harness_sha256: manifest.verifier.harness_sha256,
        verifier_sha256: manifest.verifier.verifier_sha256,
        artifact_sha256: manifest.artifact.sha256,
        pass_a_manifest_sha256: digest("1"),
        preflight_fixture_sha256: digest("2"),
        runtime_runner_sha256: digest("3"),
        node_image_digest: manifest.container.image.split("@")[1],
        node_binary_sha256: digest("4"),
        shared_library_set_sha256: digest("5"),
        shared_library_count: 17,
        upstream_package_json_sha256: manifest.upstream.package_json_sha256,
        pnpm_lock_sha256: manifest.upstream.pnpm_lock_sha256,
        runtime_package_json_sha256: digest("6"),
        package_dist_sha256: manifest.expected.dist_sha256,
        closure_sha256: manifest.expected.closure_sha256,
        closure_package_count: 148,
    };
    const final = {
        schema: FINAL_SCHEMA,
        result: "pass",
        pass: "B0",
        classification: CLASSIFICATION,
        authoritative: false,
        trust_boundary: {...TRUST_BOUNDARY},
        runtime: {
            image: manifest.container.image,
            platform: "linux/amd64",
            node: "20.19.2",
            zigbee2mqtt: "2.12.1",
            zigbee_herdsman: "10.6.1",
            zigbee_herdsman_converters: "26.76.0",
            controller_full_lifecycle_exercised: false,
        },
        bindings,
        counts: {
            cases: 8,
            closure_packages: 148,
            loaders: 1,
            journal_file_count: 1,
            probe_listener_functions_before_stop: 4,
            relevant_listener_functions_before_stop: 6,
            probe_listener_functions_after_probe_stop: 0,
            relevant_listener_functions_after_full_stop: 0,
        },
        security: {
            uid_nonzero: true,
            no_new_privs: true,
            capability_sets_zero: true,
            seccomp_filtering: true,
            read_only_root: true,
            immutable_write_attempts_blocked: true,
            loopback_only: true,
            external_route_absent: true,
            forbidden_host_paths_unavailable: true,
        },
        behavior: {
            prearm: {command_count: 0, journal_file_count: 0},
            armed: {
                arm_immediate_command_count: 0,
                command_count_after_two_physical_frames: 1,
                exact_tuya_noop: true,
                exact_expected_noop_sequence: true,
                complete_durable_phase_history_observed: true,
                challenge_phase_absent: true,
                durable_phase_history: ["awaiting_physical_target_1", "awaiting_physical_target_2", "awaiting_noop_response"],
                arm_journal_canonical_match: true,
                arm_journal_phase_physical1: true,
                arm_journal_file_count: 1,
            },
            journal: {
                file_count: 1,
                regular_file: true,
                nlink_one: true,
                mode_0600: true,
                exact_data_root_location: true,
                namespace_uid_zero: false,
                canonical_readback_match: true,
                temp_file_count: 0,
            },
            listeners: {
                emitter_counts_before_stop: {deviceMessage: 1, entityRenamed: 1, groupMembersChanged: 1, mqttMessage: 2, mqttMessagePublished: 1},
                emitter_counts_after_probe_stop: {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 1, mqttMessagePublished: 1},
                emitter_counts_after_full_stop: {deviceMessage: 0, entityRenamed: 0, groupMembersChanged: 0, mqttMessage: 0, mqttMessagePublished: 0},
                emitter_callbacks_removed: true,
                class_key_registry_entries_before_stop: 4,
                class_key_registry_entries_after_stop: 4,
                class_key_bookkeeping_retained: true,
                collision_class_key_registry_entries: 8,
                callback_registry_cleanup_proven: false,
            },
            collision: {
                test_preflight_byte_identical_collision_rejected: true,
                real_loader_sequential_same_class_replaced: true,
                runtime_collision_enforcement_proven: false,
                authority_granted: false,
            },
            stop_remove: {
                bounded_stop: true,
                listeners_removed_before_delete: true,
                out_of_band_delete: true,
                dynamic_mqtt_save_remove_used: false,
                retained_empty_array: true,
            },
            adversarial: {
                existing_journal_rejected: true,
                existing_temp_rejected: true,
                existing_symlink_rejected: true,
                duplicate_source_rejected: true,
                journal_noncanonical_rejected: true,
                journal_link_rejected: true,
                journal_mode_rejected: true,
                listener_leak_rejected: true,
            },
        },
        prohibited: {
            guarded_surfaces: GUARDED_SURFACES,
            static_not_used_surfaces: STATIC_NOT_USED_SURFACES,
            containment_only_surfaces: CONTAINMENT_ONLY_SURFACES,
            syscall_tracing_performed: false,
        },
        fetch_host_allowlist_enforced: false,
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
        claim_limits: [...CLAIM_LIMITS],
    };
    final.evidence_digest = sha256Bytes(Buffer.from(canonical(final), "utf8"));
    return final;
}

async function fdSelfTest(launcherPath) {
    const {createServer, connect} = await import("node:net");
    const server = createServer();
    await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
    });
    const socket = connect(server.address().port, "127.0.0.1");
    await new Promise((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
    });
    const child = spawnSync(launcherPath, ["--fd-probe"], {
        env: {PATH: process.env.PATH ?? "/usr/bin:/bin"},
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe", socket._handle.fd],
        timeout: 5000,
    });
    socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    gate(child.status === 1 && child.stderr === "", "fd_self_test");
    const value = JSON.parse(child.stdout);
    validateFailureObject(value);
    gate(value.failure_code === "inherited_fd", "fd_self_test");
}

async function selfTests(launcherPath, harnessText, sourceText, manifest, manifestDigest) {
    const valid = tarFixture([tarHeader("package/file.txt", "0", Buffer.from("safe"))]);
    gate(parseStrictTarGzip(valid).length === 1, "tar_self_test");
    const bad = [
        tarFixture([tarHeader("package/link", "1", Buffer.alloc(0), 0o644, "package/file")]),
        tarFixture([tarHeader("package/link", "2", Buffer.alloc(0), 0o644, "package/file")]),
        tarFixture([tarHeader("package/fifo", "6")]),
        tarFixture([tarHeader("package/file"), tarHeader("package/file")]),
        tarFixture([tarHeader("package/../escape")]),
        tarFixture([tarHeader("package/file")], Buffer.from("nonzero")),
    ];
    for (const fixture of bad) {
        let rejected = false;
        try {
            parseStrictTarGzip(fixture);
        } catch (error) {
            rejected = error instanceof VerifyError;
        }
        gate(rejected, "tar_self_test");
    }
    const resolutionFixture = (resolution, fields = []) => [
        "packages:",
        "  file-uri-to-path@2.0.0:",
        `    resolution: ${resolution}`,
        ...fields.map((field) => `    ${field}`),
        "    description: \"an unrelated path: and https://example.invalid word\"",
        "",
    ].join("\n");
    validatePackageResolutions(resolutionFixture("{integrity: sha512-AAAA==}"));
    validatePackageResolutions([
        "packages:",
        "  path:",
        "    resolution: {integrity: sha512-AAAA==}",
        "",
    ].join("\n"));
    for (const field of ["path: ../local", "tarball: archive.tgz", "repo: owner/repo", "directory: package"]) {
        let rejected = false;
        try {
            validatePackageResolutions(resolutionFixture("{integrity: sha512-AAAA==}", [field]));
        } catch (error) {
            rejected = error instanceof VerifyError && error.code === "lock_external_resolution";
        }
        gate(rejected, "lock_resolution_self_test");
    }
    for (const value of [
        "http://example.invalid/archive.tgz",
        "https://example.invalid/archive.tgz",
        "git+https://example.invalid/repo.git",
        "file:../local",
        "link:../local",
        "workspace:*",
    ]) {
        let rejected = false;
        try {
            validatePackageResolutions(resolutionFixture(value));
        } catch (error) {
            rejected = error instanceof VerifyError && error.code === "lock_external_resolution";
        }
        gate(rejected, "lock_resolution_self_test");
    }
    let malformedResolutionRejected = false;
    try {
        validatePackageResolutions(resolutionFixture("{integrity: sha1-deadbeef}"));
    } catch (error) {
        malformedResolutionRejected = error instanceof VerifyError && error.code === "lock_resolution_shape";
    }
    gate(malformedResolutionRejected, "lock_resolution_self_test");
    const expectDownloadFailure = async (operation, expected) => {
        let actual = "no_failure";
        try {
            await operation();
        } catch (error) {
            actual = error instanceof VerifyError ? error.code : "unexpected";
        }
        gate(actual === expected, "package_download_self_test");
    };
    const downloadPayload = Buffer.from("safe", "utf8");
    const downloadContract = {
        tarball_url: PACKAGE_DOWNLOAD_SPECS.z2m.tarball_url,
        filename: PACKAGE_DOWNLOAD_SPECS.z2m.filename,
        sha512_sri: sha512Sri(downloadPayload),
        compressed_size: downloadPayload.length,
        max_bytes: 8,
    };
    const downloadResponse = (overrides = {}) => ({
        statusCode: 200,
        headers: {"content-length": String(downloadPayload.length)},
        chunks: [downloadPayload.subarray(0, 2), downloadPayload.subarray(2)],
        destroy() {},
        async *[Symbol.asyncIterator]() {
            for (const chunk of this.chunks) yield chunk;
        },
        ...overrides,
    });
    const downloadSink = () => {
        const state = {chunks: [], synced: false};
        return {
            state,
            sink: {
                async write(bytes) { state.chunks.push(Buffer.from(bytes)); },
                async sync() { state.synced = true; },
            },
        };
    };
    const successfulSink = downloadSink();
    await consumePackageResponse(downloadResponse(), downloadContract, successfulSink.sink);
    gate(Buffer.concat(successfulSink.state.chunks).equals(downloadPayload) && successfulSink.state.synced, "package_download_self_test");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse({statusCode: 302}), downloadContract, downloadSink().sink), "download_redirect");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse({statusCode: 404}), downloadContract, downloadSink().sink), "download_status");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse({headers: {"content-length": "5"}}), downloadContract, downloadSink().sink), "download_length");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse({chunks: [Buffer.from("safer")], headers: {}}), downloadContract, downloadSink().sink), "download_overrun");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse({headers: {}}), {...downloadContract, compressed_size: 8, max_bytes: 3}, downloadSink().sink), "download_overrun");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse({chunks: [Buffer.from("saf")], headers: {}}), downloadContract, downloadSink().sink), "download_truncated");
    await expectDownloadFailure(() => consumePackageResponse(downloadResponse(), {...downloadContract, sha512_sri: `sha512-${Buffer.alloc(64).toString("base64")}`}, downloadSink().sink), "download_integrity");
    const exactDownloadContract = packageDownloadContract(manifest, "z2m");
    const exactRequestOptions = packageDownloadRequestOptions("z2m", exactDownloadContract);
    exactKeys(exactRequestOptions, ["protocol", "hostname", "port", "method", "path", "headers", "agent"], "package_download_self_test");
    gate(exactRequestOptions.protocol === "https:" && exactRequestOptions.hostname === "registry.npmjs.org" && exactRequestOptions.port === 443, "package_download_self_test");
    gate(exactRequestOptions.method === "GET" && exactRequestOptions.agent === false && exactRequestOptions.path === "/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz", "package_download_self_test");
    gate(!Object.hasOwn(exactRequestOptions, "proxy") && !Object.hasOwn(exactRequestOptions, "auth"), "package_download_self_test");
    const downloaderSource = [packageDownloadRequestOptions, transferPackage, downloadPackageToPath].map((item) => item.toString()).join("\n");
    gate(downloaderSource.includes("https.request") && downloaderSource.includes('method: "GET"'), "package_download_self_test");
    for (const forbidden of ["process.env", "HTTP_PROXY", "HTTPS_PROXY", "http.request", "fetch(", "error.message", "console.", "process.stderr"]) {
        gate(!downloaderSource.includes(forbidden), "package_download_self_test");
    }
    for (const tarballUrl of [
        "http://registry.npmjs.org/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz",
        "https://example.invalid/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz",
        "https://registry.npmjs.org:444/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz",
        "https://user@registry.npmjs.org/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz",
        "https://registry.npmjs.org/wrong/-/zigbee2mqtt-2.12.1.tgz",
        "https://registry.npmjs.org/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz?query=1",
        "https://registry.npmjs.org/zigbee2mqtt/-/zigbee2mqtt-2.12.1.tgz#fragment",
    ]) {
        await expectDownloadFailure(async () => packageDownloadRequestOptions("z2m", {...exactDownloadContract, tarball_url: tarballUrl}), "download_url");
    }
    await expectDownloadFailure(async () => packageDownloadSpec("wrong"), "download_kind");
    await expectDownloadFailure(async () => packageDownloadRequestOptions("z2m", {...exactDownloadContract, filename: "wrong.tgz"}), "download_contract");
    let duplicateUnlink = false;
    await expectDownloadFailure(() => downloadPackageToPath(manifest, "z2m", `/out/${exactDownloadContract.filename}`, {
        async openOutput() {
            const error = new Error("private duplicate path");
            error.code = "EEXIST";
            throw error;
        },
        async unlinkOutput() { duplicateUnlink = true; },
        async transfer() { throw new Error("unreachable"); },
    }), "download_destination_exists");
    gate(!duplicateUnlink, "package_download_self_test");
    let partialClosed = false;
    let partialUnlinked = false;
    let partialMode = 0;
    const partialHandle = {
        async chmod(mode) { partialMode = mode; },
        async write(bytes, offset, length) { return {bytesWritten: length}; },
        async sync() {},
        async close() { partialClosed = true; },
    };
    await expectDownloadFailure(() => downloadPackageToPath(manifest, "z2m", `/out/${exactDownloadContract.filename}`, {
        async openOutput(output, flags, mode) {
            gate(output === `/out/${exactDownloadContract.filename}` && flags === "wx" && mode === 0o600, "package_download_self_test");
            return partialHandle;
        },
        async unlinkOutput(output) {
            gate(output === `/out/${exactDownloadContract.filename}`, "package_download_self_test");
            partialUnlinked = true;
        },
        async transfer(kind, contract, sink) {
            gate(kind === "z2m" && same(contract, exactDownloadContract), "package_download_self_test");
            await sink.write(Buffer.from("partial", "utf8"));
            throw new VerifyError("download_integrity");
        },
    }), "download_integrity");
    gate(partialClosed && partialUnlinked && partialMode === 0o600, "package_download_self_test");
    await expectDownloadFailure(() => downloadPackageToPath(manifest, "z2m", "/out/wrong.tgz", {
        async openOutput() { throw new Error("unreachable"); },
    }), "download_destination");
    let timeoutOptions;
    let timeoutDestroyed = false;
    let timeoutCleared = false;
    await expectDownloadFailure(() => transferPackage("z2m", exactDownloadContract, downloadSink().sink, {
        request(options) {
            timeoutOptions = options;
            return {
                once() { return this; },
                end() {},
                destroy() { timeoutDestroyed = true; },
            };
        },
        setTimeout(callback, milliseconds) {
            gate(milliseconds === PACKAGE_DOWNLOAD_TIMEOUT_MS, "package_download_self_test");
            queueMicrotask(callback);
            return "timer";
        },
        clearTimeout(timer) {
            gate(timer === "timer", "package_download_self_test");
            timeoutCleared = true;
        },
    }), "download_timeout");
    gate(timeoutDestroyed && timeoutCleared && same(timeoutOptions, exactRequestOptions), "package_download_self_test");
    gate(PACKAGE_DOWNLOAD_SUCCESS_TOKEN === '{"result":"pass","schema":"true-family-pass-b0-package-download-v1"}\n', "package_download_self_test");
    gate(packageDownloadFailureToken("download_status") === '{"failure_code":"download_status","result":"fail","schema":"true-family-pass-b0-package-download-failure-v1"}\n', "package_download_self_test");
    gate(packageDownloadFailureToken("private raw error") === packageDownloadFailureToken("download_failed"), "package_download_self_test");
    const verifierSourceText = fs.readFileSync(fileURLToPath(import.meta.url), "utf8");
    const declaredModes = [...verifierSourceText.matchAll(/if \(mode === "(--[a-z-]+)"\)/gu)].map((match) => match[1]).sort();
    const expectedModes = [...Object.keys(VERIFIER_MODE_FAILURE_CODES), "--download-package", "--classify-pnpm"].sort();
    gate(same(declaredModes, expectedModes), "verifier_failure_mode_coverage");
    const invokedSource = verifierSourceText.slice(verifierSourceText.lastIndexOf("const invoked = process.argv"));
    gate(invokedSource.includes('mode !== "--download-package" && mode !== "--classify-pnpm"') && invokedSource.includes("verifierFailureToken(publicVerifierFailureCode(error, mode))"), "verifier_failure_source");
    for (const forbidden of ["error.message", "error.stack", "process.stderr", "console."]) gate(!invokedSource.includes(forbidden), "verifier_failure_source");
    const launcher = fs.readFileSync(launcherPath, "utf8");
    const original = normalizedLauncherDigestBytes(launcher).digest;
    gate(normalizedLauncherDigestBytes(`${launcher}\n# mutation\n`).digest !== original, "launcher_mutation_self_test");
    const exactLogFlags = "LOG_FLAGS=(\n  --log-driver=json-file\n  --log-opt=max-size=1m\n  --log-opt=max-file=1\n)";
    gate(launcher.includes(exactLogFlags) && !launcher.includes("--log-driver=local") && !launcher.includes("--log-driver=none"), "attach_log_policy_source");
    gate((launcher.match(/--log-driver=json-file/gu) ?? []).length === 1 && (launcher.match(/--log-opt=max-size=1m/gu) ?? []).length === 1 && (launcher.match(/--log-opt=max-file=1/gu) ?? []).length === 1, "attach_log_policy_source");
    gate((launcher.match(/\$\{LOG_FLAGS\[@\]\}/gu) ?? []).length === 1, "attach_log_policy_source");
    gate((launcher.match(/start -a/gu) ?? []).length === 1, "attach_log_policy_source");
    const shellArray = (name) => {
        const match = launcher.match(new RegExp(`${name}=\\(\\n([\\s\\S]*?)\\n\\)`, "u"));
        gate(match !== null, "nproc_policy_source");
        return match[1];
    };
    const commonFlags = shellArray("COMMON_FLAGS");
    const producerFlags = shellArray("PRODUCER_FLAGS");
    const runtimeFlags = shellArray("RUNTIME_FLAGS");
    const pnpmFailureSuffixes = shellArray("PNPM_FIXED_FAILURE_SUFFIXES").split("\n").map((line) => line.trim()).filter(Boolean);
    gate(same(pnpmFailureSuffixes, PNPM_FIXED_FAILURE_SUFFIXES), "pnpm_classifier_source");
    gate(commonFlags.includes("--pids-limit=64") && commonFlags.includes("--memory=768m") && commonFlags.includes("--memory-swap=768m") && !commonFlags.includes("--ulimit=nproc="), "nproc_policy_source");
    gate(producerFlags.includes("--user=\"$HOST_UID:$HOST_GID\"") && !producerFlags.includes("--ulimit=nproc="), "nproc_policy_source");
    gate(runtimeFlags.includes("--user=65532:65532") && runtimeFlags.includes("--ulimit=nproc=64:64"), "nproc_policy_source");
    const producerTmpfs = '--tmpfs="/tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777,uid=$HOST_UID,gid=$HOST_GID"';
    const runtimeTmpfs = "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777,uid=65532,gid=65532";
    gate(producerFlags.includes(producerTmpfs) && runtimeFlags.includes(runtimeTmpfs), "tmpfs_policy_source");
    gate((launcher.match(/--tmpfs="?\/tmp:/gu) ?? []).length === 2 && (launcher.match(/size=268435456,mode=1777/gu) ?? []).length === 2, "tmpfs_policy_source");
    gate(!launcher.includes("size=67108864,mode=1777") && !launcher.includes("/tmp:rw,exec") && !launcher.includes("/tmp:rw,noexec,nosuid,nodev,mode=1777"), "tmpfs_policy_source");
    const exactTmpfs = "rw,noexec,nosuid,nodev,size=268435456,mode=1777,uid=1000,gid=1001";
    validateTmpfsTmp(exactTmpfs, "1000", "1001");
    for (const invalidTmpfs of [
        "rw,noexec,nosuid,nodev,size=67108864,mode=1777,uid=1000,gid=1001",
        "rw,noexec,nosuid,nodev,mode=1777,uid=1000,gid=1001",
        "rw,exec,nosuid,nodev,size=268435456,mode=1777,uid=1000,gid=1001",
    ]) {
        let rejected = false;
        try {
            validateTmpfsTmp(invalidTmpfs, "1000", "1001");
        } catch (error) {
            rejected = error instanceof VerifyError;
        }
        gate(rejected, "tmpfs_policy_self_test");
    }
    gate((launcher.match(/--ulimit=nproc=/gu) ?? []).length === 1, "nproc_policy_source");
    gate((launcher.match(/--ulimit=nproc=64:64/gu) ?? []).length === 1, "nproc_policy_source");
    gate(!launcher.includes("--ulimit=nproc=16:16") && !launcher.includes("--pids-limit=16"), "nproc_policy_source");
    gate(!launcher.includes("npm_pack") && !launcher.includes("npm pack") && !launcher.includes("/usr/local/bin/npm") && !launcher.includes("NPM_CONFIG") && !launcher.includes("npm_config"), "package_fetch_source");
    gate(!launcher.includes("--userconfig") && !launcher.includes("--globalconfig") && !launcher.includes("/config/"), "package_fetch_source");
    const packageFetchSource = launcher.slice(launcher.indexOf("for kind in z2m herdsman converters pnpm"), launcher.indexOf('local z2m_tar="$fetch/zigbee2mqtt-2.12.1.tgz"'));
    for (const required of [
        "run_disposable package_fetch",
        '--network="$network"',
        "target=/verifier,readonly",
        "target=/input,readonly",
        "target=/out",
        "--entrypoint=/usr/local/bin/node",
        "--download-package",
        "/input/physical_probe_pass_b_manifest.json",
        "zigbee2mqtt-2.12.1.tgz",
        "zigbee-herdsman-10.6.1.tgz",
        "zigbee-herdsman-converters-26.76.0.tgz",
        "pnpm-10.18.3.tgz",
    ]) gate(packageFetchSource.includes(required), "package_fetch_source");
    for (const forbidden of ["--env", "HOME=", "target=/source", "--workdir", ".npmrc"]) gate(!packageFetchSource.includes(forbidden), "package_fetch_source");
    gate(launcher.includes("for upstream_file in package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc") && launcher.includes("cp /source/.npmrc /tmp/project/"), "package_fetch_source");
    gate(launcher.includes("/tool/bin/pnpm.cjs fetch") && launcher.includes("/tool/bin/pnpm.cjs install"), "package_fetch_source");
    const pnpmFetchSource = launcher.slice(launcher.indexOf('name="tf-pass-b0-$RUN_TOKEN-r$ordinal-pnpm-fetch"'), launcher.indexOf('assert_host_owned_tree "$store_fetch"'));
    const pnpmInstallSource = launcher.slice(launcher.indexOf('name="tf-pass-b0-$RUN_TOKEN-r$ordinal-pnpm-install"'), launcher.indexOf('[ ! -e "$install/lifecycle-canary" ]'));
    for (const [phase, source] of [["fetch", pnpmFetchSource], ["install", pnpmInstallSource]]) {
        for (const required of [
            "target=/verifier,readonly",
            "--env CI=true",
            "--entrypoint=/bin/sh",
            "--reporter=ndjson",
            `--classify-pnpm ${phase}`,
            `pnpm-${phase}.stdout.ndjson`,
            `pnpm-${phase}.stderr.ndjson`,
            '>"$stdout" 2>"$stderr"',
            'status=$?',
            'exit "$status"',
        ]) gate(source.includes(required), "pnpm_classifier_source");
    }
    gate(!launcher.includes("--reporter=silent") && (launcher.match(/--reporter=ndjson/gu) ?? []).length === 2, "pnpm_classifier_source");
    gate((launcher.match(/--classify-pnpm/gu) ?? []).length === 2, "pnpm_classifier_source");
    gate((launcher.match(/--env CI=true/gu) ?? []).length === 2, "pnpm_classifier_source");
    gate(launcher.includes('[[ "$pnpm_suffix" =~ ^[a-z0-9_]{1,40}$ ]]') && launcher.includes('[ "${#classification}" -le 64 ]'), "pnpm_classifier_source");
    const selfCheckBranch = launcher.slice(launcher.indexOf('  "--self-check")'), launcher.indexOf('  "--shell-self-check")'));
    gate(selfCheckBranch.includes('node_bounded 25s "$VERIFIER" --self-check'), "static_self_check_source");
    for (const forbidden of ["docker", "RUNNER_TEMP", "mktemp", "ROOT="]) {
        gate(!selfCheckBranch.includes(forbidden), "static_self_check_source");
    }
    for (const assertion of [
        'seal_readonly_file "$archive"',
        'assert_host_owned_tree "$run_root/extract-z2m"',
        'assert_host_owned_tree "$run_root/extract-pnpm"',
        'assert_host_owned_tree "$store_fetch"',
        'assert_writable_work_tree "$install"',
        'assert_host_owned_tree "$install"',
        'assert_host_owned_tree "$install/node_modules"',
        'seal_readonly_tree "$run_root/mount/z2m"',
        'seal_readonly_tree "$run_root/mount/input"',
        'seal_readonly_tree "$run_root/verification-input"',
    ]) {
        gate(launcher.includes(assertion), "actual_run_ownership_source");
    }
    for (const mount of ["/input", "/z2m", "/harness", "/verifier", "/launcher", "/upstream", "/runtime", "/"]) {
        gate(harnessText.includes(`"${mount}"`), "actual_run_immutable_source");
    }
    gate(harnessText.includes("immutable_write_attempts_blocked: immutableWriteAttemptsBlocked && immutableMountsReadOnly"), "actual_run_immutable_source");
    validateAttachLogConfig({Type: "json-file", Config: {"max-file": "1", "max-size": "1m"}});
    for (const invalidLogConfig of [
        {Type: "none", Config: {}},
        {Type: "local", Config: {"max-file": "1", "max-size": "1m"}},
        {Type: "json-file", Config: {"max-file": "1", "max-size": "2m"}},
        {Type: "json-file", Config: {"max-file": "2", "max-size": "1m"}},
        {Type: "json-file", Config: {"max-size": "1m"}},
        {Type: "json-file", Config: {"max-file": "1", "max-size": "1m", extra: "true"}},
    ]) {
        let rejected = false;
        try {
            validateAttachLogConfig(invalidLogConfig);
        } catch (error) {
            rejected = error instanceof VerifyError;
        }
        gate(rejected, "attach_log_policy_self_test");
    }
    const startState = (overrides = {}) => JSON.stringify({
        Status: "exited",
        Running: false,
        OOMKilled: false,
        ExitCode: 0,
        Error: "",
        ...overrides,
    });
    for (const stage of START_STAGES) {
        gate(classifyStageStart(stage, 0, 0, "untrusted successful output", startState()) === "pass", "container_start_classifier_self_test");
        gate(classifyStageStart(stage, 1, 0, "untrusted private process output", startState({ExitCode: 1})) === `${stage}_process_exit`, "container_start_classifier_self_test");
    }
    for (const code of PACKAGE_DOWNLOAD_FAILURE_CODES) {
        gate(classifyStageStart("package_fetch", 1, 0, packageDownloadFailureToken(code), startState({ExitCode: 1})) === `package_fetch_${code}`, "container_start_classifier_self_test");
    }
    gate(classifyStageStart("package_fetch", 1, 0, `${packageDownloadFailureToken("download_status")}spoof`, startState({ExitCode: 1})) === "package_fetch_process_exit", "container_start_classifier_self_test");
    for (const code of VERIFIER_FAILURE_CODES) {
        const token = verifierFailureToken(code);
        gate(Buffer.byteLength(token, "utf8") <= VERIFIER_FAILURE_MAX_BYTES, "verifier_failure_self_test");
        gate(verifierFailureClassification(token) === `verifier_${code}`, "verifier_failure_self_test");
        gate(classifyStageStart("verifier", 1, 0, token, startState({ExitCode: 1})) === `verifier_${code}`, "verifier_failure_self_test");
    }
    gate(publicVerifierFailureCode(new VerifyError("arguments"), "--validate-final") === "arguments", "verifier_failure_self_test");
    gate(publicVerifierFailureCode(new VerifyError("private_internal_code"), "--validate-final") === "final_verification_failed", "verifier_failure_self_test");
    gate(publicVerifierFailureCode(new VerifyError("private_internal_code"), "--unknown") === "verifier_failed", "verifier_failure_self_test");
    gate(publicVerifierFailureCode(new VerifyError("/private/path"), "--validate-final") === "verifier_failed", "verifier_failure_self_test");
    gate(publicVerifierFailureCode(new VerifyError("a".repeat(65)), "--validate-final") === "verifier_failed", "verifier_failure_self_test");
    gate(publicVerifierFailureCode(new Error("private raw message"), "--validate-final") === "verifier_failed", "verifier_failure_self_test");
    const malformedVerifierFailures = [
        "{",
        verifierFailureToken("tar_failed").trimEnd(),
        `${verifierFailureToken("tar_failed")}\n`,
        JSON.stringify({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: "tar_failed"}) + "\n",
        canonical({schema: "wrong", result: "fail", failure_code: "tar_failed"}) + "\n",
        canonical({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: "unknown"}) + "\n",
        canonical({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: "/private/path"}) + "\n",
        canonical({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: "a".repeat(56)}) + "\n",
        canonical({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: "tar\nfailed"}) + "\n",
        canonical({schema: VERIFIER_FAILURE_SCHEMA, result: "fail", failure_code: "tar_failed", path: "/private/path"}) + "\n",
        '{"failure_code":"tar_failed","failure_code":"tar_failed","result":"fail","schema":"true-family-pass-b0-verifier-failure-v1"}\n',
        "x".repeat(VERIFIER_FAILURE_MAX_BYTES + 1),
    ];
    for (const output of malformedVerifierFailures) {
        gate(verifierFailureClassification(output) === null, "verifier_failure_self_test");
        gate(classifyStageStart("verifier", 1, 0, output, startState({ExitCode: 1})) === "verifier_process_exit", "verifier_failure_self_test");
    }
    const ndjson = (...values) => `${values.map((value) => JSON.stringify(value)).join("\n")}\n`;
    const knownRootPnpm = ndjson({level: "error", code: "ERR_PNPM_OUTDATED_LOCKFILE"});
    const knownNestedPnpm = ndjson({level: "error", err: {code: "ERR_PNPM_TARBALL_INTEGRITY"}});
    gate(classifyPnpmText("fetch", knownRootPnpm, "") === "pnpm_fetch_outdated_lockfile", "pnpm_classifier_self_test");
    gate(classifyPnpmText("install", "", knownNestedPnpm) === "pnpm_install_tarball_integrity", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({code: "ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY"}), "") === "pnpm_fetch_aborted_remove_modules_dir_no_tty", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({code: "ERR_PNPM_FUTURE_123"}), "") === "pnpm_fetch_future_123", "pnpm_classifier_self_test");
    const maximumPnpmIdentifier = `ERR_PNPM_${"A".repeat(40)}`;
    gate(classifyPnpmText("install", ndjson({code: maximumPnpmIdentifier}), "") === `pnpm_install_${"a".repeat(40)}`, "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "", "") === "pnpm_fetch_diagnostic_empty", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({level: "error", message: "private"}), "") === "pnpm_fetch_diagnostic_no_code", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "{\n", "") === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    const privatePnpm = ndjson({
        level: "error",
        code: "ERR_PNPM_FETCH_404",
        path: "/private/path",
        message: "private\ncontrol",
        package: "@private/package",
        url: "https://private.invalid",
        hash: "private-hash",
        count: 42,
        timing: 99,
    });
    const privatePnpmCode = classifyPnpmText("fetch", privatePnpm, "");
    const privatePnpmToken = pnpmFailureToken(privatePnpmCode);
    gate(privatePnpmCode === "pnpm_fetch_fetch_404", "pnpm_classifier_self_test");
    for (const forbidden of ["private", "package", "hash", "42", "99", "http", "/"]) gate(!privatePnpmToken.includes(forbidden), "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({path: "/private/ERR_PNPM_PATH_INJECTION", message: "ERR_PNPM_MESSAGE_INJECTION"}), "") === "pnpm_fetch_diagnostic_no_code", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "broken /private/ERR_PNPM_PATH_INJECTION?token=secret\n", "") === "pnpm_fetch_path_injection", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", knownRootPnpm + knownRootPnpm, "") === "pnpm_fetch_outdated_lockfile", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", '{ "code": "ERR_PNPM_FETCH_404" }\n', "") === "pnpm_fetch_fetch_404", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", '{"code":"ERR_PNPM_FETCH_404","code":"ERR_PNPM_FETCH_404"}\n', "") === "pnpm_fetch_fetch_404", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({code: "ERR_PNPM_FETCH_404"}, {err: {code: "ERR_PNPM_TARBALL_INTEGRITY"}}), "") === "pnpm_fetch_multiple_codes", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "ERR_PNPM_FETCH_404 ERR_PNPM_TARBALL_INTEGRITY\n", "") === "pnpm_fetch_multiple_codes", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "ERR_PNPM_FETCH_404 ERR_PNPM_FETCH_404\n", "") === "pnpm_fetch_fetch_404", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({code: "err_pnpm_lowercase"}), "") === "pnpm_fetch_diagnostic_no_code", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "err_pnpm_lowercase\n", "") === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({code: `ERR_PNPM_${"A".repeat(41)}`}), "") === "pnpm_fetch_diagnostic_no_code", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", `ERR_PNPM_${"A".repeat(41)}\n`, "") === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "XERR_PNPM_FETCH_404\n", "") === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "ERR_PNPM_FETCH_404lower\n", "") === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "ERR_PNPM_CON\u0000TROL\n", "") === "pnpm_fetch_con", "pnpm_classifier_self_test");
    const controlledPnpm = classifyPnpmText("fetch", "\u0001ERR_PNPM_CONTROL_SAFE\u0002/private/path\n", "");
    gate(controlledPnpm === "pnpm_fetch_control_safe" && !/[\u0000-\u001f/]/u.test(controlledPnpm), "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", "x".repeat(PNPM_DIAGNOSTIC_MAX_BYTES + 1), "") === "pnpm_fetch_diagnostic_oversize", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({message: "x".repeat(PNPM_DIAGNOSTIC_LINE_MAX_BYTES)}), "") === "pnpm_fetch_diagnostic_oversize", "pnpm_classifier_self_test");
    gate(classifyPnpmText("fetch", ndjson({code: "ERR_PNPM_FETCH_404", message: "x".repeat(PNPM_DIAGNOSTIC_LINE_MAX_BYTES)}), "") === "pnpm_fetch_fetch_404", "pnpm_classifier_self_test");
    const diagnosticFiles = new Map([
        ["stdout", Buffer.from(knownRootPnpm)],
        ["stderr", Buffer.alloc(0)],
    ]);
    const regularDiagnosticDependencies = {
        lstatSync(filePath) {
            const bytes = diagnosticFiles.get(filePath);
            return {isFile: () => true, isSymbolicLink: () => false, nlink: 1, size: bytes.length};
        },
        readFileSync(filePath) { return Buffer.from(diagnosticFiles.get(filePath)); },
    };
    gate(classifyPnpmFiles("fetch", "stdout", "stderr", regularDiagnosticDependencies) === "pnpm_fetch_outdated_lockfile", "pnpm_classifier_self_test");
    gate(classifyPnpmFiles("fetch", "stdout", "stderr", {
        ...regularDiagnosticDependencies,
        lstatSync() { return {isFile: () => false, isSymbolicLink: () => true, nlink: 1, size: 1}; },
    }) === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    gate(classifyPnpmFiles("fetch", "stdout", "stderr", {
        ...regularDiagnosticDependencies,
        lstatSync() { return {isFile: () => true, isSymbolicLink: () => false, nlink: 2, size: 1}; },
    }) === "pnpm_fetch_diagnostic_non_ndjson", "pnpm_classifier_self_test");
    gate(classifyPnpmFiles("install", "stdout", "stderr", {
        ...regularDiagnosticDependencies,
        lstatSync() { return {isFile: () => true, isSymbolicLink: () => false, nlink: 1, size: PNPM_DIAGNOSTIC_MAX_BYTES + 1}; },
    }) === "pnpm_install_diagnostic_oversize", "pnpm_classifier_self_test");
    for (const code of [
        ...PNPM_FIXED_STAGE_FAILURE_CODES,
        "pnpm_fetch_future_123",
        `pnpm_install_${"a".repeat(40)}`,
    ]) {
        const phase = code.startsWith("pnpm_fetch_") ? "fetch" : "install";
        const token = pnpmFailureToken(code);
        gate(code.length <= 64 && Buffer.byteLength(token, "utf8") <= 256, "pnpm_classifier_self_test");
        gate(pnpmFailureClassification(phase, token) === code, "pnpm_classifier_self_test");
        gate(classifyStageStart(phase, 1, 0, token, startState({ExitCode: 1})) === code, "pnpm_classifier_self_test");
    }
    for (const code of [
        "pnpm_fetch_UPPERCASE",
        `pnpm_fetch_${"a".repeat(41)}`,
        "pnpm_fetch_private/path",
        "pnpm_fetch_private\npath",
    ]) gate(!allowedPnpmFailureCode(code), "pnpm_classifier_self_test");
    const malformedPnpmFailures = [
        "{",
        pnpmFailureToken("pnpm_fetch_diagnostic_non_ndjson").trimEnd(),
        `${pnpmFailureToken("pnpm_fetch_diagnostic_non_ndjson")}\n`,
        JSON.stringify({schema: PNPM_FAILURE_SCHEMA, result: "fail", failure_code: "pnpm_fetch_diagnostic_non_ndjson"}) + "\n",
        canonical({schema: "wrong", result: "fail", failure_code: "pnpm_fetch_diagnostic_non_ndjson"}) + "\n",
        canonical({schema: PNPM_FAILURE_SCHEMA, result: "fail", failure_code: "pnpm_install_diagnostic_non_ndjson"}) + "\n",
        canonical({schema: PNPM_FAILURE_SCHEMA, result: "fail", failure_code: "pnpm_fetch_/private/path"}) + "\n",
        canonical({schema: PNPM_FAILURE_SCHEMA, result: "fail", failure_code: "pnpm_fetch_\ndiagnostic_no_code"}) + "\n",
        canonical({schema: PNPM_FAILURE_SCHEMA, result: "fail", failure_code: "pnpm_fetch_diagnostic_no_code", path: "/private/path"}) + "\n",
        '{"failure_code":"pnpm_fetch_diagnostic_no_code","failure_code":"pnpm_fetch_diagnostic_no_code","result":"fail","schema":"true-family-pass-b0-pnpm-failure-v1"}\n',
        "x".repeat(257),
    ];
    for (const output of malformedPnpmFailures) {
        gate(pnpmFailureClassification("fetch", output) === null, "pnpm_classifier_self_test");
        gate(classifyStageStart("fetch", 1, 0, output, startState({ExitCode: 1})) === "fetch_process_exit", "pnpm_classifier_self_test");
    }
    const harnessFailureCodes = harnessSmokeFailureCodes(harnessText);
    gate(harnessFailureCodes.includes("prohibited_api"), "runtime_failure_source");
    for (const code of [...harnessFailureCodes, "case_failed", "internal_failure", "future_failure", "a".repeat(40)]) {
        const token = runtimeFailureToken(code);
        gate(Buffer.byteLength(token, "utf8") <= RUNTIME_FAILURE_MAX_BYTES, "runtime_failure_self_test");
        gate(runtimeFailureClassification(token) === `runtime_${code}`, "runtime_failure_self_test");
        gate(classifyStageStart("runtime", 1, 0, token, startState({ExitCode: 1})) === `runtime_${code}`, "runtime_failure_self_test");
        gate(`runtime_${code}`.length <= 64, "runtime_failure_self_test");
    }
    const malformedRuntimeFailures = [
        "{",
        runtimeFailureToken("case_failed").trimEnd(),
        runtimeFailureToken("internal_failure").trimEnd(),
        `${runtimeFailureToken("case_failed")}\n`,
        JSON.stringify({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "case_failed"}) + "\n",
        canonical({schema: "wrong", result: "fail", failure_code: "case_failed"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "pass", failure_code: "case_failed"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "UPPERCASE"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "private/path"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "private.path"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "private\npath"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "a".repeat(41)}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail", failure_code: "case_failed", path: "/private/path"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, result: "fail"}) + "\n",
        canonical({schema: RUNTIME_FAILURE_SCHEMA, failure_code: "case_failed"}) + "\n",
        canonical({result: "fail", failure_code: "case_failed"}) + "\n",
        '{"failure_code":"case_failed","failure_code":"case_failed","result":"fail","schema":"true-family-pass-b0-runtime-failure-v2"}\n',
        `${runtimeFailureToken("case_failed")}${runtimeFailureToken("internal_failure")}`,
        "x".repeat(RUNTIME_FAILURE_MAX_BYTES + 1),
    ];
    for (const output of malformedRuntimeFailures) {
        gate(runtimeFailureClassification(output) === null, "runtime_failure_self_test");
        gate(classifyStageStart("runtime", 1, 0, output, startState({ExitCode: 1})) === "runtime_process_exit", "runtime_failure_self_test");
    }
    const startClassifications = [
        ["unknown", 0, 0, "", startState(), "verifier_unknown"],
        ["runtime", -1, 0, "", startState(), "runtime_unknown"],
        ["runtime", 256, 0, "", startState(), "runtime_unknown"],
        ["runtime", 124, 0, "", startState({Status: "running", Running: true}), "runtime_start_timeout"],
        ["runtime", 137, 0, "", startState({Status: "running", Running: true}), "runtime_start_timeout"],
        ["runtime", 124, 0, "private timeout output", startState({ExitCode: 124}), "runtime_process_exit"],
        ["runtime", 137, 0, "private signal output", startState({ExitCode: 137}), "runtime_process_exit"],
        ["fetch", 1, 0, "", startState({OOMKilled: true, ExitCode: 137}), "fetch_oom"],
        ["package_fetch", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "error setting rlimit type 6"}), "package_fetch_state_error_rlimit"],
        ["fetch", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "error mounting private bind"}), "fetch_state_error_mount"],
        ["install", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "operation not permitted"}), "install_state_error_permission"],
        ["runtime", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "invalid argument"}), "runtime_state_error_invalid_argument"],
        ["verifier", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "exec format error"}), "verifier_state_error_exec"],
        ["package_fetch", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "error mounting target: no such file or directory"}), "package_fetch_state_error_no_such_file"],
        ["fetch", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "error mounting target: not a directory"}), "fetch_state_error_not_directory"],
        ["install", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "mount failed: read-only file system"}), "install_state_error_readonly"],
        ["runtime", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "cgroup operation not permitted"}), "runtime_state_error_cgroup"],
        ["verifier", 125, 0, "", startState({Status: "created", ExitCode: 128, Error: "AppArmor permission denied"}), "verifier_state_error_security"],
        ["runtime", 125, 0, "private daemon detail", startState({Status: "created", ExitCode: 128, Error: "private daemon detail"}), "runtime_state_error_unknown"],
        ["runtime", 1, 0, runtimeFailureToken("case_failed"), startState({ExitCode: 1}), "runtime_case_failed"],
        ["package_fetch", 1, 0, runtimeFailureToken("case_failed"), startState({ExitCode: 1}), "package_fetch_process_exit"],
        ["runtime", 1, 124, "private output", "private state", "runtime_inspect_timeout"],
        ["runtime", 1, 137, "private output", "private state", "runtime_inspect_timeout"],
        ["runtime", 1, 1, "private output", "private state", "runtime_inspect_failed"],
        ["runtime", 1, 0, "private output", "{", "runtime_inspect_malformed"],
        ["runtime", 1, 0, "private output", JSON.stringify({Status: "exited"}), "runtime_inspect_malformed"],
        ["runtime", 0, 0, "", startState({Status: "running", Running: true}), "runtime_unknown"],
    ];
    for (const [stage, startStatus, inspectStatus, output, state, expected] of startClassifications) {
        const actual = classifyStageStart(stage, startStatus, inspectStatus, output, state);
        gate(actual === expected && !actual.includes("private"), "container_start_classifier_self_test");
    }
    const startContainerSource = launcher.slice(launcher.indexOf("start_container() {"), launcher.indexOf("remove_container_checked() {"));
    const startCapture = startContainerSource.indexOf('capture_expected_status start_status docker_bounded "$seconds" start -a "$name"');
    const stateInspect = startContainerSource.indexOf("capture_expected_status inspect_status docker_bounded 10s inspect --format '{{json .State}}'");
    const classifier = startContainerSource.indexOf('node_bounded 5s "$VERIFIER" --classify-container-start');
    const classifiedFailure = startContainerSource.indexOf('fail "$classification"');
    gate(startCapture >= 0 && stateInspect > startCapture && classifier > stateInspect && classifiedFailure > classifier, "container_start_source");
    gate(!launcher.includes('docker_checked "container_start"') && startContainerSource.includes('>"$output" 2>"$log"') && startContainerSource.includes('2>/dev/null') && !startContainerSource.includes("remove_container_checked"), "container_start_source");
    gate(startContainerSource.includes('runtime_suffix="${classification#runtime_}"') && startContainerSource.includes('[[ "$runtime_suffix" =~ ^[a-z0-9_]{1,40}$ ]]') && startContainerSource.includes('[ "${#classification}" -le 64 ]'), "runtime_failure_source");
    gate(!startContainerSource.includes("|runtime_case_failed") && !verifierSourceText.includes(["const RUNTIME", "CASE_FAILURE"].join("_")), "runtime_failure_source");
    gate(launcher.includes(`printf '%s\\n' '${runtimeFailureToken("case_failed").trimEnd()}'`), "runtime_failure_source");
    const disposableSource = launcher.slice(launcher.indexOf("run_disposable() {"), launcher.indexOf("capture_expected_status IMAGE_PROBE_STATUS"));
    const disposableCreate = disposableSource.indexOf('create_container producer "$name"');
    const disposableStart = disposableSource.indexOf('start_container "$stage"');
    const disposableRemove = disposableSource.indexOf('remove_container_checked "$name"');
    gate(disposableCreate >= 0 && disposableStart > disposableCreate && disposableRemove > disposableStart, "container_start_source");
    for (const stageCall of ["run_disposable package_fetch", "run_disposable fetch", "run_disposable install", "run_disposable verifier", "start_container runtime"]) {
        gate(launcher.includes(stageCall), "container_start_source");
    }
    for (const code of PACKAGE_DOWNLOAD_FAILURE_CODES) gate(launcher.includes(`package_fetch_${code}`), "container_start_source");
    for (const code of VERIFIER_FAILURE_CODES) gate(launcher.includes(`verifier_${code}`), "container_start_source");
    const launcherLines = launcher.split("\n");
    for (let index = 0; index < launcherLines.length; index += 1) {
        if (launcherLines[index].trim() !== "set +e") continue;
        gate(!launcherLines.slice(index + 1, index + 7).some((line) => line.includes('="$?"')), "expected_status_source");
    }
    gate(launcher.includes('capture_expected_status() {') && launcher.includes('if "$@"; then'), "expected_status_source");
    gate(launcher.includes('capture_expected_status status docker_bounded') && launcher.includes('capture_expected_status status close_fds_exec timeout'), "expected_status_source");
    gate(launcher.includes('capture_expected_status DOCKER_INFO_STATUS docker_info_pre_root'), "expected_status_source");
    gate(launcher.includes('capture_expected_status IMAGE_PROBE_STATUS docker_bounded 15s image inspect'), "expected_status_source");
    gate(launcher.includes('if LEFTOVER_CONTAINERS="$(close_fds_exec timeout'), "expected_status_source");
    gate(launcher.includes('if LEFTOVER_NETWORKS="$(close_fds_exec timeout'), "expected_status_source");
    const finalRootRemoval = launcher.lastIndexOf('rm -rf -- "$FINAL_ROOT"');
    const finalPassOutput = launcher.lastIndexOf('printf \'%s\\n\' "$FINAL_EVIDENCE"');
    gate(finalRootRemoval >= 0 && finalPassOutput > finalRootRemoval, "attach_log_policy_source");
    gate(launcher.includes('trap \'fail "$ACTIVE_FAILURE_CODE"\' ERR'), "unexpected_failure_source");
    const shellSelfCheck = spawnSync(launcherPath, ["--shell-self-check"], {encoding: "utf8", env: {PATH: process.env.PATH}});
    gate(shellSelfCheck.status === 0 && shellSelfCheck.stderr === "", "shell_self_check");
    gate(shellSelfCheck.stdout === '{"result":"pass","schema":"true-family-pass-b0-shell-self-check-v1"}\n', "shell_self_check");
    const validateFinalCalls = launcher.split("\n").filter((line) => line.includes("--validate-final"));
    gate(validateFinalCalls.length === 3, "validate_final_launcher_arguments");
    for (const line of validateFinalCalls) {
        const suffix = line.slice(line.indexOf("--validate-final") + "--validate-final".length);
        gate([...suffix.matchAll(/"\$[^"]+"/gu)].length === 4, "validate_final_launcher_arguments");
    }
    gate(validateFinalCalls.some((line) => line.includes('"$EVIDENCE_ONE"') && line.includes('"$ROOT/run-1/mount/input/runtime_stage.json"')), "validate_final_launcher_stage");
    gate(validateFinalCalls.some((line) => line.includes('"$EVIDENCE_TWO"') && line.includes('"$ROOT/run-2/mount/input/runtime_stage.json"')), "validate_final_launcher_stage");
    for (const unsafe of [
        '{"extra":true}',
        '{"path":"/home/runner/work"}',
        '{"device":"0xa4c1380000000001"}',
        JSON.stringify({text: sourceText.slice(0, 128)}),
        '{"authorization":"sensitive"}',
        '{"url":"https://example.invalid"}',
        '"\u001b[31m"',
        "x".repeat(MAX_RAW_BYTES + 1),
        '::error title=unsafe::message',
    ]) {
        let rejected = false;
        try {
            scanSanitizedText(unsafe, sourceText);
            const value = JSON.parse(unsafe);
            exactKeys(value, [], "extra_field_self_test");
        } catch (error) {
            rejected = error instanceof VerifyError || error instanceof SyntaxError;
        }
        gate(rejected, "output_self_test");
    }
    const validFinal = finalSelfTestFixture(manifest, manifestDigest);
    const validText = canonical(validFinal);
    validateFinalBytes(Buffer.from(validText), manifest, sourceText, manifestDigest, validFinal.bindings);
    for (const mutate of [
        (value) => { value.security.extra = true; },
        (value) => { value.behavior.collision.authority_granted = true; },
        (value) => { value.bindings.verifier_sha256 = "f".repeat(64); },
    ]) {
        const forged = structuredClone(validFinal);
        mutate(forged);
        delete forged.evidence_digest;
        forged.evidence_digest = sha256Bytes(Buffer.from(canonical(forged), "utf8"));
        let rejected = false;
        try {
            validateFinalBytes(Buffer.from(canonical(forged)), manifest, sourceText, manifestDigest, validFinal.bindings);
        } catch (error) {
            rejected = error instanceof VerifyError;
        }
        gate(rejected, "forged_final_self_test");
    }
    const duplicate = validText.replace('"authoritative":false', '"authoritative":false,"authoritative":false');
    let duplicateRejected = false;
    try {
        validateFinalBytes(Buffer.from(duplicate), manifest, sourceText, manifestDigest, validFinal.bindings);
    } catch (error) {
        duplicateRejected = error instanceof VerifyError;
    }
    gate(duplicateRejected, "duplicate_final_self_test");
    let reorderedRejected = false;
    try {
        validateFinalBytes(Buffer.from(JSON.stringify(validFinal)), manifest, sourceText, manifestDigest, validFinal.bindings);
    } catch (error) {
        reorderedRejected = error instanceof VerifyError;
    }
    gate(reorderedRejected, "reordered_final_self_test");
    const missingStage = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--validate-final", "final", "manifest", "artifact"], {encoding: "utf8"});
    gate(missingStage.status === 1 && missingStage.stdout === verifierFailureToken("arguments") && missingStage.stderr === "", "validate_final_arguments_self_test");
    const invalidMode = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--invalid-mode"], {encoding: "utf8"});
    gate(invalidMode.status === 1 && invalidMode.stdout === verifierFailureToken("mode") && invalidMode.stderr === "", "verifier_failure_self_test");
    const packageFailure = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--download-package"], {encoding: "utf8"});
    gate(packageFailure.status === 1 && packageFailure.stdout === packageDownloadFailureToken("download_arguments") && packageFailure.stderr === "", "package_download_self_test");
    gate(!packageFailure.stdout.includes(VERIFIER_FAILURE_SCHEMA) && packageFailure.stdout.split("\n").length === 2, "package_download_self_test");
    const pnpmFailure = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--classify-pnpm"], {encoding: "utf8"});
    gate(pnpmFailure.status === 1 && pnpmFailure.stdout === pnpmFailureToken("pnpm_fetch_diagnostic_non_ndjson") && pnpmFailure.stderr === "", "pnpm_classifier_self_test");
    gate(!pnpmFailure.stdout.includes(VERIFIER_FAILURE_SCHEMA) && pnpmFailure.stdout.split("\n").length === 2, "pnpm_classifier_self_test");
    const timeoutResult = spawnSync("timeout", ["0.1s", process.execPath, "-e", "setTimeout(()=>{}, 10000)"], {stdio: "ignore"});
    gate(timeoutResult.status === 124, "timeout_self_test");
    await fdSelfTest(launcherPath);
}

async function main() {
    const [mode, ...args] = process.argv.slice(2);
    if (mode === "--self-check") {
        gate(args.length === 5, "arguments");
        const manifest = validateStaticBindings(...args);
        await selfTests(args[1], fs.readFileSync(args[2], "utf8"), fs.readFileSync(args[4], "utf8"), manifest, sha256File(args[0]));
        process.stdout.write(`${canonical({schema: "true-family-pass-b0-self-check-v1", result: "pass", launcher_normalized_sha256: manifest.verifier.launcher_normalized_sha256, harness_sha256: manifest.verifier.harness_sha256, verifier_sha256: manifest.verifier.verifier_sha256})}\n`);
        return;
    }
    if (mode === "--classify-container-start") {
        gate(args.length === 5, "arguments");
        process.stdout.write(`${classifyStageStartFiles(...args)}\n`);
        return;
    }
    if (mode === "--download-package") {
        if (args.length !== 3) {
            process.stdout.write(packageDownloadFailureToken("download_arguments"));
            process.exitCode = 1;
            return;
        }
        try {
            await downloadPackageFile(...args);
            process.stdout.write(PACKAGE_DOWNLOAD_SUCCESS_TOKEN);
        } catch (error) {
            process.stdout.write(packageDownloadFailureToken(error instanceof VerifyError ? error.code : "download_failed"));
            process.exitCode = 1;
        }
        return;
    }
    if (mode === "--classify-pnpm") {
        const code = args.length === 3 ? classifyPnpmFiles(...args) : "pnpm_fetch_diagnostic_non_ndjson";
        process.stdout.write(pnpmFailureToken(code));
        process.exitCode = 1;
        return;
    }
    if (mode === "--validate-tar") {
        gate(args.length === 3, "arguments");
        validateTarFile(...args);
        return;
    }
    if (mode === "--extract-tar") {
        gate(args.length === 4, "arguments");
        extractTar(...args);
        return;
    }
    if (mode === "--verify-upstream") {
        gate(args.length === 4, "arguments");
        verifyUpstream(...args);
        return;
    }
    if (mode === "--prepare-install") {
        gate(args.length === 2, "arguments");
        prepareInstall(...args);
        return;
    }
    if (mode === "--normalize-closure") {
        gate(args.length === 1, "arguments");
        normalizeClosure(args[0]);
        return;
    }
    if (mode === "--tree-evidence") {
        gate(args.length === 2, "arguments");
        process.stdout.write(`${canonical(treeEvidence(args[0], args[1] === "packages"))}\n`);
        return;
    }
    if (mode === "--runtime-hashes") {
        gate(args.length === 0, "arguments");
        process.stdout.write(`${canonical(runtimeHashes())}\n`);
        return;
    }
    if (mode === "--write-stage") {
        gate(args.length === 15, "arguments");
        const output = args.pop();
        writeCanonical(output, makeStage(args));
        return;
    }
    if (mode === "--rehash-stage") {
        gate(args.length === 15, "arguments");
        const stagePath = args.shift();
        rehashStage(stagePath, args);
        return;
    }
    if (mode === "--validate-image-inspect") {
        gate(args.length === 2, "arguments");
        const manifest = readJson(args[1], "manifest_json");
        validateManifest(manifest);
        validateImageInspect(readJson(args[0], "image_inspect_json"), manifest);
        return;
    }
    if (mode === "--verify-run") {
        gate(args.length === 17, "arguments");
        process.stdout.write(verifyRun(...args));
        return;
    }
    if (mode === "--validate-final") {
        gate(args.length === 4, "arguments");
        const [finalPath, manifestPath, artifactPath, stagePath] = args;
        const bytes = fs.readFileSync(finalPath);
        const manifest = readJson(manifestPath, "manifest_json");
        validateManifest(manifest);
        const stage = readJson(stagePath, "stage_json");
        validateStageShape(stage, manifest);
        gate(stage.manifest_sha256 === sha256File(manifestPath), "stage_manifest_digest");
        const expectedBindings = {...stage};
        delete expectedBindings.schema;
        validateFinalBytes(bytes, manifest, fs.readFileSync(artifactPath, "utf8"), sha256File(manifestPath), expectedBindings);
        return;
    }
    throw new VerifyError("mode");
}

const invoked = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (invoked) {
    try {
        await main();
    } catch (error) {
        const mode = process.argv[2];
        if (mode !== "--download-package" && mode !== "--classify-pnpm") {
            process.stdout.write(verifierFailureToken(publicVerifierFailureCode(error, mode)));
        }
        process.exitCode = 1;
    }
}
