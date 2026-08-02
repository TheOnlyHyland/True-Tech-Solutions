#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
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
        "fetch_host_allowlist_enforced",
        "explicit_fetch_targets",
        "limits",
    ], "manifest_container_shape");
    gate(manifest.container.image === IMAGE && manifest.container.index_reference_sha256 === IMAGE_INDEX, "manifest_image");
    gate(manifest.container.platform === "linux/amd64" && manifest.container.fetch_host_allowlist_enforced === false, "manifest_platform");
    gate(manifest.container.producer_user === "host-runner-numeric-nonroot" && manifest.container.runtime_user === "65532:65532", "manifest_users");
    gate(same(manifest.container.explicit_fetch_targets, ["registry.npmjs.org", "github.com"]), "manifest_fetch_targets");
    gate(same(manifest.container.limits, {
        memory_bytes: 805306368,
        memory_swap_bytes: 805306368,
        nano_cpus: 1000000000,
        pids: 64,
        nofile: 1024,
        nproc: 64,
        fsize_bytes: 268435456,
        full_run_seconds: 2040,
        workflow_timeout_minutes: 45,
        runtime_seconds: 240,
        raw_output_bytes: MAX_RAW_BYTES,
    }), "manifest_limits");
    exactKeys(manifest.runtime, ["node", "zigbee2mqtt", "zigbee_herdsman", "zigbee_herdsman_converters", "pnpm"], "manifest_runtime_shape");
    gate(same(manifest.runtime.node, {version: "20.19.2"}), "manifest_node");
    gate(same(manifest.runtime.zigbee2mqtt, {
        version: "2.12.1",
        npm_integrity: "sha512-OucrVP2raFmMEKK+4r7qHOSamAmaM4WI0WYLbLRhZ1s73frVDcppzD/6BHGPWFIalJrxGrdKHYSbRmpQqLUt5w==",
        compressed_size: 349915,
    }), "manifest_z2m");
    gate(same(manifest.runtime.zigbee_herdsman, {
        version: "10.6.1",
        npm_integrity: "sha512-BXy2jai1R6OkJ7gWFwS8J6vKJ7Mm+vfReDcuN+IPCmHdT65oiaZ6oZDY/thjG7ePMHD2m0YD8AZvi7o5LBNPpQ==",
    }), "manifest_herdsman");
    gate(same(manifest.runtime.zigbee_herdsman_converters, {
        version: "26.76.0",
        npm_integrity: "sha512-JSgW/9Yn5xdfUHvyXunKSqoPk7w6wY+0OEzOiqBs/hr67o9YSXKc4joUr/dbRMXJcv7fNlDNDRvIDS41b2758Q==",
    }), "manifest_converters");
    gate(same(manifest.runtime.pnpm, {
        version: "10.18.3",
        npm_integrity: "sha512-u9FubXKG/X4B9rPAs8kyzaKWXAapCDKPdGY/EKmupR8RKe6mFRNL+ZKDGwCeq+Fn7LcAi1l/QP+bx1lGqt+wjQ==",
        compressed_size: 4155290,
    }), "manifest_pnpm");
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
    exactKeys(manifest.verifier, ["launcher_normalization", "launcher_normalized_sha256", "harness_sha256", "verifier_sha256"], "manifest_verifier_shape");
    gate(manifest.verifier.launcher_normalization === "sha256 of launcher UTF-8 bytes after replacing only EXPECTED_LAUNCHER_SHA256=\"<64 lowercase hex>\" with the same assignment containing 64 zeroes", "manifest_launcher_rule");
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

function validateTarFile(kind, archivePath, manifestPath) {
    const manifest = readJson(manifestPath, "manifest_json");
    validateManifest(manifest);
    const contract = packageTarContract(manifest, kind);
    const compressed = fs.readFileSync(archivePath);
    gate(sha512Sri(compressed) === contract.npm_integrity, "tar_integrity");
    if (Object.hasOwn(contract, "compressed_size")) gate(compressed.length === contract.compressed_size, "tar_compressed_size");
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
    gate(!/(?:https?:\/\/|git\+|\btarball:|\brepo:|\bdirectory:|\bpath:)/u.test(lock), "lock_external_resolution");
    const importer = lock.slice(lock.indexOf("  .:\n"), lock.indexOf("    devDependencies:\n"));
    gate((importer.match(/      zigbee-herdsman:\n        specifier: 10\.6\.1\n        version: 10\.6\.1\n/gu) ?? []).length === 1, "lock_herdsman_importer");
    gate((importer.match(/      zigbee-herdsman-converters:\n        specifier: 26\.76\.0\n        version: 26\.76\.0\n/gu) ?? []).length === 1, "lock_converters_importer");
    const packages = lock.slice(lock.indexOf("packages:\n"), lock.indexOf("snapshots:\n"));
    const herdsman = /^  zigbee-herdsman@10\.6\.1:\n    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$/gmu;
    const converters = /^  zigbee-herdsman-converters@26\.76\.0:\n    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$/gmu;
    const herdsmanMatches = [...packages.matchAll(herdsman)];
    const converterMatches = [...packages.matchAll(converters)];
    gate(herdsmanMatches.length === 1 && herdsmanMatches[0][1] === manifest.runtime.zigbee_herdsman.npm_integrity, "lock_herdsman_integrity");
    gate(converterMatches.length === 1 && converterMatches[0][1] === manifest.runtime.zigbee_herdsman_converters.npm_integrity, "lock_converters_integrity");
    for (const line of packages.split("\n").filter((item) => item.trimStart().startsWith("resolution:"))) {
        gate(/^    resolution: \{integrity: sha512-[A-Za-z0-9+/=]+\}$/u.test(line), "lock_resolution_shape");
    }
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
    gate(host.Init === true && host.LogConfig?.Type === "none", "inspect_process");
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
    gate(same(host.Tmpfs ?? {}, {
        "/data": "rw,nosuid,nodev,size=268435456,mode=0700,uid=65532,gid=65532",
        "/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777,uid=65532,gid=65532",
    }), "inspect_tmpfs");
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

async function selfTests(launcherPath, sourceText, manifest, manifestDigest) {
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
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), "true-family-pass-b0-install-"));
    try {
        const source = path.join(installRoot, "source");
        const work = path.join(installRoot, "work");
        fs.mkdirSync(source, {mode: 0o700});
        fs.mkdirSync(work, {mode: 0o700});
        fs.writeFileSync(path.join(source, "package.json"), `${JSON.stringify({name: "fixture", scripts: {start: "node index.js"}}, null, 4)}\n`, {mode: 0o600});
        fs.writeFileSync(path.join(source, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n", {mode: 0o600});
        fs.chmodSync(path.join(source, "package.json"), 0o444);
        fs.chmodSync(path.join(source, "pnpm-lock.yaml"), 0o444);
        fs.chmodSync(source, 0o555);
        const sourceBefore = permissionSnapshot(source);
        prepareInstall(source, work);
        gate(same(permissionSnapshot(source), sourceBefore), "install_self_test_source");
        gate((fs.lstatSync(work).mode & 0o777) === 0o700, "install_self_test_mode");
        gate((fs.lstatSync(path.join(work, "package.json")).mode & 0o777) === 0o600, "install_self_test_mode");
        const packageFile = fs.openSync(path.join(work, "package.json"), "r+");
        fs.closeSync(packageFile);
        gate(readJson(path.join(work, "package.json"), "install_self_test_package").scripts.preinstall.includes("lifecycle-canary"), "install_self_test_package");
    } finally {
        normalizeWritableTree(installRoot);
        fs.rmSync(installRoot, {recursive: true, force: true});
    }
    const launcher = fs.readFileSync(launcherPath, "utf8");
    const original = normalizedLauncherDigestBytes(launcher).digest;
    gate(normalizedLauncherDigestBytes(`${launcher}\n# mutation\n`).digest !== original, "launcher_mutation_self_test");
    const launcherLines = launcher.split("\n");
    for (let index = 0; index < launcherLines.length; index += 1) {
        if (launcherLines[index].trim() !== "set +e") continue;
        gate(!launcherLines.slice(index + 1, index + 7).some((line) => line.includes('="$?"')), "expected_status_source");
    }
    gate(launcher.includes('capture_expected_status() {') && launcher.includes('if "$@"; then'), "expected_status_source");
    gate(launcher.includes('capture_expected_status status docker_bounded') && launcher.includes('capture_expected_status status close_fds_exec timeout'), "expected_status_source");
    gate(launcher.includes('capture_expected_status docker_status docker_info_pre_root') && launcher.includes('capture_expected_status DOCKER_INFO_STATUS docker_info_pre_root'), "expected_status_source");
    gate(launcher.includes('capture_expected_status IMAGE_PROBE_STATUS docker_bounded 15s image inspect'), "expected_status_source");
    gate(launcher.includes('if remaining_containers="$(close_fds_exec timeout') && launcher.includes('if LEFTOVER_CONTAINERS="$(close_fds_exec timeout'), "expected_status_source");
    gate(launcher.includes('if remaining_networks="$(close_fds_exec timeout') && launcher.includes('if LEFTOVER_NETWORKS="$(close_fds_exec timeout'), "expected_status_source");
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
    gate(missingStage.status === 1 && missingStage.stdout === "" && missingStage.stderr === "", "validate_final_arguments_self_test");
    const timeoutResult = spawnSync("timeout", ["0.1s", process.execPath, "-e", "setTimeout(()=>{}, 10000)"], {stdio: "ignore"});
    gate(timeoutResult.status === 124, "timeout_self_test");
    await fdSelfTest(launcherPath);
}

async function main() {
    const [mode, ...args] = process.argv.slice(2);
    if (mode === "--self-check") {
        gate(args.length === 5, "arguments");
        const manifest = validateStaticBindings(...args);
        await selfTests(args[1], fs.readFileSync(args[4], "utf8"), manifest, sha256File(args[0]));
        process.stdout.write(`${canonical({schema: "true-family-pass-b0-self-check-v1", result: "pass", launcher_normalized_sha256: manifest.verifier.launcher_normalized_sha256, harness_sha256: manifest.verifier.harness_sha256, verifier_sha256: manifest.verifier.verifier_sha256})}\n`);
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
        process.exitCode = 1;
    }
}
