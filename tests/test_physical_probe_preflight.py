"""Adversarial tests for the standalone raw-evidence preflight reports."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "physical_probe_preflight_vectors.json"
B1_MANIFEST_PATH = ROOT / "tests" / "fixtures" / "physical_probe_pass_b1_manifest.json"
MANIFEST_PATH = PACKAGE_ROOT / "probe" / "true_family_brt_probe.manifest.json"
EXTENSION_PATH = PACKAGE_ROOT / "probe" / "true_family_brt_probe.mjs"


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
    return importlib.import_module(f"{PACKAGE_NAME}.physical_probe_preflight")


def strict_json_loads(text: str):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    return json.loads(
        text,
        object_pairs_hook=object_pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
    )


def strict_equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            strict_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            strict_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


preflight = load_module()
FIXTURE_TEXT = FIXTURE_PATH.read_text(encoding="utf-8")
LEGACY_VECTORS = strict_json_loads(FIXTURE_TEXT)
B1_MANIFEST = strict_json_loads(B1_MANIFEST_PATH.read_text(encoding="utf-8"))
NOW = LEGACY_VECTORS["now_ms"]


def projection(value):
    result = {}
    for item in fields(value):
        projected = getattr(value, item.name)
        if hasattr(projected, "value"):
            projected = projected.value
        result[item.name] = projected
    return result


def current_vectors():
    """Project the committed v1 fixture through the unreleased v2 ACL fence."""

    result = deepcopy(LEGACY_VECTORS)
    plan = preflight.build_acl_plan(result["scope"])
    result["deployment_snapshot"]["effective_acl"] = preflight._thaw(
        plan.effective_policy
    )
    result["deployment_snapshot"]["fence"]["acl_digest"] = plan.policy_digest
    result["prearm_snapshot"]["deployment_snapshot_digest"] = (
        preflight.canonical_digest(
            result["deployment_snapshot"], domain=preflight._DEPLOYMENT_DIGEST_DOMAIN
        )
    )
    result["prearm_snapshot"]["fence"]["acl_digest_before"] = plan.policy_digest
    result["prearm_snapshot"]["fence"]["acl_digest_after"] = plan.policy_digest

    deployment = preflight.attest_deployment(result["deployment_snapshot"], NOW)
    before_arm = preflight.validate_prearm(
        result["prearm_snapshot"], result["deployment_snapshot"], NOW
    )
    arm_permit = preflight.authorize_arm(
        result["deployment_snapshot"],
        result["prearm_snapshot"],
        result["arm_request_json"],
        NOW,
    )
    result["expected"]["acl_scope_digest"] = plan.scope_digest
    result["expected"]["acl_policy_digest"] = plan.policy_digest
    result["expected"]["fence_digest"] = deployment.fence_digest
    result["expected"]["deployment_attestation"] = projection(deployment)
    result["expected"]["prearm_attestation"] = projection(before_arm)
    result["expected"]["arm_permit"] = projection(arm_permit)
    return result


VECTORS = current_vectors()


def deployment_snapshot():
    return deepcopy(VECTORS["deployment_snapshot"])


def prearm_snapshot():
    return deepcopy(VECTORS["prearm_snapshot"])


def arm_request():
    return deepcopy(VECTORS["arm_request"])


def canonical_arm(data=None):
    return json.dumps(
        arm_request() if data is None else data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def attest(data=None, now_ms=NOW):
    return preflight.attest_deployment(
        deployment_snapshot() if data is None else data, now_ms
    )


def prearm(data=None, deployment=None, now_ms=NOW):
    return preflight.validate_prearm(
        prearm_snapshot() if data is None else data,
        deployment_snapshot() if deployment is None else deployment,
        now_ms,
    )


def permit(deployment=None, before_arm=None, request_json=None, now_ms=NOW):
    return preflight.authorize_arm(
        deployment_snapshot() if deployment is None else deployment,
        prearm_snapshot() if before_arm is None else before_arm,
        VECTORS["arm_request_json"] if request_json is None else request_json,
        now_ms,
    )


def set_path(data, path, value):
    target = data
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return data


def delete_path(data, path):
    target = data
    for part in path[:-1]:
        target = target[part]
    del target[path[-1]]
    return data


class ManifestIdentityTests(unittest.TestCase):
    def test_manifest_is_duplicate_safe_deterministic_strict_v1_projection(self) -> None:
        text = MANIFEST_PATH.read_text(encoding="utf-8")
        manifest = strict_json_loads(text)
        expected = preflight._thaw(preflight.EXPECTED_MANIFEST)
        self.assertTrue(strict_equal(manifest, expected))
        self.assertEqual(text, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertIs(type(manifest["manifest_version"]), int)
        self.assertEqual(
            preflight.MANIFEST_DIGEST, VECTORS["expected"]["manifest_digest"]
        )
        with self.assertRaises(ValueError):
            strict_json_loads(
                text.replace(
                    '"schema": "true-family-brt-probe-manifest-v1",',
                    '"schema": "duplicate",\n  "schema": "true-family-brt-probe-manifest-v1",',
                    1,
                )
            )
        bool_manifest = deepcopy(manifest)
        bool_manifest["manifest_version"] = True
        self.assertFalse(strict_equal(bool_manifest, expected))
        bool_manifest = deepcopy(manifest)
        bool_manifest["deployment"]["fresh_deployment_only"] = 1
        self.assertFalse(strict_equal(bool_manifest, expected))

    def test_fixture_loader_rejects_duplicates_and_preserves_bool_integer_types(self) -> None:
        self.assertEqual(
            FIXTURE_TEXT,
            json.dumps(LEGACY_VECTORS, ensure_ascii=False, indent=2) + "\n",
        )
        self.assertEqual(
            hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest(),
            "cf71efabf14a22fdc0b0fced9b69e5119e026586e774826b0a06d6b70ccb10d1",
        )
        self.assertNotIn("topic_oracle", LEGACY_VECTORS)
        self.assertIs(type(VECTORS["deployment_snapshot"]["manifest_version"]), int)
        self.assertIs(
            type(VECTORS["deployment_snapshot"]["controls"]["frontend_enabled"]),
            bool,
        )
        with self.assertRaises(ValueError):
            strict_json_loads(
                FIXTURE_TEXT.replace(
                    '"now_ms": 1800000002001,',
                    '"now_ms": 0,\n  "now_ms": 1800000002001,',
                    1,
                )
            )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.attest_deployment(
                deepcopy(LEGACY_VECTORS["deployment_snapshot"]), NOW
            )

    def test_manifest_binds_actual_artifact_and_upstream_immutable_refs(self) -> None:
        manifest = strict_json_loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        source = EXTENSION_PATH.read_bytes()
        self.assertEqual(len(source), 164_691)
        self.assertEqual(
            hashlib.sha256(source).hexdigest(),
            "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1",
        )
        self.assertEqual(manifest["artifact"]["byte_length"], len(source))
        self.assertEqual(manifest["artifact"]["sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(
            manifest["runtime"],
            {
                "node": {"version": "20.19.2"},
                "zigbee2mqtt": {
                    "version": "2.12.1",
                    "commit": "aa909a8a62f76e2dd98ace3a172bca88ee56f5fe",
                    "tree": "fd134890cc89e628caa48f6f235862b0bfe40c45",
                    "npm_integrity": "sha512-OucrVP2raFmMEKK+4r7qHOSamAmaM4WI0WYLbLRhZ1s73frVDcppzD/6BHGPWFIalJrxGrdKHYSbRmpQqLUt5w==",
                },
                "zigbee_herdsman": {
                    "version": "10.6.1",
                    "commit": "b9f67e9bc2ba90f93be28fd4c21aa487f941f9a1",
                },
                "zigbee_herdsman_converters": {
                    "version": "26.76.0",
                    "commit": "1d15c0ca29d2ec80c9bc67f9186e072e15129487",
                },
            },
        )

    def test_exact_bound_export_and_canonical_parity(self) -> None:
        node_script = r"""
import {readFileSync} from "node:fs";
import {pathToFileURL} from "node:url";

const probe = await import(pathToFileURL(process.argv[1]).href);
const arm = JSON.parse(readFileSync(0, "utf8"));
const required = [
    "PROTOCOL_ID",
    "PROTOCOL_VERSION",
    "STATE_SCHEMA",
    "BUILD_ID",
    "REQUIRED_RUNTIME_VERSIONS",
    "TOPICS",
    "EXTENSION_IDENTITY",
    "BRT_PROFILE",
    "canonicalJson",
];
for (const name of required) {
    if (!Object.hasOwn(probe, name)) throw new Error(`missing export: ${name}`);
}
process.stdout.write(JSON.stringify({
    node_version: process.version,
    protocol_id: probe.PROTOCOL_ID,
    protocol_version: probe.PROTOCOL_VERSION,
    state_schema: probe.STATE_SCHEMA,
    build_id: probe.BUILD_ID,
    runtime: probe.REQUIRED_RUNTIME_VERSIONS,
    topics: probe.TOPICS,
    extension_identity: probe.EXTENSION_IDENTITY,
    profile: probe.BRT_PROFILE,
    canonical_arm: probe.canonicalJson(arm),
}));
"""
        completed = subprocess.run(
            [
                "node",
                "--input-type=module",
                "--eval",
                node_script,
                str(EXTENSION_PATH),
            ],
            input=VECTORS["arm_request_json"],
            text=True,
            capture_output=True,
            check=True,
            timeout=20,
        )
        exported = strict_json_loads(completed.stdout)
        runtime = {
            "zigbee2mqtt": preflight.ZIGBEE2MQTT_VERSION,
            "zigbee_herdsman": preflight.HERDSMAN_VERSION,
            "zigbee_herdsman_converters": preflight.CONVERTERS_VERSION,
        }
        topics = {
            "ready": preflight.READY_TOPIC,
            "status": preflight.STATUS_TOPIC,
            "request": preflight.REQUEST_TOPIC,
            "response": preflight.RESPONSE_TOPIC,
            "result": preflight.RESULT_TOPIC,
            "ack": preflight.ACK_TOPIC,
            "ackResponse": preflight.ACK_RESPONSE_TOPIC,
        }
        extension_identity = {
            "filename": preflight.DEPLOYED_FILENAME,
            "class_name": preflight.EXTENSION_CLASS,
            "protocol_id": preflight.PROTOCOL_ID,
            "protocol_version": preflight.PROTOCOL_VERSION,
            "build_id": preflight.BUILD_ID,
            "required_runtime_versions": runtime,
        }
        profile = {
            "profile_id": preflight.PROFILE_ID,
            "profile_version": preflight.PROFILE_VERSION,
            "zigbee_model": preflight._PROFILE_ZIGBEE_MODEL,
            "resolved_aliases": [
                {
                    "manufacturer_fingerprint": fingerprint,
                    "model": model,
                    "vendor": vendor,
                }
                for fingerprint, (model, vendor) in preflight._PROFILE_ALIASES.items()
            ],
            "endpoint_id": preflight._PROFILE_ENDPOINT_ID,
            "cluster_name": preflight._PROFILE_CLUSTER_NAME,
            "cluster_id": preflight._PROFILE_CLUSTER_ID,
            "datapoint": preflight._PROFILE_DATAPOINT,
            "datatype": preflight._PROFILE_DATATYPE,
            "minimum_target": preflight._PROFILE_MINIMUM_TARGET,
            "maximum_target": preflight._PROFILE_MAXIMUM_TARGET,
            "target_step": preflight._PROFILE_TARGET_STEP,
            "challenge_delta": preflight._PROFILE_CHALLENGE_DELTA,
            "required_runtime_versions": runtime,
        }
        expected_exports = {
            "node_version": f"v{preflight.NODE_VERSION}",
            "protocol_id": preflight.PROTOCOL_ID,
            "protocol_version": preflight.PROTOCOL_VERSION,
            "state_schema": preflight.STATE_SCHEMA,
            "build_id": preflight.BUILD_ID,
            "runtime": runtime,
            "topics": topics,
            "extension_identity": extension_identity,
            "profile": profile,
            "canonical_arm": VECTORS["arm_request_json"],
        }
        self.assertTrue(strict_equal(exported, expected_exports))
        self.assertEqual(exported["canonical_arm"], canonical_arm())

        manifest = strict_json_loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["protocol"],
            preflight._thaw(preflight.EXPECTED_MANIFEST)["protocol"],
        )
        self.assertEqual(
            manifest["topics"], preflight._thaw(preflight.EXPECTED_MANIFEST)["topics"]
        )
        self.assertEqual(manifest["artifact"]["deployed_filename"], extension_identity["filename"])
        self.assertEqual(manifest["artifact"]["extension_class"], extension_identity["class_name"])
        self.assertEqual(
            {name: manifest["runtime"][name]["version"] for name in runtime},
            runtime,
        )

        calculated = preflight.authorize_arm(
            deployment_snapshot(),
            prearm_snapshot(),
            exported["canonical_arm"],
            NOW,
        )
        request_topic = f'{VECTORS["scope"]["base_topic"]}/{preflight.REQUEST_TOPIC}'
        digest_projection = {
            "request_digest": preflight.canonical_digest(
                VECTORS["arm_request"], domain=preflight._ARM_REQUEST_DIGEST_DOMAIN
            ),
            "canonical_payload_digest": preflight._wire_digest(
                exported["canonical_arm"],
                preflight._ARM_WIRE_DIGEST_DOMAIN,
                preflight.PreflightErrorCode.INVALID_INPUT,
            ),
            "request_topic_digest": preflight._wire_digest(
                request_topic,
                preflight._REQUEST_TOPIC_DIGEST_DOMAIN,
                preflight.PreflightErrorCode.INVALID_INPUT,
            ),
            "permit_digest": calculated.permit_digest,
        }
        self.assertTrue(
            strict_equal(
                digest_projection,
                {
                    name: VECTORS["expected"]["arm_permit"][name]
                    for name in digest_projection
                },
            )
        )


class CanonicalAndTopicTests(unittest.TestCase):
    def test_canonical_parser_rejects_duplicates_noncanonical_and_huge_integer(self) -> None:
        text = '{"a":[1,true],"z":"safe"}'
        self.assertEqual(
            preflight.parse_canonical_mapping(text), {"a": [1, True], "z": "safe"}
        )
        invalid = (
            '{"z":"safe","a":[1,true]}',
            '{"a":1, "z":2}',
            '{"a":1,"a":2}',
            "[]",
            "NaN",
            '{"n":' + "9" * 10_000 + "}",
            "",
        )
        for value in invalid:
            with self.subTest(value=value[:30]), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.parse_canonical_mapping(value)

        encode_called = False
        loads_called = False
        original_encode = preflight._encode_utf8
        original_loads = preflight.json.loads

        def forbidden_encode(*_args, **_kwargs):
            nonlocal encode_called
            encode_called = True
            raise AssertionError("oversized input reached UTF-8 encoding")

        def forbidden_loads(*_args, **_kwargs):
            nonlocal loads_called
            loads_called = True
            raise AssertionError("oversized input reached json.loads")

        setattr(preflight, "_encode_utf8", forbidden_encode)
        setattr(preflight.json, "loads", forbidden_loads)
        try:
            with self.assertRaises(preflight.PhysicalProbePreflightError):
                preflight.parse_canonical_mapping("x" * (8 * 1024 * 1024))
        finally:
            setattr(preflight, "_encode_utf8", original_encode)
            setattr(preflight.json, "loads", original_loads)
        self.assertFalse(encode_called)
        self.assertFalse(loads_called)

        unicode_loads_called = False

        def forbidden_unicode_loads(*_args, **_kwargs):
            nonlocal unicode_loads_called
            unicode_loads_called = True
            raise AssertionError("oversized UTF-8 input reached json.loads")

        setattr(preflight.json, "loads", forbidden_unicode_loads)
        try:
            with self.assertRaises(preflight.PhysicalProbePreflightError):
                preflight.parse_canonical_mapping('{"é":0}', maximum_bytes=7)
        finally:
            setattr(preflight.json, "loads", original_loads)
        self.assertFalse(unicode_loads_called)

    def test_canonical_bounds_cover_unicode_string_list_mapping_depth_nodes_and_bytes(self) -> None:
        preflight.canonical_digest(
            {"value": "x" * preflight.MAX_JSON_STRING_LENGTH}, domain="test/bound"
        )
        preflight.canonical_digest(
            {"value": list(range(preflight.MAX_JSON_LIST_LENGTH))}, domain="test/bound"
        )
        valid_mapping = {
            f"k{index}": index for index in range(preflight.MAX_JSON_MAPPING_FIELDS)
        }
        preflight.canonical_digest(valid_mapping, domain="test/bound")
        at_nodes = [list(range(64)) for _ in range(15)] + list(range(48))
        preflight.canonical_digest(at_nodes, domain="test/nodes")
        at_depth = "leaf"
        for _ in range(preflight.MAX_JSON_DEPTH - 1):
            at_depth = [at_depth]
        preflight.canonical_digest(at_depth, domain="test/depth")
        invalid = (
            {"value": "x" * (preflight.MAX_JSON_STRING_LENGTH + 1)},
            {"value": list(range(preflight.MAX_JSON_LIST_LENGTH + 1))},
            {**valid_mapping, "extra": 1},
            at_nodes + [0],
            [at_depth],
            [["x" * 512 for _ in range(64)] for _ in range(15)],
            {"value": "\ud800"},
            {"value": preflight.MAX_SAFE_INTEGER + 1},
            {"value": 1.5},
        )
        for value in invalid:
            with self.subTest(kind=type(value).__name__), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.canonical_digest(value, domain="test/bound")

    def test_structural_rejection_happens_before_thaw_or_recursive_copy(self) -> None:
        self.assertNotIn("validate", inspect.signature(preflight._canonical_json).parameters)

        class HostileDict(dict):
            def items(self):
                raise AssertionError("hostile container traversed")

        class HostileList(list):
            def __iter__(self):
                raise AssertionError("hostile list traversed")

        deep = "leaf"
        for _ in range(preflight.MAX_JSON_DEPTH):
            deep = [deep]
        shared = ["shared"]
        aliased = {"left": shared, "right": shared}
        cycle = []
        cycle.append(cycle)
        oversized = list(range(preflight.MAX_JSON_LIST_LENGTH + 1))
        oversized_mapping = {
            f"k{index}": index
            for index in range(preflight.MAX_JSON_MAPPING_FIELDS + 1)
        }
        node_overflow = [list(range(64)) for _ in range(15)] + list(range(49))
        hostile = HostileDict(value="unsafe")
        hostile_list = HostileList(["unsafe"])
        hostile_proxy = types.MappingProxyType(hostile)

        original_thaw = preflight._thaw

        def forbidden_thaw(_value):
            raise AssertionError("thaw ran before structural rejection")

        setattr(preflight, "_thaw", forbidden_thaw)
        try:
            for value in (
                deep,
                aliased,
                cycle,
                oversized,
                oversized_mapping,
                node_overflow,
                hostile,
                hostile_list,
                hostile_proxy,
            ):
                with self.subTest(kind=type(value).__name__), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.canonical_digest(value, domain="test/pre-thaw")
        finally:
            setattr(preflight, "_thaw", original_thaw)

        for raw_scope in (hostile, hostile_list, hostile_proxy):
            self.assertFalse(
                preflight.acl_allows(
                    raw_scope,
                    "orchestrator",
                    "publish",
                    f"zigbee2mqtt/{preflight.REQUEST_TOPIC}",
                    qos=1,
                    retain=False,
                )
            )
        for raw_deployment in (
            HostileDict(deployment_snapshot()),
            types.MappingProxyType(deployment_snapshot()),
        ):
            with self.assertRaises(preflight.PhysicalProbePreflightError):
                preflight.attest_deployment(raw_deployment, NOW)
            with self.assertRaises(preflight.PhysicalProbePreflightError):
                preflight.authorize_arm(
                    raw_deployment,
                    prearm_snapshot(),
                    VECTORS["arm_request_json"],
                    NOW,
                )

    def test_base_friendly_and_set_topics_match_strict_js_boundaries(self) -> None:
        valid = deepcopy(VECTORS["scope"])
        preflight.build_acl_plan(valid)
        preflight.build_acl_plan({**valid, "base_topic": "x" * 128})
        maximum_name = "x" * 150
        preflight.build_acl_plan(
            {
                **valid,
                "friendly_name": maximum_name,
                "set_topic": f"{maximum_name}/set",
            }
        )
        for nested_name in ("spare/nested", "bridge-light"):
            preflight.build_acl_plan(
                {
                    **valid,
                    "friendly_name": nested_name,
                    "set_topic": f"{nested_name}/set",
                }
            )
        for unsafe_name in (
            "/spare",
            "spare/",
            "spare//nested",
        ):
            with self.subTest(unsafe_name=unsafe_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.build_acl_plan(
                    {
                        **valid,
                        "friendly_name": unsafe_name,
                        "set_topic": f"{unsafe_name}/set",
                    }
                )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.build_acl_plan(
                {
                    **valid,
                    "base_topic": "b" * 105,
                    "friendly_name": maximum_name,
                    "set_topic": f"{maximum_name}/set",
                }
            )
        invalid = (
            ("base_topic", "x" * 129),
            ("base_topic", "x" * 220),
            ("base_topic", " zigbee2mqtt"),
            ("base_topic", "zigbee2mqtt "),
            ("base_topic", "zigbee\tmqtt"),
            ("base_topic", "zigbee\nmqtt"),
            ("base_topic", "/zigbee2mqtt"),
            ("base_topic", "zigbee2mqtt/"),
            ("base_topic", "zigbee2mqtt/#"),
            ("base_topic", "x/bridge/request/y"),
            ("friendly_name", "x" * 151),
            ("friendly_name", " spare"),
            ("friendly_name", "spare\u0085"),
            ("set_topic", "other/set"),
            ("set_topic", "spare-brt-100//set"),
        )
        for field_name, value in invalid:
            with self.subTest(field=field_name, value=repr(value)), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.build_acl_plan({**valid, field_name: value})

    def test_reserved_bridge_and_duplicate_candidate_names_never_attest_or_authorize(self) -> None:
        for friendly_name in (
            "bridge",
            "bridge/status",
            "bridge/true_family/physical_probe/status",
            "bridge/request/true_family/physical_probe",
            "bridge/response/true_family/physical_probe",
        ):
            scope = {
                **VECTORS["scope"],
                "friendly_name": friendly_name,
                "set_topic": f"{friendly_name}/set",
            }
            deployment = deployment_snapshot()
            deployment["candidate_scope"]["friendly_name"] = friendly_name
            deployment["candidate_scope"]["set_topic"] = f"{friendly_name}/set"
            before_arm = prearm_snapshot()
            before_arm["candidate"]["friendly_name"] = friendly_name
            before_arm["candidate"]["set_topic"] = f"{friendly_name}/set"
            with self.subTest(friendly_name=friendly_name):
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.build_acl_plan(scope)
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.attest_deployment(deployment, NOW)
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.authorize_arm(
                        deployment,
                        prearm_snapshot(),
                        VECTORS["arm_request_json"],
                        NOW,
                    )
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.authorize_arm(
                        deployment_snapshot(),
                        before_arm,
                        VECTORS["arm_request_json"],
                        NOW,
                    )

        candidate_ieee = VECTORS["scope"]["candidate_ieee"]
        for duplicate_name in (candidate_ieee, f"{candidate_ieee}/nested"):
            duplicate_scope = {
                **VECTORS["scope"],
                "friendly_name": duplicate_name,
                "set_topic": f"{duplicate_name}/set",
            }
            duplicate_deployment = deployment_snapshot()
            duplicate_deployment["candidate_scope"]["friendly_name"] = (
                duplicate_name
            )
            duplicate_deployment["candidate_scope"]["set_topic"] = (
                f"{duplicate_name}/set"
            )
            duplicate_prearm = prearm_snapshot()
            duplicate_prearm["candidate"]["friendly_name"] = duplicate_name
            duplicate_prearm["candidate"]["set_topic"] = f"{duplicate_name}/set"
            with self.subTest(duplicate_name=duplicate_name):
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.build_acl_plan(duplicate_scope)
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.attest_deployment(duplicate_deployment, NOW)
                with self.assertRaises(preflight.PhysicalProbePreflightError):
                    preflight.authorize_arm(
                        deployment_snapshot(),
                        duplicate_prearm,
                        VECTORS["arm_request_json"],
                        NOW,
                    )


class AclContractTests(unittest.TestCase):
    def test_topic_oracle_enforces_mqtt_utf8_boundaries_without_normalizing(self) -> None:
        vectors = B1_MANIFEST["topic_oracle"]
        self.assertEqual(vectors["schema"], "true-family-pass-b1a-topic-oracle-v1")
        for topic in vectors["valid_topics"]:
            with self.subTest(valid_topic=repr(topic)):
                self.assertTrue(preflight._topic_is_valid(topic))
        for topic in vectors["invalid_topics"]:
            with self.subTest(invalid_topic=repr(topic)):
                self.assertFalse(preflight._topic_is_valid(topic))
        for codepoint in vectors["valid_codepoints"]:
            with self.subTest(valid_codepoint=hex(codepoint)):
                self.assertTrue(
                    preflight._topic_is_valid(f"safe/{chr(codepoint)}/topic")
                )
        for codepoint in vectors["invalid_codepoints"]:
            with self.subTest(invalid_codepoint=hex(codepoint)):
                self.assertFalse(
                    preflight._topic_is_valid(f"safe/{chr(codepoint)}/topic")
                )
        for codepoint in range(0xD800, 0xE000):
            with self.subTest(surrogate=hex(codepoint)):
                self.assertFalse(preflight._topic_is_valid(f"safe/{chr(codepoint)}/topic"))
        for plane in range(17):
            for ending in (0xFFFE, 0xFFFF):
                codepoint = plane * 0x10000 + ending
                with self.subTest(noncharacter=hex(codepoint)):
                    self.assertFalse(
                        preflight._topic_is_valid(f"safe/{chr(codepoint)}/topic")
                    )
        for codepoint in range(0xFDD0, 0xFDF0):
            with self.subTest(noncharacter=hex(codepoint)):
                self.assertFalse(
                    preflight._topic_is_valid(f"safe/{chr(codepoint)}/topic")
                )
        maximum = "x" * vectors["maximum_codepoints"]
        self.assertTrue(preflight._topic_is_valid(maximum))
        self.assertFalse(preflight._topic_is_valid(f"{maximum}x"))
        self.assertTrue(preflight._topic_is_valid("cafe\u0301/topic"))
        self.assertTrue(preflight._topic_is_valid("caf\u00e9/topic"))

        manifest = strict_json_loads(B1_MANIFEST_PATH.read_text(encoding="utf-8"))
        base_topic = manifest["scope"]["base_topic"]

        def matrix_topic(value, fixture):
            if fixture is None:
                return value
            fixed = {
                "maximum": f"{base_topic}/{('a' * 244)}",
                "overlength": f"{base_topic}/{('a' * 245)}",
                "empty": "",
                "leading_slash": f"/{base_topic}/invalid",
                "trailing_slash": f"{base_topic}/invalid/",
                "boundary_space": f" {base_topic}/invalid",
                "boundary_unicode": f"\u00a0{base_topic}/invalid",
                "control": f"{base_topic}/\u0001invalid",
                "c1_delete": f"{base_topic}/\u007finvalid",
                "c1_first": f"{base_topic}/\u0080invalid",
                "c1_last": f"{base_topic}/\u009finvalid",
                "noncharacter_fdd0": f"{base_topic}/\ufdd0invalid",
                "noncharacter_fdef": f"{base_topic}/\ufdefinvalid",
                "noncharacter_fffe": f"{base_topic}/\ufffeinvalid",
                "noncharacter_ffff": f"{base_topic}/\uffffinvalid",
                "noncharacter_plane_end": f"{base_topic}/{chr(0x10FFFF)}invalid",
                "surrogate_utf8": f"{base_topic}/{chr(0xD800)}invalid",
                "malformed_utf8": f"{base_topic}/{chr(0xD800)}invalid",
                "wildcard_plus": f"{base_topic}/+",
                "wildcard_hash": f"{base_topic}/#",
            }
            if fixture in fixed:
                return fixed[fixture]
            depth = int(fixture.removeprefix("bridge_request_depth_"))
            prefix = "" if depth == 0 else f"{('/'.join(['a'] * depth))}/"
            return f"{base_topic}/{prefix}bridge/request/action"

        for item in manifest["matrix"]["publish"]:
            if item["principal"] not in ("orchestrator", "z2m", "other"):
                continue
            topic = matrix_topic(item.get("topic"), item.get("topic_fixture"))
            role = "zigbee2mqtt" if item["principal"] == "z2m" else item["principal"]
            observed = preflight.acl_allows(
                VECTORS["scope"],
                role,
                "publish",
                topic,
                qos=item.get("qos", 1),
                retain=item.get("retain", False),
            )
            with self.subTest(kind="publish", item=item):
                self.assertEqual(observed, item["allowed"])
        for item in manifest["matrix"]["subscribe"]:
            if item["principal"] not in ("orchestrator", "z2m", "other"):
                continue
            topic = matrix_topic(item.get("filter"), item.get("filter_fixture"))
            role = "zigbee2mqtt" if item["principal"] == "z2m" else item["principal"]
            observed = preflight.acl_allows(
                VECTORS["scope"], role, "subscribe", topic
            )
            with self.subTest(kind="subscribe", item=item):
                self.assertEqual(observed, item["allowed"])

    def test_acl_policy_matches_fixture_and_is_deeply_immutable(self) -> None:
        plan = preflight.build_acl_plan(VECTORS["scope"])
        self.assertEqual(plan.scope_digest, VECTORS["expected"]["acl_scope_digest"])
        self.assertEqual(plan.policy_digest, VECTORS["expected"]["acl_policy_digest"])
        self.assertEqual(plan.schema, "true-family-physical-probe-acl-plan-v2")
        self.assertEqual(plan.scope_digest, B1_MANIFEST["preflight_acl"]["scope_digest"])
        self.assertEqual(plan.policy_digest, B1_MANIFEST["preflight_acl"]["policy_digest"])
        self.assertTrue(
            strict_equal(
                preflight._thaw(plan.effective_policy),
                VECTORS["deployment_snapshot"]["effective_acl"],
            )
        )
        self.assertTrue(
            strict_equal(
                preflight._thaw(plan.effective_policy),
                B1_MANIFEST["preflight_acl"]["effective_policy"],
            )
        )
        self.assertEqual(
            plan.effective_policy["topic_contract"][
                "zigbee2mqtt_exact_base_wildcard_subscription"
            ],
            "zigbee2mqtt/#",
        )
        enforcement = plan.effective_policy["enforcement"]
        self.assertEqual(enforcement["anonymous_access"], "disabled")
        self.assertEqual(enforcement["superuser_bypass"], "disabled")
        self.assertTrue(enforcement["dedicated_listener"])
        self.assertTrue(enforcement["effective_readback_complete"])
        with self.assertRaises(TypeError):
            plan.effective_policy["schema"] = "other"
        with self.assertRaises(FrozenInstanceError):
            plan.policy_digest = "0" * 64
        self.assertFalse(
            preflight.acl_allows(
                plan,
                "orchestrator",
                "publish",
                f"zigbee2mqtt/{preflight.REQUEST_TOPIC}",
                qos=1,
                retain=False,
            )
        )

    def test_orchestrator_request_publish_requires_exact_qos_and_retain_metadata(self) -> None:
        topics = (
            f"zigbee2mqtt/{preflight.REQUEST_TOPIC}",
            f"zigbee2mqtt/{preflight.ACK_TOPIC}",
        )
        for topic in topics:
            self.assertTrue(
                preflight.acl_allows(
                    VECTORS["scope"],
                    "orchestrator",
                    "publish",
                    topic,
                    qos=1,
                    retain=False,
                )
            )
            for qos, retain in (
                (None, None),
                (0, False),
                (2, False),
                (True, False),
                (1, True),
                (1, 0),
            ):
                with self.subTest(topic=topic, qos=qos, retain=retain):
                    self.assertFalse(
                        preflight.acl_allows(
                            VECTORS["scope"],
                            "orchestrator",
                            "publish",
                            topic,
                            qos=qos,
                            retain=retain,
                        )
                    )

    def test_bridge_request_containment_is_publish_only_and_z2m_subscribe_allows(self) -> None:
        request_topics = (
            f"zigbee2mqtt/{preflight.REQUEST_TOPIC}",
            "zigbee2mqtt/bridge/request/action",
            "zigbee2mqtt/zigbee2mqtt/bridge/request/action",
            "prefix/bridge/request/zigbee2mqtt/bridge/request/action",
        )
        for topic in request_topics:
            with self.subTest(topic=topic):
                self.assertTrue(
                    preflight.acl_allows(
                        VECTORS["scope"], "zigbee2mqtt", "subscribe", topic
                    )
                )
                self.assertFalse(
                    preflight.acl_allows(
                        VECTORS["scope"],
                        "zigbee2mqtt",
                        "publish",
                        topic,
                        qos=1,
                        retain=False,
                    )
                )
        self.assertFalse(
            preflight.acl_allows(
                VECTORS["scope"],
                "orchestrator",
                "publish",
                "zigbee2mqtt/zigbee2mqtt/bridge/request/action",
                qos=1,
                retain=False,
            )
        )

    def test_candidate_subtrees_and_unreviewed_roles_deny_while_z2m_publishes(self) -> None:
        candidate_topics = (
            "zigbee2mqtt/spare-brt-100",
            "zigbee2mqtt/spare-brt-100/set",
            "zigbee2mqtt/spare-brt-100/1/set/current_heating_setpoint",
            "zigbee2mqtt/0xa4c1380000000001/set/system_mode",
        )
        for role in ("orchestrator", "admin_recovery", "other", "anonymous", "unknown"):
            for topic in candidate_topics:
                self.assertFalse(
                    preflight.acl_allows(
                        VECTORS["scope"], role, "publish", topic, qos=0, retain=False
                    )
                )
        for topic in candidate_topics:
            self.assertTrue(
                preflight.acl_allows(
                    VECTORS["scope"],
                    "zigbee2mqtt",
                    "publish",
                    topic,
                    qos=0,
                    retain=False,
                )
            )
        for role in ("admin_recovery", "other", "anonymous", "unknown"):
            self.assertFalse(
                preflight.acl_allows(
                    VECTORS["scope"], role, "subscribe", "safe/topic"
                )
            )

    def test_orchestrator_subscribe_is_exact_and_denies_source_backup_and_broad_filters(self) -> None:
        allowed = tuple(
            f"zigbee2mqtt/{topic}"
            for topic in (
                preflight.READY_TOPIC,
                preflight.STATUS_TOPIC,
                preflight.RESULT_TOPIC,
                preflight.RESPONSE_TOPIC,
                preflight.ACK_RESPONSE_TOPIC,
            )
        )
        for topic in allowed:
            self.assertTrue(
                preflight.acl_allows(
                    VECTORS["scope"], "orchestrator", "subscribe", topic
                )
            )
        for topic in (
            "zigbee2mqtt/bridge/extensions",
            "zigbee2mqtt/bridge/response/backup",
            "zigbee2mqtt/bridge/#",
            "zigbee2mqtt/#",
            "zigbee2mqtt/spare-brt-100",
            f"zigbee2mqtt/{preflight.REQUEST_TOPIC}",
        ):
            self.assertFalse(
                preflight.acl_allows(
                    VECTORS["scope"], "orchestrator", "subscribe", topic
                )
            )

    def test_z2m_exact_root_filter_only_and_hostile_roles_fail_without_conversion(self) -> None:
        self.assertTrue(
            preflight.acl_allows(
                VECTORS["scope"], "zigbee2mqtt", "subscribe", "zigbee2mqtt/#"
            )
        )
        for role in ("orchestrator", "admin_recovery", "other", "anonymous"):
            self.assertFalse(
                preflight.acl_allows(
                    VECTORS["scope"], role, "subscribe", "zigbee2mqtt/#"
                )
            )
        for wildcard in ("zigbee2mqtt/+", "zigbee2mqtt/bridge/#", "other/#"):
            self.assertFalse(
                preflight.acl_allows(
                    VECTORS["scope"], "zigbee2mqtt", "subscribe", wildcard
                )
            )

        for shared in ("$share/group/safe/topic", "$share/group/zigbee2mqtt/#"):
            self.assertFalse(
                preflight.acl_allows(
                    VECTORS["scope"], "zigbee2mqtt", "subscribe", shared
                )
            )

        for topic in ("outside/root", "safe//topic"):
            self.assertTrue(
                preflight.acl_allows(
                    VECTORS["scope"], "zigbee2mqtt", "subscribe", topic
                )
            )
            for qos in (0, 1, 2):
                for retain in (False, True):
                    self.assertTrue(
                        preflight.acl_allows(
                            VECTORS["scope"],
                            "zigbee2mqtt",
                            "publish",
                            topic,
                            qos=qos,
                            retain=retain,
                        )
                    )

        class HostileRole:
            def __str__(self):
                raise AssertionError("conversion attempted")

        hostile = HostileRole()
        self.assertFalse(
            preflight.acl_allows(
                VECTORS["scope"], hostile, "subscribe", "safe/topic"
            )
        )
        self.assertFalse(
            preflight.acl_allows(
                VECTORS["scope"], "zigbee2mqtt", hostile, "safe/topic"
            )
        )
        for qos, retain in (
            (None, None),
            (True, False),
            (-1, False),
            (3, False),
            (0, 0),
        ):
            self.assertFalse(
                preflight.acl_allows(
                    VECTORS["scope"],
                    "zigbee2mqtt",
                    "publish",
                    "safe/topic",
                    qos=qos,
                    retain=retain,
                )
            )

    def test_every_acl_policy_branch_is_required_by_deployment_readback(self) -> None:
        base = deployment_snapshot()
        mutations = []
        for field_name, value in (
            ("anonymous_access", "enabled"),
            ("superuser_bypass", "enabled"),
            ("dedicated_listener", False),
            ("effective_readback_complete", False),
        ):
            item = deepcopy(base)
            item["effective_acl"]["enforcement"][field_name] = value
            mutations.append((field_name, item))
        for role in ("orchestrator", "zigbee2mqtt", "admin_recovery", "other", "anonymous"):
            item = deepcopy(base)
            item["effective_acl"]["principals"][role]["extra"] = "allow"
            mutations.append((role, item))
        for field_name in base["effective_acl"]["global_denies"]:
            item = deepcopy(base)
            del item["effective_acl"]["global_denies"][field_name]
            mutations.append((field_name, item))
        wildcard = deepcopy(base)
        wildcard["effective_acl"]["principals"]["orchestrator"]["publish_allow"][0]["topic"] = "zigbee2mqtt/bridge/request/#"
        mutations.append(("wildcard", wildcard))
        for label, item in mutations:
            with self.subTest(label=label), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(item, NOW)


class DeploymentReportTests(unittest.TestCase):
    def test_good_deployment_report_matches_fixture_and_safe_order_fields(self) -> None:
        report = attest()
        self.assertTrue(
            strict_equal(
                projection(report), VECTORS["expected"]["deployment_attestation"]
            )
        )
        self.assertEqual(report.observed_at_ms, 1_800_000_000_000)
        self.assertEqual(report.expected_owner_digest, VECTORS["expected"]["owner_digest"])
        rendered = repr(report)
        for private in ("spare-brt-100", "0xa4c1380000000001", "external_extensions"):
            self.assertNotIn(private, rendered)

    def test_deployment_requires_every_exact_field_and_rejects_extras(self) -> None:
        base = deployment_snapshot()
        mappings = (
            (),
            ("protocol",),
            ("runtime",),
            ("runtime", "node"),
            ("runtime", "zigbee2mqtt"),
            ("runtime", "zigbee_herdsman"),
            ("runtime", "zigbee_herdsman_converters"),
            ("artifact",),
            ("deployment",),
            ("controls",),
            ("writer_inventory",),
            ("lifecycle",),
            ("fence",),
            ("candidate_scope",),
            ("candidate_scope", "identity"),
        )
        for path in mappings:
            target = base
            for part in path:
                target = target[part]
            for field_name in tuple(target):
                with self.subTest(path=path, missing=field_name), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.attest_deployment(
                        delete_path(deepcopy(base), (*path, field_name)), NOW
                    )
            with self.subTest(path=path, extra=True), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(deepcopy(base), (*path, "unexpected"), True), NOW
                )

    def test_manifest_schema_version_digest_and_bool_integer_drift_reject(self) -> None:
        mutations = (
            (("manifest_schema",), "other"),
            (("manifest_version",), 2),
            (("manifest_version",), True),
            (("manifest_digest",), "0" * 64),
            (("protocol", "protocol_version"), True),
            (("protocol", "build_id"), "other"),
            (("protocol", "profile_id"), "other"),
            (("protocol", "profile_version"), True),
        )
        for path, value in mutations:
            with self.subTest(path=path), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(set_path(deployment_snapshot(), path, value), NOW)

    def test_every_runtime_and_artifact_identity_drift_rejects(self) -> None:
        runtime = VECTORS["deployment_snapshot"]["runtime"]
        for component, values in runtime.items():
            for field_name, value in values.items():
                with self.subTest(component=component, field=field_name), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.attest_deployment(
                        set_path(
                            deployment_snapshot(),
                            ("runtime", component, field_name),
                            f"{value}x",
                        ),
                        NOW,
                    )
        for field_name, value in (
            ("source", "custom_components/true_family/probe/true_family_brt_probe.mjt"),
            ("deployed_filename", "other.mjs"),
            ("extension_class", "TrueFamilyBrtProbeExtensioo"),
            ("byte_length", 164_690),
            ("byte_length", True),
            ("sha256", "0" * 64),
            ("matching_files", 0),
            ("matching_files", 2),
            ("external_converters", ["converter.js"]),
            ("unreviewed_command_extensions", ["writer.mjs"]),
        ):
            with self.subTest(field=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(deployment_snapshot(), ("artifact", field_name), value), NOW
                )

    def test_owner_is_derived_from_epoch_process_artifact_and_both_paths(self) -> None:
        report = attest()
        self.assertEqual(
            preflight.derive_expected_owner_digest(
                report.collection_epoch_digest, report.process_instance_digest
            ),
            report.expected_owner_digest,
        )
        for path, value in (
            (("lifecycle", "expected_owner_digest"), "d" * 64),
            (("lifecycle", "collection_epoch_digest"), "a" * 64),
            (("lifecycle", "process_instance_digest"), "b" * 64),
            (("deployment", "extension_path_digest"), "0" * 64),
            (("deployment", "journal_path_digest"), "0" * 64),
        ):
            with self.subTest(path=path), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(set_path(deployment_snapshot(), path, value), NOW)

    def test_configuration_and_acl_fence_values_are_strict_and_bound(self) -> None:
        for field_name, value in (
            ("configuration_generation", 0),
            ("configuration_generation", True),
            ("configuration_digest", "not-a-digest"),
            ("acl_generation", 0),
            ("acl_generation", False),
            ("acl_digest", "0" * 64),
        ):
            with self.subTest(field=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(deployment_snapshot(), ("fence", field_name), value), NOW
                )

    def test_any_journal_recovery_collision_dynamic_control_or_writer_evidence_rejects(self) -> None:
        unsafe_deployment = {
            "journal_main_present": True,
            "matching_journal_temps": 1,
            "matching_journal_aliases": 1,
            "recovery_evidence_present": True,
            "journal_write_in_flight": True,
            "loader_count": 0,
            "journal_owner_count": 2,
            "dynamic_mqtt_extension_save_allowed": True,
            "dynamic_mqtt_extension_remove_allowed": True,
            "dynamic_mqtt_converter_save_allowed": True,
            "dynamic_mqtt_converter_remove_allowed": True,
        }
        for field_name, value in unsafe_deployment.items():
            with self.subTest(deployment=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(deployment_snapshot(), ("deployment", field_name), value), NOW
                )
        for field_name in VECTORS["deployment_snapshot"]["controls"]:
            value = False if field_name == "advanced_enable_external_js" else True
            with self.subTest(control=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(deployment_snapshot(), ("controls", field_name), value), NOW
                )
        for field_name in VECTORS["deployment_snapshot"]["writer_inventory"]:
            with self.subTest(writer=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(deployment_snapshot(), ("writer_inventory", field_name), True),
                    NOW,
                )

    def test_full_candidate_identity_alias_scope_and_groups_are_bound(self) -> None:
        identity = deployment_snapshot()["candidate_scope"]["identity"]
        for field_name, value in (
            ("ieee_address", "0xa4c1380000000002"),
            ("model", "Other"),
            ("vendor", "Other"),
            ("zigbee_model", "TS0602"),
            ("manufacturer_fingerprint", "_TZE200_aaaaaaaa"),
            ("endpoint_id", 2),
            ("cluster_name", "genOnOff"),
            ("cluster_id", 6),
        ):
            with self.subTest(field=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(
                    set_path(
                        deployment_snapshot(), ("candidate_scope", "identity", field_name), value
                    ),
                    NOW,
                )
        for path, value in (
            (("candidate_scope", "friendly_name"), "renamed"),
            (("candidate_scope", "set_topic"), "renamed/set"),
            (("candidate_scope", "groups"), ["group"]),
        ):
            with self.subTest(path=path), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(set_path(deployment_snapshot(), path, value), NOW)
        self.assertEqual(identity["endpoint_id"], 1)

    def test_deployment_time_window_is_fresh_and_strict(self) -> None:
        for path, value in (
            (("observed_at_ms",), NOW + 1),
            (("observed_at_ms",), True),
            (("expires_at_ms",), NOW),
            (("expires_at_ms",), 1_800_000_060_001),
        ):
            with self.subTest(path=path), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.attest_deployment(set_path(deployment_snapshot(), path, value), NOW)


class PreArmRawPipelineTests(unittest.TestCase):
    def test_good_prearm_report_matches_fixture_and_revalidates_raw_deployment(self) -> None:
        report = prearm()
        self.assertTrue(
            strict_equal(
                projection(report), VECTORS["expected"]["prearm_attestation"]
            )
        )
        bad_deployment = set_path(deployment_snapshot(), ("manifest_digest",), "0" * 64)
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.validate_prearm(prearm_snapshot(), bad_deployment, NOW)

    def test_fabricated_reports_are_data_and_cannot_replace_raw_evidence(self) -> None:
        forged_deployment = preflight.DeploymentAttestation(
            **VECTORS["expected"]["deployment_attestation"]
        )
        forged_prearm = preflight.PreArmAttestation(
            **VECTORS["expected"]["prearm_attestation"]
        )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.validate_prearm(prearm_snapshot(), forged_deployment, NOW)
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.authorize_arm(
                forged_deployment,
                forged_prearm,
                VECTORS["arm_request_json"],
                NOW,
            )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.authorize_arm(
                deployment_snapshot(),
                forged_prearm,
                VECTORS["arm_request_json"],
                NOW,
            )
        self.assertEqual(
            tuple(inspect.signature(preflight.validate_prearm).parameters),
            ("prearm_snapshot", "deployment_snapshot", "now_ms"),
        )
        self.assertEqual(
            tuple(inspect.signature(preflight.authorize_arm).parameters),
            ("deployment_snapshot", "prearm_snapshot", "arm_request_json", "now_ms"),
        )

    def test_prearm_requires_every_exact_field_and_rejects_extras(self) -> None:
        base = prearm_snapshot()
        mappings = (
            (),
            ("protocol",),
            ("boot",),
            ("lifecycle",),
            ("fence",),
            ("source_inventory",),
            ("journal_observation",),
            ("candidate",),
            ("candidate", "identity"),
            ("pending_work",),
            ("probe_state",),
        )
        for path in mappings:
            target = base
            for part in path:
                target = target[part]
            for field_name in tuple(target):
                with self.subTest(path=path, missing=field_name), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.validate_prearm(
                        delete_path(deepcopy(base), (*path, field_name)),
                        deployment_snapshot(),
                        NOW,
                    )
            with self.subTest(path=path, extra=True), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(deepcopy(base), (*path, "unexpected"), True),
                    deployment_snapshot(),
                    NOW,
                )

    def test_temporal_order_is_deployment_then_prearm_then_now_then_expiry(self) -> None:
        cases = (
            (("observed_at_ms",), 1_799_999_999_999),
            (("observed_at_ms",), 1_800_000_000_000),
            (("observed_at_ms",), NOW),
            (("observed_at_ms",), NOW + 1),
            (("expires_at_ms",), NOW),
            (("expires_at_ms",), 1_800_000_060_001),
            (("expires_at_ms",), 1_800_000_007_001),
        )
        for path, value in cases:
            with self.subTest(path=path, value=value), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(prearm_snapshot(), path, value), deployment_snapshot(), NOW
                )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.validate_prearm(
                prearm_snapshot(),
                deployment_snapshot(),
                VECTORS["prearm_snapshot"]["expires_at_ms"],
            )

        same_expiry_deployment = deployment_snapshot()
        same_expiry_deployment["expires_at_ms"] = VECTORS["prearm_snapshot"][
            "expires_at_ms"
        ]
        deployment_report = preflight.attest_deployment(
            same_expiry_deployment, NOW
        )
        same_expiry_prearm = prearm_snapshot()
        same_expiry_prearm["deployment_snapshot_digest"] = (
            deployment_report.snapshot_digest
        )
        preflight.validate_prearm(
            same_expiry_prearm, same_expiry_deployment, NOW
        )

    def test_epoch_process_owner_and_fence_must_match_deployment_exactly(self) -> None:
        for section, fields_to_change in (
            ("lifecycle", ("collection_epoch_digest", "process_instance_digest", "expected_owner_digest")),
            (
                "fence",
                (
                    "configuration_generation_before",
                    "configuration_generation_after",
                    "configuration_digest_before",
                    "configuration_digest_after",
                    "acl_generation_before",
                    "acl_generation_after",
                    "acl_digest_before",
                    "acl_digest_after",
                ),
            ),
        ):
            for field_name in fields_to_change:
                original = VECTORS["prearm_snapshot"][section][field_name]
                value = original + 1 if type(original) is int else "0" * 64
                with self.subTest(section=section, field=field_name), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.validate_prearm(
                        set_path(prearm_snapshot(), (section, field_name), value),
                        deployment_snapshot(),
                        NOW,
                    )

    def test_loader_and_journal_owner_are_single_derived_same_process_epoch(self) -> None:
        for collection in ("loaders", "journal_owners"):
            zero = prearm_snapshot()
            zero[collection] = []
            two = prearm_snapshot()
            two[collection].append(deepcopy(two[collection][0]))
            for label, item in (("zero", zero), ("two", two)):
                with self.subTest(collection=collection, label=label), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.validate_prearm(item, deployment_snapshot(), NOW)
            for field_name, value in (
                ("owner_digest", "0" * 64),
                ("collection_epoch_digest", "0" * 64),
                ("process_instance_digest", "0" * 64),
                ("extension_class", "Other"),
                ("artifact_digest", "0" * 64),
                ("path_digest", "0" * 64),
                ("previous_owner_drained", False),
                ("late_completions", 1),
            ):
                with self.subTest(collection=collection, field=field_name), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    item = prearm_snapshot()
                    item[collection][0][field_name] = value
                    preflight.validate_prearm(item, deployment_snapshot(), NOW)

    def test_second_journal_observation_rejects_every_change_after_deployment(self) -> None:
        unsafe = {
            "observed_at_ms": 1_800_000_002_001,
            "journal_path": "other.state.json",
            "journal_path_digest": "0" * 64,
            "main_present": True,
            "matching_temps": 1,
            "matching_aliases": 1,
            "recovery_evidence_present": True,
            "write_in_flight": True,
        }
        for field_name, value in unsafe.items():
            with self.subTest(field=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(
                        prearm_snapshot(), ("journal_observation", field_name), value
                    ),
                    deployment_snapshot(),
                    NOW,
                )

    def test_later_candidate_alias_name_scope_group_and_event_mutations_fail(self) -> None:
        mutations = (
            (("candidate", "friendly_name"), "renamed"),
            (("candidate", "set_topic"), "renamed/set"),
            (("candidate", "identity", "ieee_address"), "0xa4c1380000000002"),
            (("candidate", "identity", "model"), "Other"),
            (("candidate", "identity", "manufacturer_fingerprint"), "_TZE200_qsoecqlk"),
            (("candidate", "identity_digest_before"), "0" * 64),
            (("candidate", "scope_digest_after"), "0" * 64),
            (("candidate", "groups"), ["group"]),
            (("candidate", "rename_events"), 1),
            (("candidate", "group_events"), 1),
        )
        for path, value in mutations:
            with self.subTest(path=path), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(prearm_snapshot(), path, value), deployment_snapshot(), NOW
                )

    def test_matching_supported_alias_across_both_raw_snapshots_and_request_is_allowed(self) -> None:
        deployment = deployment_snapshot()
        before_arm = prearm_snapshot()
        request = arm_request()
        replacement_identity = {
            **deployment["candidate_scope"]["identity"],
            "model": "Powerswitch-ZK(W)",
            "vendor": "Sibling",
            "manufacturer_fingerprint": "_TZE200_qsoecqlk",
        }
        deployment["candidate_scope"]["identity"] = deepcopy(replacement_identity)
        before_arm["candidate"]["identity"] = deepcopy(replacement_identity)
        request["candidate"] = deepcopy(replacement_identity)
        deployment_report = preflight.attest_deployment(deployment, NOW)
        before_arm["deployment_snapshot_digest"] = deployment_report.snapshot_digest
        _, identity_digest, scope_digest = preflight._normalize_candidate_scope(
            deployment["candidate_scope"], preflight.PreflightErrorCode.INVALID_INPUT
        )
        before_arm["candidate"]["identity_digest_before"] = identity_digest
        before_arm["candidate"]["identity_digest_after"] = identity_digest
        before_arm["candidate"]["scope_digest_before"] = scope_digest
        before_arm["candidate"]["scope_digest_after"] = scope_digest
        request_digest = preflight.canonical_digest(
            request, domain="true-family-physical-probe/arm-request/v1"
        )
        before_arm["expected_arm_request_digest"] = request_digest
        request_json = canonical_arm(request)
        calculated = preflight.authorize_arm(
            deployment, before_arm, request_json, NOW
        )
        self.assertEqual(calculated.request_digest, request_digest)
        self.assertTrue(
            preflight.verify_arm_permit(
                calculated, deployment, before_arm, request_json, NOW
            )
        )

    def test_endpoint_inventory_selected_endpoint_and_pending_api_are_exact(self) -> None:
        cases = []
        for field_name, value in (
            ("selected_endpoint_id", 2),
            ("endpoint_inventory_complete", False),
        ):
            item = prearm_snapshot()
            item["candidate"][field_name] = value
            cases.append((field_name, item))
        empty = prearm_snapshot()
        empty["candidate"]["endpoints"] = []
        cases.append(("empty", empty))
        missing_one = prearm_snapshot()
        missing_one["candidate"]["endpoints"] = [missing_one["candidate"]["endpoints"][1]]
        cases.append(("missing_one", missing_one))
        duplicate = prearm_snapshot()
        duplicate["candidate"]["endpoints"][1]["endpoint_id"] = 1
        cases.append(("duplicate", duplicate))
        missing_api = prearm_snapshot()
        del missing_api["candidate"]["endpoints"][0]["has_pending_requests_api"]
        cases.append(("missing_api", missing_api))
        no_api = prearm_snapshot()
        no_api["candidate"]["endpoints"][0]["has_pending_requests_api"] = False
        cases.append(("no_api", no_api))
        pending = prearm_snapshot()
        pending["candidate"]["endpoints"][1]["pending"] = True
        cases.append(("pending", pending))
        zero_endpoint = prearm_snapshot()
        zero_endpoint["candidate"]["endpoints"][1]["endpoint_id"] = 0
        cases.append(("zero_endpoint", zero_endpoint))
        endpoint_241 = prearm_snapshot()
        endpoint_241["candidate"]["endpoints"][1]["endpoint_id"] = 241
        cases.append(("endpoint_241", endpoint_241))
        for label, item in cases:
            with self.subTest(label=label), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(item, deployment_snapshot(), NOW)

    def test_source_boot_pending_and_probe_state_must_be_stable_and_idle(self) -> None:
        for field_name in (
            "installed_sha256",
            "loaded_sha256",
            "retained_inventory_sha256",
        ):
            with self.subTest(source=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(
                        prearm_snapshot(), ("source_inventory", field_name), "0" * 64
                    ),
                    deployment_snapshot(),
                    NOW,
                )
        for path, value in (
            (("boot", "boot_id_after"), "tfpp-boot-" + "2" * 32),
            (("boot", "generation_before"), 0),
            (("boot", "generation_after"), 8),
        ):
            with self.subTest(path=path), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(prearm_snapshot(), path, value), deployment_snapshot(), NOW
                )
        for field_name in VECTORS["prearm_snapshot"]["pending_work"]:
            for value in (1, False):
                with self.subTest(pending=field_name, value=value), self.assertRaises(
                    preflight.PhysicalProbePreflightError
                ):
                    preflight.validate_prearm(
                        set_path(prearm_snapshot(), ("pending_work", field_name), value),
                        deployment_snapshot(),
                        NOW,
                    )
        unsafe_probe = {
            "ready": False,
            "phase": "quiescent",
            "generation": 1,
            "record_present": True,
            "remediation_required": True,
            "arm_accepted_count": 1,
            "endpoint_commands_since_loader_start": 1,
        }
        for field_name, value in unsafe_probe.items():
            with self.subTest(probe=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                preflight.validate_prearm(
                    set_path(prearm_snapshot(), ("probe_state", field_name), value),
                    deployment_snapshot(),
                    NOW,
                )


class ArmPermitPipelineTests(unittest.TestCase):
    def test_good_raw_pipeline_matches_fixture_and_repeated_calculation_is_metadata_only(self) -> None:
        first = permit()
        second = permit()
        self.assertTrue(
            strict_equal(projection(first), VECTORS["expected"]["arm_permit"])
        )
        self.assertEqual(first, second)
        self.assertTrue(first.one_shot_required)
        self.assertFalse(first.consumption_enforced)
        self.assertFalse(first.commands_authorized)
        self.assertEqual(first.qos, 1)
        self.assertFalse(first.retain)
        self.assertRegex(first.canonical_payload_digest, r"^[0-9a-f]{64}$")
        self.assertRegex(first.request_topic_digest, r"^[0-9a-f]{64}$")
        rendered = repr(first)
        self.assertNotIn(VECTORS["arm_request_json"], rendered)
        self.assertNotIn(
            f"zigbee2mqtt/{preflight.REQUEST_TOPIC}", rendered
        )
        self.assertNotIn("0xa4c1380000000001", rendered)
        self.assertEqual(first.expires_at_ms, VECTORS["arm_request"]["request_deadline_ms"])
        self.assertGreater(
            VECTORS["arm_request"]["operation_deadline_ms"],
            VECTORS["prearm_snapshot"]["expires_at_ms"],
        )
        self.assertTrue(
            preflight.verify_arm_permit(
                first,
                deployment_snapshot(),
                prearm_snapshot(),
                VECTORS["arm_request_json"],
                NOW,
            )
        )

    def test_arm_accepts_only_exact_canonical_json_wire_bytes(self) -> None:
        canonical = canonical_arm()
        self.assertEqual(canonical, VECTORS["arm_request_json"])
        duplicate = canonical.replace(
            '"action":"arm",', '"action":"arm","action":"arm",', 1
        )
        noncanonical = (
            json.dumps(arm_request(), ensure_ascii=False, sort_keys=True, indent=2),
            json.dumps(
                arm_request(),
                ensure_ascii=False,
                sort_keys=False,
                separators=(",", ":"),
            ),
            f"{canonical}\n",
            duplicate,
            canonical.replace(
                '"request_deadline_ms":1800000006000',
                '"request_deadline_ms":' + "9" * 10_000,
            ),
        )
        for wire in noncanonical:
            with self.subTest(wire=wire[:40]), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                permit(request_json=wire)
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.authorize_arm(
                deployment_snapshot(),
                prearm_snapshot(),
                arm_request(),
                NOW,
            )

    def test_arm_mapping_requires_every_exact_field_and_no_extras(self) -> None:
        request = arm_request()
        for field_name in tuple(request):
            with self.subTest(missing=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                permit(
                    request_json=canonical_arm(
                        delete_path(deepcopy(request), (field_name,))
                    )
                )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            permit(request_json=canonical_arm({**request, "extra": True}))

    def test_arm_requires_action_quiescent_generation_zero_protocol_build_profile_and_ids(self) -> None:
        mutations = (
            ("action", "resume"),
            ("phase", "awaiting_physical_target_1"),
            ("generation", 1),
            ("generation", False),
            ("protocol_id", "other"),
            ("protocol_version", True),
            ("build_id", "other"),
            ("profile_id", "other"),
            ("profile_version", True),
            ("boot_id", "tfpp-boot-short"),
            ("request_id", "tfpp-req-short"),
            ("operation_id", "tfpp-op-short"),
            ("nonce", "private"),
        )
        for field_name, value in mutations:
            with self.subTest(field=field_name, value=value), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                permit(
                    request_json=canonical_arm(
                        {**arm_request(), field_name: value}
                    )
                )

    def test_arm_candidate_alias_targets_and_physical_pair_are_exact(self) -> None:
        identity_mutations = (
            ("ieee_address", "0xa4c1380000000002"),
            ("model", "Other"),
            ("vendor", "Other"),
            ("manufacturer_fingerprint", "_TZE200_aaaaaaaa"),
            ("endpoint_id", 2),
        )
        for field_name, value in identity_mutations:
            request = arm_request()
            request["candidate"][field_name] = value
            with self.subTest(identity=field_name), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                permit(request_json=canonical_arm(request))
        for field_name, value in (
            ("intended_target", -1),
            ("intended_target", 36),
            ("intended_target", True),
            ("physical_targets", [21, 21]),
            ("physical_targets", [18, 20]),
            ("physical_targets", [18]),
            ("physical_targets", [18, True]),
        ):
            with self.subTest(field=field_name, value=value), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                permit(
                    request_json=canonical_arm(
                        {**arm_request(), field_name: value}
                    )
                )

    def test_request_deadline_must_fit_prearm_and_operation_stays_protocol_bounded(self) -> None:
        mutations = (
            ("request_deadline_ms", NOW),
            ("request_deadline_ms", 1_800_000_007_001),
            ("request_deadline_ms", NOW + preflight.MAX_REQUEST_WINDOW_MS + 1),
            ("operation_deadline_ms", NOW),
            ("operation_deadline_ms", NOW + preflight.MAX_OPERATION_WINDOW_MS + 1),
            ("operation_deadline_ms", VECTORS["arm_request"]["request_deadline_ms"]),
        )
        for field_name, value in mutations:
            request = {**arm_request(), field_name: value}
            before_arm = prearm_snapshot()
            before_arm["expected_arm_request_digest"] = preflight.canonical_digest(
                request, domain="true-family-physical-probe/arm-request/v1"
            )
            with self.subTest(field=field_name, value=value), self.assertRaises(
                preflight.PhysicalProbePreflightError
            ):
                permit(before_arm=before_arm, request_json=canonical_arm(request))

    def test_fabricated_permit_cannot_bypass_raw_revalidation_or_exact_comparison(self) -> None:
        valid = permit()
        forged = replace(valid, permit_digest="0" * 64)
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.verify_arm_permit(
                forged,
                deployment_snapshot(),
                prearm_snapshot(),
                VECTORS["arm_request_json"],
                NOW,
            )
        bad_deployment = set_path(deployment_snapshot(), ("manifest_digest",), "0" * 64)
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.verify_arm_permit(
                valid,
                bad_deployment,
                prearm_snapshot(),
                VECTORS["arm_request_json"],
                NOW,
            )
        bad_prearm = set_path(
            prearm_snapshot(), ("journal_observation", "main_present"), True
        )
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.verify_arm_permit(
                valid,
                deployment_snapshot(),
                bad_prearm,
                VECTORS["arm_request_json"],
                NOW,
            )
        bad_request = {**arm_request(), "generation": 1}
        with self.assertRaises(preflight.PhysicalProbePreflightError):
            preflight.verify_arm_permit(
                valid,
                deployment_snapshot(),
                prearm_snapshot(),
                canonical_arm(bad_request),
                NOW,
            )


class PrivacyAndStaticTests(unittest.TestCase):
    def test_error_code_is_read_only_and_public_rejection_fails_safe_after_forced_corruption(self) -> None:
        error = preflight.PhysicalProbePreflightError(
            preflight.PreflightErrorCode.DEPLOYMENT_REJECTED
        )
        with self.assertRaises(AttributeError):
            error.code = preflight.PreflightErrorCode.ARM_REJECTED
        with self.assertRaises(AttributeError):
            error._code = preflight.PreflightErrorCode.ARM_REJECTED
        object.__setattr__(error, "_code", "private-payload-canary")
        status = preflight.public_rejection(error)
        self.assertEqual(status.code, preflight.PreflightErrorCode.INTERNAL_REJECTED)
        self.assertNotIn("private-payload-canary", repr(status))

    def test_errors_and_public_report_repr_never_expose_raw_scope_source_or_payload(self) -> None:
        canaries = (
            "private-candidate-canary",
            "0xa4c13800000000ff",
            "private/source/canary.mjs",
            "private-principal-canary",
            "private-payload-canary",
        )
        bad = deployment_snapshot()
        bad["candidate_scope"]["friendly_name"] = canaries[0]
        bad["candidate_scope"]["identity"]["ieee_address"] = canaries[1]
        bad["artifact"]["source"] = canaries[2]
        try:
            preflight.attest_deployment(bad, NOW)
        except preflight.PhysicalProbePreflightError as error:
            rendered = str(error) + repr(error) + repr(preflight.public_rejection(error))
        else:
            self.fail("Private drift passed.")
        rendered += repr(preflight.build_acl_plan(VECTORS["scope"]))
        rendered += repr(attest()) + repr(prearm()) + repr(permit())
        rendered += repr(preflight.public_rejection(RuntimeError(canaries[4])))
        for canary in canaries:
            self.assertNotIn(canary, rendered)

    def test_reports_are_frozen_data_with_only_safe_digest_metadata(self) -> None:
        reports = (attest(), prearm(), permit())
        for report in reports:
            with self.subTest(report=type(report).__name__), self.assertRaises(
                FrozenInstanceError
            ):
                report.schema = "other"
        permit_fields = {item.name for item in fields(preflight.ProbeArmPermit)}
        self.assertIn("one_shot_required", permit_fields)
        self.assertIn("consumption_enforced", permit_fields)
        self.assertIn("commands_authorized", permit_fields)
        self.assertNotIn("candidate", permit_fields)
        self.assertNotIn("payload", permit_fields)

    def test_module_is_stdlib_only_has_no_dynamic_import_or_io_surface(self) -> None:
        source_path = PACKAGE_ROOT / "physical_probe_preflight.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_imports = {
            "importlib",
            "pathlib",
            "os",
            "socket",
            "subprocess",
            "urllib",
            "aiohttp",
            "paho",
            "homeassistant",
        }
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                if node.module:
                    imported_roots.add(node.module.split(".", 1)[0])
        self.assertEqual(
            imported_roots,
            {
                "__future__",
                "collections",
                "dataclasses",
                "enum",
                "hashlib",
                "json",
                "re",
                "types",
                "typing",
            },
        )
        self.assertTrue(forbidden_imports.isdisjoint(imported_roots))
        self.assertNotIn("import_module", source)
        self.assertNotIn("__import__", source)
        self.assertNotIn("from .", source)

        forbidden_names = {"open", "input", "print", "exec", "eval", "compile"}
        forbidden_attributes = {
            "open",
            "read",
            "write",
            "read_text",
            "read_bytes",
            "write_text",
            "write_bytes",
            "connect",
            "send",
            "recv",
            "run",
            "Popen",
            "system",
            "spawn",
            "fork",
            "import_module",
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, forbidden_names)
            elif isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden_attributes)

    def test_no_package_runtime_file_imports_or_registers_preflight(self) -> None:
        module_path = PACKAGE_ROOT / "physical_probe_preflight.py"
        module_name = "custom_components.true_family.physical_probe_preflight"
        for path in sorted(PACKAGE_ROOT.rglob("*.py")):
            if path == module_path:
                continue
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        self.assertTrue(
                            all(
                                alias.name
                                not in {module_name, "physical_probe_preflight"}
                                and not alias.name.startswith(f"{module_name}.")
                                for alias in node.names
                            )
                        )
                    elif isinstance(node, ast.ImportFrom):
                        self.assertNotIn(
                            node.module,
                            {module_name, "physical_probe_preflight"},
                        )
                        self.assertTrue(
                            all(
                                alias.name != "physical_probe_preflight"
                                for alias in node.names
                            )
                        )
                    elif isinstance(node, ast.Call):
                        dynamic_import = (
                            isinstance(node.func, ast.Name)
                            and node.func.id == "__import__"
                        ) or (
                            isinstance(node.func, ast.Attribute)
                            and node.func.attr == "import_module"
                        )
                        self.assertFalse(dynamic_import)
        integration_manifest = (PACKAGE_ROOT / "manifest.json").read_text(encoding="utf-8")
        self.assertNotIn("physical_probe_preflight", integration_manifest)
        self.assertNotIn("true_family_brt_probe.manifest", integration_manifest)


if __name__ == "__main__":
    unittest.main()
