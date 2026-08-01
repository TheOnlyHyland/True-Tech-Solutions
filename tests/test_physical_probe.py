"""Pure adversarial tests for the unwired physical-probe contracts."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
import importlib
import json
from pathlib import Path
import re
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"
NOW = 1_800_000_000_000
BOOT = "tfpp-boot-" + "1" * 32
SECOND_BOOT = "tfpp-boot-" + "2" * 32
OPERATION = "tfpp-op-" + "3" * 24
SECOND_OPERATION = "tfpp-op-" + "4" * 24
REQUEST = "tfpp-req-" + "5" * 24
SECOND_REQUEST = "tfpp-req-" + "6" * 24
NONCE = "tfpp-nonce-" + "7" * 32
IEEE = "0xa4c1380000000001"
VECTORS = json.loads(
    (ROOT / "tests" / "fixtures" / "physical_probe_vectors.json").read_text(
        encoding="utf-8"
    )
)


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
    return importlib.import_module(f"{PACKAGE_NAME}.physical_probe")


probe = load_module()


def candidate(
    fingerprint: str = "_TZE200_b6wax7g0",
    *,
    model: str | None = None,
    vendor: str | None = None,
):
    aliases = {
        alias.manufacturer_fingerprint: alias
        for alias in probe.BRT_PROFILE.resolved_aliases
    }
    alias = aliases.get(fingerprint)
    return probe.NormalizedCandidateIdentity(
        ieee_address=IEEE,
        model=model or (alias.model if alias else "BRT-100-TRV"),
        vendor=vendor or (alias.vendor if alias else "Moes"),
        zigbee_model="TS0601",
        manufacturer_fingerprint=fingerprint,
        endpoint_id=1,
        cluster_name="manuSpecificTuya",
        cluster_id=0xEF00,
    )


def armed_record():
    return probe.ProbeRecoveryRecord.arm(
        profile=probe.BRT_PROFILE,
        candidate=candidate(),
        candidate_set_topic="candidate-valve/set",
        operation_id=OPERATION,
        boot_id=BOOT,
        request_id=REQUEST,
        request_deadline_ms=NOW + 10_000,
        operation_deadline_ms=NOW + 120_000,
        intended_target=21,
        physical_targets=(18, 21),
        now_ms=NOW,
    )


def proof(purpose, sequence, target):
    return probe.ProbeCommandProof(
        purpose,
        probe.ProbeFrameKind.COMMAND_RESPONSE,
        sequence,
        target,
    )


def challenge_record():
    record = armed_record().accept_proof(
        proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
        now_ms=NOW + 1,
    )
    record = record.accept_proof(
        proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
        now_ms=NOW + 2,
        next_sequence=100,
    )
    return record.accept_proof(
        proof(probe.ProbePurpose.NOOP, 100, 21),
        now_ms=NOW + 3,
        next_sequence=101,
    )


def verified_record():
    record = challenge_record().accept_proof(
        proof(probe.ProbePurpose.CHALLENGE, 101, 22),
        now_ms=NOW + 4,
        next_sequence=102,
    )
    return record.accept_proof(
        proof(probe.ProbePurpose.RESTORE, 102, 21),
        now_ms=NOW + 5,
    )


def arm_request_dict():
    return {
        "action": "arm",
        "protocol_id": probe.PROTOCOL_ID,
        "protocol_version": probe.PROTOCOL_VERSION,
        "build_id": probe.BUILD_ID,
        "profile_id": probe.BRT_PROFILE.profile_id,
        "profile_version": probe.BRT_PROFILE.profile_version,
        "boot_id": BOOT,
        "request_id": REQUEST,
        "operation_id": OPERATION,
        "nonce": NONCE,
        "phase": "quiescent",
        "generation": 0,
        "request_deadline_ms": NOW + 10_000,
        "candidate": candidate().as_dict(),
        "intended_target": 21,
        "physical_targets": [18, 21],
        "operation_deadline_ms": NOW + 120_000,
    }


class PhysicalProbeProfileTests(unittest.TestCase):
    def test_brt_profile_and_runtime_tuple_are_exact_and_immutable(self) -> None:
        profile = probe.BRT_PROFILE

        self.assertEqual(
            probe.Z2M_2_12_1_VERSION_TUPLE,
            ("2.12.1", "10.6.1", "26.76.0"),
        )
        self.assertEqual(profile.zigbee_model, "TS0601")
        self.assertEqual(profile.endpoint_id, 1)
        self.assertEqual(profile.cluster_name, "manuSpecificTuya")
        self.assertEqual(profile.cluster_id, 0xEF00)
        self.assertEqual((profile.datapoint, profile.datatype), (2, 2))
        self.assertEqual((profile.minimum_target, profile.maximum_target), (0, 35))
        self.assertEqual(profile.target_step, 1)
        self.assertEqual(profile.challenge_delta, 1)
        self.assertEqual(
            tuple(
                (
                    alias.manufacturer_fingerprint,
                    alias.model,
                    alias.vendor,
                )
                for alias in profile.resolved_aliases
            ),
            (
                ("_TZE200_b6wax7g0", "BRT-100-TRV", "Moes"),
                ("_TZE200_qsoecqlk", "Powerswitch-ZK(W)", "Sibling"),
                ("_TZE200_6y7kyjga", "BRT-100-TRV", "Moes"),
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            profile.datapoint = 3
        with self.assertRaises(TypeError):
            probe.PROFILES[("other", 1)] = profile

    def test_generic_profile_rejects_bad_fingerprints_ranges_and_bool_ints(self) -> None:
        values = {
            field.name: getattr(probe.BRT_PROFILE, field.name)
            for field in fields(probe.PhysicalProbeProfile)
        }
        mutations = {
            "alias_list": {"resolved_aliases": list(values["resolved_aliases"])},
            "duplicate_fingerprint": {
                "resolved_aliases": (
                    values["resolved_aliases"][0],
                    values["resolved_aliases"][0],
                )
            },
            "bad_alias_type": {"resolved_aliases": ("_TZE200_SHORT",)},
            "bool_endpoint": {"endpoint_id": True},
            "bool_datapoint": {"datapoint": False},
            "reversed_range": {"minimum_target": 35, "maximum_target": 0},
            "zero_step": {"target_step": 0},
            "version_list": {
                "required_runtime_versions": list(probe.Z2M_2_12_1_VERSION_TUPLE)
            },
        }
        for label, changes in mutations.items():
            with self.subTest(label=label), self.assertRaises(probe.PhysicalProbeError):
                probe.PhysicalProbeProfile(**{**values, **changes})

    def test_challenge_is_exactly_one_degree_and_stays_in_range(self) -> None:
        self.assertEqual(probe.BRT_PROFILE.challenge_target(21), 22)
        self.assertEqual(probe.BRT_PROFILE.challenge_target(35), 34)
        for invalid in (-1, 36, 21.5, True):
            with self.subTest(invalid=invalid), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.BRT_PROFILE.challenge_target(invalid)

    def test_every_pinned_fingerprint_matches_and_all_other_identity_drift_fails(self) -> None:
        for fingerprint in probe.BRT_PROFILE.manufacturer_fingerprints:
            with self.subTest(fingerprint=fingerprint):
                candidate(fingerprint).require_profile(probe.BRT_PROFILE)

        for fingerprint, model, vendor in (
            ("_TZE200_qsoecqlk", "BRT-100-TRV", "Moes"),
            ("_TZE200_b6wax7g0", "Powerswitch-ZK(W)", "Sibling"),
            ("_TZE200_6y7kyjga", "Powerswitch-ZK(W)", "Sibling"),
        ):
            with self.subTest(cross_combination=fingerprint), self.assertRaises(
                probe.PhysicalProbeError
            ):
                candidate(
                    fingerprint,
                    model=model,
                    vendor=vendor,
                ).require_profile(probe.BRT_PROFILE)

        valid = candidate().as_dict()
        mutations = {
            "model": "other",
            "vendor": "Other",
            "zigbee_model": "TS0602",
            "manufacturer_fingerprint": "_TZE200_aaaaaaaa",
            "endpoint_id": 2,
            "cluster_name": "genOnOff",
            "cluster_id": 6,
        }
        for field_name, value in mutations.items():
            with self.subTest(field=field_name), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.NormalizedCandidateIdentity.from_projection(
                    {**valid, field_name: value}
                ).require_profile(probe.BRT_PROFILE)

        for vector in VECTORS["invalid_boundary_text_vectors"]:
            value = vector.get("value")
            if value is None:
                value = "BRT-100-TRV" + chr(vector["utf16_code_unit"])
            with self.subTest(vector=vector["name"]), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.NormalizedCandidateIdentity.from_projection(
                    {**valid, "model": value}
                )


class PhysicalProbeMessageTests(unittest.TestCase):
    def test_shared_python_node_vectors_are_exact_and_utf8_canonical(self) -> None:
        for vector in VECTORS["canonical_vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(probe.canonical_json(vector["value"]), vector["canonical"])
                self.assertEqual(
                    probe.canonical_digest(
                        vector["value"],
                        domain=vector["domain"],
                    ),
                    vector["digest"],
                )

        self.assertEqual(
            probe.ProbeRequest.from_dict(VECTORS["arm_request"]).as_dict(),
            VECTORS["arm_request"],
        )
        self.assertEqual(
            probe.ProbeRecoveryRecord.from_dict(VECTORS["armed_record"]).as_dict(),
            VECTORS["armed_record"],
        )
        terminal = probe.ProbeRecoveryRecord.from_dict(VECTORS["verified_record"])
        self.assertEqual(terminal.result_id, VECTORS["result"]["result_id"])
        self.assertEqual(
            probe.calculate_result_id(VECTORS["verified_record"]),
            VECTORS["result"]["result_id"],
        )
        for record_name in (
            "failed_safe_record",
            "failed_restored_record",
            "remediation_restore_record",
            "remediation_claimed_restore_record",
        ):
            with self.subTest(record=record_name):
                self.assertEqual(
                    probe.ProbeRecoveryRecord.from_dict(
                        VECTORS[record_name]
                    ).as_dict(),
                    VECTORS[record_name],
                )
        for record_name in (
            "verified_record",
            "failed_safe_record",
            "failed_restored_record",
        ):
            with self.subTest(terminal_deadline=record_name):
                self.assertEqual(
                    VECTORS[record_name]["operation_deadline_ms"],
                    VECTORS["armed_record"]["operation_deadline_ms"],
                )
        for vector in VECTORS["deadline_immutability_vectors"]:
            with self.subTest(deadline=vector["name"]):
                record = probe.ProbeRecoveryRecord.from_dict(
                    VECTORS[vector["record"]]
                )
                self.assertEqual(
                    record.operation_deadline_ms,
                    vector["operation_deadline_ms"],
                )
                self.assertEqual(
                    record.operation_deadline_ms,
                    VECTORS["armed_record"]["operation_deadline_ms"],
                )
        window = VECTORS["claimed_restore_window"]
        self.assertEqual(
            window["last_valid_start_ms"] + probe.DIRECT_PROOF_WINDOW_MS,
            window["operation_deadline_ms"],
        )
        self.assertEqual(
            window["first_invalid_start_ms"] + probe.DIRECT_PROOF_WINDOW_MS,
            window["operation_deadline_ms"] + 1,
        )
        for vector in VECTORS["terminal_authority_vectors"]:
            terminal_data = {
                **VECTORS["failed_safe_record"],
                "result_not_before_ms": vector["result_not_before_ms"],
            }
            with self.subTest(terminal_authority=vector["name"]):
                if vector["valid"]:
                    self.assertEqual(
                        probe.ProbeRecoveryRecord.from_dict(terminal_data).as_dict(),
                        terminal_data,
                    )
                else:
                    with self.assertRaises(probe.PhysicalProbeError):
                        probe.ProbeRecoveryRecord.from_dict(terminal_data)
        control_vector, generation_vector = VECTORS["failure_generation_parity_vectors"]
        control = armed_record().fail_safe(
            control_vector["failure_code"],
            now_ms=NOW + 1,
            boot_id=BOOT,
        )
        self.assertEqual(control.failure_code, control_vector["failure_code"])
        self.assertEqual(control.generation, control_vector["expected_generation"])
        generation_source = replace(
            armed_record(),
            generation=generation_vector["source_generation"],
        )
        generation_remediation = generation_source.to_remediation(
            failure_code=generation_vector["failure_code"],
            restore_required=False,
        )
        self.assertEqual(
            generation_remediation.generation,
            generation_vector["expected_generation"],
        )
        self.assertEqual(
            generation_remediation.failure_code,
            generation_vector["failure_code"],
        )
        self.assertIs(
            generation_remediation.phase,
            probe.ProbePhase.REMEDIATION_REQUIRED,
        )
        self.assertFalse(generation_remediation.cleanup_allowed)
        self.assertIsNone(generation_remediation.result_id)
        self.assertEqual(
            probe.ProbeRequest.from_dict(VECTORS["resume_request"]).as_dict(),
            VECTORS["resume_request"],
        )
        self.assertEqual(
            probe.ProbeRequest.from_dict(VECTORS["ack_request"]).as_dict(),
            VECTORS["ack_request"],
        )
        failed_safe = probe.ProbeRecoveryRecord.from_dict(
            VECTORS["failed_safe_record"]
        )
        failed_restored = probe.ProbeRecoveryRecord.from_dict(
            VECTORS["failed_restored_record"]
        )
        remediation = probe.ProbeRecoveryRecord.from_dict(
            VECTORS["remediation_restore_record"]
        )
        public = VECTORS["public_messages"]
        self.assertEqual(probe.ready_message(BOOT), public["ready"])
        self.assertEqual(
            probe.status_message(BOOT, remediation, remediation_required=True),
            public["status"],
        )
        self.assertEqual(
            probe.result_message(BOOT, failed_safe),
            public["failed_safe_result"],
        )
        self.assertEqual(
            probe.result_message(BOOT, failed_restored),
            public["failed_restored_result"],
        )
        with self.assertRaises(probe.PhysicalProbeError):
            probe.result_message(SECOND_BOOT, failed_safe)
        with self.assertRaises(probe.PhysicalProbeError):
            probe.status_message(SECOND_BOOT, failed_safe)
        old_boot_remediation = probe.status_message(
            SECOND_BOOT,
            failed_safe,
            remediation_required=True,
        )
        self.assertEqual(old_boot_remediation["phase"], "remediation_required")
        self.assertIsNone(old_boot_remediation["result_id"])
        self.assertFalse(old_boot_remediation["cleanup_allowed"])
        self.assertEqual(
            probe.response_message(
                BOOT,
                request_id=SECOND_REQUEST,
                operation_id=OPERATION,
                action="resume",
                accepted=False,
                phase="remediation_required",
                generation=remediation.generation,
                error_code="queue_overflow",
            ),
            public["response"],
        )
        parity_values = {
            "failed_safe_record": VECTORS["failed_safe_record"],
            "remediation_claimed_restore_record": VECTORS[
                "remediation_claimed_restore_record"
            ],
            "remediation_status": public["status"],
            "resume_request": VECTORS["resume_request"],
            "ack_request": VECTORS["ack_request"],
            "utf8_public_text": {
                "message": "Physical proof café £ €",
                "phase": "remediation_required",
            },
        }
        for artifact in VECTORS["parity_artifacts"]:
            with self.subTest(parity=artifact["name"]):
                value = parity_values[artifact["name"]]
                self.assertEqual(probe.canonical_json(value), artifact["canonical"])
                self.assertEqual(probe.canonical_digest(value), artifact["sha256"])
                self.assertEqual(
                    probe.canonical_json(value).encode("utf-8"),
                    artifact["canonical"].encode("utf-8"),
                )
        self.assertEqual(
            {vector["classification"] for vector in VECTORS["frames"]},
            {"proof", "competing", "ignored"},
        )

    def test_arm_resume_and_ack_use_disjoint_exact_field_sets(self) -> None:
        arm = probe.ProbeRequest.from_dict(arm_request_dict())
        self.assertEqual(arm.as_dict(), arm_request_dict())

        resume_data = {
            key: value
            for key, value in arm_request_dict().items()
            if key
            not in {
                "candidate",
                "intended_target",
                "physical_targets",
                "operation_deadline_ms",
            }
        }
        resume_data.update(
            {
                "action": "resume",
                "phase": "awaiting_physical_target_1",
                "generation": 1,
                "request_id": SECOND_REQUEST,
            }
        )
        resume = probe.ProbeRequest.from_dict(resume_data)
        self.assertEqual(resume.as_dict(), resume_data)

        terminal = verified_record()
        ack_data = {
            **resume_data,
            "action": "ack",
            "phase": "result_pending_ack",
            "generation": terminal.generation,
            "operation_id": terminal.operation_id,
            "result_id": terminal.result_id,
        }
        ack = probe.ProbeRequest.from_dict(ack_data)
        self.assertEqual(ack.as_dict(), ack_data)

        for label, data in (
            ("arm_extra", {**arm_request_dict(), "extra": 1}),
            ("resume_arm_field", {**resume_data, "candidate": candidate().as_dict()}),
            ("ack_missing_result", {key: value for key, value in ack_data.items() if key != "result_id"}),
        ):
            with self.subTest(label=label), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRequest.from_dict(data)

    def test_request_identifiers_are_bounded_and_bool_is_not_an_integer(self) -> None:
        valid = arm_request_dict()
        invalid = {
            "boot": {**valid, "boot_id": "tfpp-boot-short"},
            "operation": {**valid, "operation_id": "tfpp-op-" + "0" * 25},
            "request": {**valid, "request_id": "tfpp-req-" + "0" * 23},
            "nonce": {**valid, "nonce": "secret"},
            "bool_generation": {**valid, "generation": False},
            "bool_deadline": {**valid, "request_deadline_ms": True},
            "bool_target": {**valid, "intended_target": True},
        }
        for label, data in invalid.items():
            with self.subTest(label=label), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRequest.from_dict(data)

    def test_public_ready_status_response_and_result_have_exact_sanitized_fields(self) -> None:
        record = verified_record()
        ready = probe.ready_message(BOOT)
        status = probe.status_message(BOOT, record)
        result = probe.result_message(BOOT, record)
        response = probe.response_message(
            BOOT,
            request_id=REQUEST,
            operation_id=OPERATION,
            action="arm",
            accepted=True,
            phase=record.phase.value,
            generation=record.generation,
            error_code=None,
        )

        self.assertEqual(
            set(ready),
            {
                "protocol_id",
                "protocol_version",
                "build_id",
                "profile_id",
                "profile_version",
                "boot_id",
                "phase",
                "required_runtime_versions",
                "request_topic",
                "ack_topic",
            },
        )
        self.assertEqual(
            set(status),
            {
                "protocol_id",
                "protocol_version",
                "build_id",
                "profile_id",
                "profile_version",
                "boot_id",
                "phase",
                "generation",
                "operation_id",
                "result_id",
                "result_not_before_ms",
                "identity",
                "restore_required",
                "restore_attempts",
                "cleanup_allowed",
            },
        )
        self.assertEqual(status["identity"], "...0001")
        self.assertEqual(status["result_id"], record.result_id)
        self.assertEqual(status["result_not_before_ms"], record.result_not_before_ms)
        self.assertEqual(result["identity"], "...0001")
        self.assertEqual(result["result_not_before_ms"], record.result_not_before_ms)
        self.assertEqual(response["request_id"], REQUEST)
        public_text = json.dumps([ready, status, result, response], sort_keys=True)
        self.assertNotIn(IEEE, public_text)
        self.assertNotIn(NONCE, public_text)
        self.assertNotIn("manufacturer_fingerprint", public_text)

    def test_canonical_message_parser_rejects_noncanonical_duplicate_and_nonobject_json(self) -> None:
        value = {"b": 2, "a": [1, True, None]}
        text = probe.canonical_json(value)
        self.assertEqual(text, '{"a":[1,true,null],"b":2}')
        self.assertEqual(probe.parse_canonical_json(text), value)

        for invalid in (
            '{"b":2,"a":1}',
            '{"a":1, "b":2}',
            '{"a":1,"a":2}',
            "[]",
            "",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.parse_canonical_json(invalid)

        with self.assertRaises(probe.PhysicalProbeError):
            probe.canonical_json({"invalid": "\ud800"})


class PhysicalProbeRecoveryTests(unittest.TestCase):
    def test_complete_flow_orders_physical_noop_challenge_restore_ack(self) -> None:
        record = armed_record()
        self.assertEqual(record.phase, probe.ProbePhase.AWAITING_PHYSICAL_TARGET_1)
        self.assertFalse(record.restore_required)
        self.assertEqual(record.expected_proof.sequence, None)

        record = record.accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
            now_ms=NOW + 1,
        )
        self.assertEqual(record.phase, probe.ProbePhase.AWAITING_PHYSICAL_TARGET_2)
        record = record.accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
            now_ms=NOW + 2,
            next_sequence=100,
        )
        self.assertEqual(record.phase, probe.ProbePhase.AWAITING_NOOP_RESPONSE)
        self.assertEqual(record.expected_proof.target, 21)
        self.assertFalse(record.restore_required)

        record = record.accept_proof(
            proof(probe.ProbePurpose.NOOP, 100, 21),
            now_ms=NOW + 3,
            next_sequence=101,
        )
        self.assertEqual(record.phase, probe.ProbePhase.AWAITING_CHALLENGE_RESPONSE)
        self.assertTrue(record.restore_required)
        self.assertEqual(record.expected_proof.target, 22)

        record = record.accept_proof(
            proof(probe.ProbePurpose.CHALLENGE, 101, 22),
            now_ms=NOW + 4,
            next_sequence=102,
        )
        self.assertEqual(record.phase, probe.ProbePhase.AWAITING_RESTORE_RESPONSE)
        self.assertEqual(record.expected_proof.target, 21)
        self.assertEqual(record.expected_proof.sequence, 102)

        record = record.accept_proof(
            proof(probe.ProbePurpose.RESTORE, 102, 21),
            now_ms=NOW + 5,
        )
        self.assertEqual(record.phase, probe.ProbePhase.RESULT_PENDING_ACK)
        self.assertEqual(record.outcome, probe.ProbeOutcome.VERIFIED)
        self.assertFalse(record.restore_required)
        self.assertFalse(record.cleanup_allowed)
        self.assertRegex(record.result_id, r"^tfpp-result-[0-9a-f]{24}$")
        self.assertEqual(
            record.result_not_before_ms,
            NOW + 5 + probe.RESULT_SETTLING_WINDOW_MS,
        )
        self.assertEqual(record.operation_deadline_ms, NOW + 120_000)

        with self.assertRaises(probe.PhysicalProbeError):
            record.acknowledge(
                boot_id=BOOT,
                request_id=SECOND_REQUEST,
                request_deadline_ms=NOW + 20_000,
                result_id=record.result_id,
                now_ms=record.result_not_before_ms - 1,
            )

        with self.assertRaises(probe.PhysicalProbeError):
            record.acknowledge(
                boot_id=SECOND_BOOT,
                request_id=SECOND_REQUEST,
                request_deadline_ms=NOW + 20_000,
                result_id=record.result_id,
                now_ms=record.result_not_before_ms,
            )

        with self.assertRaises(probe.PhysicalProbeError):
            record.acknowledge(
                boot_id=BOOT,
                request_id=SECOND_REQUEST,
                request_deadline_ms=record.operation_deadline_ms + 1_000,
                result_id=record.result_id,
                now_ms=record.operation_deadline_ms,
            )

        acknowledged = record.acknowledge(
            boot_id=BOOT,
            request_id=SECOND_REQUEST,
            request_deadline_ms=NOW + 20_000,
            result_id=record.result_id,
            now_ms=record.result_not_before_ms,
        )
        self.assertEqual(acknowledged.phase, probe.ProbePhase.QUIESCENT)
        self.assertTrue(acknowledged.cleanup_allowed)
        self.assertEqual(acknowledged.result_id, record.result_id)
        self.assertEqual(
            acknowledged.result_not_before_ms,
            record.result_not_before_ms,
        )

    def test_terminal_settling_is_strict_and_never_extends_operation_authority(self) -> None:
        record = armed_record()
        valid_time = (
            record.operation_deadline_ms
            - probe.RESULT_SETTLING_WINDOW_MS
            - 1
        )
        terminal = record.fail_safe(
            "deadline_expired",
            now_ms=valid_time,
            boot_id=BOOT,
        )
        self.assertEqual(
            terminal.operation_deadline_ms,
            record.operation_deadline_ms,
        )
        self.assertEqual(
            terminal.result_not_before_ms,
            record.operation_deadline_ms - 1,
        )
        for now_ms in (
            record.operation_deadline_ms - probe.RESULT_SETTLING_WINDOW_MS,
            record.operation_deadline_ms,
        ):
            with self.subTest(now_ms=now_ms), self.assertRaises(
                probe.PhysicalProbeError
            ):
                record.fail_safe("deadline_expired", now_ms=now_ms, boot_id=BOOT)

    def test_exact_proof_deadline_is_expired_like_javascript(self) -> None:
        record = armed_record()
        with self.assertRaises(probe.PhysicalProbeError):
            record.accept_proof(
                proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
                now_ms=record.expected_proof_deadline_ms,
            )

    def test_restore_required_is_durable_before_challenge_and_fallback_is_restore_only(self) -> None:
        record = challenge_record()
        self.assertTrue(record.restore_required)
        self.assertEqual(record.expected_proof.purpose, probe.ProbePurpose.CHALLENGE)
        self.assertIn(101, record.used_sequences)

        restoring = record.begin_restore(
            sequence=102,
            failure_code="proof_mismatch",
            now_ms=NOW + 4,
        )
        self.assertEqual(restoring.phase, probe.ProbePhase.AWAITING_RESTORE_RESPONSE)
        self.assertEqual(restoring.expected_proof.purpose, probe.ProbePurpose.RESTORE)
        self.assertEqual(restoring.expected_proof.target, 21)
        self.assertEqual(restoring.failure_code, "proof_mismatch")
        retry = restoring.begin_restore(
            sequence=103,
            failure_code="proof_mismatch",
            now_ms=NOW + 5,
        )
        self.assertEqual(retry.restore_attempts, 2)
        self.assertEqual(retry.expected_proof.sequence, 103)

        terminal = restoring.accept_proof(
            proof(probe.ProbePurpose.RESTORE, 102, 21),
            now_ms=NOW + 5,
        )
        self.assertEqual(terminal.outcome, probe.ProbeOutcome.FAILED_RESTORED)
        self.assertEqual(terminal.proofs[-1].purpose, probe.ProbePurpose.RESTORE)

    def test_claimed_restore_requires_full_window_and_preserves_original_deadline(self) -> None:
        window = VECTORS["claimed_restore_window"]
        challenge = challenge_record()
        restoring = challenge.begin_restore(
            sequence=102,
            failure_code="deadline_expired",
            now_ms=window["last_valid_start_ms"],
        )
        self.assertEqual(
            restoring.operation_deadline_ms,
            window["operation_deadline_ms"],
        )
        self.assertEqual(
            restoring.expected_proof_deadline_ms,
            window["operation_deadline_ms"],
        )
        reused = restoring.reuse_restore(
            boot_id=SECOND_BOOT,
            now_ms=window["last_valid_start_ms"],
        )
        self.assertEqual(
            reused.operation_deadline_ms,
            window["operation_deadline_ms"],
        )
        self.assertEqual(
            reused.expected_proof_deadline_ms,
            window["operation_deadline_ms"],
        )

        with self.assertRaises(probe.PhysicalProbeError):
            challenge.begin_restore(
                sequence=102,
                failure_code="deadline_expired",
                now_ms=window["first_invalid_start_ms"],
            )
        with self.assertRaises(probe.PhysicalProbeError):
            restoring.reuse_restore(
                boot_id=SECOND_BOOT,
                now_ms=window["first_invalid_start_ms"],
            )
        remediation = challenge.to_remediation(
            failure_code="deadline_expired",
            restore_required=True,
        )
        self.assertIs(remediation.phase, probe.ProbePhase.REMEDIATION_REQUIRED)
        self.assertEqual(
            remediation.operation_deadline_ms,
            window["operation_deadline_ms"],
        )
        self.assertIsNone(remediation.result_id)
        self.assertFalse(remediation.cleanup_allowed)

        for proof_time in (
            window["operation_deadline_ms"],
            window["operation_deadline_ms"] + 1,
        ):
            with self.subTest(proof_time=proof_time), self.assertRaises(
                probe.PhysicalProbeError
            ):
                restoring.accept_proof(
                    proof(probe.ProbePurpose.RESTORE, 102, 21),
                    now_ms=proof_time,
                )

    def test_durable_restore_remediation_intent_covers_every_safety_code(self) -> None:
        for index, failure_code in enumerate(
            (
                "competing_frame",
                "competing_write",
                "control_drift",
                "queue_overflow",
            )
        ):
            with self.subTest(failure_code=failure_code):
                restoring = challenge_record().begin_restore(
                    sequence=102 + index,
                    failure_code=failure_code,
                    now_ms=NOW + 4,
                )
                self.assertTrue(restoring.remediation_after_restore)
                first_restart = restoring.reuse_restore(
                    boot_id=SECOND_BOOT,
                    now_ms=NOW + 5,
                )
                second_restart = first_restart.reuse_restore(
                    boot_id="tfpp-boot-" + "3" * 32,
                    now_ms=NOW + 6,
                )
                self.assertTrue(second_restart.remediation_after_restore)
                remediated = second_restart.accept_proof(
                    proof(probe.ProbePurpose.RESTORE, 102 + index, 21),
                    now_ms=NOW + 7,
                )
                self.assertEqual(
                    remediated.phase,
                    probe.ProbePhase.REMEDIATION_REQUIRED,
                )
                self.assertFalse(remediated.cleanup_allowed)
                self.assertFalse(remediated.remediation_after_restore)

    def test_prechallenge_failure_is_safe_and_never_cleanup_allowed_before_ack(self) -> None:
        terminal = armed_record().fail_safe(
            "competing_frame",
            now_ms=NOW + 2,
            boot_id=BOOT,
        )
        self.assertEqual(terminal.outcome, probe.ProbeOutcome.FAILED_SAFE)
        self.assertEqual(terminal.phase, probe.ProbePhase.RESULT_PENDING_ACK)
        self.assertFalse(terminal.cleanup_allowed)
        self.assertFalse(terminal.restore_required)

        serialized = terminal.as_dict()
        serialized["cleanup_allowed"] = True
        with self.assertRaises(probe.PhysicalProbeError):
            probe.ProbeRecoveryRecord.from_dict(serialized)

    def test_proof_kind_sequence_target_and_order_are_exact(self) -> None:
        record = armed_record()
        invalid = (
            probe.ProbeCommandProof(
                probe.ProbePurpose.PHYSICAL_TARGET_1,
                probe.ProbeFrameKind.COMMAND_RESPONSE,
                10,
                19,
            ),
            probe.ProbeCommandProof(
                probe.ProbePurpose.PHYSICAL_TARGET_2,
                probe.ProbeFrameKind.COMMAND_RESPONSE,
                10,
                21,
            ),
        )
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(probe.PhysicalProbeError):
                record.accept_proof(item, now_ms=NOW + 1)

        with self.assertRaises(ValueError):
            probe.ProbeFrameKind("commandDataReport")
        with self.assertRaises(probe.PhysicalProbeError):
            probe.ProbeCommandProof(
                probe.ProbePurpose.NOOP,
                probe.ProbeFrameKind.COMMAND_RESPONSE,
                True,
                21,
            )

    def test_shared_invalid_proof_vectors_reject_range_step_and_unknown_fields(self) -> None:
        for vector in VECTORS["invalid_proofs"]:
            profile = replace(
                probe.BRT_PROFILE,
                minimum_target=vector["profile"]["minimum_target"],
                maximum_target=vector["profile"]["maximum_target"],
                target_step=vector["profile"]["target_step"],
            )
            with self.subTest(name=vector["name"]), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeCommandProof.from_dict(vector["proof"], profile)

    def test_duplicate_physical_and_command_sequences_are_rejected(self) -> None:
        record = armed_record().accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
            now_ms=NOW + 1,
        )
        with self.assertRaises(probe.PhysicalProbeError):
            record.accept_proof(
                proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 10, 21),
                now_ms=NOW + 2,
                next_sequence=100,
            )
        with self.assertRaises(probe.PhysicalProbeError):
            record.accept_proof(
                proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
                now_ms=NOW + 2,
                next_sequence=10,
            )

        physical_ffff = armed_record().accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 0xFFFF, 18),
            now_ms=NOW + 1,
        )
        self.assertIn(0xFFFF, physical_ffff.used_sequences)
        with self.assertRaises(probe.PhysicalProbeError):
            physical_ffff.accept_proof(
                proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
                now_ms=NOW + 2,
                next_sequence=0xFFFF,
            )

    def test_round_trip_is_canonical_and_does_not_retain_raw_or_nonce_data(self) -> None:
        record = verified_record()
        serialized = record.as_dict()
        restored = probe.ProbeRecoveryRecord.from_dict(deepcopy(serialized))

        self.assertEqual(restored, record)
        self.assertEqual(restored.canonical_json(), probe.canonical_json(serialized, maximum_bytes=probe.MAX_STATE_JSON_BYTES))
        self.assertEqual(restored.result_id, probe.calculate_result_id(serialized))
        text = restored.canonical_json()
        for forbidden in ("nonce", "payload", "rawData", "dpValues", "secret"):
            self.assertNotIn(forbidden, text)

    def test_record_exact_field_set_and_mutation_canaries(self) -> None:
        record = verified_record()
        source = record.as_dict()
        before = deepcopy(source)
        restored = probe.ProbeRecoveryRecord.from_dict(source)
        self.assertEqual(source, before)
        self.assertEqual(set(source), {field.name for field in fields(probe.ProbeRecoveryRecord)})
        with self.assertRaises(FrozenInstanceError):
            restored.generation = 1

        for label, mutated in (
            ("extra", {**source, "raw": "frame"}),
            ("missing", {key: value for key, value in source.items() if key != "proofs"}),
        ):
            with self.subTest(label=label), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRecoveryRecord.from_dict(mutated)

        active = armed_record().accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
            now_ms=NOW + 1,
        ).as_dict()
        incomplete = deepcopy(active)
        incomplete["proofs"] = []
        wrong_target = deepcopy(active)
        wrong_target["proofs"][0]["target"] = 19
        for label, mutated in (
            ("incomplete_phase_history", incomplete),
            ("wrong_completed_target", wrong_target),
        ):
            with self.subTest(label=label), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRecoveryRecord.from_dict(mutated)

    def test_record_rejects_bool_ints_unknown_profile_and_resource_overflow(self) -> None:
        base = armed_record().as_dict()
        mutations = {
            "bool_generation": {**base, "generation": True},
            "bool_deadline": {**base, "operation_deadline_ms": False},
            "bool_restore": {**base, "restore_required": 1},
            "unknown_profile": {**base, "profile_id": "other-profile"},
            "too_many_requests": {
                **base,
                "consumed_request_ids": [
                    f"tfpp-req-{index:024x}"
                    for index in range(probe.MAX_CONSUMED_REQUEST_IDS + 1)
                ],
            },
            "duplicate_request": {
                **base,
                "consumed_request_ids": [REQUEST, REQUEST],
            },
            "too_many_sequences": {
                **base,
                "used_sequences": list(range(probe.MAX_USED_SEQUENCES + 1)),
            },
        }
        for label, value in mutations.items():
            with self.subTest(label=label), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRecoveryRecord.from_dict(value)

    def test_shared_sequence_capacity_policy_matches_every_durable_phase(self) -> None:
        policy = VECTORS["sequence_capacity_policy"]
        self.assertEqual(probe.MAX_USED_SEQUENCES, policy["maximum_used_sequences"])
        self.assertEqual(probe.MAX_RESTORE_ATTEMPTS, policy["claimed_restore_attempts"])
        self.assertEqual(
            probe.MAX_UNCLAIMED_SAFETY_ATTEMPTS,
            policy["unclaimed_safety_attempts"],
        )
        physical1 = armed_record()
        physical2 = physical1.accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
            now_ms=NOW + 1,
        )
        noop = physical2.accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
            now_ms=NOW + 2,
            next_sequence=100,
        )
        challenge = noop.accept_proof(
            proof(probe.ProbePurpose.NOOP, 100, 21),
            now_ms=NOW + 3,
            next_sequence=101,
        )
        restoring = challenge.accept_proof(
            proof(probe.ProbePurpose.CHALLENGE, 101, 22),
            now_ms=NOW + 4,
            next_sequence=102,
        )
        result = restoring.accept_proof(
            proof(probe.ProbePurpose.RESTORE, 102, 21),
            now_ms=NOW + 5,
        )
        quiescent = result.acknowledge(
            boot_id=BOOT,
            request_id=SECOND_REQUEST,
            request_deadline_ms=NOW + 20_000,
            result_id=result.result_id,
            now_ms=result.result_not_before_ms,
        )
        remediation = challenge.to_remediation(
            failure_code="queue_overflow",
            restore_required=True,
        )
        bases = {
            (probe.ProbePhase.AWAITING_PHYSICAL_TARGET_1.value, 0): physical1,
            (probe.ProbePhase.AWAITING_PHYSICAL_TARGET_2.value, 0): physical2,
            (probe.ProbePhase.AWAITING_NOOP_RESPONSE.value, 0): noop,
            (probe.ProbePhase.AWAITING_CHALLENGE_RESPONSE.value, 0): challenge,
            (probe.ProbePhase.AWAITING_RESTORE_RESPONSE.value, 1): restoring,
            (probe.ProbePhase.AWAITING_RESTORE_RESPONSE.value, 2): restoring,
            (probe.ProbePhase.AWAITING_RESTORE_RESPONSE.value, 3): restoring,
            (probe.ProbePhase.RESULT_PENDING_ACK.value, 1): result,
            (probe.ProbePhase.QUIESCENT.value, 1): quiescent,
            (probe.ProbePhase.REMEDIATION_REQUIRED.value, 0): remediation,
        }
        for vector in policy["phase_vectors"]:
            key = (vector["phase"], vector["restore_attempts"])
            draft = bases[key].as_dict()
            draft["restore_attempts"] = vector["restore_attempts"]
            used = draft["used_sequences"]
            sequence = 1_000
            while len(used) < vector["maximum_used_sequences"]:
                if sequence not in used:
                    used.append(sequence)
                sequence += 1
            with self.subTest(key=key, boundary="maximum"):
                maximum = probe.ProbeRecoveryRecord.from_dict(draft)
                self.assertEqual(
                    len(maximum.used_sequences),
                    vector["maximum_used_sequences"],
                )
            overflow = deepcopy(draft)
            overflow["used_sequences"].append(2_000)
            with self.subTest(key=key, boundary="overflow"), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRecoveryRecord.from_dict(overflow)

    def test_resume_requires_fresh_boot_bound_request_and_only_rearms_noop(self) -> None:
        physical = armed_record()
        resumed = physical.resume(
            boot_id=SECOND_BOOT,
            request_id=SECOND_REQUEST,
            request_deadline_ms=NOW + 20_000,
            now_ms=NOW,
        )
        self.assertEqual(resumed.bound_boot_id, SECOND_BOOT)
        self.assertEqual(resumed.consumed_request_ids, (SECOND_REQUEST,))
        self.assertIsNone(resumed.expected_proof.sequence)

        noop = physical.accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
            now_ms=NOW + 1,
        ).accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
            now_ms=NOW + 2,
            next_sequence=100,
        )
        resumed_noop = noop.resume(
            boot_id=SECOND_BOOT,
            request_id=SECOND_REQUEST,
            request_deadline_ms=NOW + 20_000,
            now_ms=NOW,
            next_sequence=103,
        )
        self.assertEqual(resumed_noop.expected_proof.sequence, 103)
        self.assertIn(100, resumed_noop.used_sequences)
        self.assertIn(103, resumed_noop.used_sequences)

        with self.assertRaises(probe.PhysicalProbeError):
            challenge_record().resume(
                boot_id=SECOND_BOOT,
                request_id=SECOND_REQUEST,
                request_deadline_ms=NOW + 20_000,
                now_ms=NOW,
            )

        with self.assertRaises(probe.PhysicalProbeError):
            physical.resume(
                boot_id=SECOND_BOOT,
                request_id=SECOND_REQUEST,
                request_deadline_ms=NOW + 130_000,
                now_ms=NOW + 120_000,
            )

    def test_maximum_noop_resumes_preserve_every_claimed_and_unclaimed_slot(self) -> None:
        record = armed_record().accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
            now_ms=NOW + 1,
        ).accept_proof(
            proof(probe.ProbePurpose.PHYSICAL_TARGET_2, 11, 21),
            now_ms=NOW + 2,
            next_sequence=100,
        )
        policy = VECTORS["sequence_capacity_policy"]
        noop_maximum = next(
            item["maximum_used_sequences"]
            for item in policy["phase_vectors"]
            if item["phase"] == probe.ProbePhase.AWAITING_NOOP_RESPONSE.value
        )
        allowed_resumes = noop_maximum - len(record.used_sequences)
        for index in range(allowed_resumes):
            record = record.resume(
                boot_id=BOOT,
                request_id=f"tfpp-req-{0x700 + index:024x}",
                request_deadline_ms=NOW + 20_000 + index,
                now_ms=NOW,
                next_sequence=101 + index,
            )
        self.assertEqual(len(record.used_sequences), noop_maximum)

        before_rejection = record
        with self.assertRaises(probe.PhysicalProbeError):
            record.resume(
                boot_id=BOOT,
                request_id="tfpp-req-" + "f" * 24,
                request_deadline_ms=NOW + 30_000,
                now_ms=NOW,
                next_sequence=107,
            )
        self.assertIs(record, before_rejection)

        challenge = record.accept_proof(
            proof(probe.ProbePurpose.NOOP, 106, 21),
            now_ms=NOW + 3,
            next_sequence=107,
        )
        self.assertEqual(
            probe.MAX_USED_SEQUENCES - len(challenge.used_sequences),
            probe.MAX_RESTORE_ATTEMPTS + probe.MAX_UNCLAIMED_SAFETY_ATTEMPTS,
        )
        restoring = challenge.accept_proof(
            proof(probe.ProbePurpose.CHALLENGE, 107, 22),
            now_ms=NOW + 4,
            next_sequence=108,
        )
        restoring = restoring.begin_restore(
            sequence=109,
            failure_code="proof_mismatch",
            now_ms=NOW + 5,
        ).begin_restore(
            sequence=110,
            failure_code="proof_mismatch",
            now_ms=NOW + 6,
        )
        self.assertEqual(restoring.restore_attempts, probe.MAX_RESTORE_ATTEMPTS)
        terminal = restoring.accept_proof(
            proof(probe.ProbePurpose.RESTORE, 110, 21),
            now_ms=NOW + 7,
        )
        self.assertEqual(
            len(terminal.used_sequences),
            probe.MAX_USED_SEQUENCES - probe.MAX_UNCLAIMED_SAFETY_ATTEMPTS,
        )
        remediated = terminal.to_remediation(
            failure_code="control_drift",
            restore_required=True,
        )
        self.assertEqual(remediated.used_sequences, terminal.used_sequences)

    def test_previous_boot_safe_terminalization_requires_explicit_rebind(self) -> None:
        record = armed_record()
        with self.assertRaises(probe.PhysicalProbeError):
            record.fail_safe(
                "deadline_expired",
                now_ms=NOW + 1,
                boot_id=SECOND_BOOT,
            )
        remediated = record.to_remediation(
            failure_code="deadline_expired",
            restore_required=False,
        )
        self.assertIs(remediated.phase, probe.ProbePhase.REMEDIATION_REQUIRED)
        self.assertFalse(remediated.restore_required)
        self.assertIsNone(remediated.result_id)
        self.assertFalse(remediated.cleanup_allowed)

    def test_generation_limit_allows_only_in_place_safety_remediation(self) -> None:
        vector = VECTORS["failure_generation_parity_vectors"][1]
        record = replace(armed_record(), generation=vector["source_generation"])
        remediated = record.to_remediation(
            failure_code=vector["failure_code"],
            restore_required=False,
        )
        self.assertEqual(remediated.generation, vector["expected_generation"])
        self.assertIs(remediated.phase, probe.ProbePhase.REMEDIATION_REQUIRED)
        self.assertFalse(remediated.cleanup_allowed)
        self.assertIsNone(remediated.result_id)
        with self.assertRaises(probe.PhysicalProbeError):
            record.accept_proof(
                proof(probe.ProbePurpose.PHYSICAL_TARGET_1, 10, 18),
                now_ms=NOW + 1,
            )
        with self.assertRaises(probe.PhysicalProbeError):
            record.fail_safe(
                "deadline_expired",
                now_ms=NOW + 1,
                boot_id=BOOT,
            )

    def test_deadlines_are_fresh_monotonic_and_bounded(self) -> None:
        for label, changes in (
            ("stale_request", {"request_deadline_ms": NOW}),
            ("far_request", {"request_deadline_ms": NOW + probe.MAX_REQUEST_WINDOW_MS + 1}),
            ("stale_operation", {"operation_deadline_ms": NOW}),
            ("far_operation", {"operation_deadline_ms": NOW + probe.MAX_OPERATION_WINDOW_MS + 1}),
            ("request_after_operation", {"request_deadline_ms": NOW + 20_000, "operation_deadline_ms": NOW + 10_000}),
        ):
            kwargs = {
                "profile": probe.BRT_PROFILE,
                "candidate": candidate(),
                "candidate_set_topic": "candidate-valve/set",
                "operation_id": OPERATION,
                "boot_id": BOOT,
                "request_id": REQUEST,
                "request_deadline_ms": NOW + 10_000,
                "operation_deadline_ms": NOW + 120_000,
                "intended_target": 21,
                "physical_targets": (18, 21),
                "now_ms": NOW,
            }
            with self.subTest(label=label), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.ProbeRecoveryRecord.arm(**{**kwargs, **changes})

        record = armed_record()
        with self.assertRaises(probe.PhysicalProbeError):
            record.resume(
                boot_id=BOOT,
                request_id=SECOND_REQUEST,
                request_deadline_ms=record.last_request_deadline_ms,
                now_ms=NOW,
            )


class PhysicalProbeResourceAndWiringTests(unittest.TestCase):
    def test_canonical_json_enforces_depth_node_string_integer_and_byte_bounds(self) -> None:
        nested: object = "leaf"
        for _ in range(probe.MAX_JSON_DEPTH + 2):
            nested = [nested]
        cases = (
            nested,
            list(range(probe.MAX_JSON_NODES + 1)),
            {"value": "x" * (probe.MAX_JSON_STRING_LENGTH + 1)},
            {"value": probe.MAX_SAFE_INTEGER + 1},
            {"value": b"raw"},
        )
        for value in cases:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(
                probe.PhysicalProbeError
            ):
                probe.canonical_json(value, maximum_bytes=probe.MAX_STATE_JSON_BYTES)
        with self.assertRaises(probe.PhysicalProbeError):
            probe.parse_canonical_json("{" + "x" * probe.MAX_MESSAGE_JSON_BYTES)

    def test_digest_is_deterministic_domain_separated_and_ascii_canonical(self) -> None:
        left = {"z": 1, "a": "value"}
        right = {"a": "value", "z": 1}
        self.assertEqual(probe.canonical_digest(left), probe.canonical_digest(right))
        self.assertNotEqual(
            probe.canonical_digest(left, domain="one"),
            probe.canonical_digest(left, domain="two"),
        )
        self.assertEqual(len(probe.canonical_digest(left)), 64)

    def test_module_is_stdlib_only_and_integration_setup_remains_unwired(self) -> None:
        source_path = PACKAGE_ROOT / "physical_probe.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.level, 1)
                if node.module:
                    imported_roots.add(node.module.split(".", 1)[0])
        self.assertTrue(imported_roots <= set(sys.stdlib_module_names))
        self.assertNotIn("homeassistant", imported_roots)

        package_sources = sorted(PACKAGE_ROOT.rglob("*.py"))
        for path in package_sources:
            if path == source_path:
                continue
            with self.subTest(path=path.relative_to(PACKAGE_ROOT)):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("physical_probe", source)
                self.assertNotIn("true_family_brt_probe", source)

        manifest_text = (PACKAGE_ROOT / "manifest.json").read_text(encoding="utf-8")
        self.assertNotIn("physical_probe", manifest_text)
        self.assertNotIn("true_family_brt_probe", manifest_text)
        package_init = ast.parse(
            (PACKAGE_ROOT / "__init__.py").read_text(encoding="utf-8")
        )
        imported_modules = {
            node.module
            for node in ast.walk(package_init)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertNotIn("physical_probe", imported_modules)

        owners = {
            str(path.relative_to(PACKAGE_ROOT))
            for path in package_sources
            if "ProbeRecoveryRecord" in path.read_text(encoding="utf-8")
        }
        self.assertEqual(owners, {"physical_probe.py"})

    def test_extension_has_no_package_import_or_automatic_lifecycle_surface(self) -> None:
        source = (
            PACKAGE_ROOT / "probe" / "true_family_brt_probe.mjs"
        ).read_text(encoding="utf-8")
        imports = re.findall(r'(?:from|import)\s+"([^"]+)"', source)
        self.assertTrue(imports)
        self.assertTrue(all(specifier.startswith("node:") for specifier in imports))
        for forbidden in (
            "homeassistant",
            "zigbee-herdsman-converters",
            ".bind(",
            "enableDisableExtension(",
            "restartCallback(",
            "addExtension(",
            "bridge/request/extension/save",
            "bridge/request/extension/remove",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("dedicated broker principal", source)
        self.assertIn("disable the Zigbee2MQTT frontend", source)
        self.assertIn("eventBus does", source)


if __name__ == "__main__":
    unittest.main()
