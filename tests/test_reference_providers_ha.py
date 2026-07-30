"""Pure validation tests for Home Assistant reference-provider readiness."""

from __future__ import annotations

from dataclasses import asdict, fields, replace
from datetime import UTC, datetime, timedelta
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"


def load_reference_providers():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = sys.modules.get(PACKAGE_NAME)
    if package is None:
        package = types.ModuleType(PACKAGE_NAME)
        package.__path__ = [str(PACKAGE_ROOT)]
        sys.modules[PACKAGE_NAME] = package
    return importlib.import_module(f"{PACKAGE_NAME}.reference_providers_ha")


providers = load_reference_providers()
transaction = importlib.import_module(f"{PACKAGE_NAME}.reference_transaction")
NOW = datetime(2026, 7, 28, 12, tzinfo=UTC)
RAW_FENCE_TOKEN = "private-raw-fence-capability-sentinel"


def fence_token_digest(token: str):
    return transaction.derive_fence_token_digest(token)


def expected_manifest():
    return providers.ExpectedObjectManifest.from_mapping(
        "inventory-7",
        {
            provider: (f"{provider}:object",)
            for provider in providers.PROVIDER_NAMES
        },
    )


def exact_inventories(expected):
    return tuple(
        providers.ProviderInventory.readable(
            item.provider,
            (providers.InventoryObject(key, revision=1) for key in item.object_keys),
        )
        for item in expected.providers
    )


def full_capabilities():
    return providers.ProviderCapabilities(True, True, True, True, True, True)


def ready_bridges(expected):
    return tuple(
        providers.BridgeReadiness(
            provider=item.provider,
            available=True,
            capabilities=full_capabilities(),
            object_count=item.count,
            expected_manifest_digest=expected.digest,
            object_manifest_digest=item.digest,
            inventory_revision=providers.ProviderInventory.readable(
                item.provider,
                (
                    providers.InventoryObject(key, revision=1)
                    for key in item.object_keys
                ),
            ).revision_digest,
            bridge_id=f"bridge-{item.provider}-v1",
            readiness_revision=f"readiness-{item.provider}-v1",
        )
        for item in expected.providers
    )


def external_attestation(expected):
    external = expected.for_provider("external_writers")
    fence = providers.WriterFenceMetadata(
        provider="external_writers",
        writer_id="writer-1",
        fence_token_digest=fence_token_digest(RAW_FENCE_TOKEN),
        fence_epoch=9,
        fence_revision=9,
        scope_digest=external.digest,
        acquired_at=NOW - timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=10),
    )
    return providers.SignedExternalWriterAttestation(
        provider="external_writers",
        issuer="host-bridge",
        key_id="key-1",
        attestation_id="attestation-1",
        writer_id="writer-1",
        expected_manifest_digest=expected.digest,
        object_keys=external.object_keys,
        inventory_revision=1,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        fence=fence,
        signature=b"signed",
    )


class Verifier:
    def __init__(self, result=True) -> None:
        self.result = result
        self.calls = []

    def verify(self, attestation, canonical_payload):
        self.calls.append((attestation, canonical_payload))
        return self.result


class ReferenceProviderValidationTests(unittest.TestCase):
    def test_expected_manifest_is_exact_and_canonical(self) -> None:
        expected = expected_manifest()

        self.assertEqual(
            tuple(item.provider for item in expected.providers),
            providers.PROVIDER_NAMES,
        )
        self.assertEqual(len(expected.digest), 64)
        incomplete = {
            name: ()
            for name in providers.PROVIDER_NAMES
            if name != "scheduler"
        }
        with self.assertRaises(ValueError):
            providers.ExpectedObjectManifest.from_mapping("revision", incomplete)
        with self.assertRaises(ValueError):
            providers.ExpectedProviderObjects(
                "scheduler",
                ("duplicate", "duplicate"),
            )
        with self.assertRaises(ValueError):
            providers.ExpectedProviderObjects("unknown", ())

    def test_capability_and_bridge_claims_are_strict(self) -> None:
        with self.assertRaises(TypeError):
            providers.ProviderCapabilities(1, True, True, True, True, True)
        self.assertFalse(
            providers.ProviderCapabilities(
                True,
                True,
                False,
                True,
                True,
                True,
            ).production_ready
        )
        with self.assertRaises(ValueError):
            providers.BridgeReadiness(
                provider="scheduler",
                available=False,
                capabilities=full_capabilities(),
                object_count=1,
                expected_manifest_digest="0" * 64,
                object_manifest_digest="0" * 64,
                inventory_revision=1,
                bridge_id="bridge-scheduler-v1",
                readiness_revision="readiness-scheduler-v1",
            )

    def test_raw_fence_capability_never_enters_attestation_shapes(self) -> None:
        expected = expected_manifest()
        attestation = external_attestation(expected)
        readiness = ready_bridges(expected)[0]

        self.assertFalse(hasattr(providers, "DurableBridgeAcknowledgement"))
        self.assertNotIn("fence_token", {item.name for item in fields(attestation.fence)})
        self.assertFalse(
            any("token" in item.name for item in fields(providers.BridgeReadiness))
        )
        self.assertEqual(
            attestation.fence.fence_token_digest,
            fence_token_digest(RAW_FENCE_TOKEN),
        )
        self.assertNotEqual(
            str(attestation.fence.fence_token_digest),
            hashlib.sha256(RAW_FENCE_TOKEN.encode("utf-8")).hexdigest(),
        )
        rendered = "\n".join(
            (
                repr(attestation),
                repr(attestation.fence),
                repr(asdict(attestation)),
                attestation.canonical_payload().decode("ascii"),
                repr(readiness),
                repr(asdict(readiness)),
            )
        )
        self.assertNotIn(RAW_FENCE_TOKEN, rendered)
        self.assertIn("tf-fence-token-sha256-v1:", rendered)

    def test_bridge_reconciliation_requires_complete_typed_intents(self) -> None:
        methods = {
            "async_reconcile_fence_acquisition": "FenceAcquisitionIntent",
            "async_reconcile_fence_release": "FenceReleaseIntent",
            "async_observe_object": "BridgeOperationIntent",
        }
        for method_name, intent_name in methods.items():
            with self.subTest(method=method_name):
                signature = inspect.signature(
                    getattr(providers.ProviderHostBridge, method_name)
                )
                self.assertEqual(tuple(signature.parameters), ("self", "operation"))
                self.assertIn(
                    intent_name,
                    str(signature.parameters["operation"].annotation),
                )
        dispatch_methods = {
            "async_compare_and_swap": (
                "self",
                "operation",
                "authorization",
                "payload",
            ),
            "async_rollback": (
                "self",
                "operation",
                "authorization",
                "payload",
                "write_receipt",
            ),
            "async_reconcile_operation": (
                "self",
                "operation",
                "authorization",
            ),
        }
        for method_name, parameter_names in dispatch_methods.items():
            with self.subTest(method=method_name):
                signature = inspect.signature(
                    getattr(providers.ProviderHostBridge, method_name)
                )
                self.assertEqual(tuple(signature.parameters), parameter_names)
                self.assertIn(
                    "BridgeOperationIntent",
                    str(signature.parameters["operation"].annotation),
                )
                self.assertIn(
                    "BridgeDispatchAuthorization",
                    str(signature.parameters["authorization"].annotation),
                )
                self.assertIs(
                    signature.parameters["authorization"].kind,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
        operation_return = str(
            inspect.signature(
                providers.ProviderHostBridge.async_reconcile_operation
            ).return_annotation
        )
        self.assertIn("BridgeOperationReceipt", operation_return)
        for method_name in (
            "async_reconcile_fence_acquisition",
            "async_reconcile_fence_release",
        ):
            lifecycle_return = str(
                inspect.signature(
                    getattr(providers.ProviderHostBridge, method_name)
                ).return_annotation
            )
            self.assertIn("Receipt", lifecycle_return)
            self.assertIn("NoEffectReceipt", lifecycle_return)

    def test_epoch_reservation_is_opaque_and_strictly_advances(self) -> None:
        reservation = providers.BridgeEpochReservation(
            provider="scheduler",
            bridge_id="bridge-scheduler-v1",
            reservation_id="nonsecret-reservation-7",
            requested_after_epoch=5,
            previous_high_water=6,
            epoch=7,
            reserved_at=NOW,
        )

        self.assertNotIn(RAW_FENCE_TOKEN, repr(reservation))
        with self.assertRaises(ValueError):
            replace(reservation, epoch=6)

    def test_external_attestation_requires_an_injected_verifier_and_fence(self) -> None:
        expected = expected_manifest()
        attestation = external_attestation(expected)

        with self.assertRaises(providers.ExternalAttestationError):
            providers.validate_external_writer_attestation(
                attestation,
                expected,
                None,
                now=NOW,
            )
        rejecting = Verifier(False)
        with self.assertRaises(providers.ExternalAttestationError):
            providers.validate_external_writer_attestation(
                attestation,
                expected,
                rejecting,
                now=NOW,
            )
        verifier = Verifier()
        providers.validate_external_writer_attestation(
            attestation,
            expected,
            verifier,
            now=NOW,
        )
        self.assertEqual(len(verifier.calls), 1)
        self.assertNotIn(b"signed", verifier.calls[0][1])

        expired_fence = replace(
            attestation.fence,
            expires_at=NOW,
        )
        expired = replace(
            attestation,
            expires_at=NOW - timedelta(seconds=1),
            fence=expired_fence,
        )
        with self.assertRaises(providers.ExternalAttestationError):
            providers.validate_external_writer_attestation(
                expired,
                expected,
                verifier,
                now=NOW,
            )

    def test_production_readiness_requires_every_bridge_and_attestation(self) -> None:
        expected = expected_manifest()
        inventories = exact_inventories(expected)
        bridges = ready_bridges(expected)

        without_attestation = providers.assess_production_readiness(
            expected,
            inventories,
            bridges,
            now=NOW,
        )
        self.assertFalse(without_attestation.ready)
        self.assertEqual(
            without_attestation.providers[2].status,
            providers.PublicProviderStatus.UNAVAILABLE,
        )

        verifier = Verifier()
        ready = providers.assess_production_readiness(
            expected,
            inventories,
            bridges,
            external_attestation=external_attestation(expected),
            external_verifier=verifier,
            now=NOW,
        )
        self.assertTrue(ready.ready)

        scheduler_index = providers.PROVIDER_NAMES.index("scheduler")
        scheduler_bridge = bridges[scheduler_index]
        incomplete = replace(
            scheduler_bridge,
            capabilities=replace(
                scheduler_bridge.capabilities,
                conditional_write=False,
            ),
        )
        blocked_bridges = (
            *bridges[:scheduler_index],
            incomplete,
            *bridges[scheduler_index + 1 :],
        )
        blocked = providers.assess_production_readiness(
            expected,
            inventories,
            blocked_bridges,
            external_attestation=external_attestation(expected),
            external_verifier=verifier,
            now=NOW,
        )
        self.assertFalse(blocked.ready)
        self.assertEqual(
            blocked.providers[scheduler_index].status,
            providers.PublicProviderStatus.READ_ONLY,
        )

    def test_counts_and_object_manifests_are_both_enforced(self) -> None:
        expected = expected_manifest()
        inventories = list(exact_inventories(expected))
        scheduler_index = providers.PROVIDER_NAMES.index("scheduler")
        inventories[scheduler_index] = providers.ProviderInventory.readable(
            "scheduler",
            (
                providers.InventoryObject(
                    "scheduler:different",
                    revision=1,
                ),
            ),
        )
        result = providers.assess_production_readiness(
            expected,
            inventories,
            ready_bridges(expected),
            external_attestation=external_attestation(expected),
            external_verifier=Verifier(),
            now=NOW,
        )

        self.assertFalse(result.ready)
        self.assertEqual(
            result.providers[scheduler_index].status,
            providers.PublicProviderStatus.MANIFEST_MISMATCH,
        )

        count_mismatch = replace(
            ready_bridges(expected)[scheduler_index],
            object_count=2,
        )
        bridges = list(ready_bridges(expected))
        bridges[scheduler_index] = count_mismatch
        result = providers.assess_production_readiness(
            expected,
            exact_inventories(expected),
            bridges,
            external_attestation=external_attestation(expected),
            external_verifier=Verifier(),
            now=NOW,
        )
        self.assertEqual(
            result.providers[scheduler_index].status,
            providers.PublicProviderStatus.COUNT_MISMATCH,
        )

    def test_public_summary_has_only_fixed_names_statuses_and_counts(self) -> None:
        expected = expected_manifest()
        sensitive_values = [
            key
            for item in expected.providers
            for key in item.object_keys
        ]
        result = providers.assess_production_readiness(
            expected,
            exact_inventories(expected),
            (),
            external_attestation=external_attestation(expected),
            external_verifier=Verifier(),
            now=NOW,
        ).as_dict()

        self.assertEqual(set(result), {"ready", "providers"})
        self.assertEqual(
            [item["provider"] for item in result["providers"]],
            list(providers.PROVIDER_NAMES),
        )
        for item in result["providers"]:
            self.assertEqual(
                set(item),
                {"provider", "status", "expected_count", "observed_count"},
            )
        rendered = json.dumps(result, sort_keys=True)
        for sensitive in sensitive_values:
            self.assertNotIn(sensitive, rendered)

    def test_host_bridge_is_authoritative_for_yaml_and_lovelace(self) -> None:
        expected = expected_manifest()
        inventories = list(exact_inventories(expected))
        for provider in ("active_yaml", "lovelace"):
            index = providers.PROVIDER_NAMES.index(provider)
            inventories[index] = providers.ProviderInventory.unavailable(provider)

        result = providers.assess_production_readiness(
            expected,
            inventories,
            ready_bridges(expected),
            external_attestation=external_attestation(expected),
            external_verifier=Verifier(),
            now=NOW,
        )

        self.assertTrue(result.ready)


if __name__ == "__main__":
    unittest.main()
