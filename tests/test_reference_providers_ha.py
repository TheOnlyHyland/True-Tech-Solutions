"""Pure validation tests for Home Assistant reference-provider readiness."""

from __future__ import annotations

import asyncio
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
migration = importlib.import_module(f"{PACKAGE_NAME}.reference_migration")
projection = importlib.import_module(f"{PACKAGE_NAME}.reference_projection")
transaction = importlib.import_module(f"{PACKAGE_NAME}.reference_transaction")
NOW = datetime(2026, 7, 28, 12, tzinfo=UTC)
RAW_FENCE_TOKEN = "private-raw-fence-capability-sentinel"
COMPLETE_CONFIG_ENTRY_PAYLOAD = "complete-config-entry-payload-sentinel"


def fence_token_digest(token: str):
    return transaction.derive_fence_token_digest(token)


def canonical_digest(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class FakeConfigEntries:
    def __init__(self, entries) -> None:
        self.entries = tuple(entries)
        self.calls = []

    def async_entries(self, domain):
        self.calls.append(domain)
        return [entry for entry in self.entries if entry.domain == domain]


def config_entry(
    entry_id: str,
    domain: str,
    options,
    *,
    data=None,
    subentries=None,
    version: int = 1,
    minor_version: int | None = None,
    modified_at: datetime = NOW,
):
    if minor_version is None:
        minor_version = 3 if domain == "generic_thermostat" else 2
    if domain == "template" and "template_type" not in options:
        options = {"template_type": "sensor", **options}
    return types.SimpleNamespace(
        entry_id=entry_id,
        domain=domain,
        version=version,
        minor_version=minor_version,
        modified_at=modified_at,
        data={} if data is None else data,
        options=options,
        subentries={} if subentries is None else subentries,
    )


def read_config_entry_snapshot(entries, policy):
    manager = FakeConfigEntries(entries)
    hass = types.SimpleNamespace(config_entries=manager)
    snapshots = asyncio.run(
        providers.async_read_config_entry_reference_snapshot(hass, policy)
    )
    return snapshots, manager


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


class ConfigEntryReferenceSnapshotTests(unittest.TestCase):
    def test_exact_projection_is_immutable_sorted_and_revision_bound(self) -> None:
        state = "{{ states('climate.source_valve') }}"
        availability = "{{ has_value('sensor.room_temperature') }}"
        generic = config_entry(
            "01-generic",
            "generic_thermostat",
            {
                "name": COMPLETE_CONFIG_ENTRY_PAYLOAD,
                "heater": "switch.radiator_relay",
                "target_sensor": "sensor.room_temperature",
                "ac_mode": False,
                "cold_tolerance": 0.3,
                "hot_tolerance": 0.3,
            },
        )
        template = config_entry(
            "02-template",
            "template",
            {
                "name": COMPLETE_CONFIG_ENTRY_PAYLOAD,
                "template_type": "sensor",
                "state": state,
                "advanced_options": {"availability": availability},
            },
        )
        policy = (
            providers.ConfigEntryReferenceObjectPolicy(
                "01-generic", "generic_thermostat"
            ),
            providers.ConfigEntryReferenceObjectPolicy("02-template", "template"),
        )

        snapshots, manager = read_config_entry_snapshot(
            (template, generic),
            policy,
        )

        self.assertEqual(manager.calls, ["generic_thermostat", "template"])
        self.assertEqual(
            tuple(snapshot.object_id for snapshot in snapshots),
            ("01-generic", "02-template"),
        )
        self.assertEqual(
            snapshots[0].payload,
            {
                "heater": "switch.radiator_relay",
                "target_sensor": "sensor.room_temperature",
            },
        )
        self.assertEqual(
            snapshots[1].payload,
            {
                "state": state,
                "availability_template": availability,
            },
        )
        self.assertTrue(all(snapshot.writable is False for snapshot in snapshots))
        self.assertEqual(
            snapshots[1].fingerprint,
            canonical_digest(
                {
                    "state": state,
                    "availability_template": availability,
                }
            ),
        )
        self.assertEqual(
            snapshots[1].revision,
            canonical_digest(
                {
                    "modified_at": NOW.isoformat(),
                    "version": 1,
                    "minor_version": 2,
                    "projected_fingerprint": snapshots[1].fingerprint,
                }
            ),
        )

        template.options["state"] = "changed after snapshot"
        template.options["advanced_options"]["availability"] = "changed"
        self.assertEqual(snapshots[1].payload["state"], state)
        self.assertEqual(
            snapshots[1].payload["availability_template"],
            availability,
        )
        with self.assertRaises(TypeError):
            snapshots[1].payload["state"] = "mutation"  # type: ignore[index]

        reference_document = snapshots[1].as_reference_document()
        self.assertEqual(
            migration.canonical_document_fingerprint(reference_document),
            snapshots[1].fingerprint,
        )
        availability_scan = projection.scan_semantic_references(
            reference_document.payload,
            "sensor.room_temperature",
            provider="config_entry",
        )
        self.assertEqual(
            availability_scan.replaceable_paths,
            (("availability_template",),),
        )
        self.assertEqual(availability_scan.blocked, ())
        replaced, count = projection.replace_semantic_references(
            reference_document.payload,
            "sensor.room_temperature",
            "sensor.logical_room_temperature",
            provider="config_entry",
        )
        self.assertEqual(count, 1)
        self.assertEqual(
            replaced["availability_template"],
            "{{ has_value('sensor.logical_room_temperature') }}",
        )

        rendered = repr(snapshots) + json.dumps(
            [snapshot.as_public_summary() for snapshot in snapshots],
            sort_keys=True,
        )
        self.assertNotIn(COMPLETE_CONFIG_ENTRY_PAYLOAD, rendered)
        self.assertNotIn(state, rendered)
        self.assertNotIn(availability, rendered)
        self.assertNotIn("01-generic", rendered)
        self.assertNotIn("02-template", rendered)
        self.assertNotIn("data", {item.name for item in fields(snapshots[0])})
        self.assertNotIn("options", {item.name for item in fields(snapshots[0])})

    def test_template_projection_omits_absent_availability(self) -> None:
        entry = config_entry(
            "template-only",
            "template",
            {
                "template_type": "sensor",
                "state": "{{ is_state('binary_sensor.window', 'on') }}",
                "advanced_options": {},
            },
        )
        policy = (
            providers.ConfigEntryReferenceObjectPolicy("template-only", "template"),
        )

        snapshots, _manager = read_config_entry_snapshot((entry,), policy)

        self.assertEqual(
            snapshots[0].payload,
            {"state": "{{ is_state('binary_sensor.window', 'on') }}"},
        )

    def test_revision_changes_for_projected_or_modified_at_drift(self) -> None:
        policy = (
            providers.ConfigEntryReferenceObjectPolicy("template-only", "template"),
        )
        first = config_entry(
            "template-only",
            "template",
            {"state": "{{ states('sensor.first') }}"},
        )
        projected_drift = config_entry(
            "template-only",
            "template",
            {"state": "{{ states('sensor.second') }}"},
        )
        timestamp_drift = config_entry(
            "template-only",
            "template",
            {"state": "{{ states('sensor.first') }}"},
            modified_at=NOW + timedelta(microseconds=1),
        )

        first_snapshot = read_config_entry_snapshot((first,), policy)[0][0]
        projected_snapshot = read_config_entry_snapshot(
            (projected_drift,), policy
        )[0][0]
        timestamp_snapshot = read_config_entry_snapshot(
            (timestamp_drift,), policy
        )[0][0]

        self.assertNotEqual(first_snapshot.fingerprint, projected_snapshot.fingerprint)
        self.assertNotEqual(first_snapshot.revision, projected_snapshot.revision)
        self.assertEqual(first_snapshot.fingerprint, timestamp_snapshot.fingerprint)
        self.assertNotEqual(first_snapshot.revision, timestamp_snapshot.revision)

    def test_policy_is_exact_unique_and_canonically_ordered(self) -> None:
        first = config_entry("entry-a", "template", {"state": "ready"})
        second = config_entry("entry-b", "template", {"state": "ready"})
        duplicate = config_entry("entry-a", "template", {"state": "ready"})

        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            providers.ConfigEntryReferenceObjectPolicy("entry", "unknown")
        for malformed in (
            (
                providers.ConfigEntryReferenceObjectPolicy("entry-b", "template"),
                providers.ConfigEntryReferenceObjectPolicy("entry-a", "template"),
            ),
            (
                providers.ConfigEntryReferenceObjectPolicy("entry-a", "template"),
                providers.ConfigEntryReferenceObjectPolicy("entry-a", "template"),
            ),
            [providers.ConfigEntryReferenceObjectPolicy("entry-a", "template")],
        ):
            with self.subTest(policy=malformed):
                with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
                    read_config_entry_snapshot((first, second), malformed)

        policy = (
            providers.ConfigEntryReferenceObjectPolicy("entry-a", "template"),
        )
        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            read_config_entry_snapshot((), policy)
        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            read_config_entry_snapshot((first, duplicate), policy)

        snapshots, _manager = read_config_entry_snapshot((first, second), policy)
        self.assertEqual(
            tuple(snapshot.object_id for snapshot in snapshots),
            ("entry-a",),
        )

    def test_exact_policy_selects_four_of_five_thermostats_and_three_templates(
        self,
    ) -> None:
        generic_ids = tuple(f"0{index}-generic" for index in range(1, 5))
        template_ids = tuple(f"0{index}-template" for index in range(5, 8))
        selected = tuple(
            config_entry(
                entry_id,
                "generic_thermostat",
                {
                    "heater": f"switch.heater_{index}",
                    "target_sensor": f"sensor.temperature_{index}",
                },
            )
            for index, entry_id in enumerate(generic_ids, start=1)
        ) + tuple(
            config_entry(
                entry_id,
                "template",
                {"state": f"{{{{ states('climate.source_{index}') }}}}"},
            )
            for index, entry_id in enumerate(template_ids, start=5)
        )
        cinema = config_entry(
            "99-cinema",
            "generic_thermostat",
            {
                "heater": "switch.cinema_heater",
                "target_sensor": "sensor.cinema_temperature",
            },
        )
        policy = tuple(
            sorted(
                (
                    *(
                        providers.ConfigEntryReferenceObjectPolicy(
                            entry_id,
                            "generic_thermostat",
                        )
                        for entry_id in generic_ids
                    ),
                    *(
                        providers.ConfigEntryReferenceObjectPolicy(
                            entry_id,
                            "template",
                        )
                        for entry_id in template_ids
                    ),
                ),
                key=lambda item: item.entry_id,
            )
        )

        snapshots, _manager = read_config_entry_snapshot(
            tuple(reversed((*selected, cinema))),
            policy,
        )

        self.assertEqual(
            tuple(snapshot.object_id for snapshot in snapshots),
            tuple(item.entry_id for item in policy),
        )
        self.assertNotIn(
            "99-cinema",
            {snapshot.object_id for snapshot in snapshots},
        )

    def test_schema_versions_and_projected_shapes_fail_closed(self) -> None:
        secret = COMPLETE_CONFIG_ENTRY_PAYLOAD
        template_policy = (
            providers.ConfigEntryReferenceObjectPolicy("entry", "template"),
        )
        malformed_entries = (
            config_entry(
                "entry",
                "template",
                {"state": "ready"},
                version=2,
            ),
            config_entry(
                "entry",
                "template",
                {"state": "ready"},
                minor_version=1,
            ),
            config_entry(
                "entry",
                "template",
                {"state": "ready"},
                data={"private": secret},
            ),
            config_entry(
                "entry",
                "template",
                {"state": "ready", "unexpected": secret},
            ),
            config_entry("entry", "template", {"name": secret}),
            config_entry(
                "entry",
                "template",
                {
                    "state": "ready",
                    "advanced_options": {"availability": "true", "extra": secret},
                },
            ),
            config_entry(
                "entry",
                "template",
                {"template_type": "switch", "state": "ready"},
            ),
        )
        for entry in malformed_entries:
            with self.subTest(entry=entry):
                with self.assertRaises(
                    providers.ConfigEntryReferenceSnapshotError
                ) as caught:
                    read_config_entry_snapshot((entry,), template_policy)
                rendered = str(caught.exception) + repr(caught.exception)
                self.assertNotIn(secret, rendered)
                self.assertNotIn(repr(entry.options), rendered)

        generic_policy = (
            providers.ConfigEntryReferenceObjectPolicy(
                "entry", "generic_thermostat"
            ),
        )
        bad_generic = config_entry(
            "entry",
            "generic_thermostat",
            {
                "heater": "climate.not_a_heater",
                "target_sensor": "sensor.temperature",
            },
        )
        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            read_config_entry_snapshot((bad_generic,), generic_policy)

    def test_dynamic_and_ambiguous_jinja_is_rejected_without_leakage(self) -> None:
        policy = (
            providers.ConfigEntryReferenceObjectPolicy("entry", "template"),
        )
        unsafe_templates = (
            "{{ states(entity_id) }}",
            "{{ states('sensor.private') ~ states('sensor.private') }}",
            "{{ states.sensor.private.state }}",
            "{{ expand('group.private') | list }}",
            "{{ states('sensor.private')",
        )
        for template in unsafe_templates:
            with self.subTest(template=template):
                entry = config_entry("entry", "template", {"state": template})
                with self.assertRaises(
                    providers.ConfigEntryReferenceSnapshotError
                ) as caught:
                    read_config_entry_snapshot((entry,), policy)
                rendered = str(caught.exception) + repr(caught.exception)
                self.assertNotIn(template, rendered)
                self.assertNotIn(repr(entry.options), rendered)

        oversized = "{{ states('sensor.private') }}" + (
            "x" * providers._CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_BYTES
        )
        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            read_config_entry_snapshot(
                (config_entry("entry", "template", {"state": oversized}),),
                policy,
            )

    def test_template_entity_count_boundary_is_exact(self) -> None:
        policy = (
            providers.ConfigEntryReferenceObjectPolicy("entry", "template"),
        )

        def template(entity_count: int) -> str:
            return " ".join(
                f"{{{{ states('sensor.source_{index}') }}}}"
                for index in range(entity_count)
            )

        accepted = config_entry(
            "entry",
            "template",
            {
                "state": template(
                    providers._CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_ENTITIES
                )
            },
        )
        snapshots, _manager = read_config_entry_snapshot((accepted,), policy)
        self.assertEqual(snapshots[0].payload["state"], accepted.options["state"])

        rejected = config_entry(
            "entry",
            "template",
            {
                "state": template(
                    providers._CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_ENTITIES + 1
                )
            },
        )
        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            read_config_entry_snapshot((rejected,), policy)


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
