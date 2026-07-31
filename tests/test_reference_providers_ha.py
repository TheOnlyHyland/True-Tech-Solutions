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
import time
import types
import unittest
from unittest.mock import patch


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


async def read_snapshot_source(source, hass):
    return tuple(
        [document async for document in source.async_read_snapshot(hass)]
    )


def expected_manifest():
    return providers.ExpectedObjectManifest.from_mapping(
        "inventory-7",
        {
            provider: (f"{provider}:object",)
            for provider in providers.PROVIDER_NAMES
        },
    )


def opaque_object_key(provider: str, label: str) -> str:
    return "tf-test-object-sha256-v1:" + canonical_digest(
        {"provider": provider, "label": label}
    )


def config_entry_opaque_key(domain: str, entry_id: str) -> str:
    return providers._CONFIG_ENTRY_OPAQUE_KEY_PREFIX + canonical_digest(
        {
            "purpose": "true-family-config-entry-reference-object-key-v1",
            "provider": "config_entry",
            "domain": domain,
            "entry_id": entry_id,
        }
    )


def exact_snapshot_manifest(
    objects=None,
    *,
    revision: str = "exact-snapshot-1",
):
    selected = objects or {
        provider: (opaque_object_key(provider, "one"),)
        for provider in providers.PROVIDER_NAMES
    }
    return providers.ExpectedObjectManifest.from_mapping(revision, selected)


def snapshot_document(
    provider: str,
    object_key: str,
    *,
    revision=1,
    payload=None,
):
    return providers.ProviderDocumentSnapshot(
        provider=provider,
        object_id=object_key,
        revision=revision,
        payload={"value": provider} if payload is None else payload,
    )


class SyntheticSnapshotSource:
    def __init__(
        self,
        name,
        expected_objects,
        documents,
        *,
        calls=None,
        error=None,
        before_read=None,
        closed_event=None,
    ) -> None:
        self.name = name
        self.expected_objects = expected_objects
        self.documents = documents
        self.calls = [] if calls is None else calls
        self.read_count = 0
        self.error = error
        self.before_read = before_read
        self.closed_event = closed_event

    async def async_read_snapshot(self, _hass):
        self.read_count += 1
        self.calls.append(self.name)
        try:
            if self.before_read is not None:
                await self.before_read(self)
            if self.error is not None:
                raise self.error
            for document in self.documents:
                yield document
        finally:
            if self.closed_event is not None:
                self.closed_event.set()


class ProducingSnapshotSource:
    def __init__(
        self,
        name,
        expected_objects,
        count,
        producer,
        *,
        calls=None,
    ) -> None:
        self.name = name
        self.expected_objects = expected_objects
        self.count = count
        self.producer = producer
        self.calls = [] if calls is None else calls

    async def async_read_snapshot(self, _hass):
        self.calls.append(self.name)
        for index in range(self.count):
            yield self.producer(index)


class IteratorSnapshotSource:
    def __init__(self, expected_objects, iterator) -> None:
        self.name = expected_objects.provider
        self.expected_objects = expected_objects
        self.iterator = iterator

    def async_read_snapshot(self, _hass):
        return self.iterator


def synthetic_sources(
    expected,
    *,
    document_overrides=None,
    declaration_overrides=None,
    calls=None,
    errors=None,
    before_reads=None,
):
    document_overrides = document_overrides or {}
    declaration_overrides = declaration_overrides or {}
    errors = errors or {}
    before_reads = before_reads or {}
    result = []
    for item in expected.providers:
        if item.provider in document_overrides:
            documents = document_overrides[item.provider]
        else:
            documents = tuple(
                snapshot_document(item.provider, object_key)
                for object_key in item.object_keys
            )
        result.append(
            SyntheticSnapshotSource(
                item.provider,
                declaration_overrides.get(item.provider, item),
                documents,
                calls=calls,
                error=errors.get(item.provider),
                before_read=before_reads.get(item.provider),
            )
        )
    return tuple(result)


def sized_snapshot_document(
    provider: str,
    object_key: str,
    target_size: int,
):
    empty = snapshot_document(provider, object_key, payload={"blob": ""})
    empty_size = len(
        providers._canonical_json(
            {
                "provider": empty.provider,
                "object_key": empty.object_id,
                "revision": providers._canonical_revision(empty.revision),
                "payload": empty.as_reference_document().payload,
            }
        )
    )
    if target_size < empty_size:
        raise AssertionError("Target document size is below fixed metadata size")
    result = snapshot_document(
        provider,
        object_key,
        payload={"blob": "x" * (target_size - empty_size)},
    )
    actual_size = len(
        providers._canonical_json(
            {
                "provider": result.provider,
                "object_key": result.object_id,
                "revision": providers._canonical_revision(result.revision),
                "payload": result.as_reference_document().payload,
            }
        )
    )
    if actual_size != target_size:
        raise AssertionError("Canonical document size helper drifted")
    return result


def provider_traceback_locals(error: BaseException) -> str:
    rendered = []
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("reference_providers_ha.py"):
            rendered.append(repr(frame.f_locals))
        traceback = traceback.tb_next
    return "\n".join(rendered)


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


class ExactReferenceInventorySnapshotTests(unittest.TestCase):
    def test_protocol_and_exact_five_provider_order(self) -> None:
        expected = exact_snapshot_manifest()
        calls = []
        sources = synthetic_sources(expected, calls=calls)

        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                types.SimpleNamespace(data={}),
                expected,
                sources,
            )
        )

        self.assertEqual(calls, list(providers.PROVIDER_NAMES))
        self.assertEqual(
            tuple(item.provider for item in snapshot.providers),
            providers.PROVIDER_NAMES,
        )
        self.assertEqual(snapshot.expected_manifest_digest, expected.digest)
        self.assertTrue(snapshot.read_only)
        self.assertTrue(all(item.count == 1 for item in snapshot.providers))
        self.assertTrue(
            all(
                isinstance(source, providers.ReadOnlyProviderSnapshotSource)
                for source in sources
            )
        )
        self.assertFalse(
            hasattr(providers.ReadOnlyProviderSnapshotSource, "write_document")
        )
        self.assertFalse(any(hasattr(source, "write_document") for source in sources))
        stream_return = str(
            inspect.signature(
                providers.ReadOnlyProviderSnapshotSource.async_read_snapshot
            ).return_annotation
        )
        self.assertIn("AsyncIterator", stream_return)
        self.assertNotIn("tuple", stream_return)
        self.assertEqual(
            snapshot.as_public_summary(),
            {
                "read_only": True,
                "providers": [
                    {"provider": provider, "count": 1}
                    for provider in providers.PROVIDER_NAMES
                ],
            },
        )

    def test_source_shape_and_manifest_mismatch_fail_before_io(self) -> None:
        expected = exact_snapshot_manifest()
        alternate = exact_snapshot_manifest(
            {
                item.provider: (
                    (opaque_object_key(item.provider, "different"),)
                    if item.provider == "scheduler"
                    else item.object_keys
                )
                for item in expected.providers
            },
            revision="independent-manifest",
        )

        malformed_source_sets = (
            synthetic_sources(expected)[:-1],
            (*synthetic_sources(expected), synthetic_sources(expected)[0]),
            tuple(reversed(synthetic_sources(expected))),
            (
                synthetic_sources(expected)[0],
                synthetic_sources(expected)[1],
                synthetic_sources(expected)[1],
                synthetic_sources(expected)[3],
                synthetic_sources(expected)[4],
            ),
        )
        for sources in malformed_source_sets:
            with self.subTest(names=tuple(source.name for source in sources)):
                with self.assertRaises(
                    providers.ExactReferenceInventorySnapshotError
                ):
                    asyncio.run(
                        providers.async_read_exact_reference_inventory_snapshot(
                            object(),
                            expected,
                            sources,
                        )
                    )
                self.assertTrue(all(source.calls == [] for source in sources))

        calls = []
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    alternate,
                    synthetic_sources(expected, calls=calls),
                )
            )
        self.assertEqual(calls, [])

    def test_missing_extra_duplicate_wrong_provider_and_misordered_docs_fail(self) -> None:
        first_keys = tuple(
            sorted(
                (
                    opaque_object_key("active_yaml", "one"),
                    opaque_object_key("active_yaml", "two"),
                )
            )
        )
        expected = exact_snapshot_manifest(
            {
                provider: (
                    first_keys
                    if provider == "active_yaml"
                    else (opaque_object_key(provider, "one"),)
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        valid = tuple(
            snapshot_document("active_yaml", object_key)
            for object_key in first_keys
        )
        extra_key = opaque_object_key("active_yaml", "extra")
        malformed = {
            "missing": valid[:-1],
            "extra": tuple(
                sorted(
                    (*valid, snapshot_document("active_yaml", extra_key)),
                    key=lambda item: item.object_id,
                )
            ),
            "duplicate": (valid[0], valid[0], valid[1]),
            "wrong_provider": (
                snapshot_document("config_entry", first_keys[0]),
                valid[1],
            ),
            "misordered": tuple(reversed(valid)),
        }

        for case, documents in malformed.items():
            with self.subTest(case=case):
                calls = []
                with self.assertRaises(
                    providers.ExactReferenceInventorySnapshotError
                ):
                    asyncio.run(
                        providers.async_read_exact_reference_inventory_snapshot(
                            object(),
                            expected,
                            synthetic_sources(
                                expected,
                                document_overrides={"active_yaml": documents},
                                calls=calls,
                            ),
                        )
                    )
                self.assertEqual(calls, ["active_yaml"])

    def test_stream_stops_after_wrong_key_or_count_mismatch(self) -> None:
        expected_keys = tuple(
            sorted(
                opaque_object_key("active_yaml", f"stream-{index}")
                for index in range(3)
            )
        )
        expected = exact_snapshot_manifest(
            {
                provider: (expected_keys if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )

        wrong_key_constructed = []

        def produce_wrong_key(index):
            wrong_key_constructed.append(index)
            if index:
                raise AssertionError("source advanced after wrong key")
            return snapshot_document(
                "active_yaml",
                opaque_object_key("active_yaml", "wrong"),
            )

        wrong_source = ProducingSnapshotSource(
            "active_yaml",
            expected.for_provider("active_yaml"),
            len(expected_keys),
            produce_wrong_key,
        )
        wrong_sources = tuple(
            wrong_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in expected.providers
        )
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    wrong_sources,
                )
            )
        self.assertEqual(wrong_key_constructed, [0])

        one_key_expected = exact_snapshot_manifest(
            {
                provider: ((expected_keys[0],) if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )
        count_constructed = []

        def produce_extra(index):
            count_constructed.append(index)
            if index == 0:
                return snapshot_document("active_yaml", expected_keys[0])
            if index == 1:
                return snapshot_document(
                    "active_yaml",
                    opaque_object_key("active_yaml", "extra"),
                )
            raise AssertionError("source advanced after count mismatch")

        extra_source = ProducingSnapshotSource(
            "active_yaml",
            one_key_expected.for_provider("active_yaml"),
            3,
            produce_extra,
        )
        extra_sources = tuple(
            extra_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in one_key_expected.providers
        )
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    one_key_expected,
                    extra_sources,
                )
            )
        self.assertEqual(count_constructed, [0, 1])

    def test_typed_revision_and_payload_drift_change_both_digests(self) -> None:
        expected = exact_snapshot_manifest()
        active = expected.for_provider("active_yaml")
        object_key = active.object_keys[0]

        def collect(revision, payload):
            return asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    synthetic_sources(
                        expected,
                        document_overrides={
                            "active_yaml": (
                                snapshot_document(
                                    "active_yaml",
                                    object_key,
                                    revision=revision,
                                    payload=payload,
                                ),
                            )
                        },
                    ),
                )
            )

        integer_revision = collect(1, {"value": "first"})
        string_revision = collect("1", {"value": "first"})
        payload_drift = collect(1, {"value": "second"})

        self.assertNotEqual(
            integer_revision.providers[0].digest,
            string_revision.providers[0].digest,
        )
        self.assertNotEqual(integer_revision.digest, string_revision.digest)
        self.assertNotEqual(
            integer_revision.providers[0].digest,
            payload_drift.providers[0].digest,
        )
        self.assertNotEqual(integer_revision.digest, payload_drift.digest)

    def test_config_entry_source_is_opaque_and_all_public_shapes_are_payload_free(
        self,
    ) -> None:
        raw_generic_id = "raw-generic-entry-id-canary"
        raw_template_id = "raw-template-entry-id-canary"
        payload_canary = "{{ states('sensor.private_config_entry_payload_canary') }}"
        generic = config_entry(
            raw_generic_id,
            "generic_thermostat",
            {
                "name": payload_canary,
                "heater": "switch.read_only_heater",
                "target_sensor": "sensor.read_only_temperature",
            },
        )
        template = config_entry(
            raw_template_id,
            "template",
            {
                "name": "Read-only template",
                "state": payload_canary,
            },
        )
        policy = tuple(
            sorted(
                (
                    providers.ConfigEntryReferenceObjectPolicy(
                        raw_generic_id,
                        "generic_thermostat",
                    ),
                    providers.ConfigEntryReferenceObjectPolicy(
                        raw_template_id,
                        "template",
                    ),
                ),
                key=lambda item: item.entry_id,
            )
        )
        source = providers.ConfigEntryReferenceSnapshotSource(policy)
        independent_opaque_keys = tuple(
            sorted(
                (
                    config_entry_opaque_key(
                        "generic_thermostat",
                        raw_generic_id,
                    ),
                    config_entry_opaque_key("template", raw_template_id),
                )
            )
        )
        expected = exact_snapshot_manifest(
            {
                provider: (
                    independent_opaque_keys
                    if provider == "config_entry"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        sources = tuple(
            source
            if item.provider == "config_entry"
            else SyntheticSnapshotSource(
                item.provider,
                item,
                (),
            )
            for item in expected.providers
        )
        hass = types.SimpleNamespace(
            config_entries=FakeConfigEntries((template, generic)),
            data={"unchanged": object()},
        )

        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                hass,
                expected,
                sources,
            )
        )

        config_inventory = snapshot.providers[1]
        self.assertEqual(config_inventory.object_keys, independent_opaque_keys)
        self.assertTrue(
            all(
                key.startswith(providers._CONFIG_ENTRY_OPAQUE_KEY_PREFIX)
                for key in config_inventory.object_keys
            )
        )
        self.assertEqual(
            config_inventory.object_keys,
            tuple(
                sorted(
                    (
                        config_entry_opaque_key(
                            "generic_thermostat",
                            raw_generic_id,
                        ),
                        config_entry_opaque_key("template", raw_template_id),
                    )
                )
            ),
        )
        self.assertFalse(hasattr(source, "policy"))
        rendered = "\n".join(
            (
                repr(policy),
                repr(source),
                repr(expected),
                repr(config_inventory),
                repr(snapshot),
                json.dumps(snapshot.as_public_summary(), sort_keys=True),
            )
        )
        for private in (raw_generic_id, raw_template_id, payload_canary):
            self.assertNotIn(private, rendered)

        missing_hass = types.SimpleNamespace(config_entries=FakeConfigEntries(()))
        with self.assertRaises(
            providers.ConfigEntryReferenceSnapshotError
        ) as caught:
            asyncio.run(read_snapshot_source(source, missing_hass))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        for private in (raw_generic_id, raw_template_id, payload_canary):
            self.assertNotIn(private, str(caught.exception))
            self.assertNotIn(private, repr(caught.exception))
            self.assertNotIn(
                private,
                provider_traceback_locals(caught.exception),
            )

        with self.assertRaises(
            providers.ConfigEntryReferenceSnapshotError
        ) as raw_caught:
            asyncio.run(
                providers.async_read_config_entry_reference_snapshot(
                    missing_hass,
                    policy,
                )
            )
        self.assertIsNone(raw_caught.exception.__cause__)
        self.assertIsNone(raw_caught.exception.__context__)
        raw_traceback_locals = provider_traceback_locals(raw_caught.exception)
        for private in (raw_generic_id, raw_template_id, payload_canary):
            self.assertNotIn(private, raw_traceback_locals)

        with self.assertRaises(
            providers.ConfigEntryReferenceSnapshotError
        ) as policy_caught:
            providers.ConfigEntryReferenceSnapshotSource(tuple(reversed(policy)))
        policy_traceback_locals = provider_traceback_locals(policy_caught.exception)
        for private in (raw_generic_id, raw_template_id):
            self.assertNotIn(private, policy_traceback_locals)

    def test_source_failure_does_not_leak_opaque_input_or_payload(self) -> None:
        expected = exact_snapshot_manifest()
        raw_id = "raw-source-id-canary"
        payload = "source-payload-canary"
        calls = []
        sources = synthetic_sources(
            expected,
            calls=calls,
            errors={"active_yaml": RuntimeError(f"{raw_id}:{payload}")},
        )

        with self.assertRaises(
            providers.ExactReferenceInventorySnapshotError
        ) as caught:
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    sources,
                )
            )

        self.assertEqual(calls, ["active_yaml"])
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        rendered = str(caught.exception) + repr(caught.exception)
        self.assertNotIn(raw_id, rendered)
        self.assertNotIn(payload, rendered)
        traceback_locals = provider_traceback_locals(caught.exception)
        self.assertNotIn(raw_id, traceback_locals)
        self.assertNotIn(payload, traceback_locals)

    def test_payload_is_immutable_and_planner_copy_has_same_fingerprint(self) -> None:
        expected = exact_snapshot_manifest()
        active = expected.for_provider("active_yaml")
        document = snapshot_document(
            "active_yaml",
            active.object_keys[0],
            payload={"nested": {"entities": ["climate.source"]}},
        )
        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                synthetic_sources(
                    expected,
                    document_overrides={"active_yaml": (document,)},
                ),
            )
        )
        retained = snapshot.providers[0].documents[0]

        with self.assertRaises(TypeError):
            retained.payload["changed"] = True  # type: ignore[index]
        with self.assertRaises(TypeError):
            retained.payload["nested"]["changed"] = True  # type: ignore[index]
        planner_copy = retained.as_reference_document()
        self.assertEqual(
            migration.canonical_document_fingerprint(planner_copy),
            retained.fingerprint,
        )
        planner_copy.payload["nested"]["entities"].append("climate.changed")
        self.assertEqual(
            retained.payload["nested"]["entities"],
            ("climate.source",),
        )

    def test_list_root_is_immutable_and_planner_compatible(self) -> None:
        old_entity = "climate.list_root_source"
        expected = exact_snapshot_manifest()
        active = expected.for_provider("active_yaml")
        retained = snapshot_document(
            "active_yaml",
            active.object_keys[0],
            payload=[{"entity_id": old_entity}, [old_entity]],
        )

        self.assertIs(type(retained.payload), tuple)
        self.assertEqual(
            retained.fingerprint,
            canonical_digest(
                [{"entity_id": old_entity}, [old_entity]]
            ),
        )
        self.assertEqual(
            retained._canonical_payload_size,
            len(
                json.dumps(
                    [{"entity_id": old_entity}, [old_entity]],
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
        )
        planner_copy = retained.as_reference_document()
        self.assertIs(type(planner_copy.payload), list)
        self.assertIs(type(planner_copy.payload[0]), dict)
        self.assertIs(type(planner_copy.payload[1]), list)
        self.assertEqual(
            migration.canonical_document_fingerprint(planner_copy),
            retained.fingerprint,
        )
        scan = migration.scan_references(
            planner_copy.payload,
            old_entity,
            provider="active_yaml",
        )
        self.assertEqual(
            scan.exact_paths,
            ((0, "entity_id"),),
        )
        planner_copy.payload[0]["entity_id"] = "climate.changed"
        self.assertEqual(retained.payload[0]["entity_id"], old_entity)

    def test_streamed_canonical_digest_matches_json_for_escape_matrix(self) -> None:
        payload = {
            "astral": "😀",
            "controls": "\x00\b\t\n\f\r\x1f",
            "number": -0.0,
            "quote": '"\\/\x7f',
            "unicode": "é\ud800",
        }
        document = snapshot_document(
            "active_yaml",
            opaque_object_key("active_yaml", "escape-matrix"),
            payload=payload,
        )
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertEqual(document._canonical_payload_size, len(canonical))
        self.assertEqual(document.fingerprint, hashlib.sha256(canonical).hexdigest())

    def test_payload_preflight_rejects_giant_string_before_copy_or_hash(self) -> None:
        private = "payload-preflight-private-canary"
        payload = {
            "value": private
            + ("x" * (providers._REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES + 1))
        }

        with (
            patch.object(
                providers,
                "_copy_projected_payload",
                side_effect=AssertionError("copy must not run"),
            ) as copy_payload,
            patch.object(
                providers,
                "_stream_canonical_json_digest",
                side_effect=AssertionError("hash must not run"),
            ) as stream_digest,
            patch.object(
                providers,
                "_freeze_projected_payload",
                side_effect=AssertionError("freeze must not run"),
            ) as freeze_payload,
            self.assertRaises(
                providers.ConfigEntryReferenceSnapshotError
            ) as caught,
        ):
            snapshot_document(
                "active_yaml",
                opaque_object_key("active_yaml", "giant"),
                payload=payload,
            )

        copy_payload.assert_not_called()
        stream_digest.assert_not_called()
        freeze_payload.assert_not_called()
        self.assertNotIn(private, str(caught.exception))
        self.assertNotIn(private, repr(caught.exception))
        self.assertNotIn(private, provider_traceback_locals(caught.exception))

    def test_construction_uses_one_bounded_builtin_validate_and_copy_pass(self) -> None:
        raw_payload = {"nested": [{"value": "original"}]}
        with patch.object(
            providers,
            "_copy_projected_payload",
            side_effect=AssertionError("legacy recursive copy must not run"),
        ) as legacy_copy:
            document = snapshot_document(
                "active_yaml",
                opaque_object_key("active_yaml", "one-pass"),
                payload=raw_payload,
            )

        legacy_copy.assert_not_called()
        raw_payload["nested"][0]["value"] = "mutated"
        self.assertEqual(document.payload["nested"][0]["value"], "original")

        class HostileDict(dict):
            touched = False

            def items(self):
                type(self).touched = True
                raise AssertionError("custom iterator must not run")

        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            snapshot_document(
                "active_yaml",
                opaque_object_key("active_yaml", "custom-root"),
                payload=HostileDict({"value": "private"}),
            )
        self.assertFalse(HostileDict.touched)

    def test_payload_preflight_rejects_cycles_aliases_and_excess_nodes(self) -> None:
        cyclic = []
        cyclic.append(cyclic)
        shared = []
        aliased = [shared, shared]
        crowded = [None] * providers._REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES

        for case, payload in (
            ("cycle", cyclic),
            ("alias", aliased),
            ("nodes", crowded),
        ):
            with self.subTest(case=case):
                with (
                    patch.object(
                        providers,
                        "_copy_projected_payload",
                        side_effect=AssertionError("copy must not run"),
                    ) as copy_payload,
                    self.assertRaises(
                        providers.ConfigEntryReferenceSnapshotError
                    ),
                ):
                    snapshot_document(
                        "active_yaml",
                        opaque_object_key("active_yaml", case),
                        payload=payload,
                    )
                copy_payload.assert_not_called()

    def test_payload_preflight_rejects_noncanonical_roots_and_values(self) -> None:
        private = "noncanonical-payload-private-canary"
        malformed = (
            private,
            (private,),
            {1: private},
            {"value": (private,)},
            {"value": {private}},
            {"value": object()},
            {"value": float("nan")},
            {"value": float("inf")},
            {"value": 1 << (providers._REFERENCE_SNAPSHOT_MAX_INTEGER_BITS + 1)},
        )
        for payload in malformed:
            with self.subTest(root=type(payload).__name__):
                with self.assertRaises(
                    providers.ConfigEntryReferenceSnapshotError
                ) as caught:
                    snapshot_document(
                        "active_yaml",
                        opaque_object_key("active_yaml", "malformed"),
                        payload=payload,
                    )
                rendered = (
                    str(caught.exception)
                    + repr(caught.exception)
                    + provider_traceback_locals(caught.exception)
                )
                self.assertNotIn(private, rendered)

    def test_deep_payload_is_rejected_before_recursive_copy(self) -> None:
        value = "leaf"
        for _index in range(providers._REFERENCE_SNAPSHOT_MAX_PAYLOAD_DEPTH + 1):
            value = {"nested": value}

        with (
            patch.object(
                providers,
                "_copy_projected_payload",
                side_effect=AssertionError("copy must not run"),
            ) as copy_payload,
            self.assertRaises(providers.ConfigEntryReferenceSnapshotError),
        ):
            snapshot_document(
                "active_yaml",
                opaque_object_key("active_yaml", "deep"),
                payload=value,
            )
        copy_payload.assert_not_called()

    def test_read_only_document_blocks_core_migration_plan(self) -> None:
        old_entity = "climate.old_radiator"
        target_entity = "climate.logical_radiator"
        expected = exact_snapshot_manifest(
            {
                provider: (
                    (opaque_object_key(provider, "one"),)
                    if provider == "active_yaml"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        object_key = expected.for_provider("active_yaml").object_keys[0]
        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                synthetic_sources(
                    expected,
                    document_overrides={
                        "active_yaml": (
                            snapshot_document(
                                "active_yaml",
                                object_key,
                                payload={"entity_id": old_entity},
                            ),
                        )
                    },
                ),
            )
        )
        migration_providers = tuple(
            migration.InMemoryReferenceProvider(
                provider,
                (
                    (snapshot.providers[0].documents[0].as_reference_document(),)
                    if provider == "active_yaml"
                    else ()
                ),
            )
            for provider in providers.PROVIDER_NAMES
        )
        authority = migration.InMemoryMigrationAuthority(
            (
                migration.MigrationSubject(
                    room_id="guest_room",
                    room_revision=1,
                    old_entity_id=old_entity,
                    logical_unique_id="logical_valve_guest_room",
                    provider_targets=tuple(
                        (provider, target_entity)
                        for provider in sorted(providers.PROVIDER_NAMES)
                    ),
                ),
            )
        )
        coordinator = migration.ReferenceMigrationCoordinator(
            migration_providers,
            migration.InMemoryReferenceJournal(),
            authority,
        )

        with self.assertRaises(migration.MigrationPlanningBlocked) as caught:
            coordinator.create_plan(
                room_id="guest_room",
                room_revision=1,
                old_entity_id=old_entity,
                logical_unique_id="logical_valve_guest_room",
                target_entity_id=target_entity,
                required_providers=frozenset(providers.PROVIDER_NAMES),
                references_expected=True,
            )
        self.assertTrue(any("not writable" in reason for reason in caught.exception.reasons))

    def test_payload_fingerprint_is_recomputed(self) -> None:
        expected = exact_snapshot_manifest()
        active = expected.for_provider("active_yaml")
        document = snapshot_document("active_yaml", active.object_keys[0])
        object.__setattr__(document, "fingerprint", "0" * 64)

        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    synthetic_sources(
                        expected,
                        document_overrides={"active_yaml": (document,)},
                    ),
                )
            )

        node_document = snapshot_document("active_yaml", active.object_keys[0])
        object.__setattr__(
            node_document,
            "_canonical_node_count",
            node_document._canonical_node_count + 1,
        )
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    synthetic_sources(
                        expected,
                        document_overrides={"active_yaml": (node_document,)},
                    ),
                )
            )

    def test_inventory_recomputation_streams_without_payload_copy(self) -> None:
        expected = exact_snapshot_manifest()
        sources = synthetic_sources(expected)

        with patch.object(
            providers,
            "_copy_projected_payload",
            side_effect=AssertionError("inventory must not copy payloads"),
        ) as copy_payload:
            snapshot = asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    sources,
                )
            )

        copy_payload.assert_not_called()
        self.assertTrue(snapshot.read_only)

    def test_manifest_bound_snapshot_constructor_is_collector_owned(self) -> None:
        expected = exact_snapshot_manifest()
        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                synthetic_sources(expected),
            )
        )

        with self.assertRaises(TypeError):
            providers.ExactReferenceInventorySnapshot(
                expected.digest,
                snapshot.providers,
            )

    def test_document_count_limits_accept_boundaries_and_reject_next_values(
        self,
    ) -> None:
        active_keys = tuple(
            opaque_object_key("active_yaml", f"{index:04d}")
            for index in range(
                providers._REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER
            )
        )
        config_keys = tuple(
            opaque_object_key("config_entry", f"{index:04d}")
            for index in range(
                providers._REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER
            )
        )
        boundary = exact_snapshot_manifest(
            {
                provider: (
                    active_keys
                    if provider == "active_yaml"
                    else config_keys
                    if provider == "config_entry"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        constructed = []

        def boundary_source(item):
            def produce(index):
                constructed.append((item.provider, index))
                return snapshot_document(
                    item.provider,
                    item.object_keys[index],
                )

            return ProducingSnapshotSource(
                item.provider,
                item,
                item.count,
                produce,
            )

        boundary_sources = tuple(
            boundary_source(item)
            if item.provider in {"active_yaml", "config_entry"}
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in boundary.providers
        )
        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                boundary,
                boundary_sources,
            )
        )
        self.assertEqual(
            sum(item.count for item in snapshot.providers),
            providers._REFERENCE_SNAPSHOT_MAX_DOCUMENTS,
        )
        self.assertEqual(
            snapshot.providers[0].count,
            providers._REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER,
        )
        self.assertEqual(len(constructed), providers._REFERENCE_SNAPSHOT_MAX_DOCUMENTS)

        over_provider = exact_snapshot_manifest(
            {
                provider: (
                    (*active_keys, opaque_object_key(provider, "overflow"))
                    if provider == "active_yaml"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        calls = []

        def forbidden_producer(_index):
            raise AssertionError("prevalidation must prevent construction")

        over_provider_sources = tuple(
            ProducingSnapshotSource(
                item.provider,
                item,
                item.count,
                forbidden_producer,
                calls=calls,
            )
            for item in over_provider.providers
        )
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    over_provider,
                    over_provider_sources,
                )
            )
        self.assertEqual(calls, [])

        over_aggregate = exact_snapshot_manifest(
            {
                provider: (
                    active_keys
                    if provider == "active_yaml"
                    else config_keys
                    if provider == "config_entry"
                    else (opaque_object_key(provider, "overflow"),)
                    if provider == "external_writers"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        calls = []
        over_aggregate_sources = tuple(
            ProducingSnapshotSource(
                item.provider,
                item,
                item.count,
                forbidden_producer,
                calls=calls,
            )
            for item in over_aggregate.providers
        )
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    over_aggregate,
                    over_aggregate_sources,
                )
            )
        self.assertEqual(calls, [])

    def test_aggregate_node_budget_streams_to_exact_boundary_and_stops(self) -> None:
        node_budget = 6
        accepted_keys = tuple(
            sorted(
                opaque_object_key("active_yaml", f"node-{index}")
                for index in range(2)
            )
        )
        accepted_expected = exact_snapshot_manifest(
            {
                provider: (accepted_keys if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )
        accepted_constructed = []

        def produce_accepted(index):
            accepted_constructed.append(index)
            return snapshot_document(
                "active_yaml",
                accepted_keys[index],
                payload={"value": "node"},
            )

        accepted_source = ProducingSnapshotSource(
            "active_yaml",
            accepted_expected.for_provider("active_yaml"),
            2,
            produce_accepted,
        )
        accepted_sources = tuple(
            accepted_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in accepted_expected.providers
        )
        with patch.object(
            providers,
            "_REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES",
            node_budget,
        ):
            accepted_snapshot = asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    accepted_expected,
                    accepted_sources,
                )
            )

        self.assertEqual(accepted_constructed, [0, 1])
        self.assertEqual(
            accepted_snapshot.providers[0]._canonical_node_count,
            node_budget,
        )

        overflow_keys = tuple(
            sorted(
                opaque_object_key("active_yaml", f"node-overflow-{index}")
                for index in range(4)
            )
        )
        overflow_expected = exact_snapshot_manifest(
            {
                provider: (overflow_keys if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )
        overflow_constructed = []

        def produce_overflow(index):
            overflow_constructed.append(index)
            if index == 3:
                raise AssertionError("source advanced after aggregate node overflow")
            return snapshot_document(
                "active_yaml",
                overflow_keys[index],
                payload={"value": "node"},
            )

        overflow_source = ProducingSnapshotSource(
            "active_yaml",
            overflow_expected.for_provider("active_yaml"),
            4,
            produce_overflow,
        )
        overflow_sources = tuple(
            overflow_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in overflow_expected.providers
        )
        with (
            patch.object(
                providers,
                "_REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES",
                node_budget,
            ),
            patch.object(
                providers,
                "_validate_snapshot_document",
                wraps=providers._validate_snapshot_document,
            ) as validate_document,
            self.assertRaises(providers.ExactReferenceInventorySnapshotError),
        ):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    overflow_expected,
                    overflow_sources,
                )
            )

        self.assertEqual(overflow_constructed, [0, 1, 2])
        self.assertEqual(validate_document.call_count, 2)

        direct_documents = tuple(
            snapshot_document(
                "active_yaml",
                key,
                payload={"value": "node"},
            )
            for key in accepted_keys
        )
        with (
            patch.object(
                providers,
                "_REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES",
                node_budget - 1,
            ),
            self.assertRaises(providers.ExactReferenceInventorySnapshotError),
        ):
            providers.ProviderDocumentInventory("active_yaml", direct_documents)

        with (
            patch.object(
                providers,
                "_REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES",
                node_budget - 1,
            ),
            self.assertRaises(providers.ExactReferenceInventorySnapshotError),
        ):
            providers._new_exact_reference_inventory_snapshot(
                accepted_expected.digest,
                accepted_snapshot.providers,
            )

    def test_object_key_byte_limits_accept_boundaries_and_reject_next_values(
        self,
    ) -> None:
        accepted_keys = (
            "a" * providers._REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES,
            "é" * (providers._REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES // 2),
        )
        for object_key in accepted_keys:
            with self.subTest(kind="accepted", length=len(object_key)):
                expected = exact_snapshot_manifest(
                    {
                        provider: ((object_key,) if provider == "active_yaml" else ())
                        for provider in providers.PROVIDER_NAMES
                    }
                )
                snapshot = asyncio.run(
                    providers.async_read_exact_reference_inventory_snapshot(
                        object(),
                        expected,
                        synthetic_sources(expected),
                    )
                )
                self.assertEqual(snapshot.providers[0].object_keys, (object_key,))

        rejected_keys = (
            "a" * (providers._REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES + 1),
            "é" * ((providers._REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES // 2) + 1),
        )
        for object_key in rejected_keys:
            with self.subTest(kind="rejected", length=len(object_key)):
                expected = exact_snapshot_manifest(
                    {
                        provider: ((object_key,) if provider == "active_yaml" else ())
                        for provider in providers.PROVIDER_NAMES
                    }
                )
                calls = []
                with self.assertRaises(
                    providers.ExactReferenceInventorySnapshotError
                ):
                    asyncio.run(
                        providers.async_read_exact_reference_inventory_snapshot(
                            object(),
                            expected,
                            synthetic_sources(
                                expected,
                                document_overrides={"active_yaml": ()},
                                calls=calls,
                            ),
                        )
                    )
                self.assertEqual(calls, [])

    def test_document_and_aggregate_size_limits_are_exact(self) -> None:
        per_document_limit = providers._REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES
        object_key = opaque_object_key("active_yaml", "sized")
        expected = exact_snapshot_manifest(
            {
                provider: ((object_key,) if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )
        exact_document = sized_snapshot_document(
            "active_yaml",
            object_key,
            per_document_limit,
        )
        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                synthetic_sources(
                    expected,
                    document_overrides={"active_yaml": (exact_document,)},
                ),
            )
        )
        self.assertEqual(
            snapshot.providers[0]._canonical_size,
            per_document_limit,
        )

        exact_blob_size = len(exact_document.payload["blob"])
        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            snapshot_document(
                "active_yaml",
                object_key,
                payload={"blob": "x" * (exact_blob_size + 1)},
            )

        aggregate_document_count = (
            providers._REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES // per_document_limit
        )
        aggregate_keys = tuple(
            sorted(
                opaque_object_key("active_yaml", f"aggregate-{index:02d}")
                for index in range(aggregate_document_count)
            )
        )
        aggregate_expected = exact_snapshot_manifest(
            {
                provider: (aggregate_keys if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )
        aggregate_constructed = []

        def produce_aggregate(index):
            aggregate_constructed.append(index)
            return snapshot_document(
                "active_yaml",
                aggregate_keys[index],
                payload={"blob": "x" * exact_blob_size},
            )

        aggregate_source = ProducingSnapshotSource(
            "active_yaml",
            aggregate_expected.for_provider("active_yaml"),
            aggregate_document_count,
            produce_aggregate,
        )
        aggregate_sources = tuple(
            aggregate_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in aggregate_expected.providers
        )
        aggregate_snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                aggregate_expected,
                aggregate_sources,
            )
        )
        self.assertEqual(
            aggregate_snapshot.providers[0]._canonical_size,
            providers._REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES,
        )
        self.assertEqual(
            aggregate_constructed,
            list(range(aggregate_document_count)),
        )

        over_keys = tuple(
            sorted(
                opaque_object_key("active_yaml", f"overflow-{index:02d}")
                for index in range(aggregate_document_count + 2)
            )
        )
        over_expected = exact_snapshot_manifest(
            {
                provider: (
                    over_keys
                    if provider == "active_yaml"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        overflow_constructed = []

        def produce_overflow(index):
            overflow_constructed.append(index)
            if index < aggregate_document_count:
                return snapshot_document(
                    "active_yaml",
                    over_keys[index],
                    payload={"blob": "x" * exact_blob_size},
                )
            if index == aggregate_document_count:
                return snapshot_document("active_yaml", over_keys[index])
            raise AssertionError("unconsumed overflow document was constructed")

        overflow_source = ProducingSnapshotSource(
            "active_yaml",
            over_expected.for_provider("active_yaml"),
            len(over_keys),
            produce_overflow,
        )
        overflow_sources = tuple(
            overflow_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in over_expected.providers
        )
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            asyncio.run(
                providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    over_expected,
                    overflow_sources,
                )
            )
        self.assertEqual(
            overflow_constructed,
            list(range(aggregate_document_count + 1)),
        )

    def test_payload_depth_limit_accepts_100_and_rejects_101(self) -> None:
        def nested_payload(depth: int):
            value = "leaf"
            for _index in range(depth):
                value = {"nested": value}
            return value

        expected = exact_snapshot_manifest()
        active = expected.for_provider("active_yaml")
        accepted = snapshot_document(
            "active_yaml",
            active.object_keys[0],
            payload=nested_payload(providers._REFERENCE_SNAPSHOT_MAX_PAYLOAD_DEPTH),
        )
        snapshot = asyncio.run(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                synthetic_sources(
                    expected,
                    document_overrides={"active_yaml": (accepted,)},
                ),
            )
        )
        self.assertEqual(snapshot.providers[0].count, 1)

        with self.assertRaises(providers.ConfigEntryReferenceSnapshotError):
            snapshot_document(
                "active_yaml",
                active.object_keys[0],
                payload=nested_payload(
                    providers._REFERENCE_SNAPSHOT_MAX_PAYLOAD_DEPTH + 1
                ),
            )


class ExactReferenceInventoryAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_source_descriptors_are_captured_exactly_once(self) -> None:
        expected = exact_snapshot_manifest()
        calls = []

        class DescriptorSource:
            def __init__(self, declaration, documents) -> None:
                self._declaration = declaration
                self._documents = documents
                self.name_reads = 0
                self.expected_reads = 0
                self.reader_reads = 0

            @property
            def name(self):
                self.name_reads += 1
                if self.name_reads > 1:
                    raise AssertionError("name descriptor was re-read")
                return self._declaration.provider

            @property
            def expected_objects(self):
                self.expected_reads += 1
                if self.expected_reads > 1:
                    raise AssertionError("expected descriptor was re-read")
                return self._declaration

            @property
            def async_read_snapshot(self):
                self.reader_reads += 1
                if self.reader_reads > 1:
                    raise AssertionError("reader descriptor was re-read")
                return self._read

            async def _read(self, _hass):
                calls.append(self._declaration.provider)
                for document in self._documents:
                    yield document

        sources = tuple(
            DescriptorSource(
                item,
                tuple(
                    snapshot_document(item.provider, key)
                    for key in item.object_keys
                ),
            )
            for item in expected.providers
        )

        snapshot = await providers.async_read_exact_reference_inventory_snapshot(
            object(),
            expected,
            sources,
        )

        self.assertTrue(snapshot.read_only)
        self.assertEqual(calls, list(providers.PROVIDER_NAMES))
        self.assertTrue(
            all(
                (source.name_reads, source.expected_reads, source.reader_reads)
                == (1, 1, 1)
                for source in sources
            )
        )

    async def test_synchronous_metadata_returning_after_deadline_times_out(self) -> None:
        expected = exact_snapshot_manifest()
        calls = []

        class SlowMetadataSource:
            def __init__(self, declaration) -> None:
                self._declaration = declaration

            @property
            def name(self):
                time.sleep(0.02)
                return self._declaration.provider

            @property
            def expected_objects(self):
                return self._declaration

            @property
            def async_read_snapshot(self):
                return self._read

            async def _read(self, _hass):
                calls.append(self._declaration.provider)
                if False:
                    yield

        sources = (
            SlowMetadataSource(expected.providers[0]),
            *synthetic_sources(expected)[1:],
        )
        with patch.object(
            providers,
            "_EXACT_REFERENCE_INVENTORY_TIMEOUT_SECONDS",
            0.005,
        ):
            with self.assertRaises(TimeoutError) as caught:
                await providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    sources,
                )

        self.assertEqual(calls, [])
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    async def test_validation_failure_after_deadline_reports_timeout(self) -> None:
        expected = exact_snapshot_manifest(
            {
                provider: (
                    (opaque_object_key(provider, "deadline"),)
                    if provider == "active_yaml"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )
        sources = synthetic_sources(expected)

        def slow_malformed_validation(_document):
            time.sleep(0.02)
            raise providers.ExactReferenceInventorySnapshotError(
                "injected malformed document"
            )

        with (
            patch.object(
                providers,
                "_EXACT_REFERENCE_INVENTORY_TIMEOUT_SECONDS",
                0.005,
            ),
            patch.object(
                providers,
                "_validate_snapshot_document",
                side_effect=slow_malformed_validation,
            ),
            self.assertRaises(TimeoutError) as caught,
        ):
            await providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                sources,
            )

        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    async def test_aiter_and_partial_cleanup_failures_are_sanitized(self) -> None:
        private = "private-aiter-cleanup-failure"
        expected = exact_snapshot_manifest(
            {
                provider: (
                    (opaque_object_key(provider, "open-failure"),)
                    if provider == "active_yaml"
                    else ()
                )
                for provider in providers.PROVIDER_NAMES
            }
        )

        class BrokenOpenStream:
            aiter_calls = 0
            aclose_reads = 0
            close_reads = 0

            def __aiter__(self):
                type(self).aiter_calls += 1
                raise RuntimeError(private)

            @property
            def aclose(self):
                type(self).aclose_reads += 1
                raise RuntimeError(private)

            @property
            def close(self):
                type(self).close_reads += 1
                raise RuntimeError(private)

        active_source = IteratorSnapshotSource(
            expected.for_provider("active_yaml"),
            BrokenOpenStream(),
        )
        sources = tuple(
            active_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in expected.providers
        )

        with self.assertRaises(
            providers.ExactReferenceInventorySnapshotError
        ) as caught:
            await providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                sources,
            )

        self.assertEqual(BrokenOpenStream.aiter_calls, 1)
        self.assertEqual(BrokenOpenStream.aclose_reads, 1)
        self.assertEqual(BrokenOpenStream.close_reads, 1)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        rendered = (
            str(caught.exception)
            + repr(caught.exception)
            + provider_traceback_locals(caught.exception)
        )
        self.assertNotIn(private, rendered)

    async def test_aclose_failure_blocks_normal_and_early_success(self) -> None:
        private = "private-aclose-runtime-failure"
        expected_key = opaque_object_key("active_yaml", "cleanup")
        expected = exact_snapshot_manifest(
            {
                provider: ((expected_key,) if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )

        class FailingCloseIterator:
            def __init__(self, documents) -> None:
                self.documents = tuple(documents)
                self.index = 0
                self.next_calls = 0
                self.close_calls = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                self.next_calls += 1
                if self.index >= len(self.documents):
                    raise StopAsyncIteration
                document = self.documents[self.index]
                self.index += 1
                return document

            async def aclose(self):
                self.close_calls += 1
                raise RuntimeError(private)

        cases = (
            (
                "normal",
                FailingCloseIterator(
                    (snapshot_document("active_yaml", expected_key),)
                ),
                2,
            ),
            (
                "early_mismatch",
                FailingCloseIterator(
                    (
                        snapshot_document(
                            "active_yaml",
                            opaque_object_key("active_yaml", "wrong-cleanup"),
                        ),
                        snapshot_document("active_yaml", expected_key),
                    )
                ),
                1,
            ),
        )
        for case, iterator, expected_next_calls in cases:
            with self.subTest(case=case):
                active_source = IteratorSnapshotSource(
                    expected.for_provider("active_yaml"),
                    iterator,
                )
                sources = tuple(
                    active_source
                    if item.provider == "active_yaml"
                    else SyntheticSnapshotSource(item.provider, item, ())
                    for item in expected.providers
                )
                with self.assertRaises(
                    providers.ExactReferenceInventorySnapshotError
                ) as caught:
                    await providers.async_read_exact_reference_inventory_snapshot(
                        object(),
                        expected,
                        sources,
                    )
                self.assertEqual(iterator.next_calls, expected_next_calls)
                self.assertEqual(iterator.close_calls, 1)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                rendered = (
                    str(caught.exception)
                    + repr(caught.exception)
                    + provider_traceback_locals(caught.exception)
                )
                self.assertNotIn(private, rendered)

    async def test_source_cancelled_error_without_task_cancellation_is_failure(
        self,
    ) -> None:
        private_next = "private-source-next-cancelled"
        private_close = "private-source-close-cancelled"
        expected_key = opaque_object_key("active_yaml", "source-cancel")
        expected = exact_snapshot_manifest(
            {
                provider: ((expected_key,) if provider == "active_yaml" else ())
                for provider in providers.PROVIDER_NAMES
            }
        )

        class CancelledNextIterator:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise asyncio.CancelledError(private_next)

        class CancelledCloseIterator:
            def __init__(self) -> None:
                self.index = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self.index:
                    raise StopAsyncIteration
                self.index += 1
                return snapshot_document("active_yaml", expected_key)

            async def aclose(self):
                raise asyncio.CancelledError(private_close)

        for case, iterator, private in (
            ("next", CancelledNextIterator(), private_next),
            ("close", CancelledCloseIterator(), private_close),
        ):
            with self.subTest(case=case):
                active_source = IteratorSnapshotSource(
                    expected.for_provider("active_yaml"),
                    iterator,
                )
                sources = tuple(
                    active_source
                    if item.provider == "active_yaml"
                    else SyntheticSnapshotSource(item.provider, item, ())
                    for item in expected.providers
                )
                with self.assertRaises(
                    providers.ExactReferenceInventorySnapshotError
                ) as caught:
                    await providers.async_read_exact_reference_inventory_snapshot(
                        object(),
                        expected,
                        sources,
                    )
                task = asyncio.current_task()
                if task is None:
                    self.fail("test must run inside an asyncio task")
                self.assertEqual(task.cancelling(), 0)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                rendered = (
                    str(caught.exception)
                    + repr(caught.exception)
                    + provider_traceback_locals(caught.exception)
                )
                self.assertNotIn(private, rendered)

    async def test_timeout_cancels_blocking_source_without_starting_later_sources(
        self,
    ) -> None:
        expected = exact_snapshot_manifest()
        entered = asyncio.Event()
        cancelled = asyncio.Event()

        async def block(_source) -> None:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        calls = []
        sources = synthetic_sources(
            expected,
            calls=calls,
            before_reads={"active_yaml": block},
        )
        with patch.object(
            providers,
            "_EXACT_REFERENCE_INVENTORY_TIMEOUT_SECONDS",
            0.01,
        ):
            with self.assertRaises(TimeoutError):
                await providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    sources,
                )

        self.assertTrue(entered.is_set())
        self.assertTrue(cancelled.is_set())
        self.assertEqual(calls, ["active_yaml"])

    async def test_deadline_wins_when_source_temporarily_suppresses_cancellation(
        self,
    ) -> None:
        expected = exact_snapshot_manifest()
        suppressed = asyncio.Event()
        closed = asyncio.Event()
        calls = []

        async def suppress_timeout(_source) -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                suppressed.set()

        sources = synthetic_sources(
            expected,
            calls=calls,
            before_reads={"active_yaml": suppress_timeout},
        )
        sources[0].closed_event = closed
        with patch.object(
            providers,
            "_EXACT_REFERENCE_INVENTORY_TIMEOUT_SECONDS",
            0.01,
        ):
            with self.assertRaises(TimeoutError):
                await providers.async_read_exact_reference_inventory_snapshot(
                    object(),
                    expected,
                    sources,
                )

        self.assertTrue(suppressed.is_set())
        self.assertTrue(closed.is_set())
        self.assertEqual(calls, ["active_yaml"])

    async def test_source_cancels_task_before_yield_and_generator_is_closed(
        self,
    ) -> None:
        expected = exact_snapshot_manifest()
        closed = asyncio.Event()
        calls = []

        async def cancel_before_yield(_source) -> None:
            task = asyncio.current_task()
            if task is None:
                raise AssertionError("source must run inside the collector task")
            task.cancel()

        sources = synthetic_sources(
            expected,
            calls=calls,
            before_reads={"active_yaml": cancel_before_yield},
        )
        sources[0].closed_event = closed
        task = asyncio.create_task(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                sources,
            )
        )

        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertTrue(task.cancelled())
        self.assertTrue(closed.is_set())
        self.assertEqual(calls, ["active_yaml"])

    async def test_external_cancellation_propagates_and_discards_partial_work(
        self,
    ) -> None:
        expected = exact_snapshot_manifest()
        entered = asyncio.Event()
        cancelled = asyncio.Event()

        async def block(_source) -> None:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        calls = []
        sources = synthetic_sources(
            expected,
            calls=calls,
            before_reads={"external_writers": block},
        )
        task = asyncio.create_task(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                sources,
            )
        )
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertTrue(cancelled.is_set())
        self.assertEqual(
            calls,
            ["active_yaml", "config_entry", "external_writers"],
        )
        self.assertTrue(task.cancelled())

    async def test_hanging_aclose_during_cancellation_is_bounded_without_tasks(
        self,
    ) -> None:
        expected = exact_snapshot_manifest()
        entered = asyncio.Event()
        close_started = asyncio.Event()
        close_cancelled = asyncio.Event()

        class HangingCloseIterator:
            def __aiter__(self):
                return self

            async def __anext__(self):
                entered.set()
                await asyncio.Event().wait()

            async def aclose(self):
                close_started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    close_cancelled.set()
                    raise

        active_source = IteratorSnapshotSource(
            expected.for_provider("active_yaml"),
            HangingCloseIterator(),
        )
        sources = tuple(
            active_source
            if item.provider == "active_yaml"
            else SyntheticSnapshotSource(item.provider, item, ())
            for item in expected.providers
        )
        task = asyncio.create_task(
            providers.async_read_exact_reference_inventory_snapshot(
                object(),
                expected,
                sources,
            )
        )
        await entered.wait()
        started_at = asyncio.get_running_loop().time()

        with patch.object(
            providers.asyncio,
            "create_task",
            side_effect=AssertionError("cleanup must not create tasks"),
        ) as create_task:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        elapsed = asyncio.get_running_loop().time() - started_at
        create_task.assert_not_called()
        self.assertTrue(task.cancelled())
        self.assertTrue(close_started.is_set())
        self.assertTrue(close_cancelled.is_set())
        self.assertLess(elapsed, 0.75)

    async def test_reads_are_sequential_and_collector_creates_no_tasks(self) -> None:
        expected = exact_snapshot_manifest()
        tracker = {"active": 0, "maximum": 0}
        calls = []

        async def observe(_source) -> None:
            tracker["active"] += 1
            tracker["maximum"] = max(tracker["maximum"], tracker["active"])
            await asyncio.sleep(0)
            tracker["active"] -= 1

        sources = synthetic_sources(
            expected,
            calls=calls,
            before_reads={provider: observe for provider in providers.PROVIDER_NAMES},
        )
        data_canary = object()
        hass = types.SimpleNamespace(data={"canary": data_canary})

        with patch.object(
            providers.asyncio,
            "create_task",
            side_effect=AssertionError("collector must not create tasks"),
        ) as create_task:
            snapshot = await providers.async_read_exact_reference_inventory_snapshot(
                hass,
                expected,
                sources,
            )

        create_task.assert_not_called()
        self.assertEqual(tracker, {"active": 0, "maximum": 1})
        self.assertEqual(calls, list(providers.PROVIDER_NAMES))
        self.assertIs(hass.data["canary"], data_canary)
        self.assertTrue(snapshot.read_only)

    async def test_source_failure_returns_no_partial_result_or_background_work(
        self,
    ) -> None:
        expected = exact_snapshot_manifest()
        calls = []
        sources = synthetic_sources(
            expected,
            calls=calls,
            errors={"external_writers": RuntimeError("injected failure")},
        )
        result = None
        with self.assertRaises(providers.ExactReferenceInventorySnapshotError):
            result = await providers.async_read_exact_reference_inventory_snapshot(
                types.SimpleNamespace(data={}),
                expected,
                sources,
            )

        self.assertIsNone(result)
        self.assertEqual(
            calls,
            ["active_yaml", "config_entry", "external_writers"],
        )
        self.assertEqual(sources[0].read_count, 1)
        self.assertEqual(sources[1].read_count, 1)
        self.assertEqual(sources[2].read_count, 1)
        self.assertEqual(sources[3].read_count, 0)
        self.assertEqual(sources[4].read_count, 0)


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

    def test_expected_manifest_rejects_untyped_nested_records_before_getters(self) -> None:
        expected = exact_snapshot_manifest()

        class DescriptorRecord:
            accesses = 0

            @property
            def provider(self):
                type(self).accesses += 1
                raise AssertionError("provider getter must not run")

            @property
            def object_keys(self):
                type(self).accesses += 1
                raise AssertionError("object key getter must not run")

        record = DescriptorRecord()
        malformed = (record, *expected.providers[1:])
        with self.assertRaises(TypeError):
            providers.ExpectedObjectManifest("typed-records", malformed)
        self.assertEqual(DescriptorRecord.accesses, 0)

        object.__setattr__(expected, "providers", malformed)
        with self.assertRaises(TypeError):
            _digest = expected.digest
        self.assertEqual(DescriptorRecord.accesses, 0)

        class TupleSubclass(tuple):
            pass

        with self.assertRaises(TypeError):
            providers.ExpectedObjectManifest(
                "exact-tuple",
                TupleSubclass(exact_snapshot_manifest().providers),
            )

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
