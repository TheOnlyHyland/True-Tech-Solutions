"""Pure tests for strict reference migration journal codecs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import importlib
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"
OLD_ENTITY = "climate.guest_room_radiator"
TARGET_ENTITY = "climate.true_family_guest_room"
JOURNAL_ID = "true-family-reference-journal-test"


def load_modules():
    """Load package modules without executing the integration entry point."""

    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = sys.modules.get(PACKAGE_NAME)
    if package is None:
        package = types.ModuleType(PACKAGE_NAME)
        sys.modules[PACKAGE_NAME] = package
    package.__path__ = [str(PACKAGE_ROOT)]
    migration_module = importlib.import_module(f"{PACKAGE_NAME}.reference_migration")
    codec_module = importlib.import_module(f"{PACKAGE_NAME}.reference_migration_ha")
    return migration_module, codec_module


migration, codec = load_modules()


def completed_fixture():
    """Create dataclasses through the production pure coordinator."""

    providers = []
    for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST):
        documents = []
        if provider_name == "active_yaml":
            documents.append(
                migration.ReferenceDocument(
                    provider=provider_name,
                    object_id="guest_room_actuator",
                    revision="revision-7",
                    payload={
                        "target": {"entity_id": OLD_ENTITY},
                        "enabled": True,
                        "offset": 0.5,
                    },
                    writable=True,
                )
            )
        providers.append(migration.InMemoryReferenceProvider(provider_name, documents))
    targets = tuple(
        (provider_name, TARGET_ENTITY)
        for provider_name in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
    )
    authority = migration.InMemoryMigrationAuthority(
        [
            migration.MigrationSubject(
                room_id="guest_room",
                room_revision=7,
                old_entity_id=OLD_ENTITY,
                logical_unique_id="logical_valve_guest_room",
                provider_targets=targets,
            )
        ]
    )
    journal = migration.InMemoryReferenceJournal()
    coordinator = migration.ReferenceMigrationCoordinator(
        providers,
        journal,
        authority,
    )
    plan = coordinator.create_plan(
        room_id="guest_room",
        room_revision=7,
        old_entity_id=OLD_ENTITY,
        logical_unique_id="logical_valve_guest_room",
        target_entity_id=TARGET_ENTITY,
        required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
        references_expected=True,
    )
    result = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
    completion = journal.completion_for(plan.plan_id)
    original = journal.originals_for(plan.plan_id)[0]
    return plan, result, completion, original


class ReferenceMigrationCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.result, cls.completion, cls.original = completed_fixture()

    def test_every_persisted_dataclass_round_trips_canonically(self) -> None:
        cases = (
            (
                self.original.document,
                codec.encode_reference_document,
                codec.decode_reference_document,
            ),
            (
                self.plan.documents[0],
                codec.encode_planned_document,
                codec.decode_planned_document,
            ),
            (
                self.original,
                codec.encode_journaled_original,
                codec.decode_journaled_original,
            ),
            (
                self.plan,
                codec.encode_migration_plan,
                codec.decode_migration_plan,
            ),
            (
                self.result,
                codec.encode_migration_result,
                codec.decode_migration_result,
            ),
            (
                self.completion.documents[0],
                codec.encode_document_snapshot,
                codec.decode_document_snapshot,
            ),
            (
                self.completion,
                codec.encode_journaled_completion,
                codec.decode_journaled_completion,
            ),
        )

        for expected, encoder, decoder in cases:
            with self.subTest(dataclass=type(expected).__name__):
                encoded = encoder(expected)
                json.dumps(encoded, allow_nan=False, sort_keys=True)
                self.assertEqual(decoder(deepcopy(encoded)), expected)
                self.assertEqual(encoder(decoder(deepcopy(encoded))), encoded)

    def test_distinct_longer_target_entity_id_round_trips(self) -> None:
        target = f"{OLD_ENTITY}_with_term"
        providers = [
            migration.InMemoryReferenceProvider(
                provider,
                (
                    migration.ReferenceDocument(
                        provider=provider,
                        object_id="longer_target",
                        revision=1,
                        payload={"entity_id": OLD_ENTITY},
                        writable=True,
                    ),
                )
                if provider == "lovelace"
                else (),
            )
            for provider in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
        ]
        targets = tuple(
            (provider, target)
            for provider in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
        )
        coordinator = migration.ReferenceMigrationCoordinator(
            providers,
            migration.InMemoryReferenceJournal(),
            migration.InMemoryMigrationAuthority(
                (
                    migration.MigrationSubject(
                        room_id="guest_room",
                        room_revision=7,
                        old_entity_id=OLD_ENTITY,
                        logical_unique_id="logical_valve_guest_room",
                        provider_targets=targets,
                    ),
                )
            ),
        )
        plan = coordinator.create_plan(
            room_id="guest_room",
            room_revision=7,
            old_entity_id=OLD_ENTITY,
            logical_unique_id="logical_valve_guest_room",
            target_entity_id=target,
            required_providers=migration.TRUE_FAMILY_PROVIDER_MANIFEST,
            references_expected=True,
        )

        encoded = codec.encode_migration_plan(plan)

        self.assertEqual(codec.decode_migration_plan(encoded), plan)

    def test_equal_and_incomplete_targets_are_rejected(self) -> None:
        equal_target = replace(
            self.plan,
            target_entity_id=OLD_ENTITY,
            provider_targets=tuple(
                (provider, OLD_ENTITY)
                for provider in sorted(migration.TRUE_FAMILY_PROVIDER_MANIFEST)
            ),
        )
        incomplete = replace(
            self.plan,
            target_entity_id=None,
            provider_targets=self.plan.provider_targets[:-1],
        )

        for plan in (equal_target, incomplete):
            with self.subTest(plan=plan.provider_targets):
                with self.assertRaises(codec.ReferenceJournalCodecError):
                    codec.encode_migration_plan(plan)

    def test_every_dataclass_decoder_rejects_unknown_fields(self) -> None:
        cases = (
            (
                codec.encode_reference_document(self.original.document),
                codec.decode_reference_document,
            ),
            (
                codec.encode_planned_document(self.plan.documents[0]),
                codec.decode_planned_document,
            ),
            (
                codec.encode_journaled_original(self.original),
                codec.decode_journaled_original,
            ),
            (codec.encode_migration_plan(self.plan), codec.decode_migration_plan),
            (codec.encode_migration_result(self.result), codec.decode_migration_result),
            (
                codec.encode_document_snapshot(self.completion.documents[0]),
                codec.decode_document_snapshot,
            ),
            (
                codec.encode_journaled_completion(self.completion),
                codec.decode_journaled_completion,
            ),
        )

        for encoded, decoder in cases:
            with self.subTest(decoder=decoder.__name__):
                encoded["unexpected"] = "blocked"
                with self.assertRaises(codec.ReferenceJournalCodecError):
                    decoder(encoded)

    def test_typed_revisions_paths_counts_and_payloads_are_strict(self) -> None:
        document = codec.encode_reference_document(self.original.document)
        document["revision"] = {"type": "integer", "value": True}
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_document(document)

        planned = codec.encode_planned_document(self.plan.documents[0])
        planned["exact_paths"][0][0] = {"type": "index", "value": True}
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_planned_document(planned)

        result = codec.encode_migration_result(self.result)
        result["changed_documents"] = True
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_migration_result(result)

        malformed_payload = codec.encode_reference_document(self.original.document)
        malformed_payload["payload"] = {"unsupported": ("tuple",)}
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_document(malformed_payload)

    def test_completion_revalidates_plan_and_result_relationships(self) -> None:
        encoded = codec.encode_journaled_completion(self.completion)
        encoded["result"]["digest"] = "0" * 64

        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_journaled_completion(encoded)

    def test_root_schema_id_generation_and_digest_are_exact(self) -> None:
        root = codec.empty_reference_journal_data(JOURNAL_ID)

        self.assertEqual(
            codec.decode_reference_journal_data(
                deepcopy(root),
                expected_journal_id=JOURNAL_ID,
            ),
            root,
        )
        self.assertEqual(
            set(root),
            {"schema", "journal_id", "generation", "content", "content_digest"},
        )
        self.assertEqual(root["generation"], 0)

        tampered = deepcopy(root)
        tampered["generation"] = 1
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_journal_data(tampered)

        extra = deepcopy(root)
        extra["unexpected"] = True
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_journal_data(extra)

        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_journal_data(
                root,
                expected_journal_id="different-journal",
            )

        boolean_generation = deepcopy(root)
        boolean_generation["generation"] = True
        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_journal_data(boolean_generation)

    def test_completed_root_requires_every_changed_original(self) -> None:
        plan_id = self.completion.plan.plan_id
        content = {
            "states": {
                plan_id: {
                    "state": migration.MigrationState.COMPLETE.value,
                    "reason": None,
                }
            },
            "originals": {},
            "completions": {
                plan_id: codec.encode_journaled_completion(self.completion)
            },
        }
        root = codec._build_root(JOURNAL_ID, 1, content)

        with self.assertRaises(codec.ReferenceJournalCodecError):
            codec.decode_reference_journal_data(
                root,
                expected_journal_id=JOURNAL_ID,
            )


if __name__ == "__main__":
    unittest.main()
