"""Tests for pure fail-closed reference migration planning."""

from __future__ import annotations

import importlib
from dataclasses import replace
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"
OLD_ENTITY = "climate.guest_room_radiator"
TARGET_ENTITY = "climate.true_family_guest_room"
REQUIRED = frozenset(
    {
        "active_yaml",
        "config_entry",
        "external_writers",
        "lovelace",
        "scheduler",
    }
)


def load_reference_migration():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(PACKAGE_ROOT)]
    sys.modules[PACKAGE_NAME] = package
    return importlib.import_module(f"{PACKAGE_NAME}.reference_migration")


migration = load_reference_migration()


def document(
    provider: str,
    object_id: str,
    payload,
    *,
    revision=1,
    writable: bool = True,
):
    return migration.ReferenceDocument(
        provider=provider,
        object_id=object_id,
        revision=revision,
        payload=payload,
        writable=writable,
    )


def providers(*, automation_payload=None, script_payload=None):
    automation_payload = automation_payload or {"target": OLD_ENTITY}
    script_payload = script_payload or {"sequence": []}
    return (
        migration.InMemoryReferenceProvider(
            "active_yaml",
            [document("active_yaml", "arrival", automation_payload)],
        ),
        migration.InMemoryReferenceProvider(
            "scheduler",
            [document("scheduler", "heat", script_payload)],
        ),
    )


def create_plan(coordinator, **overrides):
    arguments = {
        "room_id": "guest_room",
        "room_revision": 7,
        "old_entity_id": OLD_ENTITY,
        "logical_unique_id": "logical_valve_guest_room",
        "target_entity_id": TARGET_ENTITY,
        "required_providers": REQUIRED,
        "references_expected": True,
    }
    arguments.update(overrides)
    return coordinator.create_plan(**arguments)


def subject_for(
    providers,
    *,
    target_entity_id=TARGET_ENTITY,
    provider_targets=None,
    room_revision=7,
):
    targets = {name: target_entity_id for name in REQUIRED}
    if provider_targets is not None:
        targets.update(provider_targets)
    return migration.MigrationSubject(
        room_id="guest_room",
        room_revision=room_revision,
        old_entity_id=OLD_ENTITY,
        logical_unique_id="logical_valve_guest_room",
        provider_targets=tuple(sorted(targets.items())),
    )


def complete_providers(providers):
    provider_list = list(providers)
    configured = {provider.name for provider in provider_list}
    for provider_name in sorted(REQUIRED - configured):
        provider_list.append(migration.InMemoryReferenceProvider(provider_name))
    return tuple(provider_list)


def make_coordinator(providers, journal, *, subject=None):
    provider_list = complete_providers(providers)
    authority = migration.InMemoryMigrationAuthority(
        [subject or subject_for(provider_list)]
    )
    return migration.ReferenceMigrationCoordinator(
        provider_list,
        journal,
        authority,
    )


class FailFirstWriteProvider(migration.InMemoryReferenceProvider):
    def __init__(self, name, documents):
        super().__init__(name, documents)
        self.failed = False

    def write_document(self, object_id, *, expected_revision, payload):
        if not self.failed:
            self.failed = True
            raise RuntimeError("injected provider failure")
        return super().write_document(
            object_id,
            expected_revision=expected_revision,
            payload=payload,
        )


class FailRollbackProvider(migration.InMemoryReferenceProvider):
    def __init__(self, name, documents):
        super().__init__(name, documents)
        self.write_calls = 0

    def write_document(self, object_id, *, expected_revision, payload):
        self.write_calls += 1
        if self.write_calls == 2:
            raise RuntimeError("injected restoration failure")
        return super().write_document(
            object_id,
            expected_revision=expected_revision,
            payload=payload,
        )


class ConcurrentWriteProvider(migration.InMemoryReferenceProvider):
    def write_document(self, object_id, *, expected_revision, payload):
        current = self.get_document(object_id)
        self.put_document(
            migration.ReferenceDocument(
                provider=current.provider,
                object_id=current.object_id,
                revision=current.revision + 1,
                payload={"target": "climate.concurrent_writer"},
                writable=True,
            )
        )
        raise migration.StaleMigrationPlan("injected concurrent update")


class CommitThenRaiseProvider(migration.InMemoryReferenceProvider):
    def write_document(self, object_id, *, expected_revision, payload):
        result = super().write_document(
            object_id,
            expected_revision=expected_revision,
            payload=payload,
        )
        if payload != {"target": OLD_ENTITY}:
            raise RuntimeError("injected post-commit failure")
        return result


class CompletionFailJournal(migration.InMemoryReferenceJournal):
    def set_state(self, plan_id, state, reason=None) -> None:
        if state is migration.MigrationState.COMPLETE:
            raise RuntimeError("injected completion journal failure")
        super().set_state(plan_id, state, reason)


class TamperedCompletionJournal(migration.InMemoryReferenceJournal):
    tamper = False

    def completion_for(self, plan_id):
        completion = super().completion_for(plan_id)
        if not self.tamper:
            return completion
        return replace(
            completion,
            result=replace(completion.result, digest="0" * 64),
        )


class AuthorityDriftProvider(migration.InMemoryReferenceProvider):
    def __init__(self, name, documents, drift):
        super().__init__(name, documents)
        self.drift = drift
        self.drifted = False

    def write_document(self, object_id, *, expected_revision, payload):
        result = super().write_document(
            object_id,
            expected_revision=expected_revision,
            payload=payload,
        )
        if not self.drifted:
            self.drifted = True
            self.drift()
        return result


class CapturingJournal(migration.InMemoryReferenceJournal):
    def __init__(self) -> None:
        super().__init__()
        self.recorded = []

    def record_original(self, plan_id, original, post_fingerprint) -> None:
        super().record_original(plan_id, original, post_fingerprint)
        self.recorded.append((plan_id, original))


class ReferenceMigrationTests(unittest.TestCase):
    def test_planning_is_deterministic_and_fingerprints_are_canonical(self) -> None:
        first_automations, first_scripts = providers(
            automation_payload={
                "entities": [OLD_ENTITY],
                "a": {"entity_id": OLD_ENTITY},
            }
        )
        second_automations, second_scripts = providers(
            automation_payload={
                "a": {"entity_id": OLD_ENTITY},
                "entities": [OLD_ENTITY],
            }
        )
        first = make_coordinator(
            [first_scripts, first_automations],
            migration.InMemoryReferenceJournal(),
        )
        second = make_coordinator(
            [second_automations, second_scripts],
            migration.InMemoryReferenceJournal(),
        )

        first_plan = create_plan(first)
        second_plan = create_plan(second)

        self.assertEqual(first_plan.plan_id, second_plan.plan_id)
        self.assertEqual(first_plan.digest, second_plan.digest)
        self.assertEqual(first_plan.documents, second_plan.documents)
        self.assertEqual(first_plan.exact_replacements, 2)

    def test_entity_lists_and_scalars_are_replaced_at_exact_paths(self) -> None:
        automations, scripts = providers(
            automation_payload={
                "target": {"entity_id": OLD_ENTITY},
                "entities": [OLD_ENTITY, "light.hall"],
                "nested": [{"entity_id": OLD_ENTITY}],
            },
            script_payload={"sequence": [{"target": OLD_ENTITY}]},
        )
        journal = CapturingJournal()
        coordinator = make_coordinator(
            [automations, scripts],
            journal,
        )
        plan = create_plan(coordinator)

        result = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        payload = automations.get_document("arrival").payload
        self.assertEqual(payload["target"]["entity_id"], TARGET_ENTITY)
        self.assertEqual(payload["entities"], [TARGET_ENTITY, "light.hall"])
        self.assertEqual(payload["nested"][0]["entity_id"], TARGET_ENTITY)
        self.assertEqual(
            scripts.get_document("heat").payload["sequence"][0]["target"],
            TARGET_ENTITY,
        )
        self.assertEqual(result.exact_replacements, 4)
        self.assertEqual(result.changed_documents, 2)
        self.assertEqual(len(journal.recorded), 2)

    def test_distinct_longer_entity_ids_are_not_old_references(self) -> None:
        similar = f"{OLD_ENTITY}_backup"
        automations, scripts = providers(
            automation_payload={"entity_id": OLD_ENTITY, "note": similar}
        )
        coordinator = make_coordinator(
            [automations, scripts], migration.InMemoryReferenceJournal()
        )

        scan = migration.scan_references(
            automations.get_document("arrival").payload,
            OLD_ENTITY,
        )
        self.assertEqual(len(scan.exact_paths), 1)
        self.assertEqual(len(scan.embedded), 0)
        plan = create_plan(coordinator)
        coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
        self.assertEqual(
            automations.get_document("arrival").payload["note"],
            similar,
        )

    def test_approved_jinja_literal_is_replaced(self) -> None:
        automations, scripts = providers(
            automation_payload={
                "value_template": f"{{{{ states('{OLD_ENTITY}') }}}}",
            }
        )
        coordinator = make_coordinator(
            [automations, scripts], migration.InMemoryReferenceJournal()
        )

        plan = create_plan(coordinator)
        coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(
            automations.get_document("arrival").payload["value_template"],
            f"{{{{ states('{TARGET_ENTITY}') }}}}",
        )

    def test_unknown_jinja_and_free_text_references_block_planning(self) -> None:
        for payload in (
            {"value_template": f"{{{{ unknown('{OLD_ENTITY}') }}}}"},
            {"note": f"Use {OLD_ENTITY} during recovery"},
        ):
            with self.subTest(payload=payload):
                automations, scripts = providers(automation_payload=payload)
                coordinator = make_coordinator(
                    [automations, scripts], migration.InMemoryReferenceJournal()
                )

                with self.assertRaises(migration.MigrationPlanningBlocked) as raised:
                    create_plan(coordinator)

                self.assertIn("embedded references", str(raised.exception))

    def test_kitchen_facade_is_preserved_as_a_distinct_target(self) -> None:
        old_entity = "climate.kitchen_radiator"
        facade = "climate.kitchen_radiator_with_term"
        logical = "climate.true_family_kitchen_valve"
        active_yaml = migration.InMemoryReferenceProvider(
            "active_yaml",
            [
                document(
                    "active_yaml",
                    "kitchen_actuator",
                    {
                        "value_template": (
                            "{{ state_attr('climate.kitchen_radiator', "
                            "'hvac_action') }}"
                        ),
                        "existing_facade": facade,
                    },
                )
            ],
        )
        lovelace = migration.InMemoryReferenceProvider(
            "lovelace",
            [
                document(
                    "lovelace",
                    "kitchen_card",
                    {
                        "entity": old_entity,
                        "value_template": (
                            "{{ states('climate.kitchen_radiator') | float + 1 }}"
                        ),
                    },
                )
            ],
        )
        provider_list = complete_providers([active_yaml, lovelace])
        targets = {provider: logical for provider in REQUIRED}
        targets["lovelace"] = facade
        subject = migration.MigrationSubject(
            room_id="kitchen",
            room_revision=3,
            old_entity_id=old_entity,
            logical_unique_id="logical_valve_kitchen",
            provider_targets=tuple(sorted(targets.items())),
        )
        coordinator = migration.ReferenceMigrationCoordinator(
            provider_list,
            migration.InMemoryReferenceJournal(),
            migration.InMemoryMigrationAuthority([subject]),
        )

        plan = coordinator.create_plan(
            room_id="kitchen",
            room_revision=3,
            old_entity_id=old_entity,
            logical_unique_id="logical_valve_kitchen",
            target_entity_id=None,
            provider_targets=targets,
            required_providers=REQUIRED,
            references_expected=True,
        )
        result = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        active_payload = active_yaml.get_document("kitchen_actuator").payload
        self.assertIn(logical, active_payload["value_template"])
        self.assertEqual(active_payload["existing_facade"], facade)
        self.assertEqual(
            lovelace.get_document("kitchen_card").payload["entity"],
            facade,
        )
        self.assertIn(
            f"states('{facade}')",
            lovelace.get_document("kitchen_card").payload["value_template"],
        )
        self.assertEqual(result.exact_replacements, 3)

    def test_computed_reference_blocks_a_plan_with_other_exact_references(self) -> None:
        automations, scripts = providers(
            automation_payload={
                "entity_id": OLD_ENTITY,
                "value_template": (
                    "{{ states(['climate', 'guest_room_radiator'] | join('.')) }}"
                ),
            }
        )
        coordinator = make_coordinator(
            [automations, scripts],
            migration.InMemoryReferenceJournal(),
        )

        with self.assertRaises(migration.MigrationPlanningBlocked) as raised:
            create_plan(coordinator)

        self.assertIn("embedded references", str(raised.exception))

    def test_missing_and_nonwritable_providers_block_planning(self) -> None:
        automations, _scripts = providers()
        authority = migration.InMemoryMigrationAuthority([subject_for([automations])])
        with self.assertRaises(ValueError) as raised:
            migration.ReferenceMigrationCoordinator(
                [automations],
                migration.InMemoryReferenceJournal(),
                authority,
            )
        self.assertIn("manifest is incomplete", str(raised.exception))

        readonly = migration.InMemoryReferenceProvider(
            "scheduler",
            [
                document(
                    "scheduler",
                    "heat",
                    {"target": OLD_ENTITY},
                    writable=False,
                )
            ],
        )
        coordinator = make_coordinator(
            [automations, readonly], migration.InMemoryReferenceJournal()
        )
        with self.assertRaises(migration.MigrationPlanningBlocked) as raised:
            create_plan(coordinator)
        self.assertIn("is not writable", str(raised.exception))

    def test_revision_and_fingerprint_changes_invalidate_plans(self) -> None:
        with self.subTest("revision"):
            automations, scripts = providers()
            coordinator = make_coordinator(
                [automations, scripts], migration.InMemoryReferenceJournal()
            )
            plan = create_plan(coordinator)
            original = automations.get_document("arrival")
            automations.put_document(
                document(
                    "active_yaml",
                    "arrival",
                    original.payload,
                    revision=2,
                )
            )
            with self.assertRaises(migration.StaleMigrationPlan):
                coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        with self.subTest("fingerprint"):
            automations, scripts = providers()
            coordinator = make_coordinator(
                [automations, scripts], migration.InMemoryReferenceJournal()
            )
            plan = create_plan(coordinator)
            automations.put_document(
                document(
                    "active_yaml",
                    "arrival",
                    {"target": OLD_ENTITY, "changed": True},
                    revision=1,
                )
            )
            with self.assertRaises(migration.StaleMigrationPlan):
                coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

    def test_partial_apply_restores_originals_in_reverse_order(self) -> None:
        automations = migration.InMemoryReferenceProvider(
            "active_yaml",
            [document("active_yaml", "arrival", {"target": OLD_ENTITY})],
        )
        scripts = FailFirstWriteProvider(
            "scheduler",
            [document("scheduler", "heat", {"target": OLD_ENTITY})],
        )
        journal = CapturingJournal()
        coordinator = make_coordinator(
            [automations, scripts],
            journal,
        )
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationApplyFailed) as raised:
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertTrue(raised.exception.rolled_back)
        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )
        self.assertEqual(
            scripts.get_document("heat").payload,
            {"target": OLD_ENTITY},
        )
        self.assertEqual(
            [
                f"{original.provider}/{original.object_id}"
                for _plan_id, original in journal.recorded
            ],
            ["active_yaml/arrival", "scheduler/heat"],
        )
        self.assertEqual(coordinator.state(plan.plan_id), migration.MigrationState.FAILED)
        self.assertFalse(coordinator.blocked)

    def test_failed_rollback_marks_the_coordinator_blocked(self) -> None:
        automations = FailRollbackProvider(
            "active_yaml",
            [document("active_yaml", "arrival", {"target": OLD_ENTITY})],
        )
        scripts = FailFirstWriteProvider(
            "scheduler",
            [document("scheduler", "heat", {"target": OLD_ENTITY})],
        )
        coordinator = make_coordinator(
            [automations, scripts], migration.InMemoryReferenceJournal()
        )
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationRestoreFailed) as raised:
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertIn("active_yaml/arrival", raised.exception.failed_documents)
        self.assertTrue(coordinator.blocked)
        self.assertEqual(
            coordinator.state(plan.plan_id),
            migration.MigrationState.BLOCKED,
        )

    def test_success_is_idempotent_but_changed_content_cannot_be_replayed(self) -> None:
        automations, scripts = providers()
        coordinator = make_coordinator(
            [automations, scripts], migration.InMemoryReferenceJournal()
        )
        plan = create_plan(coordinator)

        first = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
        second = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertFalse(first.idempotent)
        self.assertTrue(second.idempotent)
        completed = automations.get_document("arrival")
        automations.put_document(
            document(
                "active_yaml",
                "arrival",
                {"target": TARGET_ENTITY, "changed": True},
                revision=completed.revision + 1,
            )
        )
        with self.assertRaises(migration.StaleMigrationPlan):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

    def test_completed_plan_replays_idempotently_after_restart(self) -> None:
        automations, scripts = providers()
        journal = migration.InMemoryReferenceJournal()
        coordinator = make_coordinator([automations, scripts], journal)
        plan = create_plan(coordinator)
        coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        restarted = make_coordinator([automations, scripts], journal)
        replay = restarted.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertTrue(replay.idempotent)
        self.assertEqual(replay.state, migration.MigrationState.COMPLETE)

    def test_tampered_durable_completion_is_rejected_on_restart(self) -> None:
        automations, scripts = providers()
        journal = TamperedCompletionJournal()
        coordinator = make_coordinator([automations, scripts], journal)
        plan = create_plan(coordinator)
        coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
        journal.tamper = True

        with self.assertRaises(TypeError):
            make_coordinator([automations, scripts], journal)

    def test_logical_target_rename_changes_plan_identity(self) -> None:
        first_automations, first_scripts = providers()
        second_automations, second_scripts = providers()
        first = make_coordinator(
            [first_automations, first_scripts],
            migration.InMemoryReferenceJournal(),
        )
        second = make_coordinator(
            [second_automations, second_scripts],
            migration.InMemoryReferenceJournal(),
            subject=subject_for(
                [second_automations, second_scripts],
                target_entity_id="climate.true_family_spare_room",
            ),
        )

        original_plan = create_plan(first)
        renamed_plan = create_plan(
            second,
            target_entity_id="climate.true_family_spare_room",
        )

        self.assertNotEqual(original_plan.plan_id, renamed_plan.plan_id)
        self.assertNotEqual(original_plan.digest, renamed_plan.digest)

    def test_zero_occurrences_require_explicit_no_reference_expectation(self) -> None:
        automations, scripts = providers(
            automation_payload={"target": "light.hall"},
            script_payload={"sequence": []},
        )
        journal = CapturingJournal()
        coordinator = make_coordinator(
            [automations, scripts],
            journal,
        )
        with self.assertRaises(migration.MigrationPlanningBlocked):
            create_plan(coordinator)

        plan = create_plan(coordinator, references_expected=False)
        result = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
        replanned = create_plan(coordinator, references_expected=False)

        self.assertEqual(plan.exact_replacements, 0)
        self.assertEqual(result.changed_documents, 0)
        self.assertEqual(replanned, plan)
        self.assertEqual(
            journal.state(plan.plan_id)[0],
            migration.MigrationState.COMPLETE,
        )
        self.assertEqual(journal.recorded, [])

    def test_malformed_mapping_or_list_blocks_planning(self) -> None:
        automations, scripts = providers(
            automation_payload={"entities": (OLD_ENTITY,)},
        )
        coordinator = make_coordinator(
            [automations, scripts], migration.InMemoryReferenceJournal()
        )

        with self.assertRaises(migration.MigrationPlanningBlocked) as raised:
            create_plan(coordinator)

        self.assertIn("is malformed", str(raised.exception))

    def test_restart_with_applying_checkpoint_blocks_new_plans(self) -> None:
        automations, scripts = providers()
        journal = migration.InMemoryReferenceJournal()
        coordinator = make_coordinator(
            [automations, scripts],
            journal,
        )
        plan = create_plan(coordinator)
        journal.set_state(plan.plan_id, migration.MigrationState.APPLYING)

        restarted = make_coordinator(
            [automations, scripts],
            journal,
        )

        self.assertTrue(restarted.blocked)
        self.assertIn(plan.plan_id, restarted.blocked_reason)
        with self.assertRaises(migration.MigrationPlanningBlocked):
            create_plan(restarted)

    def test_provider_specific_targets_preserve_facade_boundaries(self) -> None:
        active_yaml = migration.InMemoryReferenceProvider(
            "active_yaml",
            [document("active_yaml", "actuator", {"target": OLD_ENTITY})],
        )
        lovelace = migration.InMemoryReferenceProvider(
            "lovelace",
            [document("lovelace", "room", {"entity": OLD_ENTITY})],
        )
        provider_targets = {name: TARGET_ENTITY for name in REQUIRED}
        provider_targets.update(
            {
                "active_yaml": "climate.true_family_guest_room_valve",
                "lovelace": "climate.guest_room_thermostat",
            }
        )
        coordinator = make_coordinator(
            [active_yaml, lovelace],
            migration.InMemoryReferenceJournal(),
            subject=subject_for(
                [active_yaml, lovelace],
                provider_targets=provider_targets,
            ),
        )

        plan = create_plan(
            coordinator,
            target_entity_id=None,
            provider_targets=provider_targets,
            required_providers=REQUIRED,
        )
        coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(
            active_yaml.get_document("actuator").payload["target"],
            "climate.true_family_guest_room_valve",
        )
        self.assertEqual(
            lovelace.get_document("room").payload["entity"],
            "climate.guest_room_thermostat",
        )

    def test_invalid_migration_targets_fail_before_planning(self) -> None:
        automations, scripts = providers()
        coordinator = make_coordinator(
            [automations, scripts],
            migration.InMemoryReferenceJournal(),
        )
        incomplete = {provider: TARGET_ENTITY for provider in REQUIRED}
        incomplete.pop("scheduler")
        cases = (
            {"target_entity_id": OLD_ENTITY},
            {"target_entity_id": "climate.Invalid-Target"},
            {
                "target_entity_id": None,
                "provider_targets": incomplete,
            },
        )

        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(migration.MigrationPlanningBlocked):
                    create_plan(coordinator, **overrides)

    def test_authoritative_room_revision_drift_invalidates_plan(self) -> None:
        automations, scripts = providers()
        provider_list = complete_providers([automations, scripts])
        subject = subject_for(provider_list)
        authority = migration.InMemoryMigrationAuthority([subject])
        coordinator = migration.ReferenceMigrationCoordinator(
            provider_list,
            migration.InMemoryReferenceJournal(),
            authority,
        )
        plan = create_plan(coordinator)
        authority.put_subject(subject_for(provider_list, room_revision=8))

        with self.assertRaises(migration.StaleMigrationPlan):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )

    def test_concurrent_update_is_preserved_and_blocks_restoration(self) -> None:
        automations = migration.InMemoryReferenceProvider(
            "active_yaml",
            [document("active_yaml", "arrival", {"target": OLD_ENTITY})],
        )
        scripts = ConcurrentWriteProvider(
            "scheduler",
            [document("scheduler", "heat", {"target": OLD_ENTITY})],
        )
        coordinator = make_coordinator(
            [automations, scripts],
            migration.InMemoryReferenceJournal(),
        )
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationRestoreFailed):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )
        self.assertEqual(
            scripts.get_document("heat").payload,
            {"target": "climate.concurrent_writer"},
        )

    def test_provider_commit_then_raise_is_detected_and_restored(self) -> None:
        automations = CommitThenRaiseProvider(
            "active_yaml",
            [document("active_yaml", "arrival", {"target": OLD_ENTITY})],
        )
        scripts = migration.InMemoryReferenceProvider(
            "scheduler",
            [document("scheduler", "heat", {"target": OLD_ENTITY})],
        )
        coordinator = make_coordinator(
            [automations, scripts],
            migration.InMemoryReferenceJournal(),
        )
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationApplyFailed):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )

    def test_failed_plan_retry_does_not_duplicate_journal_originals(self) -> None:
        automations = FailFirstWriteProvider(
            "active_yaml",
            [document("active_yaml", "arrival", {"target": OLD_ENTITY})],
        )
        scripts = migration.InMemoryReferenceProvider(
            "scheduler",
            [document("scheduler", "heat", {"target": OLD_ENTITY})],
        )
        journal = migration.InMemoryReferenceJournal()
        coordinator = make_coordinator([automations, scripts], journal)
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationApplyFailed):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
        result = coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(result.state, migration.MigrationState.COMPLETE)
        self.assertEqual(len(journal.originals_for(plan.plan_id)), 2)

    def test_mid_apply_authority_drift_restores_all_provider_writes(self) -> None:
        scripts = migration.InMemoryReferenceProvider(
            "scheduler",
            [document("scheduler", "heat", {"target": OLD_ENTITY})],
        )
        authority = migration.InMemoryMigrationAuthority()
        automations = AuthorityDriftProvider(
            "active_yaml",
            [document("active_yaml", "arrival", {"target": OLD_ENTITY})],
            lambda: authority.put_subject(
                subject_for([automations, scripts], room_revision=8)
            ),
        )
        provider_list = complete_providers([automations, scripts])
        authority.put_subject(subject_for(provider_list))
        coordinator = migration.ReferenceMigrationCoordinator(
            provider_list,
            migration.InMemoryReferenceJournal(),
            authority,
        )
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationApplyFailed):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)

        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )
        self.assertEqual(
            scripts.get_document("heat").payload,
            {"target": OLD_ENTITY},
        )

    def test_restart_recovery_restores_only_attested_postimages(self) -> None:
        automations, scripts = providers()
        journal = migration.InMemoryReferenceJournal()
        coordinator = make_coordinator(
            [automations, scripts],
            journal,
        )
        plan = create_plan(coordinator)
        journal.set_state(plan.plan_id, migration.MigrationState.APPLYING)
        provider_map = {
            "active_yaml": automations,
            "scheduler": scripts,
        }
        for item in plan.documents:
            original = provider_map[item.provider].get_document(item.object_id)
            journal.record_original(plan.plan_id, original, item.post_fingerprint)
        original = automations.get_document("arrival")
        automations.write_document(
            "arrival",
            expected_revision=original.revision,
            payload={"target": TARGET_ENTITY},
        )
        restarted = make_coordinator(
            [automations, scripts],
            journal,
        )

        restarted.recover_incomplete(plan.plan_id)

        self.assertFalse(restarted.blocked)
        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )
        self.assertEqual(
            journal.state(plan.plan_id)[0],
            migration.MigrationState.FAILED,
        )

    def test_completion_journal_failure_is_recoverable_after_restart(self) -> None:
        automations, scripts = providers()
        journal = CompletionFailJournal()
        coordinator = make_coordinator(
            [automations, scripts],
            journal,
        )
        plan = create_plan(coordinator)

        with self.assertRaises(migration.MigrationRestoreFailed):
            coordinator.apply(plan_id=plan.plan_id, digest=plan.digest)
        self.assertTrue(coordinator.blocked)
        coordinator.recover_incomplete(plan.plan_id)

        self.assertEqual(
            automations.get_document("arrival").payload,
            {"target": OLD_ENTITY},
        )
        self.assertEqual(
            coordinator.state(plan.plan_id),
            migration.MigrationState.FAILED,
        )


if __name__ == "__main__":
    unittest.main()
