"""Pure tests for strict initial True Family room bootstrap evidence."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"


def load_bootstrap():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(PACKAGE_ROOT)]
    sys.modules[PACKAGE_NAME] = package
    return importlib.import_module(f"{PACKAGE_NAME}.bootstrap")


bootstrap = load_bootstrap()


def valid_fixture():
    assignments = []
    entities = {}
    devices = {}
    states = {}
    for index, room_id in enumerate(bootstrap.CANONICAL_ROOM_IDS, start=1):
        entity_id = f"climate.{room_id}_radiator"
        ieee_address = f"0xa4c138{index:010x}"
        device_id = f"device-{index}"
        assignments.append(bootstrap.RoomEntityMapping(room_id, entity_id))
        entities[entity_id] = bootstrap.RegistryEntityData(
            registry_entry_id=f"registry-{index}",
            entity_id=entity_id,
            domain="climate",
            platform="mqtt",
            unique_id=f"{ieee_address}_climate_zigbee2mqtt",
            device_id=device_id,
        )
        devices[device_id] = bootstrap.DeviceRegistryData(
            device_id=device_id,
            identifiers=frozenset({("mqtt", f"zigbee2mqtt_{ieee_address}")}),
            model="BRT-100-TRV",
            manufacturer="Moes",
            name=f"{room_id.replace('_', ' ').title()} Radiator",
        )
        states[entity_id] = bootstrap.ClimateStateData(
            entity_id=entity_id,
            state="heat",
            attributes={
                "hvac_modes": ["off", "heat"],
                "supported_features": bootstrap.TARGET_TEMPERATURE_FEATURE,
                "min_temp": 5.0,
                "max_temp": 35.0,
                "target_temp_step": 0.5,
            },
        )
    return assignments, bootstrap.BootstrapAdapterData(entities, devices, states)


def replace_entity(adapter, entity_id, **changes):
    entities = dict(adapter.entity_registry)
    entities[entity_id] = replace(entities[entity_id], **changes)
    return replace(adapter, entity_registry=entities)


def replace_device(adapter, device_id, **changes):
    devices = dict(adapter.device_registry)
    devices[device_id] = replace(devices[device_id], **changes)
    return replace(adapter, device_registry=devices)


def replace_state(adapter, entity_id, *, state=None, attributes=None):
    states = dict(adapter.states)
    changes = {}
    if state is not None:
        changes["state"] = state
    if attributes is not None:
        changes["attributes"] = attributes
    states[entity_id] = replace(states[entity_id], **changes)
    return replace(adapter, states=states)


class BootstrapTests(unittest.TestCase):
    def test_success_round_trip_digest_and_masked_output(self) -> None:
        assignments, adapter = valid_fixture()
        record = bootstrap.resolve_bootstrap(
            {item.room_id: item.legacy_entity_id for item in reversed(assignments)},
            adapter,
        )
        repeated = bootstrap.resolve_bootstrap(reversed(assignments), adapter)

        self.assertEqual(record.state, "mapped")
        self.assertEqual(
            tuple(item.room_id for item in record.rooms),
            bootstrap.CANONICAL_ROOM_IDS,
        )
        self.assertEqual(record, repeated)
        self.assertEqual(record.canonical_json(), repeated.canonical_json())
        self.assertEqual(
            record.evidence_digest,
            hashlib.sha256(record.canonical_evidence_json().encode()).hexdigest(),
        )
        self.assertEqual(
            record.canonical_json(),
            json.dumps(
                record.as_dict(),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        self.assertEqual(bootstrap.BootstrapRecord.from_dict(record.as_dict()), record)

        public_text = json.dumps(record.public_data(), sort_keys=True)
        self.assertEqual(record.public_data()["rooms"][0]["identity"], "...0001")
        for evidence in record.rooms:
            for private_value in (
                evidence.legacy_entity_id,
                evidence.registry_entry_id,
                evidence.mqtt_unique_id,
                evidence.device_id,
                evidence.device_identifier,
                evidence.ieee_address,
            ):
                self.assertNotIn(private_value, public_text)
        with self.assertRaises(FrozenInstanceError):
            record.rooms[0].room_id = "other"

    def test_unavailable_state_is_accepted_without_capability_attributes(self) -> None:
        assignments, adapter = valid_fixture()
        entity_id = assignments[0].legacy_entity_id
        adapter = replace_state(
            adapter,
            entity_id,
            state="unavailable",
            attributes={},
        )

        record = bootstrap.resolve_bootstrap(assignments, adapter)

        self.assertEqual(record.state, "mapped")
        self.assertEqual(len(record.rooms), 7)

    def test_resolver_rejects_missing_extra_and_duplicate_rooms(self) -> None:
        assignments, adapter = valid_fixture()
        invalid_assignments = {
            "missing": assignments[:-1],
            "extra": [
                *assignments,
                bootstrap.RoomEntityMapping("garage", "climate.garage_radiator"),
            ],
            "duplicate": [*assignments, assignments[0]],
        }

        for label, supplied in invalid_assignments.items():
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_bootstrap(supplied, adapter)

    def test_stored_record_rejects_missing_extra_and_duplicate_rooms(self) -> None:
        assignments, adapter = valid_fixture()
        serialized = bootstrap.resolve_bootstrap(assignments, adapter).as_dict()
        invalid_records = {}

        missing = deepcopy(serialized)
        missing["rooms"].pop()
        invalid_records["missing"] = missing

        extra = deepcopy(serialized)
        extra["rooms"].append(
            {
                **extra["rooms"][0],
                "room_id": "garage",
                "legacy_entity_id": "climate.garage_radiator",
            }
        )
        invalid_records["extra"] = extra

        duplicate = deepcopy(serialized)
        duplicate["rooms"].append(deepcopy(duplicate["rooms"][0]))
        invalid_records["duplicate"] = duplicate

        for label, supplied in invalid_records.items():
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.BootstrapRecord.from_dict(supplied)

    def test_sources_must_be_physical_enabled_mqtt_climates(self) -> None:
        assignments, adapter = valid_fixture()
        entity_id = assignments[0].legacy_entity_id

        for label, changes in (
            ("non_mqtt", {"platform": "zha"}),
            ("disabled", {"disabled_by": "user"}),
            ("wrong_domain", {"domain": "sensor"}),
        ):
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_bootstrap(
                    assignments,
                    replace_entity(adapter, entity_id, **changes),
                )

        recursive_id = "climate.true_family_living_room"
        recursive_assignments = list(assignments)
        recursive_assignments[0] = replace(
            recursive_assignments[0], legacy_entity_id=recursive_id
        )
        recursive_entities = dict(adapter.entity_registry)
        recursive_entities[recursive_id] = replace(
            recursive_entities.pop(entity_id), entity_id=recursive_id
        )
        recursive_states = dict(adapter.states)
        recursive_states[recursive_id] = replace(
            recursive_states.pop(entity_id), entity_id=recursive_id
        )
        recursive_adapter = replace(
            adapter,
            entity_registry=recursive_entities,
            states=recursive_states,
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(recursive_assignments, recursive_adapter)

    def test_source_model_and_manufacturer_must_be_approved(self) -> None:
        assignments, adapter = valid_fixture()
        entity = adapter.entity_registry[assignments[0].legacy_entity_id]

        for label, changes in (
            ("model", {"model": "UNAPPROVED-TRV"}),
            ("manufacturer", {"manufacturer": "Other"}),
        ):
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_bootstrap(
                    assignments,
                    replace_device(adapter, entity.device_id, **changes),
                )

    def test_exact_entity_lookup_never_guesses_a_name(self) -> None:
        assignments, adapter = valid_fixture()
        assignments[0] = replace(
            assignments[0], legacy_entity_id="climate.living_room"
        )

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(assignments, adapter)

    def test_malformed_unique_and_device_identities_are_rejected(self) -> None:
        assignments, adapter = valid_fixture()
        entity_id = assignments[0].legacy_entity_id
        entity = adapter.entity_registry[entity_id]
        device = adapter.device_registry[entity.device_id]

        for label, unique_id in (
            ("short_ieee", "0x1234_climate_zigbee2mqtt"),
            ("uppercase_ieee", entity.unique_id.upper()),
            ("wrong_suffix", entity.unique_id.replace("_zigbee2mqtt", "_other")),
        ):
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_bootstrap(
                    assignments,
                    replace_entity(adapter, entity_id, unique_id=unique_id),
                )

        malformed_identifiers = (
            frozenset({("mqtt", "zigbee2mqtt_0xa4c138ffffffffff")}),
            (
                next(iter(device.identifiers)),
                ("mqtt", "zigbee2mqtt_0xa4c138ffffffffff"),
            ),
            frozenset({("zha", "0xa4c1380000000001")}),
        )
        for identifiers in malformed_identifiers:
            with self.subTest(identifiers=identifiers), self.assertRaises(
                bootstrap.BootstrapError
            ):
                bootstrap.resolve_bootstrap(
                    assignments,
                    replace_device(adapter, entity.device_id, identifiers=identifiers),
                )

    def test_available_state_capability_failures_are_rejected(self) -> None:
        assignments, adapter = valid_fixture()
        entity_id = assignments[0].legacy_entity_id
        valid_attributes = dict(adapter.states[entity_id].attributes)
        invalid_attributes = {
            "no_heat": {**valid_attributes, "hvac_modes": ["off"]},
            "no_target_feature": {**valid_attributes, "supported_features": 0},
            "non_finite_min": {**valid_attributes, "min_temp": float("nan")},
            "non_finite_max": {**valid_attributes, "max_temp": float("inf")},
            "reversed_range": {
                **valid_attributes,
                "min_temp": 35.0,
                "max_temp": 5.0,
            },
            "zero_step": {**valid_attributes, "target_temp_step": 0.0},
            "negative_step": {**valid_attributes, "target_temp_step": -0.5},
        }

        for label, attributes in invalid_attributes.items():
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_bootstrap(
                    assignments,
                    replace_state(adapter, entity_id, attributes=attributes),
                )

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(
                assignments,
                replace_state(adapter, entity_id, state="unknown"),
            )

    def test_physical_identities_must_be_unique_across_rooms(self) -> None:
        assignments, adapter = valid_fixture()
        first_entity_id = assignments[0].legacy_entity_id
        second_entity_id = assignments[1].legacy_entity_id
        first_entity = adapter.entity_registry[first_entity_id]
        second_entity = adapter.entity_registry[second_entity_id]

        duplicate_entities = list(assignments)
        duplicate_entities[1] = replace(
            duplicate_entities[1], legacy_entity_id=first_entity_id
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(duplicate_entities, adapter)

        duplicate_registry = replace_entity(
            adapter,
            second_entity_id,
            registry_entry_id=first_entity.registry_entry_id,
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(assignments, duplicate_registry)

        first_ieee = first_entity.unique_id.removesuffix("_climate_zigbee2mqtt")
        duplicate_device_entities = dict(adapter.entity_registry)
        duplicate_device_entities[second_entity_id] = replace(
            second_entity,
            unique_id=first_entity.unique_id,
            device_id=first_entity.device_id,
        )
        duplicate_device = replace(
            adapter, entity_registry=duplicate_device_entities
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(assignments, duplicate_device)

        second_device = adapter.device_registry[second_entity.device_id]
        duplicate_ieee = replace_entity(
            adapter,
            second_entity_id,
            unique_id=first_entity.unique_id,
        )
        duplicate_ieee = replace_device(
            duplicate_ieee,
            second_device.device_id,
            identifiers=frozenset({("mqtt", f"zigbee2mqtt_{first_ieee}")}),
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.resolve_bootstrap(assignments, duplicate_ieee)

    def test_malformed_stored_records_are_rejected(self) -> None:
        assignments, adapter = valid_fixture()
        serialized = bootstrap.resolve_bootstrap(assignments, adapter).as_dict()

        missing_field = deepcopy(serialized)
        missing_field["rooms"][0].pop("device_id")
        extra_field = deepcopy(serialized)
        extra_field["unexpected"] = True
        wrong_type = deepcopy(serialized)
        wrong_type["rooms"][0]["registry_entry_id"] = 42
        wrong_state = deepcopy(serialized)
        wrong_state["state"] = "pending"
        malformed_identity = deepcopy(serialized)
        malformed_identity["rooms"][0]["mqtt_unique_id"] = "not-an-mqtt-id"
        malformed_digest = deepcopy(serialized)
        malformed_digest["evidence_digest"] = "not-a-digest"

        for supplied in (
            missing_field,
            extra_field,
            wrong_type,
            wrong_state,
            malformed_identity,
            malformed_digest,
        ):
            with self.subTest(record=supplied), self.assertRaises(
                bootstrap.BootstrapError
            ):
                bootstrap.BootstrapRecord.from_dict(supplied)

    def test_evidence_tampering_is_detected(self) -> None:
        assignments, adapter = valid_fixture()
        serialized = bootstrap.resolve_bootstrap(assignments, adapter).as_dict()

        tampered_evidence = deepcopy(serialized)
        tampered_evidence["rooms"][0]["registry_entry_id"] += "-tampered"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.BootstrapRecord.from_dict(tampered_evidence)

        tampered_digest = deepcopy(serialized)
        replacement = "0" if tampered_digest["evidence_digest"][0] != "0" else "1"
        tampered_digest["evidence_digest"] = (
            replacement + tampered_digest["evidence_digest"][1:]
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.BootstrapRecord.from_dict(tampered_digest)


if __name__ == "__main__":
    unittest.main()
