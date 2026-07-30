"""Persistence tests for the phase-two integration models."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"


def load_models():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(PACKAGE_ROOT)]
    sys.modules[PACKAGE_NAME] = package
    return importlib.import_module(f"{PACKAGE_NAME}.models")


models = load_models()


class IntegrationModelTests(unittest.TestCase):
    def test_default_rooms_are_seven_unique_unbound_slots(self) -> None:
        rooms = models.default_rooms()
        self.assertEqual(len(rooms), 7)
        self.assertEqual(len(set(rooms)), 7)
        self.assertTrue(all(room.binding is None for room in rooms.values()))
        self.assertTrue(
            all(room.allowed_models == ("BRT-100-TRV",) for room in rooms.values())
        )
        self.assertTrue(
            all(room.allowed_manufacturers == ("Moes",) for room in rooms.values())
        )

    def test_room_binding_round_trip_preserves_registry_identity(self) -> None:
        rooms = models.default_rooms()
        rooms["guest_room"].binding = models.RoomBinding(
            registry_entry_id="registry-entry",
            climate_entity_id="climate.physical_valve",
            mqtt_unique_id="0xa4c1380000000000_climate_zigbee2mqtt",
            device_identifier="zigbee2mqtt_0xa4c1380000000000",
            ieee_address="0xa4c1380000000000",
            model="BRT-100-TRV",
            manufacturer="Moes",
            z2m_friendly_name="Guest Room Radiator",
        )
        rooms["guest_room"].revision = 4

        restored = models.rooms_from_dict(models.rooms_as_dict(rooms))
        self.assertEqual(restored["guest_room"], rooms["guest_room"])
        self.assertEqual(restored["guest_room"].revision, 4)

    def test_candidate_public_data_masks_ieee_address(self) -> None:
        from datetime import UTC, datetime, timedelta

        now = datetime(2026, 7, 28, tzinfo=UTC)
        session = models.ReplacementSession(
            session_id="session",
            room_id="guest_room",
            expected_revision=0,
            started_at=now,
            pairing_deadline=now + timedelta(seconds=60),
            old_binding=None,
            candidate=models.CandidateDevice(
                ieee_address="0xa4c138669e76493f",
                friendly_name="candidate",
                model="BRT-100-TRV",
                manufacturer="Moes",
                supported=True,
            ),
        )
        public = session.public_data()
        self.assertEqual(public["candidate"]["identity"], "...493F")
        self.assertNotIn("0xa4c138669e76493f", str(public))

    def test_mismatched_storage_key_is_rejected(self) -> None:
        data = models.rooms_as_dict(models.default_rooms())
        data["wrong_key"] = data.pop("guest_room")
        with self.assertRaises(ValueError):
            models.rooms_from_dict(data)

    def test_binding_rejects_recursive_logical_entity(self) -> None:
        with self.assertRaises(ValueError):
            models.RoomBinding(
                registry_entry_id="registry-entry",
                climate_entity_id="climate.true_family_guest_room_valve",
                mqtt_unique_id="0xa4c1380000000000_climate_zigbee2mqtt",
                device_identifier="zigbee2mqtt_0xa4c1380000000000",
                ieee_address="0xa4c1380000000000",
                model="BRT-100-TRV",
                manufacturer="Moes",
                z2m_friendly_name="Recursive",
            )

    def test_binding_rejects_malformed_ieee_address(self) -> None:
        with self.assertRaises(ValueError):
            models.RoomBinding(
                registry_entry_id="registry-entry",
                climate_entity_id="climate.physical_valve",
                mqtt_unique_id="0x1234_climate_zigbee2mqtt",
                device_identifier="zigbee2mqtt_0x1234",
                ieee_address="0x1234",
                model="BRT-100-TRV",
                manufacturer="Moes",
                z2m_friendly_name="Malformed",
            )

    def test_persisted_binding_cannot_be_allocated_to_two_rooms(self) -> None:
        rooms = models.default_rooms()
        binding = models.RoomBinding(
            registry_entry_id="registry-entry",
            climate_entity_id="climate.physical_valve",
            mqtt_unique_id="0xa4c1380000000000_climate_zigbee2mqtt",
            device_identifier="zigbee2mqtt_0xa4c1380000000000",
            ieee_address="0xa4c1380000000000",
            model="BRT-100-TRV",
            manufacturer="Moes",
            z2m_friendly_name="Shared",
        )
        rooms["guest_room"].binding = binding
        rooms["clarks_room"].binding = binding
        with self.assertRaises(ValueError):
            models.rooms_from_dict(models.rooms_as_dict(rooms))

    def test_boolean_room_revision_is_rejected(self) -> None:
        data = models.rooms_as_dict(models.default_rooms())
        data["guest_room"]["revision"] = True

        with self.assertRaises(ValueError):
            models.rooms_from_dict(data)


if __name__ == "__main__":
    unittest.main()
