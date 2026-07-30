"""Behavior tests for the isolated replacement state machine."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from backend.models import DeviceBinding, ReplacementPhase, RoomSlot
from backend.replacement import ReplacementEngine, ReplacementError, StaleRevisionError
from backend.z2m_protocol import parse_bridge_event


OLD_BINDING = DeviceBinding(
    registry_entry_id="old-registry-entry",
    climate_entity_id="climate.guest_room_radiator",
    ieee_address="0xold000000000001",
    model="BRT-100-TRV",
    manufacturer="Moes",
    z2m_friendly_name="Guest Room Radiator",
)


def room() -> RoomSlot:
    return RoomSlot(
        room_id="guest_room",
        display_name="Guest Room",
        allowed_models=("BRT-100-TRV",),
        binding=OLD_BINDING,
    )


def joined(ieee: str = "0xnew000000000001"):
    return parse_bridge_event(
        {
            "type": "device_joined",
            "data": {"ieee_address": ieee, "friendly_name": ieee},
        }
    )


def interviewed(
    ieee: str = "0xnew000000000001",
    model: str = "BRT-100-TRV",
    supported: bool = True,
):
    return parse_bridge_event(
        {
            "type": "device_interview",
            "data": {
                "ieee_address": ieee,
                "friendly_name": ieee,
                "status": "successful",
                "supported": supported,
                "definition": {"model": model, "vendor": "Moes"},
            },
        }
    )


class ReplacementEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
        self.room = room()
        self.engine = ReplacementEngine([self.room])

    def start_and_verify(self):
        session, intents = self.engine.start("guest_room", self.now)
        self.assertEqual(intents[0].payload["time"], 60)
        self.engine.handle_bridge_event(joined(), self.now + timedelta(seconds=2))
        close_intents = self.engine.handle_bridge_event(
            interviewed(), self.now + timedelta(seconds=8)
        )
        self.assertEqual(close_intents[0].payload["time"], 0)
        self.assertEqual(session.phase, ReplacementPhase.READY_TO_COMMIT)
        return session

    def test_successful_replacement_requires_readback(self) -> None:
        session = self.start_and_verify()
        self.engine.commit(session.session_id, "new-registry-entry", "climate.new_trv")

        self.assertEqual(session.phase, ReplacementPhase.TESTING)
        self.assertEqual(self.room.binding.climate_entity_id, "climate.new_trv")
        self.assertTrue(
            self.engine.confirm_readback(
                session.session_id,
                "climate.new_trv",
                expected_temperature=12,
                reported_temperature=12,
            )
        )
        self.assertEqual(session.phase, ReplacementPhase.COMPLETE)
        self.assertEqual(self.room.revision, 1)

    def test_wrong_model_fails_and_closes_joining(self) -> None:
        session, _ = self.engine.start("guest_room", self.now)
        self.engine.handle_bridge_event(joined(), self.now + timedelta(seconds=2))
        intents = self.engine.handle_bridge_event(
            interviewed(model="UNAPPROVED-SWITCH"),
            self.now + timedelta(seconds=5),
        )

        self.assertEqual(session.phase, ReplacementPhase.FAILED)
        self.assertIsNotNone(session.failure_reason)
        self.assertIn("not approved", session.failure_reason or "")
        self.assertEqual(intents[0].payload["time"], 0)
        self.assertEqual(self.room.binding, OLD_BINDING)

    def test_multiple_joined_devices_fail_closed(self) -> None:
        session, _ = self.engine.start("guest_room", self.now)
        self.engine.handle_bridge_event(joined(), self.now + timedelta(seconds=2))
        intents = self.engine.handle_bridge_event(
            joined("0xnew000000000002"),
            self.now + timedelta(seconds=3),
        )

        self.assertEqual(session.phase, ReplacementPhase.FAILED)
        self.assertIsNotNone(session.failure_reason)
        self.assertIn("More than one", session.failure_reason or "")
        self.assertEqual(intents[0].payload["time"], 0)

    def test_pairing_timeout_fails_closed(self) -> None:
        session, _ = self.engine.start("guest_room", self.now)
        intents = self.engine.tick(self.now + timedelta(seconds=61))

        self.assertEqual(session.phase, ReplacementPhase.FAILED)
        self.assertIsNotNone(session.failure_reason)
        self.assertIn("expired", session.failure_reason or "")
        self.assertEqual(intents[0].payload["time"], 0)

    def test_stale_room_revision_rejects_commit(self) -> None:
        session = self.start_and_verify()
        self.room.revision += 1

        with self.assertRaises(StaleRevisionError):
            self.engine.commit(
                session.session_id,
                "new-registry-entry",
                "climate.new_trv",
            )

        self.assertEqual(session.phase, ReplacementPhase.FAILED)
        self.assertEqual(self.room.binding, OLD_BINDING)

    def test_failed_readback_rolls_back_binding(self) -> None:
        session = self.start_and_verify()
        self.engine.commit(session.session_id, "new-registry-entry", "climate.new_trv")

        self.assertFalse(
            self.engine.confirm_readback(
                session.session_id,
                "climate.new_trv",
                expected_temperature=12,
                reported_temperature=14,
            )
        )
        self.assertEqual(session.phase, ReplacementPhase.ROLLED_BACK)
        self.assertEqual(self.room.binding, OLD_BINDING)
        self.assertEqual(self.room.revision, 2)

    def test_explicit_rollback_restores_completed_binding(self) -> None:
        session = self.start_and_verify()
        self.engine.commit(session.session_id, "new-registry-entry", "climate.new_trv")
        self.engine.confirm_readback(
            session.session_id,
            "climate.new_trv",
            expected_temperature=12,
            reported_temperature=12,
        )

        self.engine.rollback(session.session_id, "Customer requested rollback.")
        self.assertEqual(session.phase, ReplacementPhase.ROLLED_BACK)
        self.assertEqual(self.room.binding, OLD_BINDING)
        self.assertEqual(self.room.revision, 2)

    def test_second_session_is_rejected_while_pairing_is_active(self) -> None:
        self.engine.start("guest_room", self.now)
        with self.assertRaises(ReplacementError):
            self.engine.start("guest_room", self.now + timedelta(seconds=1))


if __name__ == "__main__":
    unittest.main()
