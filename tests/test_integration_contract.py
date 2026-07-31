"""Static safety contract for the non-installed custom integration."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "true_family"


class IntegrationContractTests(unittest.TestCase):
    def test_manifest_declares_local_mqtt_helper(self) -> None:
        manifest = json.loads((INTEGRATION / "manifest.json").read_text())
        self.assertEqual(manifest["domain"], "true_family")
        self.assertEqual(manifest["integration_type"], "helper")
        self.assertEqual(manifest["iot_class"], "local_push")
        self.assertEqual(manifest["dependencies"], ["mqtt"])
        self.assertTrue(manifest["config_flow"])
        self.assertNotIn("single_config_entry", manifest)

    def test_hacs_and_app_distribution_contract_is_complete(self) -> None:
        manifest = json.loads((INTEGRATION / "manifest.json").read_text())
        hacs = json.loads((ROOT / "hacs.json").read_text())
        self.assertEqual(
            hacs,
            {
                "name": "True Family",
                "homeassistant": "2026.7.4",
                "hide_default_branch": True,
            },
        )
        self.assertEqual(manifest["codeowners"], ["@TheOnlyHyland"])
        self.assertEqual(
            manifest["issue_tracker"],
            "https://github.com/TheOnlyHyland/True-Tech-Solutions/issues",
        )
        self.assertEqual(
            manifest["documentation"],
            "https://github.com/TheOnlyHyland/True-Tech-Solutions#supported-installation",
        )
        app_config = (ROOT / "true_family_journal" / "config.yaml").read_text()
        self.assertIn(f'version: "{manifest["version"]}"', app_config)
        self.assertIn('homeassistant: "2026.7.4"', app_config)
        readme = (ROOT / "README.md").read_text()
        self.assertIn("## Supported Installation", readme)
        self.assertIn("HACS", readme)
        self.assertIn("integration-first", readme.lower())
        self.assertIn("customers or testers with prior written authorization", readme)

        icon = (INTEGRATION / "brand" / "icon.png").read_bytes()
        self.assertEqual(icon[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", icon[16:24]), (256, 256))

        workflow = (
            ROOT / ".github" / "workflows" / "validate-integration.yaml"
        ).read_text()
        self.assertIn("hacs/action@1ebf01c408f29afcb6406bd431bc98fd8cbb15aa", workflow)
        self.assertIn(
            "home-assistant/actions/hassfest@ab22029681aa532bfe7de5774a9972d67bfbd2c0",
            workflow,
        )
        self.assertIn("ignore: license", workflow)
        self.assertIn("pytest -q tests/ha", workflow)

    def test_every_websocket_command_requires_admin(self) -> None:
        source = (INTEGRATION / "websocket.py").read_text()
        self.assertEqual(source.count("@websocket_api.websocket_command"), 12)
        self.assertEqual(source.count("@websocket_api.require_admin"), 12)

    def test_forbidden_internal_and_destructive_paths_are_absent(self) -> None:
        source = "\n".join(
            path.read_text()
            for path in INTEGRATION.rglob("*")
            if path.suffix in {".py", ".json"}
        )
        for forbidden in (
            ".storage",
            "device/remove",
            "force_remove",
            "homeassistant_rename",
            "permit_join(254",
        ):
            self.assertNotIn(forbidden, source)

    def test_mqtt_publish_is_confined_to_the_bridge_adapter(self) -> None:
        publishers = []
        for path in INTEGRATION.glob("*.py"):
            if "mqtt.async_publish" in path.read_text():
                publishers.append(path.name)
        self.assertEqual(publishers, ["mqtt.py"])

    def test_ha_2026_registry_and_websocket_context_apis_are_used(self) -> None:
        replacement = (INTEGRATION / "replacement.py").read_text()
        websocket = (INTEGRATION / "websocket.py").read_text()
        self.assertNotIn("async_get_entry(", replacement)
        self.assertIn(".async_get(binding.registry_entry_id)", replacement)
        self.assertEqual(websocket.count("connection.context(msg)"), 4)

    def test_permit_join_requires_ack_and_fresh_readback_before_persistence(self) -> None:
        mqtt_source = (INTEGRATION / "mqtt.py").read_text()
        replacement = (INTEGRATION / "replacement.py").read_text()
        self.assertIn("bridge/response/permit_join", mqtt_source)
        self.assertIn("await asyncio.wait_for(", mqtt_source)
        self.assertIn("bridge/info", mqtt_source)
        self.assertIn("bridge/state", mqtt_source)
        self.assertIn("async_reconcile_join_closed", mqtt_source)
        self.assertIn("state.generation > request_generation", mqtt_source)
        self.assertIn("and not state.retained", mqtt_source)
        self.assertIn("single-writer broker contract", mqtt_source)
        self.assertIn("_open_provisional_state", mqtt_source)
        self.assertIn("_commit_provisional_open", mqtt_source)
        self.assertIn("state.observed_at >= request_started_at", mqtt_source)
        self.assertNotIn(
            "state.observed_at < self._open_acknowledged_at",
            mqtt_source,
        )
        self.assertNotIn("_shutdown_closure_proven", replacement)
        self.assertIn("has_shutdown_safety_coverage", replacement)
        self.assertIn("state.last_updated > command_started", replacement)
        self.assertLess(
            replacement.index("await self._async_test_binding("),
            replacement.index("room.binding = binding"),
        )

    def test_runtime_tasks_are_owned_by_the_config_entry(self) -> None:
        source = (INTEGRATION / "replacement.py").read_text()
        self.assertIn("self.entry.async_create_task", source)
        self.assertNotIn("self.hass.async_create_task", source)
        self.assertNotIn("asyncio.gather", source)

    def test_startup_completion_guards_pairing_and_shutdown_mode(self) -> None:
        replacement = (INTEGRATION / "replacement.py").read_text()
        setup = (INTEGRATION / "__init__.py").read_text()
        shutdown = replacement[
            replacement.index("    async def async_shutdown(") : replacement.index(
                "    async def _async_cleanup_failed_setup("
            )
        ]
        self.assertIn("self._startup_complete = False", replacement)
        self.assertIn("self._startup_complete = True", replacement)
        self.assertLess(
            replacement.index("await self._async_reconcile_global_join_closed("),
            replacement.index("self._startup_complete = True"),
        )
        self.assertIn("if not self._startup_complete:", shutdown)
        self.assertLess(
            shutdown.index("if not self._startup_complete:"),
            shutdown.index("has_shutdown_safety_coverage"),
        )
        self.assertIn(
            'raise ReplacementError("True Family startup is incomplete.")',
            replacement,
        )
        self.assertLess(
            setup.index("await runtime.async_setup()"),
            setup.index("entry.runtime_data = runtime"),
        )

    def test_join_barrier_has_no_demo_backend_or_background_waiter(self) -> None:
        mqtt_source = (INTEGRATION / "mqtt.py").read_text()
        selected_source = "\n".join(
            (INTEGRATION / filename).read_text()
            for filename in ("mqtt.py", "replacement.py", "__init__.py", "const.py")
        )
        for forbidden in (
            "from backend",
            "import backend",
            "from tests",
            "import helpers",
            "/homeassistant/custom_components",
        ):
            self.assertNotIn(forbidden, selected_source)
        for forbidden in (
            "asyncio.create_task",
            "asyncio.gather",
            "asyncio.sleep",
        ):
            self.assertNotIn(forbidden, mqtt_source)
        self.assertNotIn("_async_retry_close", selected_source)
        self.assertIn("qos=1", mqtt_source)
        self.assertIn("retain=False", mqtt_source)

    def test_ha_mqtt_harness_patch_is_fixture_scoped(self) -> None:
        helpers = (ROOT / "tests" / "ha" / "helpers.py").read_text()
        conftest = (ROOT / "tests" / "ha" / "conftest.py").read_text()
        self.assertNotIn("mqtt_component.async_subscribe =", helpers)
        self.assertNotIn("mqtt_component.async_publish =", helpers)
        self.assertIn("def install_bridge_harness", helpers)
        self.assertIn("monkeypatch.setattr", helpers)
        self.assertIn("def install_scoped_bridge_harness", conftest)
        self.assertIn("install_bridge_harness(monkeypatch)", conftest)

    def test_unconfirmed_join_lease_blocks_new_pairing(self) -> None:
        source = (INTEGRATION / "replacement.py").read_text()
        self.assertIn("self._join_owner_session_id is not None", source)
        self.assertIn("self._timeout_tasks: dict[str, asyncio.Task]", source)
        self.assertIn("self._join_owner_session_id = None", source)

    def test_repair_and_replacement_are_explicit_operations(self) -> None:
        source = (INTEGRATION / "websocket.py").read_text()
        self.assertIn('vol.Required("operation")', source)
        self.assertIn('vol.In(["replace", "repair"])', source)

    def test_config_entry_snapshot_reader_remains_unwired(self) -> None:
        readers = [
            path.name
            for path in INTEGRATION.glob("*.py")
            if "async_read_config_entry_reference_snapshot" in path.read_text()
        ]
        self.assertEqual(readers, ["reference_providers_ha.py"])

    def test_exact_read_only_snapshot_envelope_remains_unwired(self) -> None:
        names = (
            "ReadOnlyProviderSnapshotSource",
            "ConfigEntryReferenceSnapshotSource",
            "ProviderDocumentInventory",
            "ExactReferenceInventorySnapshot",
            "async_read_exact_reference_inventory_snapshot",
        )
        owners = {
            path.name
            for path in INTEGRATION.glob("*.py")
            if any(name in path.read_text() for name in names)
        }
        self.assertEqual(owners, {"reference_providers_ha.py"})

        forbidden_wiring = (
            "__init__.py",
            "setup_manager.py",
            "websocket.py",
            "bootstrap_ha.py",
            "reference_migration.py",
            "reference_migration_ha.py",
        )
        for filename in forbidden_wiring:
            with self.subTest(filename=filename):
                source = (INTEGRATION / filename).read_text()
                for name in names:
                    self.assertNotIn(name, source)


if __name__ == "__main__":
    unittest.main()
