"""Disposable Home Assistant tests for read-only provider inventory."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
import hashlib
import json
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, patch

from homeassistant.components.lovelace.const import LOVELACE_DATA
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import storage
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.true_family import reference_providers_ha as providers


def config_entry_opaque_key(domain: str, entry_id: str) -> str:
    canonical = json.dumps(
        {
            "purpose": "true-family-config-entry-reference-object-key-v1",
            "provider": "config_entry",
            "domain": domain,
            "entry_id": entry_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return providers._CONFIG_ENTRY_OPAQUE_KEY_PREFIX + hashlib.sha256(
        canonical
    ).hexdigest()


class InertSnapshotSource:
    """Synthetic source with no Home Assistant access or mutation surface."""

    def __init__(
        self,
        expected_objects: providers.ExpectedProviderObjects,
        calls: list[str],
        *,
        error: Exception | None = None,
    ) -> None:
        self.name = expected_objects.provider
        self.expected_objects = expected_objects
        self.calls = calls
        self.error = error
        self.read_count = 0

    async def async_read_snapshot(
        self,
        _hass: HomeAssistant,
    ) -> AsyncIterator[providers.ProviderDocumentSnapshot]:
        self.read_count += 1
        self.calls.append(self.name)
        if self.error is not None:
            raise self.error
        if False:
            yield


def provider_traceback_locals(error: BaseException) -> str:
    rendered = []
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("reference_providers_ha.py"):
            rendered.append(repr(frame.f_locals))
        traceback = traceback.tb_next
    return "\n".join(rendered)


def empty_expected_manifest():
    return providers.ExpectedObjectManifest.from_mapping(
        "ha-inventory-test",
        {provider: () for provider in providers.PROVIDER_NAMES},
    )


async def test_active_yaml_inventory_requires_host_bridge_without_loading(
    hass: HomeAssistant,
) -> None:
    secret = "must-not-survive-the-probe"
    yaml_config = {
        "automation": [
            {"id": "one", "token": secret},
            {"id": "two", "nested": {"password": secret}},
        ],
        "http": {"api_password": secret},
    }
    loader = AsyncMock(return_value=yaml_config)

    with patch("homeassistant.config.async_hass_config_yaml", loader):
        inventory = await providers.async_probe_active_yaml(
            hass,
            domains=("automation",),
        )

    loader.assert_not_awaited()
    assert inventory.status is providers.InventoryStatus.UNAVAILABLE
    assert inventory.count == 0
    assert secret not in repr(inventory)
    assert all(secret not in repr(item) for item in inventory.objects)


async def test_config_entry_inventory_uses_manager_without_retaining_data(
    hass: HomeAssistant,
) -> None:
    secret = "config-entry-secret"
    entry = MockConfigEntry(
        domain="template",
        title="Synthetic Template Helper",
        unique_id="synthetic-template-helper",
        version=1,
        data={"template": secret},
    )
    entry.add_to_hass(hass)

    inventory = await providers.async_probe_config_entries(
        hass,
        domains=("template",),
    )

    assert inventory.status is providers.InventoryStatus.READABLE
    assert inventory.count == 1
    assert secret not in repr(inventory)
    assert secret not in repr(inventory.objects)
    assert entry.data["template"] == secret


async def test_lovelace_inventory_requires_host_bridge_without_loading(
    hass: HomeAssistant,
) -> None:
    secret = "dashboard-secret"

    class LoadedDashboard:
        def __init__(self) -> None:
            self.loads = []

        async def async_load(self, force):
            self.loads.append(force)
            return {
                "views": [
                    {"path": "today", "cards": [{"token": secret}]},
                    {"title": "No route", "cards": [{"password": secret}]},
                ]
            }

    dashboard = LoadedDashboard()
    hass.data[LOVELACE_DATA] = SimpleNamespace(
        dashboards={"true-family": dashboard}
    )

    inventory = await providers.async_probe_lovelace(
        hass,
        dashboards=("true-family",),
    )

    assert dashboard.loads == []
    assert inventory.status is providers.InventoryStatus.UNAVAILABLE
    assert inventory.count == 0
    assert secret not in repr(inventory)
    assert secret not in repr(inventory.objects)


async def test_scheduler_inventory_reads_states_and_never_calls_services(
    hass: HomeAssistant,
) -> None:
    calls = []

    async def service_handler(call) -> None:
        calls.append(call)

    for service in ("add", "edit", "remove"):
        hass.services.async_register("scheduler", service, service_handler)
    attributes = {
        "weekdays": ["mon"],
        "timeslots": ["06:00"],
        "entities": ["climate.synthetic_radiator"],
        "actions": [{"service": "climate.set_temperature"}],
    }
    hass.states.async_set("switch.schedule_synthetic", "off", attributes)
    hass.states.async_set("switch.unrelated", "on", {})

    inventory = await providers.async_probe_scheduler(hass)

    assert inventory.status is providers.InventoryStatus.READABLE
    assert inventory.count == 1
    assert inventory.object_keys == ("switch.schedule_synthetic",)
    assert calls == []


async def test_combined_inventory_is_fixed_order_and_read_only_without_bridges(
    hass: HomeAssistant,
) -> None:
    async def service_handler(_call) -> None:
        raise AssertionError("Inventory must not call Scheduler services")

    for service in ("add", "edit", "remove"):
        hass.services.async_register("scheduler", service, service_handler)
    hass.data[LOVELACE_DATA] = SimpleNamespace(dashboards={})
    expected = empty_expected_manifest()
    scope = providers.HomeAssistantInventoryScope(
        expected_manifest_digest=expected.digest,
        active_yaml_domains=(),
        config_entry_domains=(),
        lovelace_dashboards=(),
        scheduler_entity_ids=(),
    )

    with patch(
        "homeassistant.config.async_hass_config_yaml",
        AsyncMock(return_value={}),
    ):
        inventories = await providers.async_probe_home_assistant_inventory(
            hass,
            expected,
            scope=scope,
            now=datetime(2026, 7, 28, 12, tzinfo=UTC),
        )

    assert tuple(item.provider for item in inventories) == providers.PROVIDER_NAMES
    assert inventories[2].status is providers.InventoryStatus.UNAVAILABLE
    readiness = providers.assess_production_readiness(
        expected,
        inventories,
        (),
        now=datetime(2026, 7, 28, 12, tzinfo=UTC),
    )
    assert readiness.ready is False
    assert [item.provider for item in readiness.providers] == list(
        providers.PROVIDER_NAMES
    )


async def test_exact_snapshot_uses_real_opaque_config_source_without_mutation(
    hass: HomeAssistant,
) -> None:
    raw_generic_id = "ha-raw-generic-entry-canary"
    raw_template_id = "ha-raw-template-entry-canary"
    payload_canary = "{{ states('sensor.ha_private_payload_canary') }}"
    generic = MockConfigEntry(
        domain="generic_thermostat",
        entry_id=raw_generic_id,
        version=1,
        minor_version=3,
        data={},
        options={
            "name": "Read-only generic thermostat",
            "heater": "switch.ha_read_only_heater",
            "target_sensor": "sensor.ha_read_only_temperature",
            "ac_mode": False,
            "cold_tolerance": 0.3,
            "hot_tolerance": 0.3,
        },
    )
    template = MockConfigEntry(
        domain="template",
        entry_id=raw_template_id,
        version=1,
        minor_version=2,
        data={},
        options={
            "name": "Read-only template",
            "template_type": "sensor",
            "state": payload_canary,
            "advanced_options": {
                "availability": "{{ has_value('sensor.ha_read_only_temperature') }}"
            },
        },
    )
    generic.add_to_hass(hass)
    template.add_to_hass(hass)
    policy = tuple(
        sorted(
            (
                providers.ConfigEntryReferenceObjectPolicy(
                    generic.entry_id,
                    "generic_thermostat",
                ),
                providers.ConfigEntryReferenceObjectPolicy(
                    template.entry_id,
                    "template",
                ),
            ),
            key=lambda item: item.entry_id,
        )
    )
    config_source = providers.ConfigEntryReferenceSnapshotSource(policy)
    independent_opaque_keys = tuple(
        sorted(
            (
                config_entry_opaque_key("generic_thermostat", generic.entry_id),
                config_entry_opaque_key("template", template.entry_id),
            )
        )
    )
    expected = providers.ExpectedObjectManifest.from_mapping(
        "ha-exact-reference-inventory-1",
        {
            provider: (
                independent_opaque_keys if provider == "config_entry" else ()
            )
            for provider in providers.PROVIDER_NAMES
        },
    )
    assert config_source.expected_objects == expected.for_provider("config_entry")

    calls = []
    sources = cast(
        tuple[providers.ReadOnlyProviderSnapshotSource, ...],
        tuple(
            config_source
            if item.provider == "config_entry"
            else InertSnapshotSource(item, calls)
            for item in expected.providers
        ),
    )
    dashboard_load = AsyncMock(side_effect=AssertionError("must not load Lovelace"))
    hass.data[LOVELACE_DATA] = SimpleNamespace(
        dashboards={"canary": SimpleNamespace(async_load=dashboard_load)}
    )
    data_before = {key: id(value) for key, value in hass.data.items()}
    original_entries = hass.config_entries.async_entries
    config_read_recorded = False

    def tracked_entries(domain=None):
        nonlocal config_read_recorded
        if domain in {"generic_thermostat", "template"} and not config_read_recorded:
            calls.append("config_entry")
            config_read_recorded = True
        return original_entries(domain)

    service_call = AsyncMock()
    store_save = AsyncMock()
    mqtt_publish = AsyncMock()
    yaml_loader = AsyncMock(side_effect=AssertionError("must not load YAML"))

    with (
        patch.object(hass.config_entries, "async_entries", side_effect=tracked_entries),
        patch.object(hass.config_entries, "async_update_entry") as update_entry,
        patch.object(hass.config_entries, "async_schedule_reload") as schedule_reload,
        patch.object(type(hass.services), "async_call", service_call),
        patch.object(storage.Store, "async_save", store_save),
        patch.object(storage.Store, "async_delay_save") as store_delay_save,
        patch.object(type(hass.bus), "async_fire") as fire_event,
        patch(
            "homeassistant.helpers.dispatcher.async_dispatcher_send"
        ) as dispatcher_send,
        patch("homeassistant.components.mqtt.async_publish", mqtt_publish),
        patch.object(er, "async_get") as entity_registry_get,
        patch.object(dr, "async_get") as device_registry_get,
        patch.object(ar, "async_get") as area_registry_get,
        patch("homeassistant.config.async_hass_config_yaml", yaml_loader),
        patch.object(hass, "async_create_task") as hass_create_task,
        patch.object(
            hass,
            "async_create_background_task",
        ) as hass_create_background_task,
        patch.object(
            asyncio,
            "create_task",
            side_effect=AssertionError("collector must not create tasks"),
        ) as asyncio_create_task,
    ):
        snapshot = await providers.async_read_exact_reference_inventory_snapshot(
            hass,
            expected,
            sources,
        )

    assert calls == list(providers.PROVIDER_NAMES)
    assert tuple(item.provider for item in snapshot.providers) == providers.PROVIDER_NAMES
    assert snapshot.providers[1].object_keys == independent_opaque_keys
    assert all(
        item.writable is False for item in snapshot.providers[1].documents
    )
    assert snapshot.expected_manifest_digest == expected.digest
    assert snapshot.read_only is True
    assert {key: id(value) for key, value in hass.data.items()} == data_before
    assert tuple(item.entry_id for item in policy) == tuple(
        sorted((raw_generic_id, raw_template_id))
    )
    assert all(
        key.startswith(providers._CONFIG_ENTRY_OPAQUE_KEY_PREFIX)
        for key in snapshot.providers[1].object_keys
    )

    rendered = "\n".join(
        (
            repr(policy),
            repr(config_source),
            repr(expected),
            repr(snapshot),
            json.dumps(snapshot.as_public_summary(), sort_keys=True),
        )
    )
    for private in (raw_generic_id, raw_template_id, payload_canary):
        assert private not in rendered

    update_entry.assert_not_called()
    schedule_reload.assert_not_called()
    service_call.assert_not_awaited()
    store_save.assert_not_awaited()
    store_delay_save.assert_not_called()
    fire_event.assert_not_called()
    dispatcher_send.assert_not_called()
    mqtt_publish.assert_not_awaited()
    entity_registry_get.assert_not_called()
    device_registry_get.assert_not_called()
    area_registry_get.assert_not_called()
    yaml_loader.assert_not_awaited()
    dashboard_load.assert_not_awaited()
    hass_create_task.assert_not_called()
    hass_create_background_task.assert_not_called()
    asyncio_create_task.assert_not_called()


async def test_exact_snapshot_returns_no_partial_value_after_real_config_read(
    hass: HomeAssistant,
) -> None:
    raw_entry_id = "ha-partial-result-entry-canary"
    entry = MockConfigEntry(
        domain="template",
        entry_id=raw_entry_id,
        version=1,
        minor_version=2,
        data={},
        options={
            "name": "Read-only template",
            "template_type": "sensor",
            "state": "{{ states('sensor.ha_partial_result_canary') }}",
            "advanced_options": {},
        },
    )
    entry.add_to_hass(hass)
    source = providers.ConfigEntryReferenceSnapshotSource(
        (
            providers.ConfigEntryReferenceObjectPolicy(
                entry.entry_id,
                "template",
            ),
        )
    )
    opaque_key = config_entry_opaque_key("template", entry.entry_id)
    expected = providers.ExpectedObjectManifest.from_mapping(
        "ha-no-partial-reference-inventory-1",
        {
            provider: ((opaque_key,) if provider == "config_entry" else ())
            for provider in providers.PROVIDER_NAMES
        },
    )
    calls = []
    synthetic = {
        item.provider: InertSnapshotSource(
            item,
            calls,
            error=(
                RuntimeError(f"private failure: {raw_entry_id}")
                if item.provider == "external_writers"
                else None
            ),
        )
        for item in expected.providers
        if item.provider != "config_entry"
    }
    sources = cast(
        tuple[providers.ReadOnlyProviderSnapshotSource, ...],
        tuple(
            source if item.provider == "config_entry" else synthetic[item.provider]
            for item in expected.providers
        ),
    )
    original_entries = hass.config_entries.async_entries
    config_read_recorded = False

    def tracked_entries(domain=None):
        nonlocal config_read_recorded
        if domain == "template" and not config_read_recorded:
            calls.append("config_entry")
            config_read_recorded = True
        return original_entries(domain)

    data_before = {key: id(value) for key, value in hass.data.items()}
    result = None
    with patch.object(
        hass.config_entries,
        "async_entries",
        side_effect=tracked_entries,
    ):
        try:
            result = await providers.async_read_exact_reference_inventory_snapshot(
                hass,
                expected,
                sources,
            )
        except providers.ExactReferenceInventorySnapshotError as err:
            failure = err
        else:
            raise AssertionError("Injected source failure must block the snapshot")

    assert result is None
    assert calls == ["active_yaml", "config_entry", "external_writers"]
    assert synthetic["active_yaml"].read_count == 1
    assert synthetic["external_writers"].read_count == 1
    assert synthetic["lovelace"].read_count == 0
    assert synthetic["scheduler"].read_count == 0
    assert failure.__cause__ is None
    assert failure.__context__ is None
    assert raw_entry_id not in str(failure)
    assert raw_entry_id not in repr(failure)
    assert raw_entry_id not in provider_traceback_locals(failure)
    assert {key: id(value) for key, value in hass.data.items()} == data_before
