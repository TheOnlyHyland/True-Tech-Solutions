"""Disposable Home Assistant tests for read-only provider inventory."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from homeassistant.components.lovelace.const import LOVELACE_DATA
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.true_family import reference_providers_ha as providers


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
