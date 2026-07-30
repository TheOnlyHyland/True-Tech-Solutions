"""Test admin authorization and sanitized WebSocket results."""

from __future__ import annotations

import json

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.setup import async_setup_component

from custom_components.true_family.bootstrap import CANONICAL_ROOM_IDS
from custom_components.true_family.const import DOMAIN, SIGNAL_SESSION_UPDATED

from helpers import create_physical_climate


async def test_rooms_websocket_is_admin_only_and_sanitized(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    hass_ws_client,
    hass_read_only_access_token,
) -> None:
    """Reject read-only users and return no Zigbee identity to admins."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()

    read_only = await hass_ws_client(hass, hass_read_only_access_token)
    await read_only.send_json_auto_id({"type": "true_family/replacement/rooms"})
    response = await read_only.receive_json()
    assert response["type"] == "result"
    assert response["success"] is False
    assert response["error"]["code"] == "unauthorized"

    admin = await hass_ws_client(hass)
    await admin.send_json_auto_id({"type": "true_family/replacement/rooms"})
    response = await admin.receive_json()
    assert response["success"] is True
    assert len(response["result"]["rooms"]) == 7
    assert "ieee" not in json.dumps(response["result"]).lower()
    assert "source_entity_id" not in json.dumps(response["result"])


async def test_every_replacement_websocket_command_rejects_read_only_users(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    hass_ws_client,
    hass_read_only_access_token,
) -> None:
    """Exercise authorization on every registered replacement command."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    client = await hass_ws_client(hass, hass_read_only_access_token)
    messages = (
        {
            "type": "true_family/replacement/start",
            "room_id": "guest_room",
            "operation": "replace",
        },
        {
            "type": "true_family/replacement/commit",
            "session_id": "synthetic",
        },
        {
            "type": "true_family/replacement/cancel",
            "session_id": "synthetic",
        },
        {
            "type": "true_family/replacement/rollback",
            "room_id": "guest_room",
            "expected_revision": 0,
        },
        {"type": "true_family/replacement/subscribe"},
    )
    for message in messages:
        await client.send_json_auto_id(message)
        response = await client.receive_json()
        assert response["success"] is False
        assert response["error"]["code"] == "unauthorized"


async def test_session_subscription_survives_integration_reload(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    hass_ws_client,
) -> None:
    """Keep the browser's internal event subscription across runtime reload."""

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "true_family/replacement/subscribe"})
    response = await client.receive_json()
    assert response["success"] is True

    async_dispatcher_send(hass, SIGNAL_SESSION_UPDATED, {"phase": "before_reload"})
    event = await client.receive_json()
    assert event["event"]["phase"] == "before_reload"

    assert await hass.config_entries.async_reload(true_family_entry.entry_id)
    await hass.async_block_till_done()
    async_dispatcher_send(hass, SIGNAL_SESSION_UPDATED, {"phase": "after_reload"})
    event = await client.receive_json()
    assert event["event"]["phase"] == "after_reload"


async def test_every_setup_websocket_command_rejects_read_only_users(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    hass_ws_client,
    hass_read_only_access_token,
) -> None:
    """Require administrator access on all offline setup commands."""

    assert await async_setup_component(hass, DOMAIN, {})
    client = await hass_ws_client(hass, hass_read_only_access_token)
    assignments = {
        room_id: f"climate.private_{room_id}_canary"
        for room_id in CANONICAL_ROOM_IDS
    }
    messages = (
        {"type": "true_family/setup/status"},
        {
            "type": "true_family/bootstrap/plan",
            "assignments": assignments,
        },
        {"type": "true_family/bootstrap/commit", "token": "private-token"},
        {
            "type": "true_family/migration/plan",
            "room_id": "guest_room",
            "expected_revision": 0,
        },
        {"type": "true_family/migration/commit", "token": "private-token"},
        {"type": "true_family/migration/recover", "token": "private-token"},
    )

    for message in messages:
        await client.send_json_auto_id(message)
        response = await client.receive_json()
        assert response["success"] is False
        assert response["error"]["code"] == "unauthorized"


async def test_admin_setup_websocket_bootstraps_and_migration_stays_blocked(
    hass: HomeAssistant,
    mqtt_mock,
    true_family_entry,
    hass_ws_client,
) -> None:
    """Expose safe setup while retaining the provider-bridge migration gate."""

    assert await async_setup_component(hass, DOMAIN, {})
    if true_family_entry.state is ConfigEntryState.LOADED:
        assert await hass.config_entries.async_unload(true_family_entry.entry_id)
    mqtt_entry = hass.config_entries.async_entries("mqtt")[0]
    assignments = {}
    for index, room_id in enumerate(CANONICAL_ROOM_IDS, start=1):
        binding = create_physical_climate(
            hass,
            mqtt_entry=mqtt_entry,
            ieee_address=f"0xa4c138{index:010x}",
            object_id=f"websocket_{room_id}_radiator",
        )
        assignments[room_id] = binding.climate_entity_id
    admin = await hass_ws_client(hass)

    await admin.send_json_auto_id({"type": "true_family/setup/status"})
    status = await admin.receive_json()
    assert status["success"] is True
    assert status["result"]["entry_state"] == "not_loaded"
    assert status["result"]["migration"]["ready"] is False

    await admin.send_json_auto_id(
        {
            "type": "true_family/bootstrap/plan",
            "assignments": assignments,
        }
    )
    planned = await admin.receive_json()
    assert planned["success"] is True
    rendered = json.dumps(planned["result"], sort_keys=True)
    assert not any(entity_id in rendered for entity_id in assignments.values())
    assert "0xa4c138" not in rendered
    token = planned["result"]["token"]

    await admin.send_json_auto_id(
        {"type": "true_family/bootstrap/commit", "token": token}
    )
    committed = await admin.receive_json()
    assert committed["success"] is True
    assert committed["result"]["state"] == "complete"
    assert true_family_entry.state is ConfigEntryState.NOT_LOADED

    await admin.send_json_auto_id(
        {
            "type": "true_family/migration/plan",
            "room_id": "guest_room",
            "expected_revision": 0,
        }
    )
    unloaded = await admin.receive_json()
    assert unloaded["success"] is False
    assert unloaded["error"]["code"] == "migration_requires_load"

    assert await hass.config_entries.async_setup(true_family_entry.entry_id)
    await hass.async_block_till_done()
    await admin.send_json_auto_id(
        {
            "type": "true_family/migration/plan",
            "room_id": "guest_room",
            "expected_revision": 0,
        }
    )
    blocked = await admin.receive_json()
    assert blocked["success"] is False
    assert blocked["error"] == {
        "code": "migration_executor_missing",
        "message": "Reference migration is not configured.",
    }
