"""Admin-only WebSocket API for the replacement wizard."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
import voluptuous as vol

from .const import (
    DATA_SETUP_MANAGER,
    SIGNAL_SESSION_UPDATED,
    WS_BOOTSTRAP_COMMIT,
    WS_BOOTSTRAP_PLAN,
    WS_CANCEL,
    WS_COMMIT,
    WS_ROLLBACK,
    WS_ROOMS,
    WS_MIGRATION_COMMIT,
    WS_MIGRATION_PLAN,
    WS_MIGRATION_RECOVER,
    WS_SETUP_STATUS,
    WS_START,
    WS_SUBSCRIBE,
)
from .replacement import ReplacementError, TrueFamilyRuntime
from .setup_manager import SetupManager, SetupManagerError

_LOGGER = logging.getLogger(__name__)


@callback
def async_register_websocket_commands(hass: HomeAssistant) -> None:
    """Register the guarded replacement API once."""

    websocket_api.async_register_command(hass, ws_rooms)
    websocket_api.async_register_command(hass, ws_start)
    websocket_api.async_register_command(hass, ws_commit)
    websocket_api.async_register_command(hass, ws_cancel)
    websocket_api.async_register_command(hass, ws_rollback)
    websocket_api.async_register_command(hass, ws_subscribe)
    websocket_api.async_register_command(hass, ws_setup_status)
    websocket_api.async_register_command(hass, ws_bootstrap_plan)
    websocket_api.async_register_command(hass, ws_bootstrap_commit)
    websocket_api.async_register_command(hass, ws_migration_plan)
    websocket_api.async_register_command(hass, ws_migration_commit)
    websocket_api.async_register_command(hass, ws_migration_recover)


def _runtime(hass: HomeAssistant) -> TrueFamilyRuntime:
    from . import get_runtime

    return get_runtime(hass)


def _setup(hass: HomeAssistant) -> SetupManager:
    manager = hass.data.get(DATA_SETUP_MANAGER)
    if not isinstance(manager, SetupManager):
        raise SetupManagerError("entry_not_singleton")
    return manager


def _send_error(
    connection: websocket_api.ActiveConnection,
    message_id: int,
    err: Exception,
) -> None:
    _LOGGER.warning("True Family replacement request rejected: %s", err)
    connection.send_error(
        message_id,
        "replacement_rejected",
        "The replacement request was rejected.",
    )


def _nonnegative_integer(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise vol.Invalid("Expected a non-negative integer")
    return value


def _send_setup_error(
    connection: websocket_api.ActiveConnection,
    message_id: int,
    err: SetupManagerError,
) -> None:
    connection.send_error(message_id, err.code, err.message)


def _send_setup_internal_error(
    connection: websocket_api.ActiveConnection,
    message_id: int,
) -> None:
    connection.send_error(
        message_id,
        "true_family_internal_error",
        "True Family setup could not complete the request.",
    )


@websocket_api.websocket_command({vol.Required("type"): WS_ROOMS})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_rooms(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """List permanent room slots and binding health."""

    try:
        rooms = _runtime(hass).rooms_public_data()
    except ReplacementError as err:
        _send_error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], {"rooms": rooms})


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_START,
        vol.Required("room_id"): str,
        vol.Required("operation"): vol.In(["replace", "repair"]),
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_start(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Start one bounded Zigbee pairing session."""

    try:
        data = await _runtime(hass).async_start_pairing(
            msg["room_id"],
            msg["operation"],
        )
    except ReplacementError as err:
        _send_error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], data)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_COMMIT,
        vol.Required("session_id"): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_commit(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Commit, test, and verify the candidate binding."""

    try:
        data = await _runtime(hass).async_commit(
            msg["session_id"],
            connection.context(msg),
        )
    except ReplacementError as err:
        _send_error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], data)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_CANCEL,
        vol.Required("session_id"): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_cancel(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Cancel before commit and close joining."""

    try:
        data = await _runtime(hass).async_cancel(msg["session_id"])
    except ReplacementError as err:
        _send_error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], data)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_ROLLBACK,
        vol.Required("room_id"): str,
        vol.Required("expected_revision"): _nonnegative_integer,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_rollback(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Explicitly restore the transaction's previous binding."""

    try:
        data = await _runtime(hass).async_rollback_room(
            msg["room_id"],
            msg["expected_revision"],
            connection.context(msg),
        )
    except ReplacementError as err:
        _send_error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], data)


@websocket_api.websocket_command({vol.Required("type"): WS_SUBSCRIBE})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_subscribe(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Stream sanitized replacement state to one frontend connection."""

    @callback
    def forward(data: dict) -> None:
        connection.send_message(websocket_api.event_message(msg["id"], data))

    try:
        _runtime(hass)
    except ReplacementError as err:
        _send_error(connection, msg["id"], err)
        return
    unsubscribe = async_dispatcher_connect(hass, SIGNAL_SESSION_UPDATED, forward)
    connection.subscriptions[msg["id"]] = unsubscribe
    connection.send_result(msg["id"])


@websocket_api.websocket_command({vol.Required("type"): WS_SETUP_STATUS})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_setup_status(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return sanitized bootstrap and migration readiness."""

    try:
        result = await _setup(hass).async_status()
    except SetupManagerError as err:
        _send_setup_error(connection, msg["id"], err)
        return
    except Exception:
        _LOGGER.exception("Unexpected True Family setup status failure")
        _send_setup_internal_error(connection, msg["id"])
        return
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_BOOTSTRAP_PLAN,
        vol.Required("assignments"): {str: str},
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_bootstrap_plan(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Create one masked exactly-seven bootstrap plan."""

    try:
        result = await _setup(hass).async_plan_bootstrap(msg["assignments"])
    except SetupManagerError as err:
        _send_setup_error(connection, msg["id"], err)
        return
    except Exception:
        _LOGGER.exception("Unexpected True Family bootstrap planning failure")
        _send_setup_internal_error(connection, msg["id"])
        return
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_BOOTSTRAP_COMMIT,
        vol.Required("token"): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_bootstrap_commit(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Commit only the newest public bootstrap token."""

    try:
        result = await _setup(hass).async_commit_bootstrap(msg["token"])
    except SetupManagerError as err:
        _send_setup_error(connection, msg["id"], err)
        return
    except Exception:
        _LOGGER.exception("Unexpected True Family bootstrap commit failure")
        _send_setup_internal_error(connection, msg["id"])
        return
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_MIGRATION_PLAN,
        vol.Required("room_id"): str,
        vol.Required("expected_revision"): _nonnegative_integer,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_migration_plan(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Plan through the server-owned migration authority only."""

    try:
        result = await _setup(hass).async_plan_migration(
            msg["room_id"],
            msg["expected_revision"],
        )
    except SetupManagerError as err:
        _send_setup_error(connection, msg["id"], err)
        return
    except Exception:
        _LOGGER.exception("Unexpected True Family migration planning failure")
        _send_setup_internal_error(connection, msg["id"])
        return
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_MIGRATION_COMMIT,
        vol.Required("token"): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_migration_commit(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Commit one opaque server-owned migration plan."""

    try:
        result = await _setup(hass).async_commit_migration(
            msg["token"],
            connection.context(msg),
        )
    except SetupManagerError as err:
        _send_setup_error(connection, msg["id"], err)
        return
    except Exception:
        _LOGGER.exception("Unexpected True Family migration commit failure")
        _send_setup_internal_error(connection, msg["id"])
        return
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_MIGRATION_RECOVER,
        vol.Required("token"): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_migration_recover(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Recover a journal plan selected only by its random public token."""

    try:
        result = await _setup(hass).async_recover_migration(
            msg["token"],
            connection.context(msg),
        )
    except SetupManagerError as err:
        _send_setup_error(connection, msg["id"], err)
        return
    except Exception:
        _LOGGER.exception("Unexpected True Family migration recovery failure")
        _send_setup_internal_error(connection, msg["id"])
        return
    connection.send_result(msg["id"], result)
