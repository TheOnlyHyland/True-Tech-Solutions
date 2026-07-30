"""Strict Supervisor discovery for the True Family journal App."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.core import callback
from homeassistant.helpers.service_info.hassio import HassioServiceInfo

from .const import DOMAIN
from .reference_journal_remote import (
    PROTOCOL_ID,
    REMOTE_JOURNAL_PORT,
    RemoteJournalEndpoint,
)


DATA_REFERENCE_JOURNAL_ENDPOINT: Final = f"{DOMAIN}_reference_journal_endpoint"
DATA_REFERENCE_JOURNAL_RELOAD_PENDING: Final = (
    f"{DOMAIN}_reference_journal_reload_pending"
)

_CONFIG_KEYS: Final = frozenset({"boot_id", "host", "key", "port", "protocol"})
_CORE_ADDON_NAME_KEY: Final = "addon"


class ReferenceJournalDiscoveryError(ValueError):
    """Raised when Supervisor journal discovery is not exact and canonical."""


@dataclass(frozen=True, slots=True)
class _PendingReferenceJournalReload:
    entry_id: str
    journal: object | None


def endpoint_from_hassio_service_info(
    discovery_info: HassioServiceInfo,
) -> RemoteJournalEndpoint:
    """Validate one App discovery envelope without trusting its host value."""

    if not isinstance(discovery_info, HassioServiceInfo):
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has an invalid envelope."
        )
    if type(discovery_info.config) is not dict:
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has an invalid config mapping."
        )

    config = dict(discovery_info.config)
    # Core adds this display-only field after receiving the App's exact config.
    if _CORE_ADDON_NAME_KEY in config:
        addon_name = config.pop(_CORE_ADDON_NAME_KEY)
        if type(addon_name) is not str or addon_name != discovery_info.name:
            raise ReferenceJournalDiscoveryError(
                "Supervisor journal discovery has invalid App metadata."
            )
    if set(config) != _CONFIG_KEYS or any(type(key) is not str for key in config):
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has unexpected config keys."
        )
    if type(config["host"]) is not str:
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has an invalid host."
        )
    if type(config["port"]) is not int or config["port"] != REMOTE_JOURNAL_PORT:
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has an invalid port."
        )
    if type(config["protocol"]) is not str or config["protocol"] != PROTOCOL_ID:
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has an invalid protocol."
        )

    try:
        endpoint = RemoteJournalEndpoint(
            full_slug=discovery_info.slug,
            boot_id=config["boot_id"],
            hmac_key=config["key"],
        )
    except (TypeError, ValueError) as err:
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery has invalid endpoint identity."
        ) from err
    if config["host"] != endpoint.hostname:
        raise ReferenceJournalDiscoveryError(
            "Supervisor journal discovery host does not match its full App slug."
        )
    return endpoint


def cache_reference_journal_endpoint(
    hass: HomeAssistant,
    endpoint: RemoteJournalEndpoint,
) -> None:
    """Keep one per-boot secret endpoint in process memory only."""

    if type(endpoint) is not RemoteJournalEndpoint:
        raise TypeError("A validated remote journal endpoint is required.")
    hass.data[DATA_REFERENCE_JOURNAL_ENDPOINT] = endpoint


def get_reference_journal_endpoint(
    hass: HomeAssistant,
) -> RemoteJournalEndpoint | None:
    """Return the current validated endpoint without accepting other values."""

    endpoint = hass.data.get(DATA_REFERENCE_JOURNAL_ENDPOINT)
    return endpoint if type(endpoint) is RemoteJournalEndpoint else None


def mark_reference_journal_reload_pending(
    hass: HomeAssistant,
    entry_id: str,
    journal: object,
) -> None:
    """Bind one deferred App-generation reload to its exact entry and journal."""

    if type(entry_id) is not str or not entry_id:
        raise TypeError("A reference journal reload entry ID is required.")
    if journal is None:
        raise TypeError("A reference journal reload owner is required.")
    hass.data[DATA_REFERENCE_JOURNAL_RELOAD_PENDING] = (
        _PendingReferenceJournalReload(entry_id=entry_id, journal=journal)
    )


def mark_reference_journal_setup_reload_pending(
    hass: HomeAssistant,
    entry_id: str,
) -> None:
    """Defer an App-generation reload until setup registers its journal owner."""

    if type(entry_id) is not str or not entry_id:
        raise TypeError("A reference journal reload entry ID is required.")
    hass.data[DATA_REFERENCE_JOURNAL_RELOAD_PENDING] = (
        _PendingReferenceJournalReload(entry_id=entry_id, journal=None)
    )


def clear_reference_journal_reload_pending(
    hass: HomeAssistant,
    entry_id: str,
) -> None:
    """Clear only the deferred reload belonging to one exact entry."""

    pending = hass.data.get(DATA_REFERENCE_JOURNAL_RELOAD_PENDING)
    if (
        type(pending) is _PendingReferenceJournalReload
        and pending.entry_id == entry_id
    ):
        hass.data.pop(DATA_REFERENCE_JOURNAL_RELOAD_PENDING, None)


def reference_journal_reload_is_pending(
    hass: HomeAssistant,
    entry_id: str,
) -> bool:
    """Return whether one exact entry owns the deferred reload."""

    pending = hass.data.get(DATA_REFERENCE_JOURNAL_RELOAD_PENDING)
    return (
        type(pending) is _PendingReferenceJournalReload
        and pending.entry_id == entry_id
    )


@callback
def async_schedule_pending_reference_journal_reload(
    hass: HomeAssistant,
    journal: object,
) -> bool:
    """Atomically consume and safely schedule one journal-generation reload."""

    pending = hass.data.get(DATA_REFERENCE_JOURNAL_RELOAD_PENDING)
    if (
        type(pending) is not _PendingReferenceJournalReload
        or (pending.journal is not None and pending.journal is not journal)
    ):
        return False

    hass.data.pop(DATA_REFERENCE_JOURNAL_RELOAD_PENDING, None)
    entry = hass.config_entries.async_get_entry(pending.entry_id)
    expected_state = (
        ConfigEntryState.SETUP_IN_PROGRESS
        if pending.journal is None
        else ConfigEntryState.LOADED
    )
    if (
        entry is None
        or entry.domain != DOMAIN
        or entry.disabled_by is not None
        or entry.state is not expected_state
    ):
        return False
    try:
        runtime = entry.runtime_data
    except AttributeError:
        return False
    domain_data = hass.data.get(DOMAIN)
    if (
        not isinstance(domain_data, Mapping)
        or domain_data.get(entry.entry_id) is not runtime
        or getattr(runtime, "reference_journal", None) is not journal
        or getattr(journal, "migration_operation_in_progress", None) is not False
    ):
        return False

    hass.config_entries.async_schedule_reload(entry.entry_id)
    return True
