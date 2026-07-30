"""True Family stable room and device replacement integration."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv

from .bootstrap import BootstrapError, BootstrapRecord
from .bootstrap_ha import validate_bootstrap_rooms
from .const import (
    CONF_BOOTSTRAP,
    CONF_REFERENCE_JOURNAL_ID,
    CONF_ROOMS,
    DATA_SETUP_MANAGER,
    DOMAIN,
)
from .models import default_rooms, rooms_from_dict
from .reference_migration_ha import (
    ReferenceJournalBusyError,
    ReferenceJournalCertificationError,
    ReferenceJournalCodecError,
    ReferenceJournalDurabilityError,
    ReferenceJournalIOError,
    ReferenceJournalNotProvisionedError,
    ReferenceJournalOwnershipError,
    ReferenceJournalUnsupportedFilesystemError,
    async_load_reference_journal,
)
from .reference_journal_discovery import (
    async_schedule_pending_reference_journal_reload,
    clear_reference_journal_reload_pending,
)
from .reference_providers_ha import (
    PROVIDER_NAMES,
    ExpectedObjectManifest,
    HomeAssistantInventoryScope,
)
from .replacement import ReplacementError, TrueFamilyRuntime

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
PLATFORMS = [Platform.CLIMATE]
_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, _config: dict) -> bool:
    """Register the admin API; no MQTT or heating action occurs here."""

    from .websocket import async_register_websocket_commands
    from .setup_manager import SetupManager

    async_register_websocket_commands(hass)
    expected_manifest = ExpectedObjectManifest.from_mapping(
        "unprovisioned",
        {provider: () for provider in PROVIDER_NAMES},
    )
    hass.data[DATA_SETUP_MANAGER] = SetupManager(
        hass,
        expected_manifest=expected_manifest,
        inventory_scope=HomeAssistantInventoryScope(
            expected_manifest_digest=expected_manifest.digest,
            active_yaml_domains=(),
            config_entry_domains=(),
            lovelace_dashboards=(),
            scheduler_entity_prefix="switch.true_family_unprovisioned_",
            scheduler_entity_ids=(),
        ),
    )
    hass.data.setdefault(DOMAIN, {})
    return True


@callback
def reference_journal_reload_is_safe(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> bool:
    """Return whether discovery may reload without interrupting migration work."""

    if entry.state is not ConfigEntryState.LOADED:
        return True
    try:
        runtime = entry.runtime_data
    except AttributeError:
        return False
    if hass.data.get(DOMAIN, {}).get(entry.entry_id) is not runtime:
        return False
    journal = getattr(runtime, "reference_journal", None)
    busy = getattr(journal, "migration_operation_in_progress", None)
    return type(busy) is bool and not busy


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Load persisted room bindings and subscribe to bridge events."""

    reference_journal = None
    try:
        try:
            journal_id = entry.data[CONF_REFERENCE_JOURNAL_ID]
            if not isinstance(journal_id, str) or not journal_id:
                raise ValueError("A reference migration journal ID is required.")
            reference_journal = await async_load_reference_journal(
                hass,
                journal_id=journal_id,
            )
            bootstrap_record = None
            if CONF_BOOTSTRAP in entry.data:
                bootstrap_record = BootstrapRecord.from_dict(
                    entry.data[CONF_BOOTSTRAP]
                )
            room_data = entry.data.get(CONF_ROOMS)
            rooms = rooms_from_dict(room_data) if room_data else default_rooms()
            if bootstrap_record is not None:
                if not room_data:
                    raise BootstrapError(
                        "Mapped bootstrap data requires persisted room bindings."
                    )
                validate_bootstrap_rooms(bootstrap_record, rooms)
            runtime = TrueFamilyRuntime(hass, entry, rooms)
            runtime.reference_journal = reference_journal
        except (
            ReferenceJournalBusyError,
            ReferenceJournalCertificationError,
            ReferenceJournalIOError,
        ) as err:
            raise ConfigEntryNotReady(
                "Reference journal storage is temporarily unavailable."
            ) from err
        except (
            BootstrapError,
            KeyError,
            ReferenceJournalCodecError,
            ReferenceJournalDurabilityError,
            ReferenceJournalNotProvisionedError,
            ReferenceJournalOwnershipError,
            ReferenceJournalUnsupportedFilesystemError,
            TypeError,
            ValueError,
        ) as err:
            raise ConfigEntryError(
                "True Family persisted setup data is invalid."
            ) from err
    except BaseException:
        clear_reference_journal_reload_pending(hass, entry.entry_id)
        if reference_journal is not None:
            await reference_journal.async_close()
        raise
    try:
        await runtime.async_setup()
    except asyncio.CancelledError:
        clear_reference_journal_reload_pending(hass, entry.entry_id)
        try:
            await runtime.async_shutdown()
        finally:
            await reference_journal.async_close()
        raise
    except Exception as err:
        clear_reference_journal_reload_pending(hass, entry.entry_id)
        try:
            await runtime.async_shutdown()
        finally:
            await reference_journal.async_close()
        raise ConfigEntryNotReady("MQTT is not ready for True Family") from err
    entry.runtime_data = runtime
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except asyncio.CancelledError:
        clear_reference_journal_reload_pending(hass, entry.entry_id)
        try:
            await runtime.async_shutdown()
        finally:
            await reference_journal.async_close()
        raise
    except Exception:
        clear_reference_journal_reload_pending(hass, entry.entry_id)
        try:
            await runtime.async_shutdown()
        finally:
            await reference_journal.async_close()
        raise
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime
    async_schedule_pending_reference_journal_reload(hass, reference_journal)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload entities, close joining if needed, and release MQTT listeners."""

    runtime: TrueFamilyRuntime = entry.runtime_data
    try:
        await runtime.async_shutdown()
    except ReplacementError as err:
        _LOGGER.warning("True Family unload blocked until joining closes: %s", err)
        return False
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False
    if runtime.reference_journal is not None:
        await runtime.reference_journal.async_close()
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True


def get_runtime(hass: HomeAssistant) -> TrueFamilyRuntime:
    """Return the single loaded runtime or fail closed."""

    runtimes = list(hass.data.get(DOMAIN, {}).values())
    if len(runtimes) != 1:
        raise ReplacementError("True Family is not ready for replacement commands.")
    return runtimes[0]
