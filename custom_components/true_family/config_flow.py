"""Config flow for the singleton True Family integration."""

from __future__ import annotations

import secrets
from typing import Any

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState, ConfigFlowResult
from homeassistant.helpers.service_info.hassio import HassioServiceInfo
import voluptuous as vol

from . import reference_journal_reload_is_safe
from .const import (
    CONF_BASE_TOPIC,
    CONF_REFERENCE_JOURNAL_ID,
    CONF_ROOMS,
    DEFAULT_BASE_TOPIC,
    DOMAIN,
    NAME,
)
from .models import default_rooms, rooms_as_dict
from .mqtt import validate_base_topic
from .reference_migration_ha import (
    ReferenceJournalAlreadyProvisionedError,
    ReferenceJournalCodecError,
    ReferenceJournalDurabilityError,
    async_provision_reference_journal,
)
from .reference_journal_discovery import (
    ReferenceJournalDiscoveryError,
    cache_reference_journal_endpoint,
    clear_reference_journal_reload_pending,
    endpoint_from_hassio_service_info,
    get_reference_journal_endpoint,
    mark_reference_journal_reload_pending,
    mark_reference_journal_setup_reload_pending,
)


def valid_base_topic(value: Any) -> str:
    """Validate a concrete Zigbee2MQTT base topic without wildcards."""

    try:
        return validate_base_topic(value)
    except ValueError as err:
        raise vol.Invalid("A concrete MQTT base topic is required.") from err


class TrueFamilyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Create one local True Family helper entry."""

    VERSION = 1

    async def async_step_hassio(
        self,
        discovery_info: HassioServiceInfo,
    ) -> ConfigFlowResult:
        """Cache one strict journal App endpoint without creating an entry."""

        try:
            endpoint = endpoint_from_hassio_service_info(discovery_info)
        except (ReferenceJournalDiscoveryError, TypeError, ValueError):
            return self.async_abort(reason="journal_app_discovery_invalid")
        previous_endpoint = get_reference_journal_endpoint(self.hass)
        cache_reference_journal_endpoint(self.hass, endpoint)
        entries = self.hass.config_entries.async_entries(DOMAIN)
        if len(entries) == 1:
            entry = entries[0]
            endpoint_changed = previous_endpoint != endpoint
            reload_needed = entry.state in {
                ConfigEntryState.NOT_LOADED,
                ConfigEntryState.SETUP_RETRY,
            } or (
                entry.state is ConfigEntryState.LOADED
                and endpoint_changed
            )
            if (
                entry.state is ConfigEntryState.SETUP_IN_PROGRESS
                and endpoint_changed
                and entry.disabled_by is None
            ):
                mark_reference_journal_setup_reload_pending(
                    self.hass,
                    entry.entry_id,
                )
            elif reload_needed and entry.disabled_by is None:
                if not reference_journal_reload_is_safe(self.hass, entry):
                    try:
                        journal = entry.runtime_data.reference_journal
                    except AttributeError:
                        clear_reference_journal_reload_pending(
                            self.hass,
                            entry.entry_id,
                        )
                    else:
                        if (
                            getattr(
                                journal,
                                "migration_operation_in_progress",
                                None,
                            )
                            is True
                        ):
                            mark_reference_journal_reload_pending(
                                self.hass,
                                entry.entry_id,
                                journal,
                            )
                        else:
                            clear_reference_journal_reload_pending(
                                self.hass,
                                entry.entry_id,
                            )
                else:
                    clear_reference_journal_reload_pending(
                        self.hass,
                        entry.entry_id,
                    )
                    self.hass.config_entries.async_schedule_reload(entry.entry_id)
        return self.async_abort(reason="journal_app_discovered")

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Confirm creation of the local logical-room layer."""

        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is not None:
            journal_id = getattr(self, "_reference_journal_id", None)
            if journal_id is None:
                journal_id = secrets.token_hex(16)
                self._reference_journal_id = journal_id
            try:
                await async_provision_reference_journal(
                    self.hass,
                    journal_id=journal_id,
                )
            except (
                ReferenceJournalAlreadyProvisionedError,
                ReferenceJournalCodecError,
            ):
                return self.async_show_form(
                    step_id="user",
                    data_schema=vol.Schema(
                        {
                            vol.Required(
                                CONF_BASE_TOPIC,
                                default=user_input[CONF_BASE_TOPIC],
                            ): valid_base_topic
                        }
                    ),
                    errors={"base": "journal_corrupt_or_unsafe"},
                )
            except ReferenceJournalDurabilityError:
                return self.async_show_form(
                    step_id="user",
                    data_schema=vol.Schema(
                        {
                            vol.Required(
                                CONF_BASE_TOPIC,
                                default=user_input[CONF_BASE_TOPIC],
                            ): valid_base_topic
                        }
                    ),
                    errors={"base": "journal_durability_unavailable"},
                )
            return self.async_create_entry(
                title=NAME,
                data={
                    CONF_BASE_TOPIC: user_input[CONF_BASE_TOPIC],
                    CONF_REFERENCE_JOURNAL_ID: journal_id,
                    CONF_ROOMS: rooms_as_dict(default_rooms()),
                },
            )
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_BASE_TOPIC,
                        default=DEFAULT_BASE_TOPIC,
                    ): valid_base_topic
                }
            ),
        )
