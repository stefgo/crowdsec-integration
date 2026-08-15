"""Services for creating and removing decisions.

The services are attached to a config entry, not to an entity: they act on the
instance as a whole, and with several instances set up it has to be clear
which one is meant.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.selector import ConfigEntrySelector

from .api import CrowdSecAuthError, CrowdSecConnectionError
from .const import (
    ATTR_CONFIG_ENTRY_ID,
    ATTR_DURATION,
    ATTR_IP,
    ATTR_REASON,
    DEFAULT_BAN_DURATION,
    DEFAULT_BAN_REASON,
    DOMAIN,
    SERVICE_BAN_IP,
    SERVICE_REFRESH,
    SERVICE_UNBAN_IP,
)
from .validation import normalize_ban_duration, normalize_ip_target

_LOGGER = logging.getLogger(__name__)

ENTRY_SELECTOR = ConfigEntrySelector({"integration": DOMAIN})

BASE_SCHEMA = {
    vol.Required(ATTR_CONFIG_ENTRY_ID): ENTRY_SELECTOR,
}

BAN_SCHEMA = vol.Schema(
    {
        **BASE_SCHEMA,
        vol.Required(ATTR_IP): cv.string,
        vol.Optional(ATTR_DURATION, default=DEFAULT_BAN_DURATION): cv.string,
        vol.Optional(ATTR_REASON, default=DEFAULT_BAN_REASON): cv.string,
    }
)

UNBAN_SCHEMA = vol.Schema({**BASE_SCHEMA, vol.Required(ATTR_IP): cv.string})

REFRESH_SCHEMA = vol.Schema(BASE_SCHEMA)


def _coordinator(hass: HomeAssistant, call: ServiceCall):
    """Fetch the coordinator for the given config entry."""
    entry_id = call.data[ATTR_CONFIG_ENTRY_ID]
    entry = hass.config_entries.async_get_entry(entry_id)
    if entry is None or entry.domain != DOMAIN:
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="entry_not_found",
            translation_placeholders={"entry_id": entry_id},
        )
    if entry.state is not ConfigEntryState.LOADED:
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="entry_not_loaded",
            translation_placeholders={"name": entry.title},
        )
    return entry.runtime_data


def _validated_ip(call: ServiceCall) -> str:
    """Validate the target address before it goes to the LAPI.

    Single addresses and CIDR ranges are both allowed — CrowdSec uses the
    scope "Ip" for both.
    """
    raw = str(call.data[ATTR_IP])
    try:
        return normalize_ip_target(raw)
    except ValueError as err:
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="invalid_ip",
            translation_placeholders={"ip": raw.strip()},
        ) from err


def _validated_duration(call: ServiceCall) -> str:
    """Validate the ban duration.

    Deliberately here and not in the schema: a schema violation reaches the
    user as an untranslated voluptuous message, whereas a
    ``ServiceValidationError`` carries a translated text and says what is
    wrong with the value.
    """
    raw = str(call.data[ATTR_DURATION])
    try:
        return normalize_ban_duration(raw)
    except ValueError as err:
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="invalid_duration",
            translation_placeholders={"duration": raw.strip(), "error": str(err)},
        ) from err


def _wrap_api_error(err: Exception) -> ServiceValidationError:
    """Translate an error from the LAPI into a message for the UI."""
    return ServiceValidationError(
        translation_domain=DOMAIN,
        translation_key="service_failed",
        translation_placeholders={"error": str(err)},
    )


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the services once for the whole integration."""
    if hass.services.has_service(DOMAIN, SERVICE_BAN_IP):
        return

    async def async_ban(call: ServiceCall) -> None:
        coordinator = _coordinator(hass, call)
        ip = _validated_ip(call)
        duration = _validated_duration(call)
        try:
            await coordinator.client.async_ban_ip(ip, duration, call.data[ATTR_REASON])
        except (CrowdSecAuthError, CrowdSecConnectionError) as err:
            raise _wrap_api_error(err) from err
        _LOGGER.info("Banned %s (%s)", ip, duration)
        await coordinator.async_request_refresh()

    async def async_unban(call: ServiceCall) -> None:
        coordinator = _coordinator(hass, call)
        ip = _validated_ip(call)
        try:
            deleted = await coordinator.client.async_unban_ip(ip)
        except (CrowdSecAuthError, CrowdSecConnectionError) as err:
            raise _wrap_api_error(err) from err
        _LOGGER.info("Deleted %d decision(s) for %s", deleted, ip)
        await coordinator.async_request_refresh()

    async def async_refresh(call: ServiceCall) -> None:
        coordinator = _coordinator(hass, call)
        await coordinator.async_request_refresh()

    services: dict[str, tuple[Any, vol.Schema]] = {
        SERVICE_BAN_IP: (async_ban, BAN_SCHEMA),
        SERVICE_UNBAN_IP: (async_unban, UNBAN_SCHEMA),
        SERVICE_REFRESH: (async_refresh, REFRESH_SCHEMA),
    }
    for name, (handler, schema) in services.items():
        hass.services.async_register(DOMAIN, name, handler, schema=schema)


@callback
def async_unload_services(hass: HomeAssistant) -> None:
    """Remove the services when the last instance goes away."""
    for name in (SERVICE_BAN_IP, SERVICE_UNBAN_IP, SERVICE_REFRESH):
        hass.services.async_remove(DOMAIN, name)
