"""Dienste zum Setzen und Löschen von Decisions.

Die Dienste hängen an einem Config-Entry, nicht an einer Entität: Sie wirken
auf die Instanz als Ganzes, und bei mehreren eingerichteten Instanzen muss
klar sein, welche gemeint ist.
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

_LOGGER = logging.getLogger(__name__)

ENTRY_SELECTOR = ConfigEntrySelector({"integration": DOMAIN})

# Eine Dauer wie "4h", "30m" oder "1d" — genau das Format von cscli.
DURATION_PATTERN = r"^\d+(\.\d+)?[smhd]$"

BASE_SCHEMA = {
    vol.Required(ATTR_CONFIG_ENTRY_ID): ENTRY_SELECTOR,
}

BAN_SCHEMA = vol.Schema(
    {
        **BASE_SCHEMA,
        vol.Required(ATTR_IP): cv.string,
        vol.Optional(ATTR_DURATION, default=DEFAULT_BAN_DURATION): vol.Match(
            DURATION_PATTERN
        ),
        vol.Optional(ATTR_REASON, default=DEFAULT_BAN_REASON): cv.string,
    }
)

UNBAN_SCHEMA = vol.Schema({**BASE_SCHEMA, vol.Required(ATTR_IP): cv.string})

REFRESH_SCHEMA = vol.Schema(BASE_SCHEMA)


def _coordinator(hass: HomeAssistant, call: ServiceCall):
    """Hole den Coordinator zum angegebenen Config-Entry."""
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
    """Prüfe die Zieladresse, bevor sie an die LAPI geht."""
    raw = str(call.data[ATTR_IP]).strip()
    try:
        # Einzeladressen und CIDR-Bereiche sind beide erlaubt — CrowdSec kennt
        # den Scope "Ip" für beides.
        cv.matches_regex(r"^[0-9a-fA-F:.]+(/\d{1,3})?$")(raw)
    except vol.Invalid as err:
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="invalid_ip",
            translation_placeholders={"ip": raw},
        ) from err
    return raw


def _wrap_api_error(err: Exception) -> ServiceValidationError:
    """Übersetze einen Fehler der LAPI in eine Meldung für die Oberfläche."""
    return ServiceValidationError(
        translation_domain=DOMAIN,
        translation_key="service_failed",
        translation_placeholders={"error": str(err)},
    )


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Registriere die Dienste einmalig für die gesamte Integration."""
    if hass.services.has_service(DOMAIN, SERVICE_BAN_IP):
        return

    async def async_ban(call: ServiceCall) -> None:
        coordinator = _coordinator(hass, call)
        ip = _validated_ip(call)
        try:
            await coordinator.client.async_ban_ip(
                ip, call.data[ATTR_DURATION], call.data[ATTR_REASON]
            )
        except (CrowdSecAuthError, CrowdSecConnectionError) as err:
            raise _wrap_api_error(err) from err
        _LOGGER.info("Ban für %s gesetzt (%s)", ip, call.data[ATTR_DURATION])
        await coordinator.async_request_refresh()

    async def async_unban(call: ServiceCall) -> None:
        coordinator = _coordinator(hass, call)
        ip = _validated_ip(call)
        try:
            deleted = await coordinator.client.async_unban_ip(ip)
        except (CrowdSecAuthError, CrowdSecConnectionError) as err:
            raise _wrap_api_error(err) from err
        _LOGGER.info("%d Decision(s) für %s gelöscht", deleted, ip)
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
    """Entferne die Dienste, wenn die letzte Instanz verschwindet."""
    for name in (SERVICE_BAN_IP, SERVICE_UNBAN_IP, SERVICE_REFRESH):
        hass.services.async_remove(DOMAIN, name)
