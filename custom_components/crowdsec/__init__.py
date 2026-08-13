"""Die CrowdSec-Integration für Home Assistant."""

from __future__ import annotations

import logging

from homeassistant.const import CONF_TIMEOUT, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import CrowdSecClient
from .const import (
    CONF_BOUNCER_API_KEY,
    CONF_LAPI_URL,
    CONF_MACHINE_ID,
    CONF_MACHINE_PASSWORD,
    CONF_METRICS_URL,
    DEFAULT_TIMEOUT,
)
from .coordinator import CrowdSecConfigEntry, CrowdSecCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]


def build_client(
    hass: HomeAssistant,
    data: dict,
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> CrowdSecClient:
    """Erzeuge einen Client aus den Entry-Daten (auch vom Config-Flow genutzt)."""
    return CrowdSecClient(
        async_get_clientsession(hass, verify_ssl=verify_ssl),
        metrics_url=data[CONF_METRICS_URL],
        lapi_url=data[CONF_LAPI_URL],
        machine_id=data[CONF_MACHINE_ID],
        machine_password=data[CONF_MACHINE_PASSWORD],
        bouncer_api_key=data.get(CONF_BOUNCER_API_KEY),
        verify_ssl=verify_ssl,
        timeout=timeout,
    )


async def async_setup_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    """Richte eine CrowdSec-Instanz ein."""
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)
    timeout = int(entry.options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT))
    client = build_client(hass, dict(entry.data), verify_ssl, timeout)

    coordinator = CrowdSecCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    """Entferne eine Instanz."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_reload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> None:
    """Nach Optionsänderung neu laden (Intervall und Schwellwerte)."""
    await hass.config_entries.async_reload(entry.entry_id)
