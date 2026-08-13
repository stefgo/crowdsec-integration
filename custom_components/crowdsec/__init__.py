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
    DOMAIN,
)
from .coordinator import CrowdSecConfigEntry, CrowdSecCoordinator
from .services import async_setup_services, async_unload_services

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


async def async_migrate_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    """Hebe ältere Einträge auf das aktuelle Schema.

    Version 1 hat eine Instanz allein über ihre LAPI-Adresse identifiziert.
    Zwei Engines hinter derselben Adresse — etwa über unterschiedliche Tunnel
    oder mit getrennten Machines — ließen sich damit nicht parallel einrichten.
    Ab Version 2 gehört die Machine-ID zur Kennung.
    """
    if entry.version > 2:
        # Herabgestufte Integration: der Eintrag stammt aus einer neueren
        # Version und darf nicht angefasst werden.
        return False

    if entry.version == 1:
        from .config_flow import build_unique_id

        hass.config_entries.async_update_entry(
            entry, unique_id=build_unique_id(entry.data), version=2
        )
        _LOGGER.debug("Config-Entry %s auf Version 2 gehoben", entry.title)

    return True


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
    async_setup_services(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    """Entferne eine Instanz."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded and len(hass.config_entries.async_loaded_entries(DOMAIN)) <= 1:
        # Der eigene Eintrag zählt hier noch mit — bleibt kein weiterer übrig,
        # sind die Dienste ohne Ziel.
        async_unload_services(hass)
    return unloaded


async def async_reload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> None:
    """Nach Optionsänderung neu laden (Intervall und Schwellwerte)."""
    await hass.config_entries.async_reload(entry.entry_id)
