"""The CrowdSec integration for Home Assistant."""

from __future__ import annotations

import logging
from pathlib import Path

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.const import CONF_TIMEOUT, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import CrowdSecClient
from .const import (
    CARD_FILENAME,
    CARD_URL_PATH,
    CONF_BOUNCER_API_KEY,
    CONF_LAPI_URL,
    CONF_MACHINE_ID,
    CONF_MACHINE_PASSWORD,
    CONF_METRICS_URL,
    DEFAULT_TIMEOUT,
    DOMAIN,
    INTEGRATION_VERSION,
)
from .coordinator import CrowdSecConfigEntry, CrowdSecCoordinator
from .services import async_setup_services, async_unload_services
from .websocket_api import async_register_websocket_api

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

# The card is registered once per Home Assistant run, not once per instance —
# a second registration of the same static path raises.
CARD_REGISTERED = f"{DOMAIN}_card_registered"


def build_client(
    hass: HomeAssistant,
    data: dict,
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> CrowdSecClient:
    """Build a client from the entry data (also used by the config flow)."""
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
    """Migrate older entries to the current schema.

    Version 1 identified an instance solely by its LAPI address. Two engines
    behind the same address — via different tunnels, say, or with separate
    machines — could therefore not be set up side by side. From version 2 on,
    the machine ID is part of the identifier.
    """
    if entry.version > 2:
        # Downgraded integration: the entry comes from a newer version and
        # must not be touched.
        return False

    if entry.version == 1:
        from .config_flow import build_unique_id

        hass.config_entries.async_update_entry(
            entry, unique_id=build_unique_id(entry.data), version=2
        )
        _LOGGER.debug("Migrated config entry %s to version 2", entry.title)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    """Set up a CrowdSec instance."""
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)
    timeout = int(entry.options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT))
    client = build_client(hass, dict(entry.data), verify_ssl, timeout)

    coordinator = CrowdSecCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    async_setup_services(hass)
    async_register_websocket_api(hass)
    await _async_register_card(hass)
    return True


async def _async_register_card(hass: HomeAssistant) -> None:
    """Serve the Lovelace card and register it with the frontend.

    This removes the need to maintain a Lovelace resource by hand; if the build
    is missing (a checkout without ``npm run build``), nothing happens at all.
    """
    if hass.data.get(CARD_REGISTERED):
        return

    www_dir = Path(__file__).parent / "www"
    card_file = www_dir / CARD_FILENAME
    if not await hass.async_add_executor_job(card_file.is_file):
        _LOGGER.warning(
            "Card %s not found — please run 'npm run build' in the card/ "
            "directory and deploy again",
            card_file,
        )
        return

    hass.data[CARD_REGISTERED] = True
    await hass.http.async_register_static_paths(
        [StaticPathConfig(CARD_URL_PATH, str(www_dir), False)]
    )
    # Version in the query string: otherwise the browser keeps holding on to
    # the old card after an update.
    add_extra_js_url(hass, f"{CARD_URL_PATH}/{CARD_FILENAME}?v={INTEGRATION_VERSION}")


async def async_unload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    """Remove an instance."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unloaded:
        return False

    # The entry being unloaded is already out of async_loaded_entries by the
    # time this runs, so it must not be counted against the total — filtering
    # by entry_id keeps this correct either way. Removing the services while
    # another instance is still loaded would disarm them for that one too.
    remaining = [
        other
        for other in hass.config_entries.async_loaded_entries(DOMAIN)
        if other.entry_id != entry.entry_id
    ]
    if not remaining:
        async_unload_services(hass)
    return True


async def async_reload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> None:
    """Reload after an options change (interval and thresholds)."""
    await hass.config_entries.async_reload(entry.entry_id)
