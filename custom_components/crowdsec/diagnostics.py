"""Diagnosedaten für Support-Anfragen."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_BOUNCER_API_KEY, CONF_MACHINE_ID, CONF_MACHINE_PASSWORD
from .coordinator import CrowdSecConfigEntry

TO_REDACT = {CONF_MACHINE_ID, CONF_MACHINE_PASSWORD, CONF_BOUNCER_API_KEY}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: CrowdSecConfigEntry
) -> dict[str, Any]:
    """Konfiguration (redigiert) plus letzter Datenstand."""
    coordinator = entry.runtime_data
    data = asdict(coordinator.data) if coordinator.data else None

    if data is not None:
        for key in ("last_restart", "last_update"):
            if data.get(key) is not None:
                data[key] = data[key].isoformat()

    return {
        "config": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
        "data": data,
    }
