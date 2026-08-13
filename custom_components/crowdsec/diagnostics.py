"""Diagnosedaten für Support-Anfragen."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_BOUNCER_API_KEY, CONF_MACHINE_ID, CONF_MACHINE_PASSWORD
from .coordinator import CrowdSecConfigEntry

TO_REDACT = {CONF_MACHINE_ID, CONF_MACHINE_PASSWORD, CONF_BOUNCER_API_KEY}


def _redact_addresses(data: dict[str, Any]) -> None:
    """Ersetze IP-Adressen durch Platzhalter, Häufigkeiten bleiben erhalten."""
    if isinstance(data.get("top_attackers"), list):
        data["top_attackers"] = [
            {**entry, "ip": "**REDACTED**"} if isinstance(entry, dict) else entry
            for entry in data["top_attackers"]
        ]
    if data.get("top_attacker") is not None:
        data["top_attacker"] = "**REDACTED**"


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: CrowdSecConfigEntry
) -> dict[str, Any]:
    """Konfiguration (redigiert), letzter Datenstand und die Rohmetriken."""
    coordinator = entry.runtime_data
    data = asdict(coordinator.data) if coordinator.data else None

    if data is not None:
        for key, value in list(data.items()):
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        _redact_addresses(data)

    return {
        "config": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
        "data": data,
        # Ohne die rohen Zähler lässt sich bei einem Rechenfehler nicht
        # nachvollziehen, was CrowdSec tatsächlich geliefert hat.
        "metrics": coordinator.raw_metrics,
    }
