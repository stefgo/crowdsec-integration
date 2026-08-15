"""Diagnostics data for support requests."""

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
    """Replace IP addresses with placeholders; the counts are preserved."""
    if isinstance(data.get("top_attackers"), list):
        data["top_attackers"] = [
            {**entry, "ip": "**REDACTED**"} if isinstance(entry, dict) else entry
            for entry in data["top_attackers"]
        ]
    if data.get("top_attacker") is not None:
        data["top_attacker"] = "**REDACTED**"

    # The decision table is the one place where every banned address is listed
    # in full. What a support request needs is the shape of the rows, not who
    # is in them — so the addresses go and everything else stays.
    if isinstance(data.get("decisions"), list):
        data["decisions"] = [
            {
                **{
                    key: value
                    for key, value in entry.items()
                    if key not in ("value", "as_name", "as_number")
                },
                "value": "**REDACTED**",
            }
            if isinstance(entry, dict)
            else entry
            for entry in data["decisions"]
        ]


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: CrowdSecConfigEntry
) -> dict[str, Any]:
    """Configuration (redacted), latest data and the raw metrics."""
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
        # Without the raw counters there is no way to tell what CrowdSec
        # actually returned when a calculation goes wrong.
        "metrics": coordinator.raw_metrics,
    }
