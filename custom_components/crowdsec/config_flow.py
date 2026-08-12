"""Config- und Options-Flow der CrowdSec-Integration."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_NAME, CONF_SCAN_INTERVAL, CONF_VERIFY_SSL
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv

from . import build_client
from .api import CrowdSecAuthError, CrowdSecConnectionError
from .const import (
    CONF_BOUNCER_API_KEY,
    CONF_BOUNCER_IDLE_INTERVALS,
    CONF_LAPI_URL,
    CONF_MACHINE_ID,
    CONF_MACHINE_PASSWORD,
    CONF_METRICS_URL,
    CONF_PARSE_ERROR_THRESHOLD,
    DEFAULT_BOUNCER_IDLE_INTERVALS,
    DEFAULT_LAPI_PORT,
    DEFAULT_METRICS_PORT,
    DEFAULT_NAME,
    DEFAULT_PARSE_ERROR_THRESHOLD,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, default=DEFAULT_NAME): cv.string,
        vol.Required(
            CONF_METRICS_URL, default=f"http://localhost:{DEFAULT_METRICS_PORT}/metrics"
        ): cv.string,
        vol.Required(CONF_LAPI_URL, default=f"http://localhost:{DEFAULT_LAPI_PORT}"): cv.string,
        vol.Required(CONF_MACHINE_ID): cv.string,
        vol.Required(CONF_MACHINE_PASSWORD): cv.string,
        vol.Optional(CONF_BOUNCER_API_KEY): cv.string,
        vol.Required(CONF_VERIFY_SSL, default=True): cv.boolean,
    }
)


def _unique_id(user_input: dict[str, Any]) -> str:
    """Eine Instanz wird über ihre LAPI-Adresse identifiziert."""
    parts = urlsplit(user_input[CONF_LAPI_URL].rstrip("/"))
    return f"{parts.scheme}://{parts.netloc}".lower()


async def _async_validate(hass, user_input: dict[str, Any]) -> str | None:
    """Verbindung testen; gibt einen Fehlerschlüssel zurück oder ``None``."""
    client = build_client(hass, user_input, user_input.get(CONF_VERIFY_SSL, True))
    try:
        await client.async_validate()
    except CrowdSecAuthError:
        return "invalid_auth"
    except CrowdSecConnectionError:
        return "cannot_connect"
    except Exception:  # noqa: BLE001 - unerwartetes soll den Flow nicht sprengen
        _LOGGER.exception("Unerwarteter Fehler beim Prüfen der CrowdSec-Instanz")
        return "unknown"
    return None


class CrowdSecConfigFlow(ConfigFlow, domain=DOMAIN):
    """Einrichtung über die Oberfläche; mehrere Instanzen sind erlaubt."""

    VERSION = 1

    def __init__(self) -> None:
        self._reauth_data: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Erste und einzige Eingabemaske."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(_unique_id(user_input))
            self._abort_if_unique_id_configured()

            error = await _async_validate(self.hass, user_input)
            if error is None:
                return self.async_create_entry(
                    title=user_input[CONF_NAME], data=user_input
                )
            errors["base"] = error

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                STEP_USER_SCHEMA, user_input or {}
            ),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Wird ausgelöst, wenn die LAPI die Anmeldedaten ablehnt."""
        self._reauth_data = dict(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Neue Zugangsdaten abfragen."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()

        if user_input is not None:
            merged = {**self._reauth_data, **user_input}
            error = await _async_validate(self.hass, merged)
            if error is None:
                return self.async_update_reload_and_abort(entry, data=merged)
            errors["base"] = error

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_MACHINE_ID,
                        default=self._reauth_data.get(CONF_MACHINE_ID, ""),
                    ): cv.string,
                    vol.Required(CONF_MACHINE_PASSWORD): cv.string,
                    vol.Optional(CONF_BOUNCER_API_KEY): cv.string,
                }
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        """Options-Flow für Intervall und Schwellwerte."""
        return CrowdSecOptionsFlow()


class CrowdSecOptionsFlow(OptionsFlow):
    """Pollintervall und Störungs-Schwellwerte anpassen."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=3600)),
                vol.Required(
                    CONF_PARSE_ERROR_THRESHOLD,
                    default=options.get(
                        CONF_PARSE_ERROR_THRESHOLD, DEFAULT_PARSE_ERROR_THRESHOLD
                    ),
                ): vol.All(vol.Coerce(float), vol.Range(min=0, max=100)),
                vol.Required(
                    CONF_BOUNCER_IDLE_INTERVALS,
                    default=options.get(
                        CONF_BOUNCER_IDLE_INTERVALS, DEFAULT_BOUNCER_IDLE_INTERVALS
                    ),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=100)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
