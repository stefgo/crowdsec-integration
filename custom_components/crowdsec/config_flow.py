"""Config- und Options-Flow der CrowdSec-Integration."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import (
    CONF_NAME,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    CONF_VERIFY_SSL,
)
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from . import build_client
from .api import (
    ENDPOINT_ALERTS,
    ENDPOINT_BOUNCER,
    ENDPOINT_METRICS,
    CrowdSecAuthError,
    CrowdSecConnectionError,
)
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
    DEFAULT_TIMEOUT,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# Echtes Passwortfeld: verdeckt die Eingabe und hält die Autovervollständigung
# des Browsers von einem einfachen Textfeld fern.
SECRET_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

# Eingabefeld statt Schieberegler: die Anzahl der Intervalle wird direkt getippt.
BOUNCER_IDLE_INTERVALS_SELECTOR = NumberSelector(
    NumberSelectorConfig(min=1, max=100, step=1, mode=NumberSelectorMode.BOX)
)

# Gilt pro Anfrage; die Obergrenze hält ihn deutlich unter dem Abfrageintervall.
TIMEOUT_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=1, max=60, step=1, mode=NumberSelectorMode.BOX, unit_of_measurement="s"
    )
)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, default=DEFAULT_NAME): cv.string,
        vol.Required(
            CONF_METRICS_URL, default=f"http://localhost:{DEFAULT_METRICS_PORT}/metrics"
        ): cv.string,
        vol.Required(CONF_LAPI_URL, default=f"http://localhost:{DEFAULT_LAPI_PORT}"): cv.string,
        vol.Required(CONF_MACHINE_ID): cv.string,
        vol.Required(CONF_MACHINE_PASSWORD): SECRET_SELECTOR,
        vol.Optional(CONF_BOUNCER_API_KEY): SECRET_SELECTOR,
        vol.Required(CONF_VERIFY_SSL, default=True): cv.boolean,
    }
)


def _unique_id(user_input: dict[str, Any]) -> str:
    """Eine Instanz wird über ihre LAPI-Adresse identifiziert."""
    parts = urlsplit(user_input[CONF_LAPI_URL].rstrip("/"))
    return f"{parts.scheme}://{parts.netloc}".lower()


# Jeder der drei Zugänge bekommt eine eigene Meldung — sonst rät man, welcher
# abgelehnt hat.
AUTH_ERRORS = {
    ENDPOINT_METRICS: "invalid_auth_metrics",
    ENDPOINT_ALERTS: "invalid_auth_alerts",
    ENDPOINT_BOUNCER: "invalid_auth_bouncer",
}


async def _async_validate(
    hass, user_input: dict[str, Any]
) -> tuple[str, str] | None:
    """Verbindung testen.

    Liefert ``(fehlerschlüssel, klartext)`` oder ``None`` bei Erfolg. Der
    Klartext enthält Endpunkt, Statuscode und die Antwort von CrowdSec und
    wird im Formular mit angezeigt — sonst rät man im Log herum.
    """
    client = build_client(hass, user_input, user_input.get(CONF_VERIFY_SSL, True))
    try:
        await client.async_validate()
    except CrowdSecAuthError as err:
        _LOGGER.debug("Prüfung abgelehnt (%s): %s", err.endpoint, err)
        return AUTH_ERRORS.get(err.endpoint, "invalid_auth"), str(err)
    except CrowdSecConnectionError as err:
        _LOGGER.debug("Prüfung fehlgeschlagen: %s", err)
        return "cannot_connect", str(err)
    except Exception as err:  # noqa: BLE001 - unerwartetes soll den Flow nicht sprengen
        _LOGGER.exception("Unerwarteter Fehler beim Prüfen der CrowdSec-Instanz")
        return "unknown", f"{type(err).__name__}: {err}"
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
        detail = ""

        if user_input is not None:
            await self.async_set_unique_id(_unique_id(user_input))
            self._abort_if_unique_id_configured()

            result = await _async_validate(self.hass, user_input)
            if result is None:
                return self.async_create_entry(
                    title=user_input[CONF_NAME], data=user_input
                )
            errors["base"], detail = result

        # Geheimnisse bewusst nicht vorbefüllen: Sonst schickt ein erneutes
        # Absenden unsichtbar denselben falschen Wert noch einmal.
        suggested = {
            key: value
            for key, value in (user_input or {}).items()
            if key not in (CONF_MACHINE_PASSWORD, CONF_BOUNCER_API_KEY)
        }

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                STEP_USER_SCHEMA, suggested
            ),
            errors=errors,
            description_placeholders={"error_detail": detail},
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
        detail = ""
        entry = self._get_reauth_entry()

        if user_input is not None:
            merged = {**self._reauth_data, **user_input}
            result = await _async_validate(self.hass, merged)
            if result is None:
                return self.async_update_reload_and_abort(entry, data=merged)
            errors["base"], detail = result

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_MACHINE_ID,
                        default=self._reauth_data.get(CONF_MACHINE_ID, ""),
                    ): cv.string,
                    vol.Required(CONF_MACHINE_PASSWORD): SECRET_SELECTOR,
                    vol.Optional(CONF_BOUNCER_API_KEY): SECRET_SELECTOR,
                }
            ),
            errors=errors,
            description_placeholders={"error_detail": detail},
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
        errors: dict[str, str] = {}
        options = dict(self.config_entry.options)

        if user_input is not None:
            # Die Number-Selectoren liefern Floats; intern wird ganzzahlig gerechnet.
            user_input[CONF_BOUNCER_IDLE_INTERVALS] = int(
                user_input[CONF_BOUNCER_IDLE_INTERVALS]
            )
            user_input[CONF_TIMEOUT] = int(user_input[CONF_TIMEOUT])
            # Ein Update-Zyklus stellt mehrere Anfragen. Reicht schon eine
            # einzelne bis ins nächste Intervall, überholen sich die Zyklen.
            if user_input[CONF_TIMEOUT] >= int(user_input[CONF_SCAN_INTERVAL]):
                errors[CONF_TIMEOUT] = "timeout_too_long"
            else:
                return self.async_create_entry(title="", data=user_input)
            options = user_input

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=3600)),
                vol.Required(
                    CONF_TIMEOUT,
                    default=options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
                ): TIMEOUT_SELECTOR,
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
                ): BOUNCER_IDLE_INTERVALS_SELECTOR,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
