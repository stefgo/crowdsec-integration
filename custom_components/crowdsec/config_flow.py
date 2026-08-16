"""Config and options flow of the CrowdSec integration."""

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
    CONF_ALERTS_FULL_INTERVAL,
    CONF_ALERTS_LIMIT,
    CONF_BOUNCER_API_KEY,
    CONF_BOUNCER_IDLE_INTERVALS,
    CONF_LAPI_URL,
    CONF_MACHINE_ID,
    CONF_MACHINE_PASSWORD,
    CONF_METRICS_URL,
    CONF_PARSE_ERROR_THRESHOLD,
    DEFAULT_ALERTS_FULL_INTERVAL,
    DEFAULT_ALERTS_LIMIT,
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

# A real password field: it masks the input and keeps the browser's
# autocompletion away from a plain text field.
SECRET_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

# Input box instead of a slider: the number of intervals is typed directly.
BOUNCER_IDLE_INTERVALS_SELECTOR = NumberSelector(
    NumberSelectorConfig(min=1, max=100, step=1, mode=NumberSelectorMode.BOX)
)

# Applies per request; the upper bound keeps it well below the poll interval.
TIMEOUT_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=1, max=60, step=1, mode=NumberSelectorMode.BOX, unit_of_measurement="s"
    )
)

# High values noticeably enlarge the LAPI response — alerts are bulky objects
# including their decisions.
ALERTS_LIMIT_SELECTOR = NumberSelector(
    NumberSelectorConfig(min=100, max=10000, step=1, mode=NumberSelectorMode.BOX)
)

# How often the whole 24h window is refetched. In between only the minutes
# since the last cycle are queried, so this is the knob for how much the
# instance is asked for, not for how quickly a new ban is noticed.
ALERTS_FULL_INTERVAL_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=60, max=3600, step=30, mode=NumberSelectorMode.BOX, unit_of_measurement="s"
    )
)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, default=DEFAULT_NAME): cv.string,
        vol.Required(
            CONF_METRICS_URL, default=f"http://localhost:{DEFAULT_METRICS_PORT}/metrics"
        ): cv.string,
        vol.Required(
            CONF_LAPI_URL, default=f"http://localhost:{DEFAULT_LAPI_PORT}"
        ): cv.string,
        vol.Required(CONF_MACHINE_ID): cv.string,
        vol.Required(CONF_MACHINE_PASSWORD): SECRET_SELECTOR,
        vol.Optional(CONF_BOUNCER_API_KEY): SECRET_SELECTOR,
        vol.Required(CONF_VERIFY_SSL, default=True): cv.boolean,
    }
)

# Reconfigure has no name field — the title is renamed through Home Assistant
# itself — and its secrets are optional: an empty field keeps the stored value,
# so the addresses can be corrected without retyping the password.
STEP_RECONFIGURE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_METRICS_URL): cv.string,
        vol.Required(CONF_LAPI_URL): cv.string,
        vol.Required(CONF_MACHINE_ID): cv.string,
        vol.Optional(CONF_MACHINE_PASSWORD): SECRET_SELECTOR,
        vol.Optional(CONF_BOUNCER_API_KEY): SECRET_SELECTOR,
        vol.Required(CONF_VERIFY_SSL, default=True): cv.boolean,
    }
)


def merge_secrets(stored: dict[str, Any], user_input: dict[str, Any]) -> dict[str, Any]:
    """Combine a form with the stored data, keeping untouched secrets.

    A password field cannot be prefilled meaningfully — it would either show
    the secret or hand back a placeholder that gets saved as the new password.
    Leaving it empty therefore means "unchanged", and an explicitly emptied
    bouncer key means "remove it".
    """
    merged = {**stored, **user_input}
    for key in (CONF_MACHINE_PASSWORD, CONF_BOUNCER_API_KEY):
        if not str(user_input.get(key, "")).strip():
            if key == CONF_BOUNCER_API_KEY and key in user_input:
                # Present but empty: the user cleared the field on purpose.
                merged.pop(key, None)
            elif key in stored:
                merged[key] = stored[key]
            else:
                merged.pop(key, None)
    return merged


def build_unique_id(user_input: dict[str, Any]) -> str:
    """Identifier of an instance: LAPI address plus machine ID.

    The address alone is not enough — several engines can sit behind the same
    URL via separate machines, and ``localhost:8080`` is not the same instance
    when seen through different tunnels.
    """
    parts = urlsplit(user_input[CONF_LAPI_URL].rstrip("/"))
    machine = str(user_input.get(CONF_MACHINE_ID, "")).strip()
    return f"{parts.scheme}://{parts.netloc}".lower() + f"|{machine}"


# Each of the three access paths gets its own message — otherwise you are left
# guessing which one rejected you.
AUTH_ERRORS = {
    ENDPOINT_METRICS: "invalid_auth_metrics",
    ENDPOINT_ALERTS: "invalid_auth_alerts",
    ENDPOINT_BOUNCER: "invalid_auth_bouncer",
}


async def _async_validate(hass, user_input: dict[str, Any]) -> tuple[str, str] | None:
    """Test the connection.

    Returns ``(error_key, plain text)`` or ``None`` on success. The plain text
    contains the endpoint, status code and the response from CrowdSec and is
    shown in the form — otherwise you end up guessing in the log.
    """
    client = build_client(hass, user_input, user_input.get(CONF_VERIFY_SSL, True))
    try:
        await client.async_validate()
    except CrowdSecAuthError as err:
        _LOGGER.debug("Validation rejected (%s): %s", err.endpoint, err)
        return AUTH_ERRORS.get(err.endpoint, "invalid_auth"), str(err)
    except CrowdSecConnectionError as err:
        _LOGGER.debug("Validation failed: %s", err)
        return "cannot_connect", str(err)
    except Exception as err:
        _LOGGER.exception("Unexpected error while validating the CrowdSec instance")
        return "unknown", f"{type(err).__name__}: {err}"
    return None


class CrowdSecConfigFlow(ConfigFlow, domain=DOMAIN):
    """Setup through the UI; several instances are allowed."""

    VERSION = 2

    def __init__(self) -> None:
        self._reauth_data: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """First and only input form."""
        errors: dict[str, str] = {}
        detail = ""

        if user_input is not None:
            await self.async_set_unique_id(build_unique_id(user_input))
            self._abort_if_unique_id_configured()

            result = await _async_validate(self.hass, user_input)
            if result is None:
                return self.async_create_entry(
                    title=user_input[CONF_NAME], data=user_input
                )
            errors["base"], detail = result

        # Deliberately do not prefill secrets: otherwise submitting again
        # would invisibly send the same wrong value once more.
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

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Triggered when the LAPI rejects the credentials."""
        self._reauth_data = dict(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for new credentials."""
        errors: dict[str, str] = {}
        detail = ""
        entry = self._get_reauth_entry()

        if user_input is not None:
            merged = {**self._reauth_data, **user_input}
            result = await _async_validate(self.hass, merged)
            if result is None:
                # The machine ID is part of the identifier — if it is swapped
                # here, the identifier has to move with it.
                return self.async_update_reload_and_abort(
                    entry, data=merged, unique_id=build_unique_id(merged)
                )
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

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change addresses and credentials of an existing instance.

        Without this the only way to move an instance to a different address —
        or to add a bouncer key afterwards — is to delete the entry and set it
        up again, which throws away the entity IDs and their history.
        """
        errors: dict[str, str] = {}
        detail = ""
        entry = self._get_reconfigure_entry()
        stored = dict(entry.data)

        if user_input is not None:
            merged = merge_secrets(stored, user_input)
            # The identifier is derived from the address and the machine ID, so
            # it moves with them — unlike a serial number it cannot be used to
            # check that this is still the same engine. What has to be caught is
            # the entry being pointed at an instance that is already set up:
            # two entries with one identifier would fight over the same device.
            unique_id = build_unique_id(merged)
            taken = any(
                other.unique_id == unique_id and other.entry_id != entry.entry_id
                for other in self._async_current_entries()
            )
            if taken:
                return self.async_abort(reason="already_configured")

            result = await _async_validate(self.hass, merged)
            if result is None:
                return self.async_update_reload_and_abort(
                    entry, data=merged, unique_id=unique_id
                )
            errors["base"], detail = result

        suggested = {
            key: value
            for key, value in {**stored, **(user_input or {})}.items()
            if key not in (CONF_MACHINE_PASSWORD, CONF_BOUNCER_API_KEY)
        }

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(
                STEP_RECONFIGURE_SCHEMA, suggested
            ),
            errors=errors,
            description_placeholders={"error_detail": detail},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        """Options flow for the interval and the thresholds."""
        return CrowdSecOptionsFlow()


class CrowdSecOptionsFlow(OptionsFlow):
    """Adjust the poll interval and the problem thresholds."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        options = dict(self.config_entry.options)

        if user_input is not None:
            # The number selectors return floats; internally we work with ints.
            user_input[CONF_BOUNCER_IDLE_INTERVALS] = int(
                user_input[CONF_BOUNCER_IDLE_INTERVALS]
            )
            user_input[CONF_TIMEOUT] = int(user_input[CONF_TIMEOUT])
            user_input[CONF_ALERTS_LIMIT] = int(user_input[CONF_ALERTS_LIMIT])
            user_input[CONF_ALERTS_FULL_INTERVAL] = int(
                user_input[CONF_ALERTS_FULL_INTERVAL]
            )
            scan_interval = int(user_input[CONF_SCAN_INTERVAL])
            # An update cycle makes several requests. If a single one already
            # reaches into the next interval, the cycles overtake each other.
            if user_input[CONF_TIMEOUT] >= scan_interval:
                errors[CONF_TIMEOUT] = "timeout_too_long"
            elif user_input[CONF_ALERTS_FULL_INTERVAL] < scan_interval:
                # Below the poll interval the setting has no effect: every
                # cycle would be a full query, which is what it is there to
                # avoid.
                errors[CONF_ALERTS_FULL_INTERVAL] = "full_interval_too_short"
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
                vol.Required(
                    CONF_ALERTS_LIMIT,
                    default=options.get(CONF_ALERTS_LIMIT, DEFAULT_ALERTS_LIMIT),
                ): ALERTS_LIMIT_SELECTOR,
                vol.Required(
                    CONF_ALERTS_FULL_INTERVAL,
                    default=options.get(
                        CONF_ALERTS_FULL_INTERVAL, DEFAULT_ALERTS_FULL_INTERVAL
                    ),
                ): ALERTS_FULL_INTERVAL_SELECTOR,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
