"""WebSocket commands for the Lovelace card.

The card needs more than an entity state can carry: a whole table with one row
per decision, and a way to remove a single one. Both go through these commands
rather than through attributes — attributes are size-limited, kept in the state
machine and recorded by the recorder, none of which a ban list wants.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, callback

from .api import CrowdSecAuthError, CrowdSecConnectionError
from .const import (
    DEFAULT_BAN_DURATION,
    DEFAULT_BAN_REASON,
    DOMAIN,
    ORIGIN_KIND_LOCAL,
    WS_DECISIONS_DELETE,
    WS_DECISIONS_LIST,
    WS_INSTANCES,
    WS_IP_BAN,
    WS_IP_LOOKUP,
)
from .coordinator import CrowdSecCoordinator
from .decisions import build_ip_report
from .validation import normalize_ban_duration, normalize_ip_target

_LOGGER = logging.getLogger(__name__)

# How many rows one answer carries. The card asks for more when the user
# scrolls; sending everything at once is what a WebSocket message should not be
# doing for a table that can hold thousands of entries.
DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 2000


@callback
def async_register_websocket_api(hass: HomeAssistant) -> None:
    """Register all commands once for the whole integration."""
    websocket_api.async_register_command(hass, ws_instances)
    websocket_api.async_register_command(hass, ws_decisions_list)
    websocket_api.async_register_command(hass, ws_decisions_delete)
    websocket_api.async_register_command(hass, ws_ip_lookup)
    websocket_api.async_register_command(hass, ws_ip_ban)


@callback
def _coordinator(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> CrowdSecCoordinator | None:
    """Resolve the config entry of a message, or answer with an error."""
    entry_id = msg["config_entry_id"]
    entry = hass.config_entries.async_get_entry(entry_id)
    if entry is None or entry.domain != DOMAIN:
        connection.send_error(
            msg["id"],
            "entry_not_found",
            f"No CrowdSec instance found for {entry_id}.",
        )
        return None
    if entry.state is not ConfigEntryState.LOADED:
        connection.send_error(
            msg["id"],
            "entry_not_loaded",
            f'The CrowdSec instance "{entry.title}" is not loaded.',
        )
        return None
    coordinator = getattr(entry, "runtime_data", None)
    if not isinstance(coordinator, CrowdSecCoordinator):
        connection.send_error(
            msg["id"], "not_ready", "The instance is still starting up."
        )
        return None
    return coordinator


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): WS_INSTANCES})
@callback
def ws_instances(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """The configured instances, so the card can offer a picker."""
    instances = []
    for entry in hass.config_entries.async_entries(DOMAIN):
        coordinator = getattr(entry, "runtime_data", None)
        instances.append(
            {
                "config_entry_id": entry.entry_id,
                "title": entry.title,
                "loaded": entry.state is ConfigEntryState.LOADED
                and isinstance(coordinator, CrowdSecCoordinator),
            }
        )
    connection.send_result(msg["id"], {"instances": instances})


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_DECISIONS_LIST,
        vol.Required("config_entry_id"): str,
        # Fetch fresh data instead of the last polling cycle. The card uses it
        # for its refresh button; the normal open costs no request at all.
        vol.Optional("refresh", default=False): bool,
        # One page of the table. The rows are already sorted — active first,
        # then by remaining time — so the first page is the interesting one and
        # the card only fetches further pages when asked.
        vol.Optional("limit", default=DEFAULT_PAGE_SIZE): vol.All(
            int, vol.Range(min=1, max=MAX_PAGE_SIZE)
        ),
        vol.Optional("offset", default=0): vol.All(int, vol.Range(min=0)),
    }
)
@websocket_api.async_response
async def ws_decisions_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """One page of the table: active decisions plus the 24h history."""
    coordinator = _coordinator(hass, connection, msg)
    if coordinator is None:
        return

    if msg["refresh"]:
        # A manual refresh should show the current picture, not whatever the
        # incremental alert query happened to catch.
        coordinator.request_full_alert_poll()
        await coordinator.async_request_refresh()

    data = coordinator.data
    if data is None:
        connection.send_error(msg["id"], "not_ready", "No data fetched yet.")
        return

    offset: int = msg["offset"]
    limit: int = msg["limit"]
    page = data.decisions[offset : offset + limit]

    connection.send_result(
        msg["id"],
        {
            "decisions": [row.as_dict() for row in page],
            "total": len(data.decisions),
            "offset": offset,
            "available": data.decisions_available,
            "reachable": data.reachable,
            "alerts_truncated": data.alerts_truncated,
            # The table itself hit the row cap — there are more decisions than
            # are being kept, never mind paged.
            "decisions_truncated": data.decisions_truncated,
            "local_only": data.decisions_local_only,
            "last_update": (data.last_update.isoformat() if data.last_update else None),
        },
    )


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_DECISIONS_DELETE,
        vol.Required("config_entry_id"): str,
        # Either a single decision by ID, or every decision of an address.
        vol.Exclusive("decision_id", "target"): int,
        vol.Exclusive("ip", "target"): str,
    }
)
@websocket_api.async_response
async def ws_decisions_delete(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Remove one decision, or all decisions of an address."""
    coordinator = _coordinator(hass, connection, msg)
    if coordinator is None:
        return

    decision_id = msg.get("decision_id")
    ip = msg.get("ip")
    if decision_id is None and ip is None:
        connection.send_error(
            msg["id"], "invalid_target", "Either decision_id or ip is required."
        )
        return

    targets: set[str] = set()
    if ip is not None:
        # The same check the services do. The card only ever sends addresses it
        # got from the table, but a WebSocket command is a public interface —
        # an unchecked value would go straight to the LAPI.
        try:
            normalized = normalize_ip_target(ip)
        except ValueError as err:
            connection.send_error(msg["id"], "invalid_target", str(err))
            return
        # Both spellings count when looking for the rows: CrowdSec stores the
        # address the way it received it, which does not have to match the
        # normal form (``2001:0db8::1`` vs. ``2001:db8::1``).
        targets = {ip.strip(), normalized}
        ip = normalized

    rows = coordinator.data.decisions if coordinator.data else []
    if decision_id is not None:
        target = next((row for row in rows if row.decision_id == decision_id), None)
        if target is not None and not target.deletable:
            # CAPI and blocklist decisions are pushed by the central API; a
            # local delete would be undone by the next pull.
            connection.send_error(
                msg["id"],
                "not_deletable",
                f'The decision comes from "{target.origin}" and is managed '
                "centrally — it cannot be removed locally.",
            )
            return
    else:
        matching = [row for row in rows if row.value in targets]
        if matching and not any(
            row.origin_kind == ORIGIN_KIND_LOCAL for row in matching
        ):
            connection.send_error(
                msg["id"],
                "not_deletable",
                f"All decisions for {ip} are managed centrally — they cannot "
                "be removed locally.",
            )
            return

    try:
        if decision_id is not None:
            deleted = await coordinator.client.async_delete_decision(decision_id)
        else:
            deleted = await coordinator.client.async_unban_ip(str(ip))
    except (CrowdSecAuthError, CrowdSecConnectionError) as err:
        connection.send_error(msg["id"], "request_failed", str(err))
        return

    _LOGGER.info(
        "Removed %d decision(s) via the card (%s)",
        deleted,
        f"id {decision_id}" if decision_id is not None else str(ip),
    )
    await coordinator.async_request_refresh()

    # Only the first page comes back: after a delete the card redraws from the
    # top anyway, and the answer must not be the one place that still ships the
    # whole table.
    rows = coordinator.data.decisions if coordinator.data else []
    connection.send_result(
        msg["id"],
        {
            "deleted": deleted,
            "decisions": [row.as_dict() for row in rows[:DEFAULT_PAGE_SIZE]],
            "total": len(rows),
            "offset": 0,
        },
    )


# -- Looking up a single address --------------------------------------------


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_IP_LOOKUP,
        vol.Required("config_entry_id"): str,
        vol.Required("ip"): str,
    }
)
@websocket_api.async_response
async def ws_ip_lookup(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Everything the instance knows about one address or range.

    Deliberately not served from the coordinator's data: that is the table,
    which is filtered by the configured scope and cannot show a range covering
    the address. This asks the LAPI directly, and only when someone asks.
    """
    coordinator = _coordinator(hass, connection, msg)
    if coordinator is None:
        return

    try:
        target = normalize_ip_target(msg["ip"])
    except ValueError as err:
        connection.send_error(msg["id"], "invalid_target", str(err))
        return

    decisions, alerts = await asyncio.gather(
        coordinator.client.async_lookup_ip(target),
        coordinator.client.async_lookup_alerts(target),
        return_exceptions=True,
    )

    if isinstance(decisions, BaseException):
        if not isinstance(decisions, (CrowdSecAuthError, CrowdSecConnectionError)):
            raise decisions
        connection.send_error(msg["id"], "request_failed", str(decisions))
        return

    # The history is context, not the answer — losing it must not lose the
    # decisions with it, but the card has to know it is missing.
    alerts_available = not isinstance(alerts, BaseException)
    if not alerts_available:
        if not isinstance(alerts, (CrowdSecAuthError, CrowdSecConnectionError)):
            raise alerts
        _LOGGER.debug("Alert lookup for %s failed: %s", target, alerts)

    report = build_ip_report(
        target,
        decisions or [],
        alerts if alerts_available else [],
        alerts_available=alerts_available,
    )
    # None means the decision route itself is closed — "not blocked" would be
    # a lie in that case.
    result = report.as_dict()
    result["decisions_available"] = decisions is not None
    connection.send_result(msg["id"], result)


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_IP_BAN,
        vol.Required("config_entry_id"): str,
        vol.Required("ip"): str,
        vol.Optional("duration", default=DEFAULT_BAN_DURATION): str,
        vol.Optional("reason", default=DEFAULT_BAN_REASON): str,
    }
)
@websocket_api.async_response
async def ws_ip_ban(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Ban an address from the card, the same way the service does."""
    coordinator = _coordinator(hass, connection, msg)
    if coordinator is None:
        return

    try:
        target = normalize_ip_target(msg["ip"])
    except ValueError as err:
        connection.send_error(msg["id"], "invalid_target", str(err))
        return
    try:
        duration = normalize_ban_duration(msg["duration"])
    except ValueError as err:
        connection.send_error(msg["id"], "invalid_duration", str(err))
        return

    reason = str(msg["reason"]).strip() or DEFAULT_BAN_REASON
    try:
        await coordinator.client.async_ban_ip(target, duration, reason)
    except (CrowdSecAuthError, CrowdSecConnectionError) as err:
        connection.send_error(msg["id"], "request_failed", str(err))
        return

    _LOGGER.info("Banned %s for %s via the card (%s)", target, duration, reason)
    await coordinator.async_request_refresh()

    # The fresh state comes straight back, so the card can show the result of
    # the click without a second round trip.
    decisions = await coordinator.client.async_lookup_ip(target)
    alerts = await coordinator.client.async_lookup_alerts(target)
    report = build_ip_report(target, decisions or [], alerts)
    connection.send_result(msg["id"], report.as_dict())
