"""Constants for the CrowdSec integration."""

from __future__ import annotations

import json
from pathlib import Path

DOMAIN = "crowdsec"


def _manifest_version() -> str:
    """Read the version from the manifest.

    Single source of truth: a second constant here would sooner or later drift
    apart. Home Assistant imports an integration in the executor, so the file
    access does not block the event loop.
    """
    try:
        manifest = json.loads(
            (Path(__file__).parent / "manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return "0.0.0"
    version = manifest.get("version")
    return version if isinstance(version, str) and version else "0.0.0"


INTEGRATION_VERSION = _manifest_version()

# CrowdSec reads the user agent and stores it as the version of the machine.
# It has to follow the pattern "name/version" — the composite user agent of
# Home Assistant cannot be parsed and leads to a 401 on login.
USER_AGENT = f"hass-crowdsec/{INTEGRATION_VERSION}"

# --- Configuration keys ---------------------------------------------------
CONF_METRICS_URL = "metrics_url"
CONF_LAPI_URL = "lapi_url"
CONF_MACHINE_ID = "machine_id"
CONF_MACHINE_PASSWORD = "machine_password"
CONF_BOUNCER_API_KEY = "bouncer_api_key"
CONF_PARSE_ERROR_THRESHOLD = "parse_error_threshold"
CONF_BOUNCER_IDLE_INTERVALS = "bouncer_idle_intervals"
CONF_ALERTS_LIMIT = "alerts_limit"
CONF_ALERTS_FULL_INTERVAL = "alerts_full_interval"
CONF_DECISIONS_SCOPE = "decisions_scope"

# --- Defaults -------------------------------------------------------------
DEFAULT_NAME = "CrowdSec"
DEFAULT_METRICS_PORT = 6060
DEFAULT_LAPI_PORT = 8080
DEFAULT_SCAN_INTERVAL = 60
DEFAULT_TIMEOUT = 15
DEFAULT_PARSE_ERROR_THRESHOLD = 5.0
DEFAULT_BOUNCER_IDLE_INTERVALS = 5

# Time window for the 24h evaluation via the LAPI.
ALERTS_SINCE = "24h"
# How often the *whole* window is fetched. In between, every cycle only asks
# for the minutes since the last query and merges the result into the cache —
# see ``AlertCache``. Refetching 24 hours once a minute transfers the same
# alert objects over and over, and with the window splitting behind it that is
# up to 16 requests per cycle.
DEFAULT_ALERTS_FULL_INTERVAL = 300
# An incremental query covers a little more than the elapsed time: alerts that
# arrive while the request is in flight would otherwise fall between two
# windows.
ALERTS_INCREMENT_OVERLAP_MINUTES = 2
# Upper limit of *a single* alert query. If it is hit, the client splits the
# time window and queries again — so the value is no longer a hard ceiling but
# the size of one partial query.
DEFAULT_ALERTS_LIMIT = 1000
# How often a window may be halved before the client gives up and reports the
# numbers as truncated. 4 levels are 16 partial queries.
MAX_WINDOW_SPLITS = 4
TOP_SCENARIO_COUNT = 5

# --- Events and services --------------------------------------------------
EVENT_NEW_BAN = f"{DOMAIN}_new_ban"
SERVICE_BAN_IP = "ban_ip"
SERVICE_UNBAN_IP = "unban_ip"
SERVICE_REFRESH = "refresh"

ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_IP = "ip"
ATTR_DURATION = "duration"
ATTR_REASON = "reason"

DEFAULT_BAN_DURATION = "4h"
DEFAULT_BAN_REASON = "Home Assistant"

# Origin of the decisions created through this integration. It makes CrowdSec
# show them as their own source in `cscli decisions list`.
DECISION_ORIGIN = "cscli"

# --- Decisions and the card ----------------------------------------------
# Origins pushed by the central API. Deleting such a decision locally is
# pointless — the next pull brings it back — so the card offers no unban for
# them. Everything else (crowdsec, cscli, console, cscli-import, …) is local.
REMOTE_ORIGINS = frozenset({"capi", "lists", "list"})

ORIGIN_KIND_LOCAL = "local"
ORIGIN_KIND_CAPI = "capi"
ORIGIN_KIND_LISTS = "lists"

# The origins CrowdSec uses for decisions made on the instance itself. The LAPI
# takes them as an ``origins`` filter, which is what keeps a subscribed
# blocklist with a few hundred thousand addresses out of every update cycle.
LOCAL_ORIGINS = ("crowdsec", "cscli", "console", "cscli-import")

# Which decisions end up in the card's table.
DECISIONS_SCOPE_LOCAL = "local"
DECISIONS_SCOPE_ALL = "all"
DEFAULT_DECISIONS_SCOPE = DECISIONS_SCOPE_LOCAL

# Upper bound on the rows of the table. A browser is not going to render a
# hundred thousand rows usefully, and the whole list travels through the
# WebSocket connection.
MAX_DECISION_ROWS = 2000

DECISION_STATUS_ACTIVE = "active"
DECISION_STATUS_EXPIRED = "expired"

# The card is served by the integration itself, so no Lovelace resource has to
# be maintained by hand.
CARD_FILENAME = "crowdsec-bans-card.js"
CARD_URL_PATH = f"/{DOMAIN}_static"

# WebSocket commands behind the card.
WS_DECISIONS_LIST = f"{DOMAIN}/decisions/list"
WS_DECISIONS_DELETE = f"{DOMAIN}/decisions/delete"
WS_INSTANCES = f"{DOMAIN}/instances"
# The lookup card: one address, checked against every source, and the
# counterpart that puts a ban there.
WS_IP_LOOKUP = f"{DOMAIN}/ip/lookup"
WS_IP_BAN = f"{DOMAIN}/ip/ban"

# --- Repair issues --------------------------------------------------------
ISSUE_ALERTS_TRUNCATED = "alerts_truncated"
# The LAPI will not hand the decision list to a machine token. A bouncer key
# is the way out, and the repair flow asks for one instead of leaving the
# reason buried in a log warning.
ISSUE_DECISIONS_UNAVAILABLE = "decisions_unavailable"

# --- Metric names of the CrowdSec Prometheus endpoint ---------------------
METRIC_ACTIVE_DECISIONS = "cs_active_decisions"
METRIC_BUCKETS = "cs_buckets"
METRIC_PARSER_HITS = "cs_parser_hits_total"
METRIC_PARSER_OK = "cs_parser_hits_ok_total"
METRIC_PARSER_KO = "cs_parser_hits_ko_total"
METRIC_READER_HITS = "cs_reader_hits_total"
METRIC_LAPI_ROUTE_REQUESTS = "cs_lapi_route_requests_total"
METRIC_LAPI_DECISIONS_OK = "cs_lapi_decisions_ok_total"
METRIC_LAPI_DECISIONS_KO = "cs_lapi_decisions_ko_total"
METRIC_PROCESS_START = "process_start_time_seconds"
METRIC_INFO = "cs_info"

# Prefix of CrowdSec's own metrics — only those end up in the diagnostics.
METRIC_PREFIX = "cs_"

# Internal keys of the counter history (see rates.py).
COUNTER_LINES = "lines"
COUNTER_PARSE_OK = "parse_ok"
COUNTER_PARSE_KO = "parse_ko"
COUNTER_BOUNCER = "bouncer_queries"
