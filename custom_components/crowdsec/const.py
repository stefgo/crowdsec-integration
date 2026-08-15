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

# --- Repair issues --------------------------------------------------------
ISSUE_ALERTS_TRUNCATED = "alerts_truncated"

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
