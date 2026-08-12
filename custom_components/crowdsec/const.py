"""Konstanten für die CrowdSec-Integration."""

from __future__ import annotations

DOMAIN = "crowdsec"
INTEGRATION_VERSION = "1.0.0"

# CrowdSec liest den User-Agent aus und legt ihn als Version der Machine ab.
# Er muss dem Muster "name/version" folgen — der zusammengesetzte User-Agent
# von Home Assistant lässt sich nicht parsen und führt zu einem 401 beim Login.
USER_AGENT = f"hass-crowdsec/{INTEGRATION_VERSION}"

# --- Konfigurationsschlüssel ---------------------------------------------
CONF_METRICS_URL = "metrics_url"
CONF_LAPI_URL = "lapi_url"
CONF_MACHINE_ID = "machine_id"
CONF_MACHINE_PASSWORD = "machine_password"
CONF_BOUNCER_API_KEY = "bouncer_api_key"
CONF_PARSE_ERROR_THRESHOLD = "parse_error_threshold"
CONF_BOUNCER_IDLE_INTERVALS = "bouncer_idle_intervals"

# --- Vorgaben -------------------------------------------------------------
DEFAULT_NAME = "CrowdSec"
DEFAULT_METRICS_PORT = 6060
DEFAULT_LAPI_PORT = 8080
DEFAULT_SCAN_INTERVAL = 60
DEFAULT_TIMEOUT = 15
DEFAULT_PARSE_ERROR_THRESHOLD = 5.0
DEFAULT_BOUNCER_IDLE_INTERVALS = 5

# Zeitfenster für die 24h-Auswertung über die LAPI.
ALERTS_SINCE = "24h"
ALERTS_LIMIT = 1000
TOP_SCENARIO_COUNT = 5

# --- Metriknamen des CrowdSec-Prometheus-Endpunkts ------------------------
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

# Interne Schlüssel des Zählerverlaufs (siehe rates.py).
COUNTER_LINES = "lines"
COUNTER_PARSE_OK = "parse_ok"
COUNTER_PARSE_KO = "parse_ko"
COUNTER_BOUNCER = "bouncer_queries"
