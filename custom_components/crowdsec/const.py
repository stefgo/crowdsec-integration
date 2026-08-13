"""Konstanten für die CrowdSec-Integration."""

from __future__ import annotations

import json
from pathlib import Path

DOMAIN = "crowdsec"


def _manifest_version() -> str:
    """Lies die Version aus dem Manifest.

    Einzige Quelle der Wahrheit: Eine zweite Konstante hier würde früher oder
    später auseinanderlaufen. Der Import einer Integration läuft bei Home
    Assistant im Executor, der Dateizugriff blockiert den Event-Loop also
    nicht.
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
CONF_ALERTS_LIMIT = "alerts_limit"

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
# Obergrenze *einer einzelnen* Alert-Abfrage. Wird sie erreicht, teilt der
# Client das Zeitfenster auf und fragt erneut — deshalb ist der Wert keine
# harte Obergrenze mehr, sondern die Größe einer Teilabfrage.
DEFAULT_ALERTS_LIMIT = 1000
# So oft darf ein Fenster halbiert werden, bevor der Client aufgibt und die
# Zahlen als abgeschnitten meldet. 4 Ebenen sind 16 Teilabfragen.
MAX_WINDOW_SPLITS = 4
TOP_SCENARIO_COUNT = 5

# --- Events und Services --------------------------------------------------
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

# Herkunft der über diese Integration gesetzten Decisions. CrowdSec zeigt sie
# damit in `cscli decisions list` als eigene Quelle an.
DECISION_ORIGIN = "cscli"

# --- Reparaturhinweise ----------------------------------------------------
ISSUE_ALERTS_TRUNCATED = "alerts_truncated"

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

# Präfix der CrowdSec-eigenen Metriken — nur die landen in den Diagnosedaten.
METRIC_PREFIX = "cs_"

# Interne Schlüssel des Zählerverlaufs (siehe rates.py).
COUNTER_LINES = "lines"
COUNTER_PARSE_OK = "parse_ok"
COUNTER_PARSE_KO = "parse_ko"
COUNTER_BOUNCER = "bouncer_queries"
