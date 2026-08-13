"""Update-Coordinator: holt beide Endpunkte und leitet die Kennzahlen ab."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from time import monotonic
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .alerts import AlertSummary, new_bans, summarize_alerts
from .api import (
    ENDPOINT_LAPI,
    AlertResult,
    CrowdSecAuthError,
    CrowdSecClient,
    CrowdSecConnectionError,
)
from .const import (
    CONF_ALERTS_LIMIT,
    CONF_BOUNCER_IDLE_INTERVALS,
    CONF_PARSE_ERROR_THRESHOLD,
    COUNTER_BOUNCER,
    COUNTER_LINES,
    COUNTER_PARSE_KO,
    COUNTER_PARSE_OK,
    DEFAULT_ALERTS_LIMIT,
    DEFAULT_BOUNCER_IDLE_INTERVALS,
    DEFAULT_PARSE_ERROR_THRESHOLD,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_NEW_BAN,
    ISSUE_ALERTS_TRUNCATED,
    METRIC_ACTIVE_DECISIONS,
    METRIC_BUCKETS,
    METRIC_INFO,
    METRIC_LAPI_DECISIONS_KO,
    METRIC_LAPI_DECISIONS_OK,
    METRIC_LAPI_ROUTE_REQUESTS,
    METRIC_PARSER_HITS,
    METRIC_PARSER_KO,
    METRIC_PARSER_OK,
    METRIC_PREFIX,
    METRIC_PROCESS_START,
    METRIC_READER_HITS,
    TOP_SCENARIO_COUNT,
)
from .metrics import MetricSet, Sample
from .rates import RateTracker, error_ratio

_LOGGER = logging.getLogger(__name__)

# Labelnamen, unter denen CrowdSec je nach Version die LAPI-Route ablegt.
ROUTE_LABELS = ("endpoint", "route", "path")

# Mehr Ban-Events pro Zyklus deuten auf einen Nachlauf hin (Instanz war lange
# weg, Alert-Fenster füllt sich schlagartig). Dann lieber eine Sammelmeldung
# als hunderte Events, die den Bus fluten.
MAX_BAN_EVENTS_PER_CYCLE = 25


@dataclass(slots=True)
class CrowdSecData:
    """Alles, was die Entitäten eines Update-Zyklus brauchen."""

    reachable: bool = False
    errors: list[str] = field(default_factory=list)
    problem: bool = False
    problem_reasons: list[str] = field(default_factory=list)

    scrape_duration: float | None = None
    last_restart: datetime | None = None
    last_update: datetime | None = None

    active_decisions: int | None = None
    decisions_by_reason: dict[str, float] = field(default_factory=dict)
    decisions_by_action: dict[str, float] = field(default_factory=dict)

    new_bans_24h: int | None = None
    alerts_24h: int | None = None
    alerts_truncated: bool = False
    unique_attackers_24h: int | None = None
    banned_attackers_24h: int | None = None
    last_alert: datetime | None = None

    top_scenario: str | None = None
    top_scenarios: list[dict[str, Any]] = field(default_factory=list)
    top_country: str | None = None
    top_countries: list[dict[str, Any]] = field(default_factory=list)
    top_attacker: str | None = None
    top_attackers: list[dict[str, Any]] = field(default_factory=list)

    active_buckets: int | None = None
    buckets_by_name: dict[str, float] = field(default_factory=dict)

    lines_total: float | None = None
    lines_per_minute: float | None = None
    parse_error_rate: float | None = None
    bouncer_queries_per_minute: float | None = None

    version: str | None = None


def _route_is_decisions(sample: Sample) -> bool:
    """Trifft das Sample eine der Decision-Routen der LAPI?"""
    for label in ROUTE_LABELS:
        value = sample.labels.get(label)
        if value and value.startswith("/v1/decisions"):
            return True
    return False


class CrowdSecCoordinator(DataUpdateCoordinator[CrowdSecData]):
    """Pollt eine CrowdSec-Instanz und hält den Zählerverlauf."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: CrowdSecClient,
    ) -> None:
        options = entry.options
        interval = int(options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {entry.title}",
            update_interval=timedelta(seconds=interval),
            config_entry=entry,
        )
        self.client = client
        self._rates = RateTracker()
        self._seen_traffic = False
        self._bouncer_idle_cycles = 0
        # Kennungen der zuletzt gesehenen Alerts. ``None`` heißt „noch nichts
        # gesehen" — dann werden keine Ban-Events gefeuert.
        self._known_alert_ids: set[str] | None = None
        self._device_version: str | None = None
        self._truncation_reported = False
        # Rohe CrowdSec-Metriken des letzten erfolgreichen Scrapes, nur für
        # die Diagnosedaten.
        self.raw_metrics: dict[str, list[dict[str, Any]]] = {}
        self._parse_threshold = float(
            options.get(CONF_PARSE_ERROR_THRESHOLD, DEFAULT_PARSE_ERROR_THRESHOLD)
        )
        self._bouncer_idle_limit = int(
            options.get(CONF_BOUNCER_IDLE_INTERVALS, DEFAULT_BOUNCER_IDLE_INTERVALS)
        )
        self._alerts_limit = int(options.get(CONF_ALERTS_LIMIT, DEFAULT_ALERTS_LIMIT))

    # -- Update-Zyklus ----------------------------------------------------

    async def _async_update_data(self) -> CrowdSecData:
        started = monotonic()
        previous = self.data
        data = CrowdSecData()

        # Die drei Abfragen hängen nicht voneinander ab. Nacheinander summieren
        # sich im schlechtesten Fall drei Zeitlimits — parallel bleibt der
        # Zyklus innerhalb eines einzigen.
        metrics_result, alerts_result, decisions_result = await asyncio.gather(
            self.client.async_get_metrics(),
            self.client.async_get_alerts(limit=self._alerts_limit),
            self.client.async_get_active_decision_count(),
            return_exceptions=True,
        )

        metrics = self._unwrap(data, metrics_result, MetricSet)
        alerts = self._unwrap(data, alerts_result, AlertResult)
        decision_count = self._unwrap(data, decisions_result, int)

        data.scrape_duration = round(monotonic() - started, 3)
        data.reachable = not data.errors

        if metrics is not None:
            self.raw_metrics = metrics.as_dict(METRIC_PREFIX)
            self._apply_metrics(data, metrics)
        else:
            # Ohne frische Counter ist jeder Ratenvergleich wertlos.
            self._rates.reset()

        if alerts is not None:
            self._apply_alerts(data, alerts)

        if decision_count is not None:
            data.active_decisions = decision_count

        now = datetime.now(timezone.utc)
        if data.reachable:
            data.last_update = now
        else:
            # Zeitstempel des letzten *erfolgreichen* Scrapes behalten — genau
            # daran erkennt eine Automation veraltete Werte.
            data.last_update = previous.last_update if previous else None
            if previous is not None:
                # Diese beiden Zeitstempel überdauern einen Ausfall bewusst:
                # Sie beschreiben die Vergangenheit, nicht den aktuellen Stand.
                if data.last_restart is None:
                    data.last_restart = previous.last_restart
                if data.last_alert is None:
                    data.last_alert = previous.last_alert

        self._evaluate_problem(data)
        self._update_device_version(data)
        return data

    def _unwrap(
        self, data: CrowdSecData, result: Any, expected: type
    ) -> Any | None:
        """Werte ein Ergebnis aus ``asyncio.gather`` aus.

        Erwartete Fehler landen als Meldung in den Daten (bzw. lösen einen
        Reauth aus); alles andere wird weitergereicht, damit es nicht
        stillschweigend als „nicht erreichbar" durchgeht.
        """
        if isinstance(result, CrowdSecAuthError):
            self._handle_auth_error(data, result)
            return None
        if isinstance(result, CrowdSecConnectionError):
            data.errors.append(str(result))
            return None
        if isinstance(result, BaseException):
            raise result
        if result is None or isinstance(result, expected):
            return result
        return None

    def _handle_auth_error(self, data: CrowdSecData, err: CrowdSecAuthError) -> None:
        """Entscheide, ob ein Zugriffsfehler den Eintrag blockieren muss.

        Nur ein abgelehnter Login heißt „falsche Zugangsdaten" und rechtfertigt
        einen Reauth-Dialog. Verweigert eine einzelne Route trotz gültigem
        Token, laufen die übrigen Entitäten weiter — der Ausfall steht in der
        Störung.
        """
        if err.endpoint == ENDPOINT_LAPI:
            raise ConfigEntryAuthFailed(str(err)) from err
        _LOGGER.warning("Zugriff auf %s verweigert: %s", err.endpoint, err)
        data.errors.append(str(err))

    # -- Auswertung -------------------------------------------------------

    def _apply_metrics(self, data: CrowdSecData, metrics: MetricSet) -> None:
        data.version = metrics.label_of(METRIC_INFO, "version")

        start_time = metrics.single(METRIC_PROCESS_START)
        if start_time:
            data.last_restart = datetime.fromtimestamp(start_time, tz=timezone.utc)

        active = metrics.total(METRIC_ACTIVE_DECISIONS)
        if active is not None:
            data.active_decisions = int(active)
            data.decisions_by_reason = metrics.group_sum(
                METRIC_ACTIVE_DECISIONS, "reason"
            )
            data.decisions_by_action = metrics.group_sum(
                METRIC_ACTIVE_DECISIONS, "action"
            )

        buckets = metrics.total(METRIC_BUCKETS)
        if buckets is not None:
            data.active_buckets = int(buckets)
            data.buckets_by_name = {
                name: value
                for name, value in metrics.group_sum(METRIC_BUCKETS, "name").items()
                if value > 0
            }

        parse_ok = metrics.total(METRIC_PARSER_OK)
        parse_ko = metrics.total(METRIC_PARSER_KO)
        lines = metrics.first_total((METRIC_PARSER_HITS, METRIC_READER_HITS))
        if lines is None and (parse_ok is not None or parse_ko is not None):
            # Fehlender ok/ko-Counter zählt als 0 — CrowdSec exportiert die
            # ko-Metrik erst nach dem ersten Parse-Fehler.
            lines = (parse_ok or 0.0) + (parse_ko or 0.0)
        data.lines_total = lines

        bouncer = metrics.total(METRIC_LAPI_ROUTE_REQUESTS, _route_is_decisions)
        if bouncer is None:
            ok = metrics.total(METRIC_LAPI_DECISIONS_OK) or 0.0
            ko = metrics.total(METRIC_LAPI_DECISIONS_KO)
            bouncer = ok + ko if ko is not None else None

        counters: dict[str, float] = {}
        if lines is not None:
            counters[COUNTER_LINES] = lines
        if parse_ok is not None:
            counters[COUNTER_PARSE_OK] = parse_ok
        if parse_ko is not None:
            counters[COUNTER_PARSE_KO] = parse_ko
        if bouncer is not None:
            counters[COUNTER_BOUNCER] = bouncer

        window = self._rates.update(counters, start_time, monotonic())
        if window is None:
            # Erster Zyklus oder Neustart: lieber „unbekannt" als ein Sprung.
            data.parse_error_rate = error_ratio(parse_ok, parse_ko)
            return

        data.lines_per_minute = window.per_minute(COUNTER_LINES)
        data.bouncer_queries_per_minute = window.per_minute(COUNTER_BOUNCER)

        interval_rate = error_ratio(
            window.deltas.get(COUNTER_PARSE_OK), window.deltas.get(COUNTER_PARSE_KO)
        )
        # Ohne Zeilen im Intervall gibt es keine Intervall-Quote — dann zeigt
        # der Sensor die Quote über die gesamte Laufzeit.
        data.parse_error_rate = (
            interval_rate if interval_rate is not None else error_ratio(parse_ok, parse_ko)
        )

    def _apply_alerts(self, data: CrowdSecData, result: AlertResult) -> None:
        summary = summarize_alerts(result.alerts, TOP_SCENARIO_COUNT)

        data.alerts_truncated = result.truncated
        data.alerts_24h = summary.alerts
        data.new_bans_24h = summary.ban_decisions
        data.unique_attackers_24h = summary.unique_sources
        data.banned_attackers_24h = summary.banned_sources
        data.last_alert = summary.latest_alert

        data.top_scenarios = summary.top_scenarios
        data.top_scenario = summary.top_scenario
        data.top_countries = summary.top_countries
        data.top_country = summary.top_country
        data.top_attackers = summary.top_sources
        data.top_attacker = summary.top_source

        self._fire_ban_events(summary)
        self._known_alert_ids = summary.seen_ids
        self._report_truncation(result.truncated)

    def _fire_ban_events(self, summary: AlertSummary) -> None:
        """Feuere ein Event je neu erkanntem Ban."""
        fresh = new_bans(summary, self._known_alert_ids)
        if not fresh:
            return
        if len(fresh) > MAX_BAN_EVENTS_PER_CYCLE:
            _LOGGER.info(
                "%d neue Bans in einem Zyklus — es werden nur die %d jüngsten "
                "als Event gemeldet",
                len(fresh),
                MAX_BAN_EVENTS_PER_CYCLE,
            )
            fresh.sort(
                key=lambda ban: ban.created_at or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            fresh = fresh[:MAX_BAN_EVENTS_PER_CYCLE]

        entry_id = self.config_entry.entry_id if self.config_entry else None
        for ban in fresh:
            self.hass.bus.async_fire(
                EVENT_NEW_BAN,
                {"entry_id": entry_id, "instance": self.name, **ban.as_event_data()},
            )

    def _report_truncation(self, truncated: bool) -> None:
        """Lege einen Reparaturhinweis an, wenn die 24h-Zahlen unvollständig sind."""
        if truncated == self._truncation_reported:
            return
        self._truncation_reported = truncated
        entry = self.config_entry
        if entry is None:
            return

        issue_id = f"{ISSUE_ALERTS_TRUNCATED}_{entry.entry_id}"
        if not truncated:
            ir.async_delete_issue(self.hass, DOMAIN, issue_id)
            return

        ir.async_create_issue(
            self.hass,
            DOMAIN,
            issue_id,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_ALERTS_TRUNCATED,
            translation_placeholders={
                "name": entry.title,
                "limit": str(self._alerts_limit),
            },
        )

    def _update_device_version(self, data: CrowdSecData) -> None:
        """Halte die Firmware-Angabe des Geräts aktuell.

        Die Version steckt in ``cs_info`` und ändert sich beim Update von
        CrowdSec. Ohne diesen Abgleich bliebe im Geräteregister für immer die
        Version stehen, die beim ersten Start galt.
        """
        if data.version is None or data.version == self._device_version:
            return
        entry = self.config_entry
        if entry is None:
            return

        registry = dr.async_get(self.hass)
        device = registry.async_get_device(identifiers={(DOMAIN, entry.entry_id)})
        if device is None:
            # Die Entitäten sind noch nicht angelegt — sie tragen die Version
            # dann ohnehin selbst ein.
            self._device_version = data.version
            return
        if device.sw_version != data.version:
            registry.async_update_device(device.id, sw_version=data.version)
        self._device_version = data.version

    def _evaluate_problem(self, data: CrowdSecData) -> None:
        """Sammelflag für Automationen setzen."""
        reasons: list[str] = []

        if not data.reachable:
            reasons.extend(data.errors)

        if (
            data.parse_error_rate is not None
            and data.parse_error_rate > self._parse_threshold
        ):
            reasons.append(
                f"Parse-Fehlerquote {data.parse_error_rate:.1f} % über Schwellwert "
                f"{self._parse_threshold:.1f} %"
            )

        if data.lines_per_minute is not None:
            if data.lines_per_minute > 0:
                self._seen_traffic = True
            elif self._seen_traffic:
                reasons.append("Keine Logzeilen mehr verarbeitet — CrowdSec sieht nichts")

        if data.bouncer_queries_per_minute is not None:
            if data.bouncer_queries_per_minute > 0:
                self._bouncer_idle_cycles = 0
            else:
                self._bouncer_idle_cycles += 1
                if self._bouncer_idle_cycles >= self._bouncer_idle_limit:
                    reasons.append(
                        f"Seit {self._bouncer_idle_cycles} Intervallen keine "
                        "Bouncer-Abfragen — Decisions werden nicht durchgesetzt"
                    )

        data.problem_reasons = reasons
        data.problem = bool(reasons)


# Typisierter Entry: der Coordinator hängt in entry.runtime_data.
CrowdSecConfigEntry = ConfigEntry[CrowdSecCoordinator]
