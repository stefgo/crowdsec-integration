"""Update-Coordinator: holt beide Endpunkte und leitet die Kennzahlen ab."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from time import monotonic
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import CrowdSecAuthError, CrowdSecClient, CrowdSecConnectionError
from .const import (
    ALERTS_LIMIT,
    CONF_BOUNCER_IDLE_INTERVALS,
    CONF_PARSE_ERROR_THRESHOLD,
    COUNTER_BOUNCER,
    COUNTER_LINES,
    COUNTER_PARSE_KO,
    COUNTER_PARSE_OK,
    DEFAULT_BOUNCER_IDLE_INTERVALS,
    DEFAULT_PARSE_ERROR_THRESHOLD,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    METRIC_ACTIVE_DECISIONS,
    METRIC_BUCKETS,
    METRIC_INFO,
    METRIC_LAPI_DECISIONS_KO,
    METRIC_LAPI_DECISIONS_OK,
    METRIC_LAPI_ROUTE_REQUESTS,
    METRIC_PARSER_HITS,
    METRIC_PARSER_KO,
    METRIC_PARSER_OK,
    METRIC_PROCESS_START,
    METRIC_READER_HITS,
    TOP_SCENARIO_COUNT,
)
from .metrics import MetricSet, Sample
from .rates import RateTracker, error_ratio

_LOGGER = logging.getLogger(__name__)

# Labelnamen, unter denen CrowdSec je nach Version die LAPI-Route ablegt.
ROUTE_LABELS = ("endpoint", "route", "path")


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
    top_scenario: str | None = None
    top_scenarios: list[dict[str, Any]] = field(default_factory=list)

    active_buckets: int | None = None
    buckets_by_name: dict[str, float] = field(default_factory=dict)

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
        self._parse_threshold = float(
            options.get(CONF_PARSE_ERROR_THRESHOLD, DEFAULT_PARSE_ERROR_THRESHOLD)
        )
        self._bouncer_idle_limit = int(
            options.get(CONF_BOUNCER_IDLE_INTERVALS, DEFAULT_BOUNCER_IDLE_INTERVALS)
        )

    # -- Update-Zyklus ----------------------------------------------------

    async def _async_update_data(self) -> CrowdSecData:
        started = monotonic()
        previous = self.data
        data = CrowdSecData()

        metrics: MetricSet | None = None
        try:
            metrics = await self.client.async_get_metrics()
        except CrowdSecAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CrowdSecConnectionError as err:
            data.errors.append(str(err))

        alerts: list[dict[str, Any]] | None = None
        decision_count: int | None = None
        try:
            alerts = await self.client.async_get_alerts()
            decision_count = await self.client.async_get_active_decision_count()
        except CrowdSecAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CrowdSecConnectionError as err:
            data.errors.append(str(err))

        data.scrape_duration = round(monotonic() - started, 3)
        data.reachable = not data.errors

        if metrics is not None:
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
            if previous is not None and data.last_restart is None:
                data.last_restart = previous.last_restart

        self._evaluate_problem(data)
        return data

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
        if lines is None and parse_ok is not None and parse_ko is not None:
            lines = parse_ok + parse_ko

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

    def _apply_alerts(self, data: CrowdSecData, alerts: list[dict[str, Any]]) -> None:
        data.alerts_truncated = len(alerts) >= ALERTS_LIMIT
        scenarios: Counter[str] = Counter()
        bans = 0
        counted = 0

        for alert in alerts:
            if alert.get("simulated"):
                continue
            counted += 1
            scenario = alert.get("scenario")
            if isinstance(scenario, str) and scenario:
                scenarios[scenario] += 1
            for decision in alert.get("decisions") or []:
                if not isinstance(decision, dict):
                    continue
                if str(decision.get("type", "")).lower() == "ban":
                    bans += 1

        data.alerts_24h = counted
        data.new_bans_24h = bans
        data.top_scenarios = [
            {"scenario": name, "alerts": count}
            for name, count in scenarios.most_common(TOP_SCENARIO_COUNT)
        ]
        data.top_scenario = data.top_scenarios[0]["scenario"] if data.top_scenarios else None

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
