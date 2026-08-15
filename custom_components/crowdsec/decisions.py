"""Evaluation of the LAPI decision objects.

Like :mod:`alerts` this module is deliberately free of Home Assistant imports:
it turns the raw JSON of ``/v1/decisions`` — plus the alerts that are fetched
anyway — into the flat records the Lovelace card renders.

Two sources are merged here:

* ``/v1/decisions`` gives what CrowdSec is enforcing *right now*, but only the
  bare decision: no country, no AS, no alert context.
* ``/v1/alerts`` gives the past 24 hours with all the context, including bans
  that have already expired.

The card wants both in one table, so the alerts fill in the details of the
active decisions and additionally contribute the expired ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .alerts import parse_timestamp, source_value
from .const import (
    DECISION_STATUS_ACTIVE,
    DECISION_STATUS_EXPIRED,
    ORIGIN_KIND_CAPI,
    ORIGIN_KIND_LISTS,
    ORIGIN_KIND_LOCAL,
    REMOTE_ORIGINS,
)

# A Go duration as CrowdSec writes it: "3h59m58.5s", "-1h30m", "168h0m0s".
# The sign belongs to the whole value — an expired decision counts backwards.
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)([a-zµ]+)")
_DURATION_UNITS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}


def _text(value: Any) -> str | None:
    """Non-empty string or ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def parse_go_duration(raw: Any) -> float | None:
    """Translate a Go duration into seconds.

    CrowdSec reports the *remaining* time as ``duration``, and once a decision
    has run out that value turns negative. The sign is therefore kept: it is
    the only hint some LAPI versions give that a decision is over.
    """
    text = _text(raw)
    if text is None:
        return None
    body = text.lower()
    sign = 1.0
    if body[0] in "+-":
        sign = -1.0 if body[0] == "-" else 1.0
        body = body[1:]

    matches = _DURATION_PART.findall(body)
    if not matches:
        return None

    total = 0.0
    for amount, unit in matches:
        factor = _DURATION_UNITS.get(unit)
        if factor is None:
            # An unknown unit makes the whole value untrustworthy — better no
            # remaining time at all than one that is wrong by a factor.
            return None
        total += float(amount) * factor
    return sign * total


def origin_kind(origin: str | None) -> str:
    """Classify where a decision comes from.

    Only local decisions can be deleted for good. CAPI and blocklist entries
    are pushed by the central API; deleting them locally would make them
    reappear on the next pull, so the card must not offer it.
    """
    normalized = (origin or "").strip().lower()
    if normalized == "capi":
        return ORIGIN_KIND_CAPI
    if normalized in REMOTE_ORIGINS:
        return ORIGIN_KIND_LISTS
    return ORIGIN_KIND_LOCAL


@dataclass(frozen=True, slots=True)
class SourceInfo:
    """What the alerts know about an address, beyond the decision itself."""

    country: str | None = None
    as_name: str | None = None
    as_number: str | None = None
    scenario: str | None = None
    created_at: datetime | None = None
    alerts: int = 0


@dataclass(slots=True)
class DecisionRecord:
    """One row of the card's table."""

    key: str
    decision_id: int | None
    origin: str | None
    origin_kind: str
    type: str | None
    scope: str | None
    value: str | None
    scenario: str | None
    duration: str | None
    until: datetime | None
    created_at: datetime | None
    country: str | None
    as_name: str | None
    as_number: str | None
    seconds_left: float | None
    status: str
    simulated: bool
    deletable: bool
    alerts_24h: int = 0

    def as_dict(self) -> dict[str, Any]:
        """JSON-serialisable form for the WebSocket answer."""
        return {
            "key": self.key,
            "id": self.decision_id,
            "origin": self.origin,
            "origin_kind": self.origin_kind,
            "type": self.type,
            "scope": self.scope,
            "value": self.value,
            "scenario": self.scenario,
            "duration": self.duration,
            "until": self.until.isoformat() if self.until else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "country": self.country,
            "as_name": self.as_name,
            "as_number": self.as_number,
            "seconds_left": (
                None if self.seconds_left is None else round(self.seconds_left)
            ),
            "status": self.status,
            "simulated": self.simulated,
            "deletable": self.deletable,
            "alerts_24h": self.alerts_24h,
        }


def _source_field(alert: dict[str, Any], key: str) -> str | None:
    source = alert.get("source")
    if not isinstance(source, dict):
        return None
    return _text(source.get(key))


def build_source_index(alerts: Iterable[dict[str, Any]]) -> dict[str, SourceInfo]:
    """Collect per address what the 24h alerts know about it.

    The most recent alert wins for country, AS and scenario — an address can
    show up in several scenarios, and the latest one describes best why it is
    banned right now.
    """
    index: dict[str, SourceInfo] = {}
    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("simulated"):
            continue
        value = source_value(alert)
        if value is None:
            continue

        created = parse_timestamp(alert.get("created_at")) or parse_timestamp(
            alert.get("start_at")
        )
        previous = index.get(value)
        count = (previous.alerts if previous else 0) + 1

        if previous is not None and previous.created_at is not None:
            if created is None or created <= previous.created_at:
                # Older alert: it only raises the counter.
                index[value] = SourceInfo(
                    country=previous.country,
                    as_name=previous.as_name,
                    as_number=previous.as_number,
                    scenario=previous.scenario,
                    created_at=previous.created_at,
                    alerts=count,
                )
                continue

        index[value] = SourceInfo(
            country=_source_field(alert, "cn"),
            as_name=_source_field(alert, "as_name"),
            as_number=_source_field(alert, "as_number"),
            scenario=_text(alert.get("scenario")),
            created_at=created,
            alerts=count,
        )
    return index


def normalize_decision(
    raw: dict[str, Any],
    now: datetime,
    index: dict[str, SourceInfo] | None = None,
) -> DecisionRecord | None:
    """Turn one ``/v1/decisions`` entry into a record.

    ``None`` for anything that is not a usable object — a decision without a
    value cannot be shown and certainly not unbanned.
    """
    if not isinstance(raw, dict):
        return None
    value = _text(raw.get("value"))
    if value is None:
        return None

    raw_id = raw.get("id")
    decision_id = (
        int(raw_id) if isinstance(raw_id, (int, float)) and not isinstance(raw_id, bool)
        else None
    )

    duration = _text(raw.get("duration"))
    seconds_left = parse_go_duration(duration)
    until = parse_timestamp(raw.get("until"))
    if until is None and seconds_left is not None:
        # Not every version sends ``until`` — derive it, otherwise the card has
        # no absolute expiry to show.
        until = now + timedelta(seconds=seconds_left)
    elif until is not None and seconds_left is None:
        seconds_left = (until - now).total_seconds()

    origin = _text(raw.get("origin"))
    kind = origin_kind(origin)
    scenario = _text(raw.get("scenario"))

    info = (index or {}).get(value, SourceInfo())
    status = (
        DECISION_STATUS_EXPIRED
        if seconds_left is not None and seconds_left <= 0
        else DECISION_STATUS_ACTIVE
    )

    return DecisionRecord(
        key=f"id:{decision_id}" if decision_id is not None else f"val:{origin}:{value}",
        decision_id=decision_id,
        origin=origin,
        origin_kind=kind,
        type=_text(raw.get("type")),
        scope=_text(raw.get("scope")),
        value=value,
        scenario=scenario or info.scenario,
        duration=duration,
        until=until,
        created_at=info.created_at,
        country=info.country,
        as_name=info.as_name,
        as_number=info.as_number,
        seconds_left=seconds_left,
        status=status,
        simulated=bool(raw.get("simulated")),
        # An ID is what makes a targeted delete possible at all; without one
        # only the "all decisions for this IP" route remains.
        deletable=kind == ORIGIN_KIND_LOCAL,
        alerts_24h=info.alerts,
    )


def normalize_decisions(
    raw: Iterable[Any],
    now: datetime,
    index: dict[str, SourceInfo] | None = None,
) -> list[DecisionRecord]:
    """Normalise a whole response, skipping what cannot be used."""
    records = []
    for entry in raw:
        record = normalize_decision(entry, now, index)
        if record is not None:
            records.append(record)
    return records


def history_from_alerts(
    alerts: Iterable[dict[str, Any]],
    active: Iterable[DecisionRecord],
    now: datetime,
) -> list[DecisionRecord]:
    """Bans of the last 24 hours that are no longer being enforced.

    The active decisions are passed in so their addresses can be skipped: a ban
    that is still running is already in the table with live data, and a second
    row from the alert history would only duplicate it.
    """
    covered = {record.value for record in active if record.value}
    history: list[DecisionRecord] = []
    seen: set[str] = set()

    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("simulated"):
            continue

        created = parse_timestamp(alert.get("created_at")) or parse_timestamp(
            alert.get("start_at")
        )
        country = _source_field(alert, "cn")
        as_name = _source_field(alert, "as_name")
        as_number = _source_field(alert, "as_number")
        scenario = _text(alert.get("scenario"))

        for decision in alert.get("decisions") or []:
            if not isinstance(decision, dict):
                continue
            value = _text(decision.get("value"))
            if value is None or value in covered:
                continue

            duration = _text(decision.get("duration"))
            seconds = parse_go_duration(duration)
            until = created + timedelta(seconds=seconds) if (
                created is not None and seconds is not None
            ) else None
            if until is not None and until > now:
                # Still running, but not in the decision list — the LAPI query
                # may have failed. Trust the live list and leave it out.
                continue

            origin = _text(decision.get("origin"))
            key = f"hist:{value}:{scenario}:{created.isoformat() if created else '?'}"
            if key in seen:
                continue
            seen.add(key)

            history.append(
                DecisionRecord(
                    key=key,
                    decision_id=None,
                    origin=origin,
                    origin_kind=origin_kind(origin),
                    type=_text(decision.get("type")),
                    scope=_text(decision.get("scope")),
                    value=value,
                    scenario=scenario or _text(decision.get("scenario")),
                    duration=duration,
                    until=until,
                    created_at=created,
                    country=country,
                    as_name=as_name,
                    as_number=as_number,
                    seconds_left=(
                        (until - now).total_seconds() if until is not None else None
                    ),
                    status=DECISION_STATUS_EXPIRED,
                    simulated=False,
                    # Nothing left to delete — the decision is gone already.
                    deletable=False,
                )
            )

    return history


def build_table(
    raw_decisions: Iterable[Any],
    alerts: Iterable[dict[str, Any]],
    now: datetime | None = None,
    include_history: bool = True,
) -> list[DecisionRecord]:
    """Everything the card shows, in one list, newest expiry first."""
    moment = now or datetime.now(timezone.utc)
    alert_list = [alert for alert in alerts if isinstance(alert, dict)]

    index = build_source_index(alert_list)
    active = normalize_decisions(raw_decisions, moment, index)

    rows = list(active)
    if include_history:
        rows.extend(history_from_alerts(alert_list, active, moment))

    # Active first, then by remaining time — that is the order someone
    # skimming the table for "who is banned right now" expects.
    def order(record: DecisionRecord) -> tuple[int, float]:
        active_first = 0 if record.status == DECISION_STATUS_ACTIVE else 1
        remaining = record.seconds_left
        if remaining is None:
            remaining = float("-inf") if active_first else float("inf")
        return (active_first, -remaining)

    rows.sort(key=order)
    return rows
