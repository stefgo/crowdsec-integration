"""Rate calculation from monotonically increasing counters.

CrowdSec exposes ``*_total`` metrics as counters. For "per minute" values the
integration has to compare two consecutive measurements. When the service
restarts, all counters jump back to zero — that must not show up as negative
throughput, so a restart is detected and the affected interval is discarded.
"""

from __future__ import annotations

from dataclasses import dataclass

# Tolerance when comparing ``process_start_time_seconds``, in seconds.
START_TIME_TOLERANCE = 1.0


@dataclass(frozen=True, slots=True)
class RateWindow:
    """Result of a valid comparison of two measurements."""

    deltas: dict[str, float]
    elapsed: float

    def per_minute(self, key: str) -> float | None:
        """Increase of a counter per minute."""
        if key not in self.deltas or self.elapsed <= 0:
            return None
        return self.deltas[key] / self.elapsed * 60.0


class RateTracker:
    """Keeps the last measurement and returns deltas to the current one."""

    def __init__(self) -> None:
        self._counters: dict[str, float] | None = None
        self._start_time: float | None = None
        self._timestamp: float | None = None

    def reset(self) -> None:
        """Discard the history, e.g. after a failed scrape."""
        self._counters = None
        self._start_time = None
        self._timestamp = None

    def update(
        self,
        counters: dict[str, float],
        start_time: float | None,
        timestamp: float,
    ) -> RateWindow | None:
        """Record a measurement and return the window to the previous one.

        ``None`` means: no reliable comparison possible — first measurement,
        restart of the service, or a counter that jumped backwards.
        """
        previous = self._counters
        previous_start = self._start_time
        previous_timestamp = self._timestamp

        self._counters = dict(counters)
        self._start_time = start_time
        self._timestamp = timestamp

        if previous is None or previous_timestamp is None:
            return None

        elapsed = timestamp - previous_timestamp
        if elapsed <= 0:
            return None

        restarted = (
            start_time is not None
            and previous_start is not None
            and abs(start_time - previous_start) > START_TIME_TOLERANCE
        )
        if restarted:
            return None

        deltas: dict[str, float] = {}
        for key, value in counters.items():
            before = previous.get(key)
            if before is None:
                continue
            if value < before:
                # Counter jumped backwards without a detectable restart:
                # discard the whole interval instead of guessing single values.
                return None
            deltas[key] = value - before

        if not deltas:
            return None

        return RateWindow(deltas=deltas, elapsed=elapsed)


def error_ratio(ok: float | None, ko: float | None) -> float | None:
    """Error share in percent from an ok/ko pair.

    If one of the two values is missing, it counts as 0: CrowdSec only exports
    ``cs_parser_hits_ko_total`` after the first parse error, but an error-free
    parser should show 0 % instead of "unknown". ``None`` is reserved for the
    case "no data at all".
    """
    if ok is None and ko is None:
        return None
    ok = ok or 0.0
    ko = ko or 0.0
    total = ok + ko
    if total <= 0:
        return None
    return ko / total * 100.0
