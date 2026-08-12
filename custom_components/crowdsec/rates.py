"""Ratenbildung aus monoton steigenden Countern.

CrowdSec liefert ``*_total``-Metriken als Counter. Für „pro Minute"-Werte muss
die Integration zwei aufeinanderfolgende Messungen vergleichen. Startet der
Dienst neu, springen alle Counter auf null zurück — das darf nicht als
negativer Durchsatz durchschlagen, deshalb wird ein Neustart erkannt und das
betroffene Intervall verworfen.
"""

from __future__ import annotations

from dataclasses import dataclass

# Toleranz beim Vergleich von ``process_start_time_seconds`` in Sekunden.
START_TIME_TOLERANCE = 1.0


@dataclass(frozen=True, slots=True)
class RateWindow:
    """Ergebnis eines gültigen Vergleichs zweier Messungen."""

    deltas: dict[str, float]
    elapsed: float

    def per_minute(self, key: str) -> float | None:
        """Zuwachs eines Counters pro Minute."""
        if key not in self.deltas or self.elapsed <= 0:
            return None
        return self.deltas[key] / self.elapsed * 60.0


class RateTracker:
    """Hält die letzte Messung und liefert Deltas zur aktuellen."""

    def __init__(self) -> None:
        self._counters: dict[str, float] | None = None
        self._start_time: float | None = None
        self._timestamp: float | None = None

    def reset(self) -> None:
        """Verwirf den Verlauf, etwa nach einem fehlgeschlagenen Scrape."""
        self._counters = None
        self._start_time = None
        self._timestamp = None

    def update(
        self,
        counters: dict[str, float],
        start_time: float | None,
        timestamp: float,
    ) -> RateWindow | None:
        """Nimm eine Messung auf und liefere das Fenster zur vorigen.

        ``None`` bedeutet: kein belastbarer Vergleich möglich — erste Messung,
        Neustart des Dienstes oder ein zurückgesprungener Counter.
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
                # Counter-Rücksprung ohne erkennbaren Neustart: Intervall
                # komplett verwerfen statt einzelne Werte zu raten.
                return None
            deltas[key] = value - before

        if not deltas:
            return None

        return RateWindow(deltas=deltas, elapsed=elapsed)


def error_ratio(ok: float | None, ko: float | None) -> float | None:
    """Fehleranteil in Prozent aus einem ok/ko-Paar."""
    if ok is None or ko is None:
        return None
    total = ok + ko
    if total <= 0:
        return None
    return ko / total * 100.0
