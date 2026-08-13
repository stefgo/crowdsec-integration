"""Zeitfenster für die Alert-Abfrage.

Die LAPI kennt keine Pagination — sie schneidet bei ``limit`` ab. Um trotzdem
an alle Alerts eines Zeitraums zu kommen, wird ein abgeschnittenes Fenster
halbiert und in Teilen erneut abgefragt. Die Rechnerei dahinter ist reine
Arithmetik und liegt deshalb hier, getrennt vom HTTP-Client.
"""

from __future__ import annotations

from typing import NamedTuple

# Feiner als eine Minute lohnt das Aufteilen nicht: Wenn in 60 Sekunden mehr
# Alerts anfallen als das Limit erlaubt, hilft nur ein höheres Limit.
MIN_WINDOW_MINUTES = 1


class Window(NamedTuple):
    """Ein halboffener Zeitraum, in Minuten rückwärts von jetzt gerechnet.

    ``start`` liegt weiter in der Vergangenheit als ``end`` — ``Window(1440, 0)``
    sind die letzten 24 Stunden.
    """

    start: int
    end: int

    @property
    def minutes(self) -> int:
        return self.start - self.end


def parse_duration(text: str) -> int | None:
    """Übersetze eine CrowdSec-Dauer wie ``24h`` oder ``90m`` in Minuten."""
    value = text.strip().lower()
    if not value:
        return None

    units = {"m": 1, "h": 60, "d": 1440}
    factor = units.get(value[-1])
    if factor is None:
        return None
    try:
        amount = float(value[:-1])
    except ValueError:
        return None
    if amount <= 0:
        return None
    return max(1, int(round(amount * factor)))


def window_params(window: Window) -> dict[str, str]:
    """Query-Parameter für ``/v1/alerts``.

    ``until`` bleibt beim jüngsten Fenster weg — sonst würden Alerts fehlen,
    die zwischen zwei Teilabfragen eintreffen.
    """
    params = {"since": f"{window.start}m"}
    if window.end > 0:
        params["until"] = f"{window.end}m"
    return params


def split_window(window: Window) -> tuple[Window, Window] | None:
    """Halbiere ein Fenster; ``None``, wenn es zu klein zum Teilen ist.

    Zurück kommt (älterer Teil, jüngerer Teil) — in dieser Reihenfolge werden
    sie auch abgefragt, damit die Reihenfolge der Alerts grob erhalten bleibt.
    """
    if window.minutes < 2 * MIN_WINDOW_MINUTES:
        return None
    middle = window.end + window.minutes // 2
    return Window(window.start, middle), Window(middle, window.end)
