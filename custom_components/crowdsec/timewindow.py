"""Time windows for the alert query.

The LAPI has no pagination — it truncates at ``limit``. To get all alerts of a
period anyway, a truncated window is halved and queried again in parts. The
maths behind that is pure arithmetic and therefore lives here, separate from
the HTTP client.
"""

from __future__ import annotations

from typing import NamedTuple

# Splitting finer than a minute is not worth it: if more alerts occur within
# 60 seconds than the limit allows, only a higher limit helps.
MIN_WINDOW_MINUTES = 1


class Window(NamedTuple):
    """A half-open period, counted in minutes backwards from now.

    ``start`` lies further in the past than ``end`` — ``Window(1440, 0)`` is
    the last 24 hours.
    """

    start: int
    end: int

    @property
    def minutes(self) -> int:
        return self.start - self.end


def parse_duration(text: str) -> int | None:
    """Translate a CrowdSec duration such as ``24h`` or ``90m`` into minutes."""
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
    """Query parameters for ``/v1/alerts``.

    ``until`` is omitted for the most recent window — otherwise alerts that
    arrive between two partial queries would be missing.
    """
    params = {"since": f"{window.start}m"}
    if window.end > 0:
        params["until"] = f"{window.end}m"
    return params


def split_window(window: Window) -> tuple[Window, Window] | None:
    """Halve a window; ``None`` if it is too small to split.

    Returns (older part, newer part) — they are queried in that order so that
    the order of the alerts is roughly preserved.
    """
    if window.minutes < 2 * MIN_WINDOW_MINUTES:
        return None
    middle = window.end + window.minutes // 2
    return Window(window.start, middle), Window(middle, window.end)
