"""Validation of the values a user hands to the services and the card.

Like :mod:`alerts` and :mod:`decisions` this module is deliberately free of
Home Assistant imports — it is pure input checking and is tested without the
framework.

Both functions raise :class:`ValueError`; turning that into a
``ServiceValidationError`` or a WebSocket error is the caller's job, because
only the caller knows which translation key belongs to it.
"""

from __future__ import annotations

import ipaddress

from .decisions import parse_go_duration


def normalize_ip_target(raw: str) -> str:
    """Check an address or a CIDR range and return it in normal form.

    CrowdSec uses the scope ``Ip`` for both a single address and a range, so
    both are allowed here. The check goes through :mod:`ipaddress` rather than
    a pattern: a regular expression over the character set of an address lets
    ``1.2.3.4.5``, ``::::`` and a ``/999`` prefix through, and those only fail
    later at the LAPI — with an error message that says nothing about what was
    actually wrong.

    A range is returned in its network form (``10.0.0.5/24`` becomes
    ``10.0.0.0/24``), because that is what CrowdSec stores and what a
    subsequent unban has to match.
    """
    text = raw.strip()
    if not text:
        raise ValueError("Empty address")

    if "/" in text:
        # strict=False: host bits set are not an error, they are the normal
        # case when someone copies an address out of a log line.
        return str(ipaddress.ip_network(text, strict=False))
    return str(ipaddress.ip_address(text))


def normalize_ban_duration(raw: str) -> str:
    """Check a ban duration and return it the way CrowdSec expects it.

    The format is the one of ``cscli``: a Go duration such as ``4h``, ``30m``
    or ``1h30m``. The previous pattern only allowed a single unit, which meant
    the services rejected values that this integration's own duration parser
    understands perfectly well — the two now share one definition.

    Days are worth a note: Go itself has no ``d`` unit and CrowdSec's own
    parser rejects it, so it is refused here rather than being passed on and
    failing at the LAPI.
    """
    text = raw.strip()
    if not text:
        raise ValueError("Empty duration")
    if "d" in text.lower():
        raise ValueError(
            "CrowdSec does not know the unit 'd' — use hours instead (e.g. 168h)"
        )

    seconds = parse_go_duration(text)
    if seconds is None:
        raise ValueError(f"Unusable duration: {text!r}")
    if seconds <= 0:
        raise ValueError("The duration has to be positive")
    return text
