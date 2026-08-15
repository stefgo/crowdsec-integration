"""Checks on the input validation of the services and the WebSocket API."""

from __future__ import annotations

import pytest
from crowdsec_component.validation import normalize_ban_duration, normalize_ip_target


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3.4", "1.2.3.4"),
        ("  1.2.3.4  ", "1.2.3.4"),
        ("2001:0db8::1", "2001:db8::1"),
        ("::1", "::1"),
        ("10.0.0.0/24", "10.0.0.0/24"),
        # Host bits set: someone copied the address out of a log line and
        # appended the prefix — that is the network they mean.
        ("10.0.0.5/24", "10.0.0.0/24"),
        ("2001:db8::/32", "2001:db8::/32"),
    ],
)
def test_valid_addresses(raw, expected):
    assert normalize_ip_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        # All of these passed the old pattern and only failed at the LAPI.
        "1.2.3.4.5",
        "::::",
        "1.2.3.4/999",
        "999.1.1.1",
        "...",
        "localhost",
        "1.2.3.4 ; rm -rf /",
    ],
)
def test_invalid_addresses(raw):
    with pytest.raises(ValueError):
        normalize_ip_target(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "4h",
        "30m",
        "90s",
        # Composite durations: the old pattern rejected these, even though the
        # integration's own parser reads them without trouble.
        "1h30m",
        "168h0m0s",
        "1.5h",
    ],
)
def test_valid_durations(raw):
    assert normalize_ban_duration(raw) == raw


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "4",
        "h",
        "-4h",
        "0s",
        "4 hours",
        # Go has no day unit and neither does CrowdSec's parser.
        "1d",
        "7d12h",
    ],
)
def test_invalid_durations(raw):
    with pytest.raises(ValueError):
        normalize_ban_duration(raw)


def test_duration_keeps_the_spelling():
    """The value goes to CrowdSec unchanged — only the whitespace is dropped."""
    assert normalize_ban_duration("  12h  ") == "12h"
