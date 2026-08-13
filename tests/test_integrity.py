"""Tests, die Manifest, Konstanten und Übersetzungen zusammenhalten.

Diese Dateien werden von Hand gepflegt und laufen sonst unbemerkt
auseinander — ein fehlender Schlüssel fällt erst in der Oberfläche auf.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COMPONENT = (
    Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec"
)
sys.path.insert(0, str(COMPONENT))

import const  # noqa: E402

MANIFEST = json.loads((COMPONENT / "manifest.json").read_text(encoding="utf-8"))
STRINGS = json.loads((COMPONENT / "strings.json").read_text(encoding="utf-8"))
TRANSLATIONS = sorted((COMPONENT / "translations").glob("*.json"))


def _keys(node, prefix=""):
    """Alle Blattpfade eines verschachtelten Dicts."""
    if not isinstance(node, dict):
        return {prefix}
    result = set()
    for key, value in node.items():
        result |= _keys(value, f"{prefix}.{key}" if prefix else key)
    return result


def test_version_comes_from_the_manifest():
    assert const.INTEGRATION_VERSION == MANIFEST["version"]
    assert const.INTEGRATION_VERSION != "0.0.0"


def test_user_agent_is_parseable_by_crowdsec():
    # CrowdSec legt den User-Agent als Version der Machine ab und erwartet
    # genau ein "name/version" — sonst scheitert der Login mit 401.
    name, _, version = const.USER_AGENT.partition("/")
    assert name and version
    assert "/" not in version
    assert " " not in const.USER_AGENT


def test_domain_matches_manifest():
    assert const.DOMAIN == MANIFEST["domain"]


def test_translations_exist():
    assert TRANSLATIONS, "keine Übersetzungsdateien gefunden"


def test_translations_cover_all_strings():
    expected = _keys(STRINGS)
    for path in TRANSLATIONS:
        actual = _keys(json.loads(path.read_text(encoding="utf-8")))
        assert not expected - actual, f"{path.name} fehlen: {sorted(expected - actual)}"
        assert not actual - expected, f"{path.name} hat zu viel: {sorted(actual - expected)}"


def test_services_are_documented():
    """Jeder in services.yaml angebotene Dienst braucht einen Text."""
    raw = (COMPONENT / "services.yaml").read_text(encoding="utf-8")
    declared = {
        line.split(":")[0]
        for line in raw.splitlines()
        if line and not line[0].isspace() and line.rstrip().endswith(":")
    }
    assert declared == {
        const.SERVICE_BAN_IP,
        const.SERVICE_UNBAN_IP,
        const.SERVICE_REFRESH,
    }
    assert declared == set(STRINGS["services"])
