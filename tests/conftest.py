"""Gemeinsame Testeinrichtung.

Die Module der Integration verweisen mit relativen Importen aufeinander
(``from .const import …``). Flach geladen scheitert das, und über
``custom_components.crowdsec`` geladen zöge es ``__init__.py`` samt Home
Assistant herein. Deshalb wird das Verzeichnis hier als eigenes Paket
angemeldet, ohne dessen ``__init__.py`` auszuführen: Relative Importe lösen
sich damit auf, die HA-Abhängigkeit bleibt außen vor.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec"

# Name bewusst nicht "crowdsec": Er darf nicht mit einem echten Paket
# kollidieren, das jemand parallel installiert hat.
PACKAGE = "crowdsec_component"


def register_package() -> None:
    """Melde das Komponentenverzeichnis als importierbares Paket an."""
    if PACKAGE in sys.modules:
        return
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package


register_package()

# Daneben bleibt der flache Import erhalten — die älteren Testmodule laden
# rates und metrics direkt.
if str(COMPONENT) not in sys.path:
    sys.path.insert(0, str(COMPONENT))
