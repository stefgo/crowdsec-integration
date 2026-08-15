"""Shared test setup.

The modules of the integration reference each other with relative imports
(``from .const import …``). Loaded flat that fails, and loaded via
``custom_components.crowdsec`` it would pull in ``__init__.py`` together with
Home Assistant. The directory is therefore registered here as a package of its
own, without executing its ``__init__.py``: relative imports resolve, while the
HA dependency stays out.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec"

# Deliberately not named "crowdsec": it must not collide with a real package
# somebody has installed alongside.
PACKAGE = "crowdsec_component"


def register_package() -> None:
    """Register the component directory as an importable package."""
    if PACKAGE in sys.modules:
        return
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package


register_package()

# The flat import stays available alongside — the older test modules load
# rates and metrics directly.
if str(COMPONENT) not in sys.path:
    sys.path.insert(0, str(COMPONENT))
