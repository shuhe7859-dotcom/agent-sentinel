"""Shared test setup.

Putting ``src`` on the path lets the suite run straight from a checkout, without
requiring ``pip install -e .`` first.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
