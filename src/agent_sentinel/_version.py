"""The single definition of the version string.

It lives in its own module so that anything inside the package -- including
modules imported *by* ``agent_sentinel/__init__.py`` -- can read it without
running into a partially initialised package.
"""

from __future__ import annotations

__version__ = "0.1.0"
