"""Cooperating writers share a reentrant, cross-process journal lock."""

from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import SentinelError

_registry_guard = threading.Lock()
_registry: dict[str, tuple[threading.RLock, threading.local]] = {}


@contextmanager
def journal_lock(path: Path) -> Iterator[None]:
    """Lock a persistent sidecar; never unlink it while writers may be alive."""
    name = os.path.normcase(str(path.resolve()))
    with _registry_guard:
        mutex, state = _registry.setdefault(name, (threading.RLock(), threading.local()))
    with mutex:
        if getattr(state, "active", False):
            yield
            return
        lock_path = Path(name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + 10
            while True:
                try:
                    handle.seek(0)
                    if sys.platform == "win32":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise SentinelError(f"timed out locking journal {path}") from exc
                    time.sleep(0.01)
            state.active = True
            try:
                yield
            finally:
                state.active = False
                handle.seek(0)
                if sys.platform == "win32":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
