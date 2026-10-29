"""Finding the Collector's own console script, so a service can launch it."""

from __future__ import annotations

import shutil
import sys
from collections.abc import Callable
from pathlib import Path

from scanner_agent.collector_version_constants import (
    COLLECTOR_PACKAGE_NAME,
    COLLECTOR_PACKAGE_SOURCE,
    COLLECTOR_VENV_DIR,
    COLLECTOR_WINDOWS_VENV_DIR,
)
from scanner_agent.service_constants import COLLECTOR_EXECUTABLE
from scanner_agent.service_contracts import ServiceError


def resolve_collector_executable(
    name: str = COLLECTOR_EXECUTABLE,
    *,
    python_executable: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    exists: Callable[[Path], bool] = Path.is_file,
) -> str:
    """The absolute path of the ``risklence-scanner`` script.

    The environment this process is running in is asked first (its ``bin`` or,
    on Windows, its ``Scripts`` folder), because on Windows the Scripts folder is
    often not on ``PATH`` after a pip or pipx install. ``PATH`` is the fallback.
    """
    python = Path(python_executable or sys.executable)
    for candidate in (python.parent / name, python.parent / "Scripts" / name):
        if exists(candidate):
            return str(candidate)
    found = which(name)
    if found is None:
        raise ServiceError(
            f"Could not find the `{name}` program. Install the Collector first "
            f"(Mac and Linux: `{COLLECTOR_VENV_DIR}/bin/pip install {COLLECTOR_PACKAGE_SOURCE}` "
            f"after `python3 -m venv {COLLECTOR_VENV_DIR}`; Windows: "
            f"`{COLLECTOR_WINDOWS_VENV_DIR}\\Scripts\\pip.exe install {COLLECTOR_PACKAGE_SOURCE}` "
            f"after `python -m venv {COLLECTOR_WINDOWS_VENV_DIR}`), then run this again."
        )
    return str(Path(found))
