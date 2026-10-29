"""The ``PATH`` a service runs with.

A user service does not inherit the shell's ``PATH``, so without this nmap from
Homebrew or a tool the installer put in ``~/.local/bin`` would be "missing" only
when run as a service. Holds no secrets: directories only.
"""

from __future__ import annotations

from pathlib import Path

from scanner_agent.service_constants import SERVICE_EXTRA_PATH_DIRS


def service_search_path(executable: str, home: Path, separator: str = ":") -> str:
    ordered: list[str] = [str(Path(executable).parent)]
    for entry in SERVICE_EXTRA_PATH_DIRS:
        ordered.append(str(home / entry[2:]) if entry.startswith("~/") else entry)
    unique = list(dict.fromkeys(ordered))
    return separator.join(unique)
