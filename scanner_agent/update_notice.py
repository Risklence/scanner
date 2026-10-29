"""The plain-language notice that a newer Collector is available.

Notice only. It never blocks a heartbeat, a scan or a self-check, and it stays
silent whenever either version is unknown (a dev image, an older platform).

The steps depend on how this Collector was installed: a container is rebuilt and
replaced; a local install (its own private folder, on every OS) is
upgraded with its own pip and its service restarted. Either
way the existing identity is kept and ``activate`` is never the answer.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from scanner_agent.collector_version import is_newer_collector_version
from scanner_agent.collector_version_constants import (
    COLLECTOR_CONTAINER_NAME,
    COLLECTOR_PACKAGE_NAME,
    COLLECTOR_REBUILD_COMMAND,
    COLLECTOR_UPGRADE_COMMAND,
    COLLECTOR_VENV_EXECUTABLE,
    COLLECTOR_VENV_UPGRADE_COMMAND,
    COLLECTOR_WINDOWS_VENV_EXECUTABLE,
    COLLECTOR_WINDOWS_VENV_UPGRADE_COMMAND,
)
from scanner_agent.install_method import detect_install_method
from scanner_agent.install_method_contracts import InstallMethod
from scanner_agent.service import restart_commands


def collector_version_line(current: str | None) -> str:
    """The 'Collector version' line of the self-check output."""
    return f"Collector version: {current or 'unknown'}"


def _headline(current: str | None, latest: str | None) -> list[str]:
    return [
        f"A newer Risklence Collector is available (you run {current}, the latest is {latest}).",
        "Long scans may not finish on the older Collector, so please update it.",
    ]


_NEVER_ACTIVATE = (
    "Never run `activate` for an existing scanner: it is only for a new one."
)


def _container_steps(container_name: str | None) -> list[str]:
    return [
        "To update and keep this scanner's identity:",
        f"  1. Rebuild the image: {COLLECTOR_REBUILD_COMMAND}",
        f"  2. Remove the container: docker rm -f {container_name or COLLECTOR_CONTAINER_NAME}",
        "  3. Start it again with the same `run` command, on the same data volume.",
        _NEVER_ACTIVATE,
    ]


_UPGRADE_LINE: dict[InstallMethod, str] = {
    InstallMethod.PIPX: f"Upgrade the program: {COLLECTOR_UPGRADE_COMMAND}",
    # Not made by our install line: the right command depends on how it was put there.
    InstallMethod.LOCAL: (
        "Upgrade the program with the tool you installed it with "
        f"(`pip install --upgrade {COLLECTOR_PACKAGE_NAME}` in its environment, "
        f"or `{COLLECTOR_UPGRADE_COMMAND}` if you used pipx)"
    ),
}


def _is_windows() -> bool:
    return sys.platform == "win32"


def _upgrade_line(method: InstallMethod, windows: bool) -> str:
    if method is InstallMethod.VENV:
        command = (
            COLLECTOR_WINDOWS_VENV_UPGRADE_COMMAND
            if windows
            else COLLECTOR_VENV_UPGRADE_COMMAND
        )
        return f"Upgrade the program: {command}"
    return _UPGRADE_LINE[method]


def _program(method: InstallMethod, windows: bool) -> str:
    """How this install's own command is typed: by path when it is not on PATH."""
    if method is InstallMethod.VENV:
        return (
            COLLECTOR_WINDOWS_VENV_EXECUTABLE if windows else COLLECTOR_VENV_EXECUTABLE
        )
    return COLLECTOR_PACKAGE_NAME


def _local_steps(
    restart: tuple[str, ...], method: InstallMethod, windows: bool, scanner_key: str | None = None
) -> list[str]:
    program = _program(method, windows)
    # Named, on a computer that runs several scanners' Collectors, so the one restarted is this scanner's.
    named = f" --scanner {scanner_key}" if scanner_key else ""
    restart_text = " and then ".join(f"`{command}`" for command in restart)
    return [
        "To update and keep this scanner's identity (its credentials stay where they are):",
        f"  1. {_upgrade_line(method, windows)}",
        (
            f"  2. If you installed it as a service (`{program} install{named}`), restart it: {restart_text}"
            if restart
            else "  2. If it runs as a service, restart that service."
        ),
        f"     If you started it yourself with `{program} run{named}`, stop it (Ctrl+C) and start it again.",
        _NEVER_ACTIVATE,
    ]


def update_notice(
    current: str | None,
    latest: str | None,
    container_name: str | None = None,
    *,
    install_method: Callable[[], InstallMethod] = detect_install_method,
    restart: Callable[[], tuple[str, ...]] = restart_commands,
    is_windows: Callable[[], bool] = _is_windows,
    scanner_key: str | None = None,
) -> str | None:
    """The notice text, or ``None`` when there is nothing to say.

    ``container_name`` is this scanner's own container, as the platform named it
    in the heartbeat. An older platform names none, and the notice then falls
    back to the original shared container name. ``install_method`` and
    ``restart`` are injected so a test never inspects the real machine.
    """
    if not is_newer_collector_version(latest, current):
        return None
    method = install_method()
    steps = (
        _container_steps(container_name)
        if method is InstallMethod.CONTAINER
        else _local_steps(restart(), method, is_windows(), scanner_key)
    )
    return "\n".join([*_headline(current, latest), *steps])
