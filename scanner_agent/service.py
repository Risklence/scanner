"""Run the Collector as an operating-system service (start at boot or logon).

The Docker installation method does not need any of this: a container's own
restart policy and ``docker stop`` / ``docker rm`` already are its pause and
uninstall. This module is for the ``local_cli`` / ``server`` installation
methods, where nothing else keeps the process alive.

One module per platform, all behind ``ServiceManager``; this file only chooses
one by operating system. Adding a platform is a new module and one registry
entry, not an edit to the others.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from scanner_agent.service_contracts import (
    InstallOptions,
    ServiceError,
    ServiceInstallResult,
    ServiceManager,
    ServiceStatus,
)
from scanner_agent.service_launchd import LaunchdServiceManager
from scanner_agent.service_systemd import SystemdServiceManager
from scanner_agent.service_windows import WindowsTaskServiceManager

__all__ = [
    "ServiceError",
    "current_service_manager",
    "install_service",
    "restart_commands",
    "service_status",
    "uninstall_service",
]

#: ``sys.platform`` prefix to the manager for that operating system.
_MANAGERS: dict[str, Callable[..., ServiceManager]] = {
    "linux": SystemdServiceManager,
    "darwin": LaunchdServiceManager,
    "win32": WindowsTaskServiceManager,
}


def current_service_manager(
    platform: str | None = None, scanner_key: str | None = None
) -> ServiceManager:
    """``scanner_key`` names the scanner whose service it is: one per scanner on a computer that runs several."""
    name = platform or sys.platform
    for prefix, factory in _MANAGERS.items():
        if name.startswith(prefix):
            return factory(scanner_key=scanner_key)
    raise ServiceError(f"Running as a service is not supported on this operating system ({name}).")


def install_service(
    options: InstallOptions | None = None, manager: ServiceManager | None = None
) -> ServiceInstallResult:
    return (manager or current_service_manager()).install(options or InstallOptions())


def uninstall_service(manager: ServiceManager | None = None) -> None:
    (manager or current_service_manager()).uninstall()


def service_status(manager: ServiceManager | None = None) -> ServiceStatus:
    return (manager or current_service_manager()).status()


def restart_commands(manager: ServiceManager | None = None) -> tuple[str, ...]:
    try:
        return (manager or current_service_manager()).restart_commands()
    except ServiceError:
        return ()
