"""The one small interface every platform's service manager implements, and the
values it exchanges with the CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class ServiceError(RuntimeError):
    """Raised when the service cannot be installed, removed or inspected."""


@dataclass(frozen=True)
class ServiceNames:
    """What one scanner's service is called, and what it runs (``service_constants.service_names``)."""

    launchd_label: str
    systemd_unit: str
    windows_task: str
    #: Added to the log file's name ("scanner-<key>.log"); empty for the unnamed service, which keeps its log.
    log_suffix: str
    #: The Collector's arguments, after its executable.
    run_arguments: tuple[str, ...]


@dataclass(frozen=True)
class InstallOptions:
    #: Linux only: also run ``loginctl enable-linger`` so the user service starts
    #: at boot and survives logout. Ignored elsewhere.
    enable_linger: bool = False


@dataclass(frozen=True)
class ServiceInstallResult:
    #: Plain-language name of what was installed, e.g. "systemd --user service".
    kind: str
    #: Where its definition lives (a file path or a task name).
    location: str
    #: Things the person must know afterwards (when it starts, how to see logs).
    notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ServiceStatus:
    installed: bool
    #: ``None`` when the platform could not tell.
    running: bool | None
    detail: str
    hint: str = ""


class ServiceManager(Protocol):
    """One implementation per operating system; ``service.py`` picks one."""

    kind: str

    def install(self, options: InstallOptions) -> ServiceInstallResult: ...

    def uninstall(self) -> None: ...

    def status(self) -> ServiceStatus: ...

    def restart_commands(self) -> tuple[str, ...]: ...
