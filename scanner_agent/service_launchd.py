"""macOS: a per-user LaunchAgent.

A LaunchAgent runs while its user is logged in (from login, and again after a
crash); a machine that has rebooted but where nobody has logged in yet is not
covered. Covering that needs a system-wide LaunchDaemon, which needs root, and
this CLI does not do that. Logs go under ``~/Library/Logs/Risklence``.
"""

from __future__ import annotations

import os
import plistlib
from collections.abc import Callable
from pathlib import Path

from scanner_agent.command_runner import CommandRunner, run_captured
from scanner_agent.service_constants import service_names
from scanner_agent.service_contracts import (
    InstallOptions,
    ServiceError,
    ServiceInstallResult,
    ServiceNames,
    ServiceStatus,
)
from scanner_agent.service_executable import resolve_collector_executable
from scanner_agent.service_paths import service_search_path

#: Seconds launchd waits before restarting a process that exited.
_RESTART_THROTTLE_SECONDS = 10


def render_plist(executable: str, home: Path, log_path: Path, names: ServiceNames | None = None) -> bytes:
    """The LaunchAgent definition. Holds no credential: that stays in the
    credentials file under the user's home."""
    names = names or service_names()
    definition = {
        "Label": names.launchd_label,
        "ProgramArguments": [executable, *names.run_arguments],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": _RESTART_THROTTLE_SECONDS,
        "ProcessType": "Background",
        "EnvironmentVariables": {"PATH": service_search_path(executable, home)},
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(log_path),
    }
    return plistlib.dumps(definition)


class LaunchdServiceManager:
    kind = "launchd LaunchAgent"

    def __init__(
        self,
        runner: CommandRunner = run_captured,
        *,
        home: Path | None = None,
        uid: Callable[[], int] = os.getuid,
        resolve_executable: Callable[[], str] = resolve_collector_executable,
        scanner_key: str | None = None,
    ) -> None:
        self._names = service_names(scanner_key)
        self._runner = runner
        self._home = home or Path.home()
        self._uid = uid
        self._resolve_executable = resolve_executable

    @property
    def plist_path(self) -> Path:
        return self._home / "Library" / "LaunchAgents" / f"{self._names.launchd_label}.plist"

    @property
    def log_path(self) -> Path:
        return self._home / "Library" / "Logs" / "Risklence" / f"scanner{self._names.log_suffix}.log"

    @property
    def _domain(self) -> str:
        return f"gui/{self._uid()}"

    @property
    def _target(self) -> str:
        return f"{self._domain}/{self._names.launchd_label}"

    def install(self, options: InstallOptions) -> ServiceInstallResult:
        """Write the plist and load it. Idempotent: an already loaded agent is
        unloaded first, because ``bootstrap`` refuses one that is already there."""
        executable = self._resolve_executable()
        self.plist_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.plist_path.write_bytes(render_plist(executable, self._home, self.log_path, self._names))
        self._runner(["launchctl", "bootout", self._target])
        result = self._runner(["launchctl", "bootstrap", self._domain, str(self.plist_path)])
        if not result.ok:
            raise ServiceError(
                f"launchctl bootstrap failed: {(result.stderr or result.stdout).strip()}"
            )
        return ServiceInstallResult(
            self.kind,
            str(self.plist_path),
            (
                "It starts when you log in and restarts if it stops. It does not run on a Mac that has "
                "rebooted but where nobody has logged in yet (that needs a system service and root).",
                f"Its log: {self.log_path}",
            ),
        )

    def uninstall(self) -> None:
        """Unload and remove the agent. Safe when it was never installed."""
        if not self.plist_path.exists():
            return
        self._runner(["launchctl", "bootout", self._target])
        self.plist_path.unlink()

    def status(self) -> ServiceStatus:
        if not self.plist_path.exists():
            return ServiceStatus(
                False, False, "not installed", "Install it with: risklence-scanner install"
            )
        result = self._runner(["launchctl", "print", self._target])
        if not result.ok:
            return ServiceStatus(
                True,
                False,
                "installed but not loaded",
                "Load it again with: risklence-scanner install",
            )
        running = "state = running" in result.stdout
        return ServiceStatus(
            True, running, "running" if running else "loaded, not running", f"Log: {self.log_path}"
        )

    def restart_commands(self) -> tuple[str, ...]:
        return (f"launchctl kickstart -k {self._target}",)
