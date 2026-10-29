"""Linux: a per-user systemd unit (``systemctl --user``).

Deliberately user-level: no root to install or remove, matching the rest of this
CLI's self-service model (credentials live in the user's own home too). A user
unit stops at logout unless lingering is enabled, so ``install`` checks that and
either warns or, with ``--enable-linger``, runs ``loginctl enable-linger``.
"""

from __future__ import annotations

import getpass
import shutil
from collections.abc import Callable
from pathlib import Path

from scanner_agent.command_runner import CommandResult, CommandRunner, run_captured
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

_NO_SYSTEMD = "systemctl not found — service install/uninstall requires a systemd host."

_UNIT_TEMPLATE = """[Unit]
Description=Risklence Scanner Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Environment=PATH={search_path}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""


def _quote_if_needed(value: str) -> str:
    return f'"{value}"' if " " in value else value


def render_unit(executable: str, home: Path, names: ServiceNames | None = None) -> str:
    names = names or service_names()
    exec_start = " ".join([_quote_if_needed(executable), *names.run_arguments])
    return _UNIT_TEMPLATE.format(
        exec_start=exec_start, search_path=service_search_path(executable, home)
    )


class SystemdServiceManager:
    kind = "systemd --user service"

    def __init__(
        self,
        runner: CommandRunner = run_captured,
        *,
        home: Path | None = None,
        which: Callable[[str], str | None] = shutil.which,
        resolve_executable: Callable[[], str] = resolve_collector_executable,
        username: Callable[[], str] = getpass.getuser,
        scanner_key: str | None = None,
    ) -> None:
        self._names = service_names(scanner_key)
        self._runner = runner
        self._home = home or Path.home()
        self._which = which
        self._resolve_executable = resolve_executable
        self._username = username

    @property
    def unit_path(self) -> Path:
        return self._home / ".config" / "systemd" / "user" / self._names.systemd_unit

    def _systemctl(self, *args: str) -> CommandResult:
        return self._runner(["systemctl", "--user", *args])

    def _require_systemd(self) -> None:
        """Fail before anything is written when this machine has no systemd."""
        if self._which("systemctl") is None:
            raise ServiceError(_NO_SYSTEMD)

    def _must(self, *args: str) -> None:
        result = self._systemctl(*args)
        if not result.ok:
            raise ServiceError(f"systemctl {' '.join(args)} failed: {result.stderr.strip()}")

    def _lingering(self) -> bool | None:
        result = self._runner(["loginctl", "show-user", self._username(), "--property=Linger"])
        if not result.ok:
            return None
        return result.stdout.strip() == "Linger=yes"

    def _linger_notes(self, enable: bool) -> tuple[str, ...]:
        user = self._username()
        if self._lingering() is True:
            return ("It also starts at boot: lingering is already enabled for this user.",)
        if enable:
            result = self._runner(["loginctl", "enable-linger", user])
            if result.ok:
                return (
                    "Lingering is now enabled, so it starts at boot and keeps running after you log out.",
                )
            return (
                f"Could not enable lingering ({result.stderr.strip() or 'no reason given'}). "
                f"Run `sudo loginctl enable-linger {user}` yourself.",
            )
        return (
            "Without lingering this service stops when you log out and only starts after you log in. "
            f"To have it start at boot, run `loginctl enable-linger {user}` "
            "(or install again with `--enable-linger`).",
        )

    def install(self, options: InstallOptions) -> ServiceInstallResult:
        """Write the unit and enable+start it. Idempotent."""
        self._require_systemd()
        executable = self._resolve_executable()
        self.unit_path.parent.mkdir(parents=True, exist_ok=True)
        self.unit_path.write_text(render_unit(executable, self._home, self._names))
        self._must("daemon-reload")
        self._must("enable", "--now", self._names.systemd_unit)
        notes = self._linger_notes(options.enable_linger) + (
            f"See its log with: journalctl --user -u {self._names.systemd_unit} -f",
        )
        return ServiceInstallResult(self.kind, str(self.unit_path), notes)

    def uninstall(self) -> None:
        """Stop, disable and remove the unit. Safe when it was never installed."""
        if not self.unit_path.exists():
            return
        self._must("disable", "--now", self._names.systemd_unit)
        self.unit_path.unlink()
        self._must("daemon-reload")

    def status(self) -> ServiceStatus:
        if not self.unit_path.exists():
            return ServiceStatus(
                False, False, "not installed", "Install it with: risklence-scanner install"
            )
        active = self._systemctl("is-active", self._names.systemd_unit).stdout.strip()
        return ServiceStatus(
            True,
            active == "active",
            active or "unknown",
            f"Log: journalctl --user -u {self._names.systemd_unit} -f",
        )

    def restart_commands(self) -> tuple[str, ...]:
        return (f"systemctl --user restart {self._names.systemd_unit}",)
