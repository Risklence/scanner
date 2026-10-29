"""Windows: a Task Scheduler task that runs at the user's logon.

NOT run on a real Windows machine by the people who wrote it: the task XML and
the ``schtasks`` command lines are covered by tests that check their exact text,
nothing more. Treat the first install on Windows as a test.

A task that runs *at logon, as the current user, with limited rights* can be
created without administrator rights. Running before anybody logs on (a startup
task, or "whether the user is logged on or not") needs administrator rights and
a stored password, and this CLI does not do that.
"""

from __future__ import annotations

import getpass
import os
import tempfile
from collections.abc import Callable
from html import escape
from pathlib import Path

from scanner_agent.command_runner import CommandRunner, run_captured
from scanner_agent.service_constants import (
    COLLECTOR_EXECUTABLE_WINDOWS,
    SERVICE_DESCRIPTION,
    service_names,
)
from scanner_agent.service_contracts import (
    InstallOptions,
    ServiceError,
    ServiceInstallResult,
    ServiceNames,
    ServiceStatus,
)
from scanner_agent.service_executable import resolve_collector_executable

_RESTART_INTERVAL = "PT1M"
_RESTART_COUNT = 999
_ACCESS_DENIED_MARKERS = ("access is denied", "0x80070005")

_TASK_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_id}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_id}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>{restart_interval}</Interval>
      <Count>{restart_count}</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def render_command_arguments(executable: str, log_path: str, names: ServiceNames | None = None) -> str:
    """The ``cmd.exe`` arguments: run the Collector and append its output to a log.

    The whole thing sits in one extra pair of quotes, the form ``cmd /c`` needs
    when the program path and the log path both contain quoted parts.
    """
    arguments = " ".join((names or service_names()).run_arguments)
    return f'/c ""{executable}" {arguments} >> "{log_path}" 2>&1"'


def render_task_xml(
    executable: str, user_id: str, log_path: str, names: ServiceNames | None = None
) -> str:
    """The task definition. Holds no credential: that stays in the credentials
    file under the user's profile."""
    return _TASK_XML_TEMPLATE.format(
        description=escape(SERVICE_DESCRIPTION),
        user_id=escape(user_id),
        restart_interval=_RESTART_INTERVAL,
        restart_count=_RESTART_COUNT,
        arguments=escape(render_command_arguments(executable, log_path, names)),
    )


def _current_user_id() -> str:
    domain = os.environ.get("USERDOMAIN")
    user = getpass.getuser()
    return f"{domain}\\{user}" if domain else user


def _local_app_data() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")


class WindowsTaskServiceManager:
    kind = "Windows Task Scheduler task"

    def __init__(
        self,
        runner: CommandRunner = run_captured,
        *,
        user_id: Callable[[], str] = _current_user_id,
        local_app_data: Callable[[], Path] = _local_app_data,
        resolve_executable: Callable[[], str] | None = None,
        temp_dir: Path | None = None,
        scanner_key: str | None = None,
    ) -> None:
        self._names = service_names(scanner_key)
        self._runner = runner
        self._user_id = user_id
        self._local_app_data = local_app_data
        self._resolve_executable = resolve_executable or (
            lambda: resolve_collector_executable(COLLECTOR_EXECUTABLE_WINDOWS)
        )
        self._temp_dir = temp_dir

    @property
    def log_path(self) -> Path:
        return self._local_app_data() / "Risklence" / "Scanner" / f"collector{self._names.log_suffix}.log"

    def _import_task(self, xml: str) -> None:
        """Hand the definition to ``schtasks`` through a short-lived UTF-16 file."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".xml", delete=False, encoding="utf-16", dir=self._temp_dir
        ) as handle:
            handle.write(xml)
            xml_path = Path(handle.name)
        try:
            result = self._runner(
                ["schtasks", "/Create", "/TN", self._names.windows_task, "/XML", str(xml_path), "/F"]
            )
        finally:
            xml_path.unlink(missing_ok=True)
        if result.ok:
            return
        message = (result.stderr or result.stdout).strip()
        if any(marker in message.lower() for marker in _ACCESS_DENIED_MARKERS):
            raise ServiceError(
                f"Windows refused to create the task ({message}). Open PowerShell with "
                "'Run as administrator' and run `risklence-scanner install` again."
            )
        raise ServiceError(f"schtasks /Create failed: {message}")

    def install(self, options: InstallOptions) -> ServiceInstallResult:
        """Create (or replace) the logon task and start it now."""
        executable = self._resolve_executable()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._import_task(render_task_xml(executable, self._user_id(), str(self.log_path), self._names))
        started = self._runner(["schtasks", "/Run", "/TN", self._names.windows_task])
        notes = [
            "It starts each time you log on to Windows, and is restarted (once a minute, up to "
            f"{_RESTART_COUNT} times) if it stops with an error. It does not run before anybody has "
            "logged on: that needs administrator rights, which this command does not use.",
            f"Its log: {self.log_path} (it is appended to and never trimmed).",
        ]
        if not started.ok:
            notes.insert(
                0,
                f"The task is created but did not start now ({started.stderr.strip()}); it starts at logon.",
            )
        return ServiceInstallResult(self.kind, f'"{self._names.windows_task}"', tuple(notes))

    def _installed(self) -> bool:
        return self._runner(["schtasks", "/Query", "/TN", self._names.windows_task]).ok

    def uninstall(self) -> None:
        """Stop and delete the task. Safe when it was never installed."""
        if not self._installed():
            return
        self._runner(["schtasks", "/End", "/TN", self._names.windows_task])
        result = self._runner(["schtasks", "/Delete", "/TN", self._names.windows_task, "/F"])
        if not result.ok:
            raise ServiceError(
                f"schtasks /Delete failed: {(result.stderr or result.stdout).strip()}"
            )

    def status(self) -> ServiceStatus:
        result = self._runner(["schtasks", "/Query", "/TN", self._names.windows_task, "/FO", "LIST"])
        if not result.ok:
            return ServiceStatus(
                False, False, "not installed", "Install it with: risklence-scanner install"
            )
        state = next(
            (
                line.split(":", 1)[1].strip()
                for line in result.stdout.splitlines()
                if line.startswith("Status:")
            ),
            None,
        )
        # The label is localised on a non-English Windows; then running is unknown.
        running = None if state is None else state == "Running"
        return ServiceStatus(True, running, state or "installed", f"Log: {self.log_path}")

    def restart_commands(self) -> tuple[str, ...]:
        return (
            f'schtasks /End /TN "{self._names.windows_task}"',
            f'schtasks /Run /TN "{self._names.windows_task}"',
        )
