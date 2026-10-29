"""Names, labels and paths for running the Collector as an operating-system service."""

from __future__ import annotations

from scanner_agent.service_contracts import ServiceNames

#: Seconds between cycles in a service. Same number as ``DEFAULT_RUN_INTERVAL_SECONDS``
#: in ``cli.py`` (a test pins them; ``cli`` imports this module, so it cannot import back).
SERVICE_RUN_INTERVAL_SECONDS = 60

#: Name of the console script a package install puts on the machine.
COLLECTOR_EXECUTABLE = "risklence-scanner"
COLLECTOR_EXECUTABLE_WINDOWS = "risklence-scanner.exe"

SYSTEMD_UNIT_NAME = "risklence-scanner.service"
LAUNCHD_LABEL = "com.risklence.scanner"
WINDOWS_TASK_NAME = "Risklence Scanner"

#: Linux and macOS user services start with a minimal ``PATH`` that finds neither
#: Homebrew's nmap nor a tool the installer placed in ``~/.local/bin``. These are
#: appended after the directory of the Collector itself.
SERVICE_EXTRA_PATH_DIRS = (
    "~/.local/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
)

SERVICE_DESCRIPTION = "Risklence Collector (scanner agent)"

_SCANNER_OPTION = "--scanner"


def service_names(scanner_key: str | None = None) -> ServiceNames:
    """One service per scanner on a computer that runs several (2026-10-28), each named for its scanner and starting
    that scanner's Collector. Without a scanner: the original names, which a service installed before keeps."""
    run = ("run", "--interval", str(SERVICE_RUN_INTERVAL_SECONDS))
    if not scanner_key:
        return ServiceNames(LAUNCHD_LABEL, SYSTEMD_UNIT_NAME, WINDOWS_TASK_NAME, "", run)
    return ServiceNames(
        launchd_label=f"{LAUNCHD_LABEL}.{scanner_key}",
        systemd_unit=SYSTEMD_UNIT_NAME.replace(".service", f"-{scanner_key}.service"),
        windows_task=f"{WINDOWS_TASK_NAME} {scanner_key}",
        log_suffix=f"-{scanner_key}",
        run_arguments=(*run, _SCANNER_OPTION, scanner_key),
    )
