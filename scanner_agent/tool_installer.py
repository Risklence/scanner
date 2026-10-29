"""``risklence-scanner install-tools``: install or verify nmap, subfinder, nuclei
and the pinned nuclei template pack, on this machine, for this user.

Safe by construction: it shows the exact plan first, runs nothing until the
person confirms (``--yes`` to skip), never pipes a download into a shell, checks
every download against a pinned checksum, and needs administrator rights only
where the operating system's package manager does (nmap on Linux, sometimes
Windows), saying so in the plan.
"""

from __future__ import annotations

import os
import platform
import shutil
from collections.abc import Callable
from pathlib import Path

from scanner_agent.command_runner import InteractiveRunner, run_interactive
from scanner_agent.tool_checks import (
    NUCLEI_TEMPLATES_DIR,
    check_nuclei_templates,
    check_tool,
)
from scanner_agent.tool_installer_constants import POSIX_BIN_DIR, WINDOWS_BIN_DIR
from scanner_agent.tool_installer_contracts import (
    Downloader,
    HostInfo,
    InstallPlan,
    StepKind,
    ToolInstallError,
    ToolState,
    Which,
)
from scanner_agent.tool_installer_download import download_file
from scanner_agent.tool_installer_execute import StepExecutor
from scanner_agent.tool_installer_plan import build_install_plan
from scanner_agent.tool_pins import pinned_template_version

_BINARY_TOOLS = ("nmap", "subfinder", "nuclei")


def detect_host() -> HostInfo:
    system = platform.system()
    home = Path.home()
    if system == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        bin_dir = (
            Path(local_app_data) / "Risklence" / "bin" if local_app_data else home / WINDOWS_BIN_DIR
        )
        is_root = False
    else:
        bin_dir = home / POSIX_BIN_DIR
        is_root = os.geteuid() == 0
    return HostInfo(
        system=system,
        machine=platform.machine(),
        is_root=is_root,
        home=home,
        bin_dir=bin_dir,
        templates_dir=NUCLEI_TEMPLATES_DIR,
        path_dirs=tuple(os.environ.get("PATH", "").split(os.pathsep)),
    )


def detect_state(templates_dir: Path = NUCLEI_TEMPLATES_DIR) -> ToolState:
    present = {tool for tool in _BINARY_TOOLS if check_tool(tool).available}
    templates = check_nuclei_templates(templates_dir)
    if templates.available:
        present.add("nuclei_templates")
    return ToolState(frozenset(present), templates.version)


def render_plan(plan: InstallPlan) -> list[str]:
    lines: list[str] = []
    if plan.already_present:
        lines.append(f"Already in place, left alone: {', '.join(plan.already_present)}")
    if not plan.steps:
        lines.append("Nothing to install.")
        return lines
    lines.append("This is what will be done, in this order:")
    for number, step in enumerate(plan.steps, start=1):
        lines.append(f"  {number}. {step.summary}")
        if step.asset is not None:
            lines.append(f"       from:   {step.asset.url}")
            lines.append(
                f"       sha256: {step.asset.sha256} (must match, or nothing is installed)"
            )
        for note in step.notes:
            lines.append(f"       {note}")
    lines.append("Nothing is run through a shell, and nothing is changed until you confirm.")
    lines.extend(plan.path_hint)
    return lines


def run_install_tools(
    *,
    dry_run: bool,
    assume_yes: bool,
    echo: Callable[[str], None],
    confirm: Callable[[str], bool],
    host: HostInfo | None = None,
    state: ToolState | None = None,
    which: Which = shutil.which,
    runner: InteractiveRunner = run_interactive,
    downloader: Downloader = download_file,
) -> int:
    """Returns the process exit code: 0 when everything is in place."""
    host = host or detect_host()
    template_version = pinned_template_version()
    plan = build_install_plan(
        host, state or detect_state(host.templates_dir), template_version, which
    )
    for line in render_plan(plan):
        echo(line)
    if not plan.steps:
        return 0
    manual = [step for step in plan.steps if step.kind is StepKind.MANUAL]
    if dry_run:
        echo("Dry run: nothing was changed.")
        return 1 if manual else 0
    runnable = [step for step in plan.steps if step.kind is not StepKind.MANUAL]
    if runnable and not assume_yes and not confirm("Go ahead with these steps?"):
        echo("Cancelled. Nothing was changed.")
        return 1
    executor = StepExecutor(runner, downloader, template_version)
    failed = bool(manual)
    for step in runnable:
        echo(f"Working on: {step.summary}")
        try:
            executor.execute(step)
        except ToolInstallError as exc:
            echo(f"FAILED: {exc}")
            failed = True
            break
        echo("  done.")
    if manual:
        echo("These need you: " + "; ".join(step.summary for step in manual))
    echo("Run `risklence-scanner validate-tools` to confirm what the Collector now sees.")
    return 1 if failed else 0
