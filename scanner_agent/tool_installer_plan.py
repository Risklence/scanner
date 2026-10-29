"""Deciding, without touching anything, what ``install-tools`` would do.

Pure: the same inputs always give the same plan, so ``--dry-run`` prints exactly
what a real run would do.
"""

from __future__ import annotations

from scanner_agent.tool_installer_constants import (
    ASSET_ARCH,
    ASSET_OS,
    NMAP_MANUAL_DOWNLOAD,
    NMAP_RECIPES,
    RELEASE_SHA256,
    RELEASE_URL,
    TEMPLATE_PACK_SHA256,
    TEMPLATE_PACK_URL,
    TOOL_VERSIONS,
)
from scanner_agent.tool_installer_contracts import (
    DownloadAsset,
    HostInfo,
    InstallPlan,
    PlanStep,
    StepKind,
    ToolState,
    Which,
)

_DOWNLOADED_TOOLS = ("subfinder", "nuclei")


def _nmap_step(host: HostInfo, which: Which) -> PlanStep:
    recipes = NMAP_RECIPES.get(host.system, ())
    for recipe in recipes:
        if which(recipe.manager) is None:
            continue
        argv = recipe.argv
        notes = [recipe.note] if recipe.note else []
        if recipe.needs_admin and not host.is_root and host.system != "Windows":
            if which("sudo") is None:
                return PlanStep(
                    "nmap",
                    StepKind.MANUAL,
                    f"Install nmap as root: {' '.join(recipe.argv)}",
                    notes=(
                        "`sudo` was not found, so this command cannot ask for administrator rights.",
                    ),
                )
            argv = ("sudo", *argv)
            notes.append("This step needs administrator rights: sudo will ask for your password.")
        elif recipe.needs_admin and host.system == "Windows":
            notes.append("Run this from a PowerShell opened with 'Run as administrator'.")
        return PlanStep(
            "nmap",
            StepKind.PACKAGE_MANAGER,
            f"Install nmap with {recipe.manager}: {' '.join(argv)}",
            argv=argv,
            needs_admin=recipe.needs_admin,
            notes=tuple(notes),
        )
    return PlanStep(
        "nmap",
        StepKind.MANUAL,
        f"Install nmap yourself from {NMAP_MANUAL_DOWNLOAD}, or with your system's package manager.",
        notes=("No supported package manager was found on this machine.",),
    )


def _binary_step(tool: str, host: HostInfo) -> PlanStep:
    os_word = ASSET_OS.get(host.system)
    arch = ASSET_ARCH.get(host.machine.lower())
    sha256 = RELEASE_SHA256.get((tool, os_word or "", arch or ""))
    if os_word is None or arch is None or sha256 is None:
        return PlanStep(
            tool,
            StepKind.MANUAL,
            f"Install {tool} yourself: there is no pinned build for {host.system} {host.machine}.",
            notes=(f"https://github.com/projectdiscovery/{tool}/releases",),
        )
    version = TOOL_VERSIONS[tool]
    file_name = f"{tool}.exe" if host.system == "Windows" else tool
    return PlanStep(
        tool,
        StepKind.DOWNLOAD_BINARY,
        f"Download {tool} {version} and install it to {host.bin_dir / file_name}",
        asset=DownloadAsset(
            url=RELEASE_URL.format(tool=tool, version=version, os=os_word, arch=arch),
            sha256=sha256,
            member=file_name,
        ),
        destination=host.bin_dir / file_name,
        notes=(
            "No administrator rights needed. The download is checked against a checksum pinned in this program.",
        ),
    )


def _template_step(host: HostInfo, version: str, installed_version: str | None) -> PlanStep:
    sha256 = TEMPLATE_PACK_SHA256.get(version)
    if sha256 is None:
        return PlanStep(
            "nuclei_templates",
            StepKind.MANUAL,
            f"The pinned template pack {version} has no checksum in this program, so it will not be downloaded.",
            notes=("This is a defect in this release of the Collector; please report it.",),
        )
    notes = [
        "No administrator rights needed. The download is checked against a checksum pinned in this program."
    ]
    if host.templates_dir.exists():
        notes.append(
            f"{host.templates_dir} already exists ({installed_version or 'no version recorded'}): "
            "it is moved aside to a `.previous-<time>` folder, not deleted."
        )
    return PlanStep(
        "nuclei_templates",
        StepKind.TEMPLATE_PACK,
        f"Download the pinned nuclei template pack {version} into {host.templates_dir}",
        asset=DownloadAsset(url=TEMPLATE_PACK_URL.format(version=version), sha256=sha256),
        destination=host.templates_dir,
        notes=tuple(notes),
    )


def _path_hint(host: HostInfo) -> tuple[str, ...]:
    if str(host.bin_dir) in host.path_dirs:
        return ()
    if host.system == "Windows":
        return (
            f"{host.bin_dir} is not on your PATH. Add it for your user (then open a new terminal):",
            f'  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";{host.bin_dir}", "User")',
        )
    return (
        f"{host.bin_dir} is not on your PATH. Add it (then open a new terminal):",
        f"  echo 'export PATH=\"{host.bin_dir}:$PATH\"' >> ~/.profile",
    )


def build_install_plan(
    host: HostInfo, state: ToolState, template_version: str, which: Which
) -> InstallPlan:
    steps: list[PlanStep] = []
    present: list[str] = []

    if "nmap" in state.present:
        present.append("nmap")
    else:
        steps.append(_nmap_step(host, which))
    for tool in _DOWNLOADED_TOOLS:
        if tool in state.present:
            present.append(tool)
        else:
            steps.append(_binary_step(tool, host))
    if "nuclei_templates" in state.present and state.template_version == template_version:
        present.append("nuclei_templates")
    else:
        steps.append(_template_step(host, template_version, state.template_version))

    lands_in_bin_dir = any(step.kind is StepKind.DOWNLOAD_BINARY for step in steps)
    return InstallPlan(
        steps=tuple(steps),
        already_present=tuple(present),
        path_hint=_path_hint(host) if lands_in_bin_dir else (),
    )
