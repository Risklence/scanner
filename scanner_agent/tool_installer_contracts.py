"""Types for ``risklence-scanner install-tools``."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol


class StepKind(str, Enum):
    #: Run an operating-system package manager (nmap).
    PACKAGE_MANAGER = "package_manager"
    #: Download a pinned release archive and verify its sha256 (subfinder, nuclei).
    DOWNLOAD_BINARY = "download_binary"
    #: Download the pinned nuclei template pack and verify its sha256.
    TEMPLATE_PACK = "template_pack"
    #: Nothing this command can safely do: tells the person what to do.
    MANUAL = "manual"


class ToolInstallError(RuntimeError):
    """An install step failed. Nothing half-installed is left in place."""


@dataclass(frozen=True)
class PackageRecipe:
    """How one package manager installs nmap."""

    manager: str
    argv: tuple[str, ...]
    #: Needs root (Linux) or an administrator shell (choco).
    needs_admin: bool = False
    note: str = ""


@dataclass(frozen=True)
class DownloadAsset:
    url: str
    sha256: str
    #: Name of the file inside a zip archive (``subfinder`` or ``subfinder.exe``).
    member: str = ""


@dataclass(frozen=True)
class PlanStep:
    tool: str
    kind: StepKind
    summary: str
    argv: tuple[str, ...] = ()
    asset: DownloadAsset | None = None
    destination: Path | None = None
    needs_admin: bool = False
    #: Printed under the step.
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class InstallPlan:
    steps: tuple[PlanStep, ...]
    #: Tools already in place, left untouched.
    already_present: tuple[str, ...] = ()
    #: Set when a downloaded program lands in a folder that is not on PATH.
    path_hint: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class HostInfo:
    """What the plan depends on about this machine, gathered once."""

    system: str  # platform.system(): "Darwin", "Linux", "Windows"
    machine: str  # platform.machine()
    is_root: bool
    home: Path
    bin_dir: Path
    templates_dir: Path
    path_dirs: tuple[str, ...]


@dataclass(frozen=True)
class ToolState:
    """What is already installed."""

    present: frozenset[str]
    template_version: str | None


class Downloader(Protocol):
    """Fetches ``url`` to ``destination`` over HTTPS."""

    def __call__(self, url: str, destination: Path) -> None: ...


Which = Callable[[str], str | None]
