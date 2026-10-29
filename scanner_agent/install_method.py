"""Telling a container install from a local one, so an update notice gives the
steps that actually work for this installation."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from scanner_agent.collector_version_constants import (
    COLLECTOR_PACKAGE_NAME,
    COLLECTOR_VENV_FOLDER_NAME,
    COLLECTOR_WINDOWS_VENV_RELATIVE_DIR,
    PIPX_VENVS_FOLDER_NAME,
)
from scanner_agent.install_method_contracts import InstallMethod

#: Set by the Dockerfile, the one explicit marker. The two checks below are for
#: images built without it.
CONTAINER_ENV_MARKER = "RISKLENCE_INSTALL_METHOD"
CONTAINER_ENV_VALUE = "docker"
_DOCKER_ENV_FILE = Path("/.dockerenv")
_CGROUP_FILE = Path("/proc/1/cgroup")
_CONTAINER_CGROUP_WORDS = ("docker", "containerd", "kubepods", "podman", "lxc")


def _default_read_cgroup() -> str:
    try:
        return _CGROUP_FILE.read_text()
    except OSError:
        return ""


def detect_install_method(
    env: Mapping[str, str] | None = None,
    docker_env_exists: Callable[[], bool] = _DOCKER_ENV_FILE.exists,
    read_cgroup: Callable[[], str] = _default_read_cgroup,
    prefix: str | None = None,
    home: Path | None = None,
    local_app_data: str | None = None,
) -> InstallMethod:
    """``prefix`` is the running environment (``sys.prefix``), ``home`` the user's
    home folder and ``local_app_data`` ``%LOCALAPPDATA%`` (Windows); both are injectable so a test never inspects the real machine.
    """
    environment = os.environ if env is None else env
    if environment.get(CONTAINER_ENV_MARKER) == CONTAINER_ENV_VALUE:
        return InstallMethod.CONTAINER
    if docker_env_exists():
        return InstallMethod.CONTAINER
    cgroup = read_cgroup().lower()
    if any(word in cgroup for word in _CONTAINER_CGROUP_WORDS):
        return InstallMethod.CONTAINER
    return _local_install_kind(
        Path(prefix or sys.prefix),
        home or Path.home(),
        os.environ.get("LOCALAPPDATA") if local_app_data is None else local_app_data,
    )


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return a == b


def _local_install_kind(
    prefix: Path, home: Path, local_app_data: str | None
) -> InstallMethod:
    if _same_path(prefix, home / COLLECTOR_VENV_FOLDER_NAME):
        return InstallMethod.VENV
    if local_app_data and _same_path(
        prefix,
        Path(local_app_data) / COLLECTOR_WINDOWS_VENV_RELATIVE_DIR.replace("\\", "/"),
    ):
        return InstallMethod.VENV
    if (
        prefix.parent.name == PIPX_VENVS_FOLDER_NAME
        and prefix.name == COLLECTOR_PACKAGE_NAME
    ):
        return InstallMethod.PIPX
    return InstallMethod.LOCAL
