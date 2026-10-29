"""Carrying out one planned step of ``install-tools``.

Every external effect goes through an injected port (``InteractiveRunner`` and
``Downloader``) so tests never install anything. Each step leaves nothing
half-done: files are written beside their destination and moved into place only
once complete.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from scanner_agent.command_runner import InteractiveRunner
from scanner_agent.tool_installer_constants import TEMPLATE_VERSION_MARKER
from scanner_agent.tool_installer_contracts import (
    Downloader,
    PlanStep,
    StepKind,
    ToolInstallError,
)
from scanner_agent.tool_installer_download import (
    extract_tar_stripping_top_folder,
    read_zip_member,
    verify_sha256,
)


class StepExecutor:
    def __init__(
        self,
        runner: InteractiveRunner,
        downloader: Downloader,
        template_version: str,
        now: Callable[[], datetime] = datetime.now,
    ) -> None:
        self._runner = runner
        self._downloader = downloader
        self._template_version = template_version
        self._now = now

    def execute(self, step: PlanStep) -> None:
        if step.kind is StepKind.PACKAGE_MANAGER:
            self._package_manager(step)
        elif step.kind is StepKind.DOWNLOAD_BINARY:
            self._download_binary(step)
        elif step.kind is StepKind.TEMPLATE_PACK:
            self._template_pack(step)
        else:
            raise ToolInstallError(f"This step is manual: {step.summary}")

    def _package_manager(self, step: PlanStep) -> None:
        code = self._runner(step.argv)
        if code != 0:
            raise ToolInstallError(f"`{' '.join(step.argv)}` exited with code {code}.")

    def _fetch_verified(self, step: PlanStep, work_dir: Path, name: str) -> Path:
        assert step.asset is not None
        archive = work_dir / name
        self._downloader(step.asset.url, archive)
        verify_sha256(archive, step.asset.sha256)
        return archive

    def _download_binary(self, step: PlanStep) -> None:
        assert step.asset is not None and step.destination is not None
        destination = step.destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=destination.parent) as work:
            archive = self._fetch_verified(step, Path(work), "download.zip")
            content = read_zip_member(archive, step.asset.member)
            staged = Path(work) / "staged"
            staged.write_bytes(content)
            staged.chmod(staged.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            os.replace(staged, destination)

    def _template_pack(self, step: PlanStep) -> None:
        assert step.destination is not None
        destination = step.destination
        with tempfile.TemporaryDirectory(dir=destination.parent) as work:
            archive = self._fetch_verified(step, Path(work), "templates.tar.gz")
            staged = Path(work) / "pack"
            staged.mkdir()
            extract_tar_stripping_top_folder(archive, staged)
            (staged / TEMPLATE_VERSION_MARKER).write_text(self._template_version + "\n")
            if destination.exists():
                stamp = self._now().strftime("%Y%m%d%H%M%S")
                shutil.move(
                    str(destination),
                    str(destination.with_name(f"{destination.name}.previous-{stamp}")),
                )
            shutil.move(str(staged), str(destination))
