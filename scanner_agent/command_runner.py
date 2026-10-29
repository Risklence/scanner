"""Running an external command, behind one seam.

Every module that shells out (the service managers, the tool installer) takes a
``CommandRunner`` instead of calling ``subprocess`` itself, so a test can hand it
a fake and no test ever starts a real ``launchctl``, ``schtasks`` or package
manager (DIP). A missing program is reported as an ordinary failed result, not an
exception, so callers have one failure path.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

#: The shell convention for "command not found". Used when the program is absent.
COMMAND_NOT_FOUND_EXIT_CODE = 127
_COMMAND_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(Protocol):
    """Runs ``argv`` (never through a shell) and captures its output."""

    def __call__(self, argv: Sequence[str]) -> CommandResult: ...


class InteractiveRunner(Protocol):
    """Runs ``argv`` attached to the user's terminal (for ``sudo`` prompts) and
    returns the exit code."""

    def __call__(self, argv: Sequence[str]) -> int: ...


def run_captured(argv: Sequence[str]) -> CommandResult:
    try:
        done = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(COMMAND_NOT_FOUND_EXIT_CODE, "", f"{argv[0]}: command not found")
    except subprocess.TimeoutExpired:
        return CommandResult(1, "", f"{argv[0]}: timed out after {_COMMAND_TIMEOUT_SECONDS}s")
    return CommandResult(done.returncode, done.stdout or "", done.stderr or "")


def run_interactive(argv: Sequence[str]) -> int:
    try:
        return subprocess.run(list(argv), check=False).returncode
    except FileNotFoundError:
        return COMMAND_NOT_FOUND_EXIT_CODE
