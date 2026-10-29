"""Which scanner's Collector a command is for, on a computer that runs several (Søren, 2026-10-28).

"There should be as many local collectors as needed." Each scanner's credential lives in its own folder,
``~/.risklence-scanner/scanners/<key>/``, named by the scanner's short name that every command Risklence shows
carries (``--scanner <key>``). Starting, pairing or updating one scanner's Collector never reaches another's.

A Collector set up before this keeps its credential in ``~/.risklence-scanner`` itself. It keeps working as it is,
and a command naming a scanner adopts it only once Risklence has said that credential belongs to that scanner.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scanner_agent import config
from scanner_agent.config import (
    ScannerCredentials,
    credentials_path,
    load_credentials,
    save_credentials,
)

SCANNERS_DIRNAME = "scanners"
#: The option every command takes, the same one Risklence's commands carry.
SCANNER_OPTION = "--scanner"
#: Lower-case letters and digits only (the platform's ``collector_key``), so it is always a plain folder name.
_KEY = re.compile(r"^[a-z0-9]{1,36}$")


class CollectorHomeError(RuntimeError):
    """Which scanner is meant cannot be told, or its Collector is not here; the message is for the person."""


@dataclass(frozen=True)
class PairedScanner:
    key: str
    name: str | None
    folder: Path


def _home(home: Path | None) -> Path:
    # Read at call time, so ``RISKLENCE_SCANNER_HOME`` set by a test or a wrapper is honoured.
    return home if home is not None else config.DEFAULT_CONFIG_DIR


def valid_key(key: str) -> str:
    key = key.strip().lower()
    if not _KEY.match(key):
        raise CollectorHomeError(
            f"{key!r} is not a scanner name. Copy the command Risklence shows for the scanner; it ends in "
            f"{SCANNER_OPTION} and the scanner's name."
        )
    return key


def scanner_folder(key: str, home: Path | None = None) -> Path:
    return _home(home) / SCANNERS_DIRNAME / valid_key(key)


def paired_scanners(home: Path | None = None) -> list[PairedScanner]:
    """Every scanner this computer holds a Collector credential for, in its own folder."""
    root = _home(home) / SCANNERS_DIRNAME
    if not root.is_dir():
        return []
    found = []
    for folder in sorted(root.iterdir()):
        path = credentials_path(folder)
        if not path.is_file():
            continue
        try:
            name = json.loads(path.read_text()).get("scanner_name")
        except (OSError, ValueError):
            name = None
        found.append(PairedScanner(key=folder.name, name=name, folder=folder))
    return found


def folder_for_earlier(home: Path | None = None) -> Path:
    """Where a Collector set up before folders existed keeps its credential: the home folder itself."""
    return _home(home)


def _earlier_collector(home: Path) -> bool:
    return credentials_path(home).is_file()


def folder_for(scanner_key: str | None, home: Path | None = None) -> Path:
    """Where the credential of the scanner a command is for lives.

    Named: that scanner's own folder (``adopt_earlier`` covers a Collector set up before folders existed). Not
    named: the Collector set up before folders existed, as it always was (a service installed then runs without a
    name); else the one scanner this computer has; else a refusal that lists them, so a command never starts a
    scanner nobody asked for.
    """
    home = _home(home)
    if scanner_key:
        return scanner_folder(scanner_key, home)
    found = paired_scanners(home)
    if _earlier_collector(home) or not found:
        return home
    if len(found) == 1:
        return found[0].folder
    lines = [f"  {scanner.name or 'A scanner'}: {SCANNER_OPTION} {scanner.key}" for scanner in found]
    raise CollectorHomeError(
        "This computer runs Collectors for more than one scanner. Say which one:\n" + "\n".join(lines)
    )


def adopt_earlier(
    scanner_key: str,
    ask_platform: Callable[[ScannerCredentials], dict],
    home: Path | None = None,
) -> Path:
    """A command names a scanner whose folder is empty, on a computer with a Collector set up before folders
    existed. Risklence is asked whom that credential belongs to: the named scanner, and it is copied into that
    scanner's folder (the original stays, so a service still reading it keeps working); another scanner, and
    nothing is touched, with words that say which."""
    home = _home(home)
    folder = scanner_folder(scanner_key, home)
    if credentials_path(folder).is_file():
        return folder
    if not _earlier_collector(home):
        raise CollectorHomeError(
            "There is no Collector for this scanner on this computer yet. Run the install command Risklence "
            "shows for the scanner: it connects one with a code."
        )
    earlier = load_credentials(home)
    answer = ask_platform(earlier)
    if answer.get("collector_key") != scanner_folder(scanner_key, home).name:
        owner = answer.get("scanner_name")
        belongs = f'is for "{owner}"' if owner else "is for another scanner"
        raise CollectorHomeError(
            f"The Collector already set up on this computer {belongs}, not this one. It is left as it is. "
            "To add this scanner, run the install command Risklence shows for it: it connects one with a code."
        )
    save_credentials(
        ScannerCredentials(
            base_url=earlier.base_url,
            activation_token=earlier.activation_token,
            scanner_instance_id=answer.get("scanner_instance_id") or earlier.scanner_instance_id,
            scanner_name=answer.get("scanner_name"),
        ),
        folder,
    )
    return folder
