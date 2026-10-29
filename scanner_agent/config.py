"""Local credential storage for the Risklence Scanner CLI.

The activation token is issued once by the platform (copied from the
Evidence Source setup screen) and persisted here so later commands
(heartbeat / validate-tools / test-scan) don't need it re-entered.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_DIR = Path(os.environ.get("RISKLENCE_SCANNER_HOME", str(Path.home() / ".risklence-scanner")))
CREDENTIALS_FILENAME = "credentials.json"


@dataclass(frozen=True)
class ScannerCredentials:
    base_url: str
    activation_token: str
    # CA-04.1 — captured from the activate command's own heartbeat response.
    # Needed locally so `poll` can reject a "wrong instance" command (a
    # command whose scanner_instance_id doesn't match this one) instead of
    # blindly trusting whatever the platform claims to have sent. None for
    # credentials saved before this shipped, until the next `activate`.
    scanner_instance_id: str | None = None
    #: The scanner's name as Risklence knows it ("Auth & Access"), so the Collector can say which scanner it runs for
    #: on a computer that runs several. Not a secret; None for credentials saved before 2026-10-28.
    scanner_name: str | None = None


def _folder(config_dir: Path | None) -> Path:
    """``DEFAULT_CONFIG_DIR`` read at call time, never bound as a default argument: a default bound when the module
    loaded ignored a home set later, and a test meant for a scratch folder overwrote a real credential (2026-10-28)."""
    return config_dir if config_dir is not None else DEFAULT_CONFIG_DIR


def credentials_path(config_dir: Path | None = None) -> Path:
    return _folder(config_dir) / CREDENTIALS_FILENAME


def save_credentials(credentials: ScannerCredentials, config_dir: Path | None = None) -> Path:
    config_dir = _folder(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    path = credentials_path(config_dir)
    path.write_text(
        json.dumps(
            {
                "base_url": credentials.base_url,
                "activation_token": credentials.activation_token,
                "scanner_instance_id": credentials.scanner_instance_id,
                "scanner_name": credentials.scanner_name,
            }
        )
    )
    path.chmod(0o600)
    return path


def load_credentials(config_dir: Path | None = None) -> ScannerCredentials:
    path = credentials_path(config_dir)
    if not path.exists():
        raise FileNotFoundError(f"No scanner credentials found at {path}. Run `risklence-scanner activate` first.")
    data = json.loads(path.read_text())
    return ScannerCredentials(
        base_url=data["base_url"],
        activation_token=data["activation_token"],
        scanner_instance_id=data.get("scanner_instance_id"),
        scanner_name=data.get("scanner_name"),
    )
