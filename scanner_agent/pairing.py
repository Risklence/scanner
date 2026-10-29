"""Pairing this Collector with a code the owner types in Risklence (#647, 2026-10-28).

The Collector asks for a code, shows it, and waits. Once the owner has typed the code and connected it, the platform
hands over this scanner's credential once. The credential never passes through a command, a screen or a chat.
Talks to ``apps/server/src/api/routes/scanner_pairing.py``; it holds no credential yet, so it sends none.
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

import requests

PAIRING_PATH = "/api/v1/scanner-agent/pairing"
PAIRING_COLLECT_PATH = "/api/v1/scanner-agent/pairing/collect"
#: A name for this computer the owner will recognise. Inside Docker the hostname is the container's id, so the
#: Docker command passes the host's own name in this variable.
COMPUTER_NAME_ENV = "RISKLENCE_COMPUTER_NAME"
_SYSTEM_NAMES = {"Darwin": "macOS"}


class PairingError(RuntimeError):
    """The platform refused, or could not be reached; the message is for the person at the computer."""


@dataclass(frozen=True)
class PairingCode:
    code: str
    secret: str
    expires_in_seconds: int
    poll_seconds: int


@dataclass(frozen=True)
class Paired:
    activation_token: str
    scanner_instance_id: str
    #: The scanner's short name and name, from a platform that sends them (older ones do not).
    collector_key: str | None = None
    scanner_name: str | None = None


def _mac_computer_name(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> str | None:
    """The name a Mac shows in System Settings ("Søren's MacBook Pro"), not its network name
    ("Srens-MacBook-Pro.local", which drops letters like ø): the one its owner recognises (Søren, 2026-10-28)."""
    try:
        result = run(["scutil", "--get", "ComputerName"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    name = result.stdout.strip() if result.returncode == 0 else ""
    return name or None


def pairing_identity(
    *,
    system: str | None = None,
    mac_name: Callable[[], str | None] = _mac_computer_name,
) -> tuple[str, str]:
    """The computer's name and system, as the owner will see them before connecting it."""
    system = system or platform.system()
    name = os.environ.get(COMPUTER_NAME_ENV) or (mac_name() if system == "Darwin" else None) or socket.gethostname()
    return name, _SYSTEM_NAMES.get(system, system)


def _post(base_url: str, path: str, body: dict, timeout: float) -> requests.Response:
    try:
        return requests.post(f"{base_url.rstrip('/')}{path}", json=body, timeout=timeout)
    except requests.RequestException as exc:
        raise PairingError(f"Could not reach Risklence at {base_url}: {exc}") from exc


def _refusal(response: requests.Response) -> PairingError:
    try:
        detail = response.json().get("detail")
    except ValueError:
        detail = None
    return PairingError(detail if isinstance(detail, str) else f"Risklence answered {response.status_code}.")


def request_code(
    base_url: str,
    *,
    computer_name: str,
    os_name: str,
    collector_version: str | None,
    collector_key: str | None = None,
    timeout: float = 15.0,
) -> PairingCode:
    """``collector_key`` is the scanner this Collector was started for (``--scanner``); Risklence then refuses the
    code if it is typed for any other scanner."""
    body = {"computer_name": computer_name, "os_name": os_name, "collector_version": collector_version}
    if collector_key:
        body["collector_key"] = collector_key
    response = _post(base_url, PAIRING_PATH, body, timeout)
    if response.status_code >= 400:
        raise _refusal(response)
    body = response.json()
    return PairingCode(
        code=body["code"],
        secret=body["secret"],
        expires_in_seconds=int(body["expires_in_seconds"]),
        poll_seconds=int(body["poll_seconds"]),
    )


def wait_until_connected(
    base_url: str,
    code: PairingCode,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    timeout: float = 15.0,
) -> Paired:
    """Ask every few seconds until the owner has connected the code, or it has expired."""
    deadline = clock() + code.expires_in_seconds
    while True:
        try:
            response = _post(base_url, PAIRING_COLLECT_PATH, {"secret": code.secret}, timeout)
        except PairingError:
            # A dropped connection while waiting is not the end: the code is still good until it expires.
            response = None
        if response is not None:
            if response.status_code >= 400:
                raise _refusal(response)
            body = response.json()
            if body.get("status") == "connected":
                return Paired(
                    activation_token=body["activation_token"],
                    scanner_instance_id=body["scanner_instance_id"],
                    collector_key=body.get("collector_key"),
                    scanner_name=body.get("scanner_name"),
                )
        if clock() >= deadline:
            raise PairingError("The code has expired. Run pair again to get a new one.")
        sleep(code.poll_seconds)
