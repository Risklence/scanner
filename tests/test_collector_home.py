"""As many Collectors on one computer as needed, each for its own scanner (Søren, 2026-10-28).

A bare ``run`` started Auth & Access's Collector when the owner wanted another scanner's, and pairing a second
scanner would have overwritten the first one's credential. Each scanner now has its own folder, named as the
commands Risklence shows name it (``--scanner``).
"""

from pathlib import Path

import pytest
import responses
from click.testing import CliRunner

from scanner_agent import config
from scanner_agent.cli import cli
from scanner_agent.collector_home import (
    CollectorHomeError,
    adopt_earlier,
    folder_for,
    paired_scanners,
    scanner_folder,
)
from scanner_agent.config import ScannerCredentials, load_credentials, save_credentials
from scanner_agent.pairing import PAIRING_COLLECT_PATH, PAIRING_PATH

BASE = "https://api.example.com"
AUTH = "aaaaaaaa1111"
OTHER = "bbbbbbbb2222"


def _home() -> Path:
    return config.DEFAULT_CONFIG_DIR


def _paired(key: str, name: str, token: str = "tok") -> None:
    save_credentials(
        ScannerCredentials(base_url=BASE, activation_token=token, scanner_name=name), scanner_folder(key)
    )


def test_each_scanner_keeps_its_credential_in_its_own_folder():
    _paired(AUTH, "Auth & Access", token="tok-a")
    _paired(OTHER, "Pairing test", token="tok-b")

    assert load_credentials(folder_for(AUTH)).activation_token == "tok-a"
    assert load_credentials(folder_for(OTHER)).activation_token == "tok-b"
    assert [(s.key, s.name) for s in paired_scanners()] == [(AUTH, "Auth & Access"), (OTHER, "Pairing test")]


def test_without_a_name_it_starts_the_only_one_and_refuses_to_guess_between_several():
    _paired(AUTH, "Auth & Access")
    assert folder_for(None) == scanner_folder(AUTH)

    _paired(OTHER, "Pairing test")
    with pytest.raises(CollectorHomeError) as refused:
        folder_for(None)
    assert "Auth & Access: --scanner aaaaaaaa1111" in str(refused.value)
    assert "Pairing test: --scanner bbbbbbbb2222" in str(refused.value)


def test_a_collector_set_up_before_folders_keeps_working_without_a_name():
    # A service installed before 2026-10-28 runs `run` without --scanner.
    save_credentials(ScannerCredentials(base_url=BASE, activation_token="old"))
    _paired(OTHER, "Pairing test")

    assert folder_for(None) == _home()


def test_a_name_that_is_not_a_scanners_is_refused():
    with pytest.raises(CollectorHomeError):
        scanner_folder("../../etc")


def test_the_earlier_collector_is_adopted_only_by_the_scanner_risklence_says_it_is_for():
    save_credentials(ScannerCredentials(base_url=BASE, activation_token="old"))

    with pytest.raises(CollectorHomeError, match='is for "Auth & Access", not this one'):
        adopt_earlier(OTHER, lambda _c: {"collector_key": AUTH, "scanner_name": "Auth & Access"})
    assert not scanner_folder(OTHER).exists()

    folder = adopt_earlier(
        AUTH, lambda _c: {"collector_key": AUTH, "scanner_name": "Auth & Access", "scanner_instance_id": "i-1"}
    )
    adopted = load_credentials(folder)
    assert (adopted.activation_token, adopted.scanner_name) == ("old", "Auth & Access")
    # The original stays, so a service still reading it keeps working.
    assert load_credentials(_home()).activation_token == "old"


def test_a_scanner_with_no_collector_here_says_how_to_add_one():
    with pytest.raises(CollectorHomeError, match="install command Risklence shows"):
        adopt_earlier(OTHER, lambda _c: {})


@responses.activate
def test_pair_tells_risklence_its_scanner_and_keeps_the_key_in_that_scanners_folder(monkeypatch):
    monkeypatch.setattr("scanner_agent.pairing.time.sleep", lambda _seconds: None)
    _paired(AUTH, "Auth & Access", token="tok-a")
    responses.add(
        responses.POST,
        f"{BASE}{PAIRING_PATH}",
        json={"code": "4K7Q-2M9X", "secret": "s", "expires_in_seconds": 600, "poll_seconds": 5},
    )
    responses.add(
        responses.POST,
        f"{BASE}{PAIRING_COLLECT_PATH}",
        json={
            "status": "connected",
            "activation_token": "tok-b",
            "scanner_instance_id": "inst-b",
            "collector_key": OTHER,
            "scanner_name": "Pairing test",
        },
    )
    responses.add(responses.POST, f"{BASE}/api/v1/scanner-agent/heartbeat", json={"status": "online"})

    result = CliRunner().invoke(cli, ["pair", "--base-url", BASE, "--scanner", OTHER])

    assert result.exit_code == 0, result.output
    assert '"Pairing test"' in result.output
    assert '"collector_key": "bbbbbbbb2222"' in responses.calls[0].request.body.decode()
    assert load_credentials(scanner_folder(OTHER)).activation_token == "tok-b"
    # The other scanner's Collector on this computer is untouched.
    assert load_credentials(scanner_folder(AUTH)).activation_token == "tok-a"


@responses.activate
def test_a_key_for_another_scanner_is_not_saved_under_this_ones_name():
    responses.add(
        responses.POST,
        f"{BASE}/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "i", "status": "online", "collector_key": AUTH, "scanner_name": "Auth & Access"},
    )

    result = CliRunner().invoke(cli, ["activate", "--base-url", BASE, "--token", "t", "--scanner", OTHER])

    assert result.exit_code != 0
    assert 'This key is for "Auth & Access"' in result.output
    assert not scanner_folder(OTHER).exists()


@responses.activate
def test_a_named_run_that_finds_another_scanners_collector_says_so_and_starts_nothing():
    save_credentials(ScannerCredentials(base_url=BASE, activation_token="old"))
    responses.add(
        responses.POST,
        f"{BASE}/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "i", "status": "online", "collector_key": AUTH, "scanner_name": "Auth & Access"},
    )

    result = CliRunner().invoke(cli, ["run", "--scanner", OTHER])

    assert result.exit_code != 0
    assert 'is for "Auth & Access", not this one' in result.output
    assert "Starting Risklence Scanner agent loop" not in result.output
