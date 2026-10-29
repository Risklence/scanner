"""Pairing with a code the owner types in Risklence (#647, Søren 2026-10-28): no key is copied anywhere."""

import json

import pytest
import responses
from click.testing import CliRunner

from scanner_agent import cli as cli_module
from scanner_agent.cli import cli
from scanner_agent.config import ScannerCredentials
from scanner_agent.pairing import (
    COMPUTER_NAME_ENV,
    PAIRING_COLLECT_PATH,
    PAIRING_PATH,
    PairingCode,
    PairingError,
    pairing_identity,
    request_code,
    wait_until_connected,
)

BASE = "https://api.example.com"
CODE = PairingCode(code="4K7Q-2M9X", secret="s3cret", expires_in_seconds=600, poll_seconds=5)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@responses.activate
def test_the_code_request_says_which_computer_asks_and_sends_no_credential():
    responses.add(
        responses.POST,
        f"{BASE}{PAIRING_PATH}",
        json={"code": "4K7Q-2M9X", "secret": "s3cret", "expires_in_seconds": 600, "poll_seconds": 5},
    )

    code = request_code(BASE, computer_name="Sorens-MacBook", os_name="macOS", collector_version="0.3.0")

    assert code == CODE
    sent = responses.calls[0].request
    assert json.loads(sent.body) == {
        "computer_name": "Sorens-MacBook",
        "os_name": "macOS",
        "collector_version": "0.3.0",
    }
    assert "Authorization" not in sent.headers


@responses.activate
def test_it_waits_until_the_owner_connects_it():
    collect = f"{BASE}{PAIRING_COLLECT_PATH}"
    responses.add(responses.POST, collect, json={"status": "waiting"})
    responses.add(responses.POST, collect, json={"status": "waiting"})
    responses.add(
        responses.POST,
        collect,
        json={"status": "connected", "activation_token": "tok", "scanner_instance_id": "inst-1"},
    )
    clock = _Clock()

    paired = wait_until_connected(BASE, CODE, sleep=clock.sleep, clock=clock)

    assert (paired.activation_token, paired.scanner_instance_id) == ("tok", "inst-1")
    assert clock.now == 10  # asked every poll_seconds


@responses.activate
def test_a_code_nobody_typed_runs_out():
    responses.add(responses.POST, f"{BASE}{PAIRING_COLLECT_PATH}", json={"status": "waiting"})
    clock = _Clock()

    with pytest.raises(PairingError, match="expired"):
        wait_until_connected(BASE, CODE, sleep=clock.sleep, clock=clock)


@responses.activate
def test_the_platforms_own_words_are_shown_when_it_refuses():
    responses.add(
        responses.POST,
        f"{BASE}{PAIRING_COLLECT_PATH}",
        json={"detail": "This code has expired. Start the Collector's pairing again to get a new code."},
        status=410,
    )
    clock = _Clock()

    with pytest.raises(PairingError, match="has expired"):
        wait_until_connected(BASE, CODE, sleep=clock.sleep, clock=clock)


def test_inside_docker_the_computer_is_named_by_the_host_not_the_container(monkeypatch):
    monkeypatch.setenv(COMPUTER_NAME_ENV, "office-server")
    assert pairing_identity()[0] == "office-server"


@responses.activate
def test_pair_shows_the_code_then_stores_what_it_collected(monkeypatch):
    saved: dict[str, ScannerCredentials] = {}

    def _fake_save(credentials: ScannerCredentials):
        saved["credentials"] = credentials
        return "/fake/credentials.json"

    monkeypatch.setattr(cli_module, "save_credentials", _fake_save)
    monkeypatch.setattr("scanner_agent.pairing.time.sleep", lambda _seconds: None)
    responses.add(
        responses.POST,
        f"{BASE}{PAIRING_PATH}",
        json={"code": "4K7Q-2M9X", "secret": "s3cret", "expires_in_seconds": 600, "poll_seconds": 5},
    )
    responses.add(responses.POST, f"{BASE}{PAIRING_COLLECT_PATH}", json={"status": "waiting"})
    responses.add(
        responses.POST,
        f"{BASE}{PAIRING_COLLECT_PATH}",
        json={"status": "connected", "activation_token": "tok_paired", "scanner_instance_id": "inst-1"},
    )
    responses.add(
        responses.POST,
        f"{BASE}/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "inst-1", "status": "online"},
    )

    result = CliRunner().invoke(cli, ["pair", "--base-url", BASE])

    assert result.exit_code == 0, result.output
    assert "4K7Q-2M9X" in result.output
    assert "tok_paired" not in result.output  # the key is never shown
    assert "Connected to Risklence" in result.output
    assert saved["credentials"] == ScannerCredentials(
        base_url=BASE, activation_token="tok_paired", scanner_instance_id="inst-1"
    )
    # The first heartbeat uses the collected key, so the page says "Connected".
    assert responses.calls[-1].request.headers["Authorization"] == "Bearer tok_paired"


def test_a_mac_is_named_as_its_owner_knows_it(monkeypatch):
    monkeypatch.delenv(COMPUTER_NAME_ENV, raising=False)
    assert pairing_identity(system="Darwin", mac_name=lambda: "Søren's MacBook Pro") == (
        "Søren's MacBook Pro",
        "macOS",
    )
    # Without that name (scutil missing or failing) the network name is used.
    monkeypatch.setattr("scanner_agent.pairing.socket.gethostname", lambda: "Srens-MacBook-Pro.local")
    assert pairing_identity(system="Darwin", mac_name=lambda: None)[0] == "Srens-MacBook-Pro.local"
    # Linux and Windows are named by their hostname, which is already the name their owners use.
    assert pairing_identity(system="Linux", mac_name=lambda: "never asked")[0] == "Srens-MacBook-Pro.local"
