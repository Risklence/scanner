"""``validate-tools`` exit status and the raw-packet explanation."""

import pytest
import responses
from click.testing import CliRunner

from scanner_agent import cli as cli_module
from scanner_agent.cli import cli
from scanner_agent.config import ScannerCredentials
from scanner_agent.privilege_guidance import guidance_for_checks, raw_packet_guidance
from scanner_agent.tool_checks import (
    RAW_PACKET_CAPABILITY,
    ToolCheckResult,
    missing_required_tools,
)


def _tool(name: str, available: bool = True) -> ToolCheckResult:
    return ToolCheckResult(name, available, "1" if available else None, "/x" if available else None)


ALL_PRESENT = [_tool("nmap"), _tool("subfinder"), _tool("nuclei"), _tool("nuclei_templates")]


def _run(monkeypatch, checks, args=()):
    monkeypatch.setattr(
        cli_module,
        "load_credentials",
        lambda *_args: ScannerCredentials(base_url="https://api.example.com", activation_token="t"),
    )
    monkeypatch.setattr(cli_module, "check_all_tools", lambda: checks)
    monkeypatch.setattr(cli_module, "installed_collector_version", lambda: "0.2.0")
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/readiness",
        json={"scanner_instance_id": "a", "status": "online"},
    )
    return CliRunner().invoke(cli, ["validate-tools", *args])


@responses.activate
def test_exits_zero_when_every_tool_is_present(monkeypatch):
    assert _run(monkeypatch, ALL_PRESENT).exit_code == 0


@responses.activate
def test_exits_non_zero_when_nmap_is_missing_but_still_reports(monkeypatch):
    result = _run(monkeypatch, [_tool("nmap", False), *ALL_PRESENT[1:]])
    assert result.exit_code == 1
    assert "Reported to Risklence" in result.output
    assert len(responses.calls) == 1
    assert "Missing required tool(s): nmap" in result.output
    assert "install-tools --dry-run" in result.output


@responses.activate
def test_a_missing_optional_tool_only_fails_under_strict(monkeypatch):
    checks = [
        ALL_PRESENT[0],
        _tool("subfinder", False),
        _tool("nuclei"),
        _tool("nuclei_templates", False),
    ]
    assert _run(monkeypatch, checks).exit_code == 0
    responses.reset()
    strict = _run(monkeypatch, checks, ["--strict"])
    assert strict.exit_code == 1
    assert "subfinder, nuclei_templates" in strict.output


@responses.activate
def test_missing_raw_packet_access_is_explained_and_never_fails(monkeypatch):
    raw = ToolCheckResult(RAW_PACKET_CAPABILITY, False, None, "PermissionError")
    result = _run(monkeypatch, [*ALL_PRESENT, raw], ["--strict"])
    assert result.exit_code == 0
    assert "cannot send raw network packets" in result.output
    assert "It still scans" in result.output


@responses.activate
def test_no_guidance_when_raw_packet_access_is_available(monkeypatch):
    raw = ToolCheckResult(RAW_PACKET_CAPABILITY, True, None, None)
    assert "raw network packets" not in _run(monkeypatch, [*ALL_PRESENT, raw]).output


def test_required_tools_logic():
    assert missing_required_tools([_tool("nmap", False)]) == ["nmap"]
    assert missing_required_tools([_tool("nuclei", False)]) == []
    assert missing_required_tools([_tool("nuclei", False)], strict=True) == ["nuclei"]


@pytest.mark.parametrize(
    "platform,expected",
    [
        ("linux", ["setcap cap_net_raw,cap_net_admin+eip", "NMAP_PRIVILEGED=1"]),
        ("darwin", ["needs root", "connect scans"]),
        ("win32", ["Npcap", "Run as administrator"]),
    ],
)
def test_guidance_per_operating_system(platform, expected):
    text = "\n".join(raw_packet_guidance(platform))
    for fragment in expected:
        assert fragment in text


def test_guidance_has_a_fallback_and_stays_silent_when_not_needed():
    assert "elevated rights" in "\n".join(raw_packet_guidance("freebsd14"))
    assert guidance_for_checks([ToolCheckResult(RAW_PACKET_CAPABILITY, True, None, None)]) == []
