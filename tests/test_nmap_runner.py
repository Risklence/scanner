import pytest

from scanner_agent import nmap_runner
from scanner_agent.nmap_runner import NmapNotAvailableError, NmapScanResult, _parse_open_ports, run_discovery_scan

NMAP_SAMPLE_OUTPUT = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -T4 --top-ports 50 -oX - 127.0.0.1" start="1784289600">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="6390"><state state="open"/><service name="unknown"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_open_ports_extracts_open_tcp_ports():
    assert _parse_open_ports(NMAP_SAMPLE_OUTPUT) == [80, 6390]


def test_parse_open_ports_ignores_closed_and_non_tcp_ports():
    output = """<nmaprun><host><ports>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports></host></nmaprun>"""
    assert _parse_open_ports(output) == []


def test_parse_open_ports_handles_empty_output():
    assert _parse_open_ports("") == []


def test_parse_open_ports_survives_malformed_xml():
    """BUG-DISC-08: nmap can emit a truncated document when it is killed. The
    scan must still report rather than crash the poll loop."""
    assert _parse_open_ports("<nmaprun><host><ports>") == []


def test_scan_requests_xml_output(monkeypatch):
    """The server's evidence adapter parses NMAP_XML, so -oX - is not optional:
    without it nmap prints human-readable text that no parser accepts."""
    captured: dict = {}

    class _Completed:
        returncode = 0
        stdout = NMAP_SAMPLE_OUTPUT
        stderr = ""

    def _fake_run(command, **kwargs):
        captured["command"] = command
        return _Completed()

    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _binary: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "run", _fake_run)

    result = nmap_runner.run_safe_test_scan("127.0.0.1")

    assert "-oX" in captured["command"] and "-" in captured["command"]
    assert result.open_ports == [80, 6390]
    assert result.raw_output == NMAP_SAMPLE_OUTPUT


def test_merge_scan_xml_returns_a_single_valid_document():
    """A command may carry several targets but produces one evidence package.
    Concatenated XML documents are unparseable, so the hosts are merged."""
    import xml.etree.ElementTree as ET

    second = NMAP_SAMPLE_OUTPUT.replace("127.0.0.1", "127.0.0.2")
    merged = nmap_runner.merge_scan_xml(
        [
            NmapScanResult(target="a", open_ports=[80], raw_output=NMAP_SAMPLE_OUTPUT),
            NmapScanResult(target="b", open_ports=[80], raw_output=second),
        ]
    )

    root = ET.fromstring(merged)
    assert len(root.findall("host")) == 2


def test_merge_scan_xml_passes_a_single_document_through_unchanged():
    merged = nmap_runner.merge_scan_xml(
        [NmapScanResult(target="a", open_ports=[80], raw_output=NMAP_SAMPLE_OUTPUT)]
    )
    assert merged == NMAP_SAMPLE_OUTPUT


def test_merge_scan_xml_handles_no_evidence():
    assert nmap_runner.merge_scan_xml([]) == ""


def test_run_discovery_scan_scans_every_target(monkeypatch):
    calls: list[str] = []

    def _fake_scan(target: str, *, timeout: float = 60.0, fingerprint: bool = False) -> NmapScanResult:
        calls.append(target)
        return NmapScanResult(target=target, open_ports=[80] if target == "example.com" else [], raw_output="")

    monkeypatch.setattr(nmap_runner, "run_safe_test_scan", _fake_scan)

    results = run_discovery_scan(["example.com", "10.0.0.0/24"])

    assert calls == ["example.com", "10.0.0.0/24"]
    assert [r.open_ports for r in results] == [[80], []]


def test_run_discovery_scan_raises_immediately_when_nmap_is_missing(monkeypatch):
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _binary: None)

    with pytest.raises(NmapNotAvailableError):
        run_discovery_scan(["example.com"])


# ── Hostile XML (Plane #137 — Semgrep use-defused-xml) ──────────────────────
# The Collector produces this XML but does not author its content: hostnames,
# service banners and script output come from whatever answers on the scanned
# network. These prove the parser refuses the two classic attacks and that a
# refusal degrades the scan rather than crashing it.

XXE_EXTERNAL_ENTITY = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="&xxe;"/></hostnames>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
  </host>
</nmaprun>
"""

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<nmaprun><host><ports>
  <port protocol="tcp" portid="80"><state state="open"/><service name="&lol4;"/></port>
</ports></host></nmaprun>
"""


@pytest.mark.parametrize(
    ("name", "document"),
    [("external entity", XXE_EXTERNAL_ENTITY), ("entity expansion", BILLION_LAUGHS)],
)
def test_parse_open_ports_refuses_hostile_xml(name, document):
    """A hostile document is refused outright — no file read, no expansion —
    and the refusal is absorbed like any other unreadable output, so one
    malicious host on the scanned network cannot break the Collector."""
    assert _parse_open_ports(document) == []


def test_hostile_xml_raises_a_defused_exception_not_a_parse_error():
    """The reason _XML_REJECTED exists: defusedxml's refusals are ValueError
    subclasses, not ET.ParseError. An `except ParseError` alone would let a
    blocked attack crash the caller instead of degrading it."""
    import defusedxml.ElementTree as defused_et
    from defusedxml.common import DefusedXmlException

    with pytest.raises(DefusedXmlException):
        defused_et.fromstring(XXE_EXTERNAL_ENTITY)

    assert not issubclass(DefusedXmlException, defused_et.ParseError)


def test_merge_scan_xml_keeps_good_evidence_when_one_document_is_hostile():
    """One rejected document must not discard the evidence collected from every
    other target in the same command."""
    merged = nmap_runner.merge_scan_xml(
        [
            NmapScanResult(target="10.0.0.1", open_ports=[], raw_output=XXE_EXTERNAL_ENTITY),
            NmapScanResult(target="127.0.0.1", open_ports=[80, 6390], raw_output=NMAP_SAMPLE_OUTPUT),
        ]
    )

    assert "etc/passwd" not in merged
    assert _parse_open_ports(merged) == [80, 6390]


# --- CA-07.1 slice 1: fingerprinting runs only when the profile approves it ---


def _capture_command(monkeypatch) -> dict:
    captured: dict = {}

    class _Completed:
        returncode = 0
        stdout = NMAP_SAMPLE_OUTPUT
        stderr = ""

    def _fake_run(command, **kwargs):
        captured["command"] = command
        captured["timeout"] = kwargs.get("timeout")
        return _Completed()

    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _binary: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "run", _fake_run)
    return captured


def test_the_default_scan_does_not_fingerprint():
    """Version detection probes each open port rather than only completing a
    handshake. It happens because an organisation approved it, never by default."""
    command = nmap_runner.build_scan_command("10.0.0.1", fingerprint=False)
    assert "-sV" not in command
    assert "--script" not in command


def test_an_approved_profile_adds_version_detection_and_the_naming_scripts():
    """Without -sV, nmap fills <service name=…> from its port-number table
    alone, so port 8080 reads 'http-proxy' whether it is Plane or a coffee
    machine. http-title is the single probe that tells them apart."""
    command = nmap_runner.build_scan_command("10.0.0.1", fingerprint=True)
    assert "-sV" in command
    assert "http-title" in command[command.index("--script") + 1]
    assert "ssl-cert" in command[command.index("--script") + 1]


def test_fingerprinting_never_adds_os_detection_or_vulnerability_scripts():
    """Deeper identification, not a wider grant. OS fingerprinting and
    vulnerability scripts remain separately approved capabilities."""
    command = nmap_runner.build_scan_command("10.0.0.1", fingerprint=True)
    assert "-O" not in command
    assert "-A" not in command
    assert "vuln" not in " ".join(command)


def test_the_test_scan_never_fingerprints(monkeypatch):
    """`test-scan` targets an operator-supplied host with no approved profile
    behind it, so there is nothing that could authorise a deeper scan."""
    captured = _capture_command(monkeypatch)
    nmap_runner.run_safe_test_scan("127.0.0.1")
    assert "-sV" not in captured["command"]


def test_a_fingerprinting_run_is_given_longer_than_a_connect_sweep(monkeypatch):
    """Timing out mid-probe would report a partial result as a whole one, which
    is exactly how 'nothing was determined' becomes indistinguishable from
    'we stopped looking'."""
    captured = _capture_command(monkeypatch)
    nmap_runner.run_discovery_scan(["10.0.0.1"], fingerprint=True)
    assert captured["timeout"] == nmap_runner.FINGERPRINT_TIMEOUT_SECONDS
    assert captured["timeout"] > 60.0


def test_an_explicit_timeout_still_wins(monkeypatch):
    captured = _capture_command(monkeypatch)
    nmap_runner.run_discovery_scan(["10.0.0.1"], fingerprint=True, timeout=12.0)
    assert captured["timeout"] == 12.0


def test_the_time_a_target_may_take_follows_its_size_not_one_flat_number():
    from scanner_agent.nmap_runner import scan_timeout_seconds

    assert scan_timeout_seconds("example.com", fingerprint=False) == 60.0
    assert scan_timeout_seconds("example.com", fingerprint=True) == 300.0
    # A /24 swept by connect scans takes minutes; a flat 60 or 300 s made every range a timeout.
    assert scan_timeout_seconds("192.168.50.0/24", fingerprint=False) == 256 * 1.5
    assert scan_timeout_seconds("192.168.50.0/24", fingerprint=True) == 768.0
    # Bounded, so a stray /8 cannot hold the Collector for days, and never past what the platform will wait.
    assert scan_timeout_seconds("10.0.0.0/8", fingerprint=True) == 3600.0
    assert scan_timeout_seconds("192.168.50.0/24", fingerprint=True, budget_seconds=120.0) == 120.0


def test_a_target_nmap_could_not_finish_is_marked_unfinished_never_as_a_clean_empty_scan(monkeypatch):
    from scanner_agent.nmap_runner import NmapScanError

    def _times_out(target: str, *, timeout: float = 60.0, fingerprint: bool = False) -> NmapScanResult:
        raise NmapScanError(f"nmap scan of {target} timed out after {timeout}s.")

    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _binary: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner, "run_safe_test_scan", _times_out)

    [result] = run_discovery_scan(["192.168.50.0/24"], fingerprint=True)

    assert result.completed is False
    assert result.open_ports == []


def test_a_scan_that_finished_is_marked_completed(monkeypatch):
    monkeypatch.setattr(
        nmap_runner, "run_safe_test_scan", lambda target, **_: NmapScanResult(target=target, open_ports=[], raw_output="")
    )

    [result] = run_discovery_scan(["10.0.0.5"])

    assert result.completed is True


def test_every_scan_is_rate_limited_so_it_cannot_starve_the_collectors_own_traffic():
    """An unthrottled -sV over a /24 saturated the route to the platform; the
    heartbeats that keep the lease alive could not get out."""
    for fingerprint in (False, True):
        command = nmap_runner.build_scan_command("10.0.0.0/24", fingerprint=fingerprint)
        assert int(command[command.index("--max-rate") + 1]) <= 200
        assert "--max-retries" in command
