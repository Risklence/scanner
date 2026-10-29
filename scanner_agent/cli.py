"""Risklence Scanner CLI — the standalone agent process operators install
per Step 3.5 (Evidence Source: Scanner). Talks to the platform only via
the scanner-agent routes (never the browser/user JWT surface); everything
it reports comes from real, locally-executed checks.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import signal
import time

import click

from scanner_agent.api_client import ScannerApiClient, ScannerApiError
from scanner_agent.command_signing import CommandVerificationError, verify_command
from scanner_agent.collector_attribution_constants import (
    COLLECTOR_ATTRIBUTION_LINE,
    COLLECTOR_THIRD_PARTY_LINE,
)
from scanner_agent.collector_version import installed_collector_version
from scanner_agent.update_notice import collector_version_line, update_notice
from scanner_agent.host_credentials import (
    HostCredential,
    HostCredentialError,
    is_world_readable,
    load_host_credential,
    save_host_credential,
)
from scanner_agent.host_inspection import SshNotAvailableError, run_inspection
from scanner_agent.lease_heartbeat import heartbeat_while_working
from scanner_agent.network_position import detect_network_segments
from scanner_agent.pairing import PairingError, pairing_identity, request_code, wait_until_connected
from scanner_agent.config import ScannerCredentials, load_credentials, save_credentials
from scanner_agent.collector_home import (
    SCANNER_OPTION,
    SCANNERS_DIRNAME,
    CollectorHomeError,
    adopt_earlier,
    folder_for,
    folder_for_earlier,
    scanner_folder,
)
from scanner_agent.nmap_runner import merge_scan_xml, NmapNotAvailableError, NmapScanError, run_discovery_scan, run_safe_test_scan
from scanner_agent.nuclei_runner import NucleiNotAvailableError, run_nuclei_discovery
from scanner_agent.service import (
    ServiceError,
    current_service_manager,
    install_service,
    restart_commands,
    service_status,
    uninstall_service,
)
from scanner_agent.service_contracts import InstallOptions
from scanner_agent.subfinder_runner import SubfinderNotAvailableError, SubfinderScanError, run_subfinder_discovery
from scanner_agent.system_info import describe_host, detect_architecture, detect_os
from scanner_agent.config import DEFAULT_CONFIG_DIR
from scanner_agent.health_checks import (
    HealthResult,
    check_evidence_storage,
    check_platform_connectivity,
)
from scanner_agent.privilege_guidance import guidance_for_checks
from scanner_agent.tool_installer import run_install_tools
from scanner_agent.tool_checks import ToolCheckResult, check_all_tools, missing_required_tools

#: Seconds between heartbeat/poll cycles. Must stay well below the platform's 300s
#: worker lease (#322: 300 matched the lease, so every long run retried). The README
#: and the platform's install snippet (``SCANNER_RUN_INTERVAL_SECONDS``) say the same
#: number; a server test pins all three.
DEFAULT_RUN_INTERVAL_SECONDS = 60


#: Every command takes the scanner it is for, as the commands Risklence shows name it (2026-10-28): a computer can
#: run as many scanners' Collectors as needed, each with its own credential (``collector_home``).
_scanner_option = click.option(
    SCANNER_OPTION,
    "scanner_key",
    default=None,
    metavar="NAME",
    help="The scanner this is for, as the command Risklence shows names it. Needed when this computer runs "
    "Collectors for more than one scanner.",
)


def _for_scanner(name: str | None) -> str:
    return f'"{name}"' if name else "this scanner"


def _heartbeat_line(result: dict, credentials: ScannerCredentials) -> str:
    """Named, so whoever reads the output knows which scanner reported (2026-10-28: "online" from one scanner's
    Collector was taken as another scanner connecting)."""
    name = result.get("scanner_name") or credentials.scanner_name
    return f"Heartbeat OK — {name}: {result['status']}." if name else f"Heartbeat OK — status: {result['status']}."


def _send_heartbeat(client: ScannerApiClient) -> dict:
    """CA-02.3 slice 3 — reports each fact under the scope it can vouch for.

    ``detect_os()`` is deliberately no longer used here: it reads
    ``/etc/os-release``, which inside a container describes the image. That is
    what made the platform store a container's OS as the machine's.
    """
    host = describe_host()
    runtime = (
        f"{host.container_runtime} ({host.runtime_distribution_name})"
        if host.container_runtime and host.runtime_distribution_name
        else host.container_runtime
    )
    return client.heartbeat(
        # #321 — where this Collector is standing. Reported, never
        # interpreted here: whether a segment covers an approved target is
        # the platform's judgement, because the platform holds the targets
        # — and a Collector deciding it need not scan something would be a
        # Collector deciding scope.
        network_segments=[
            {"interface": s.interface, "address": s.address, "network": s.network}
            for s in detect_network_segments()
        ],
        os_name=host.distribution_name,
        os_version=host.distribution_version,
        architecture=host.architecture,
        kernel_release=host.kernel_release,
        container_runtime=runtime,
        runtime_os_name=host.runtime_distribution_name,
        runtime_os_version=host.runtime_distribution_version,
        collector_version=installed_collector_version(),
    )


@click.group()
@click.version_option(
    version=installed_collector_version() or "unknown",
    prog_name="risklence-scanner",
    message=f"%(prog)s %(version)s\n{COLLECTOR_ATTRIBUTION_LINE}\n{COLLECTOR_THIRD_PARTY_LINE}",
)
def cli() -> None:
    """Risklence Scanner agent. Made by Risklence (Apache License 2.0)."""


@cli.command()
@click.option("--base-url", required=True, help="Risklence API base URL, e.g. https://api.risklence.com")
@click.option("--token", required=True, help="Activation token shown once on the Evidence Source setup screen.")
@_scanner_option
def activate(base_url: str, token: str, scanner_key: str | None) -> None:
    """Bind this machine to a scanner instance and store the credential locally."""
    client = ScannerApiClient(base_url, token)
    try:
        folder = scanner_folder(scanner_key) if scanner_key else None
        result = _send_heartbeat(client)
    except (ScannerApiError, CollectorHomeError) as exc:
        raise click.ClickException(str(exc)) from exc
    # A key for one scanner is never kept in another scanner's folder.
    if folder is not None and result.get("collector_key") not in (None, folder.name):
        raise click.ClickException(
            f"This key is for {_for_scanner(result.get('scanner_name'))}, not the scanner this command names. "
            "Nothing was saved."
        )
    credentials = ScannerCredentials(
        base_url=base_url,
        activation_token=token,
        scanner_instance_id=result["scanner_instance_id"],
        scanner_name=result.get("scanner_name"),
    )
    path = save_credentials(credentials, folder) if folder is not None else save_credentials(credentials)
    click.echo(f"Activated scanner instance {result['scanner_instance_id']} (status: {result['status']}).")
    click.echo(f"Credentials stored at {path}.")


@cli.command()
@click.option("--base-url", required=True, help="Risklence API base URL, e.g. https://api.risklence.com")
@_scanner_option
def pair(base_url: str, scanner_key: str | None) -> None:
    """Connect this machine with a code typed in Risklence: no key is copied anywhere (#647)."""
    computer_name, os_name = pairing_identity()
    try:
        named = scanner_folder(scanner_key).name if scanner_key else None
        code = request_code(
            base_url,
            computer_name=computer_name,
            os_name=os_name,
            collector_version=installed_collector_version(),
            collector_key=named,
        )
        click.echo("")
        click.echo("To connect this Collector, type this code in Risklence")
        click.echo("(in the assistant, or in the scanner's install step):")
        click.echo("")
        click.echo(f"    {code.code}")
        click.echo("")
        click.echo(f"It works for {code.expires_in_seconds // 60} minutes. Waiting for you to connect it...")
        paired = wait_until_connected(base_url, code)
        credentials = ScannerCredentials(
            base_url=base_url,
            activation_token=paired.activation_token,
            scanner_instance_id=paired.scanner_instance_id,
            scanner_name=paired.scanner_name,
        )
        # Kept in the folder of the scanner it was connected to, beside any other scanner's on this computer.
        key = paired.collector_key or named
        path = save_credentials(credentials, scanner_folder(key)) if key else save_credentials(credentials)
        _send_heartbeat(ScannerApiClient(base_url, paired.activation_token))
    except (PairingError, ScannerApiError, CollectorHomeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Connected to Risklence for {_for_scanner(paired.scanner_name)}. Credentials stored at {path}.")


@cli.command()
@_scanner_option
def heartbeat(scanner_key: str | None) -> None:
    """Send a liveness ping to Risklence."""
    credentials = _require_credentials(scanner_key)
    client = ScannerApiClient(credentials.base_url, credentials.activation_token)
    try:
        result = _send_heartbeat(client)
    except ScannerApiError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_heartbeat_line(result, credentials))


#: Cycles between unattended self-checks. At the default 300s interval that is
#: roughly hourly — often enough that a broken component is noticed the same
#: working day, rare enough that the subprocesses it spawns are not a cost.
SELF_CHECK_EVERY_CYCLES = 12

#: Must match the platform's READINESS_SCHEMA_VERSION — a report whose version
#: the platform does not recognise cannot be trusted to mean what it says.
READINESS_SCHEMA_VERSION = "1"

#: Why a self-check ran (the platform's CollectorReadinessTrigger).
READINESS_TRIGGER_STARTUP = "startup"
READINESS_TRIGGER_PERIODIC = "periodic"
READINESS_TRIGGER_REQUESTED = "requested"

#: The instructions the platform can hand back on a heartbeat.
INSTRUCTION_SELF_CHECK = "self_check"
INSTRUCTION_TEST_SCAN = "test_scan"
#: The controlled test scan looks only at the Collector's own machine.
TEST_SCAN_TARGET = "127.0.0.1"

#: How many recent platform calls the agent remembers when describing how
#: stable its link has been. Ten cycles is five minutes at the default
#: interval — long enough for a pattern, short enough that a fault fixed an
#: hour ago is not still being reported.
LINK_HISTORY_SIZE = 10


@dataclass
class LinkStability:
    """What the agent observed about its own link to the platform.

    Kept by the run loop because it is the only party that can know it: the
    platform sees a gap in heartbeats and cannot tell a Collector that was
    switched off from one whose network kept dropping.
    """

    outcomes: deque[bool] = field(default_factory=lambda: deque(maxlen=LINK_HISTORY_SIZE))

    def record(self, *, ok: bool) -> None:
        self.outcomes.append(ok)

    @property
    def attempts(self) -> int:
        return len(self.outcomes)

    @property
    def failures(self) -> int:
        return sum(1 for ok in self.outcomes if not ok)


def _restart_for(scanner_key: str | None):
    """How to restart this scanner's own service, for the update notice."""
    return lambda: restart_commands(current_service_manager(scanner_key=scanner_key))


def _echo_collector_version(
    latest: str | None, container_name: str | None = None, scanner_key: str | None = None
) -> None:
    """The version line of a self-check, and the update notice if one applies."""
    current = installed_collector_version()
    click.echo(f"  {collector_version_line(current)}")
    notice = update_notice(
        current, latest, container_name, restart=_restart_for(scanner_key), scanner_key=scanner_key
    )
    if notice:
        click.echo(notice)


def _run_self_check(
    client: ScannerApiClient,
    *,
    echo: bool = True,
    trigger: str = READINESS_TRIGGER_PERIODIC,
    link: LinkStability | None = None,
    latest_collector_version: str | None = None,
    collector_container_name: str | None = None,
    checks: list[ToolCheckResult] | None = None,
) -> dict:
    """Check our own components and report the result.

    Shared by the ``validate-tools`` command and the persistent run loop so the
    two cannot drift: the platform now treats this report as the *only*
    authoritative statement about whether this Collector can work (CA-02.3), so
    a self-check that only happens when someone types a command by hand is not
    good enough — an unattended Collector would never report at all.

    Reports through ``/readiness`` rather than the legacy ``/tools/validate``
    shim, because that is the route carrying *why* the check ran. ``trigger``
    says what this Collector was asked to do; **it never names a person.** The
    platform resolves that from its own pending instruction, so an agent cannot
    attribute a report to an arbitrary user.
    """
    checks = checks if checks is not None else check_all_tools()
    if echo:
        for check in checks:
            marker = "OK" if check.available else "MISSING"
            detail = check.version or check.binary_path or "not found"
            click.echo(f"  [{marker}] {check.tool}: {detail}")

    template_pack_version = next(
        (check.version for check in checks if check.tool == "nuclei_templates" and check.available),
        None,
    )

    storage = check_evidence_storage(DEFAULT_CONFIG_DIR)
    # No observed history (a one-shot `validate-tools`, or the very first cycle)
    # means unknown, not healthy — the run loop is what accumulates this.
    connectivity = (
        check_platform_connectivity(
            recent_failures=link.failures, recent_attempts=link.attempts
        )
        if link is not None
        else HealthResult("unknown", "no_attempts_recorded")
    )
    if echo:
        _echo_collector_version(latest_collector_version, collector_container_name)
        click.echo(f"  [{storage.status}] evidence storage: {storage.detail or storage.reason_code or ''}")
        click.echo(
            f"  [{connectivity.status}] platform link: {connectivity.detail or connectivity.reason_code or ''}"
        )

    return client.report_readiness(
        {
            "schemaVersion": READINESS_SCHEMA_VERSION,
            "components": [
                {
                    "componentKey": check.tool,
                    "status": "ready" if check.available else "unavailable",
                    "version": check.version,
                }
                for check in checks
            ],
            "platformConnectivityStatus": connectivity.status,
            "evidenceStorageStatus": storage.status,
            "templatePackVersion": template_pack_version,
            "collectorVersion": installed_collector_version(),
            "trigger": trigger,
            "failureReasonCodes": [
                code for code in (storage.reason_code, connectivity.reason_code) if code
            ],
        }
    )


@cli.command("validate-tools")
@click.option(
    "--strict",
    is_flag=True,
    help="Also fail when subfinder, nuclei or the nuclei template pack is missing, not only nmap.",
)
@_scanner_option
def validate_tools(strict: bool, scanner_key: str | None) -> None:
    """Detect installed scan tools locally and report their status to Risklence.

    Exits non-zero when nmap is missing (with --strict: when any of nmap, subfinder,
    nuclei or the template pack is missing), after reporting to Risklence as usual.
    A missing raw-packet permission is explained but never fails the command."""
    credentials = _require_credentials(scanner_key)
    client = ScannerApiClient(credentials.base_url, credentials.activation_token)
    checks = check_all_tools()
    try:
        result = _run_self_check(client, checks=checks)
    except ScannerApiError as exc:
        raise click.ClickException(str(exc)) from exc
    for line in guidance_for_checks(checks):
        click.echo(line)
    click.echo(f"Reported to Risklence — instance status: {result['status']}.")
    missing = missing_required_tools(checks, strict=strict)
    if missing:
        click.echo(
            f"Missing required tool(s): {', '.join(missing)}. "
            "`risklence-scanner install-tools --dry-run` shows how to install them.",
            err=True,
        )
        raise SystemExit(1)


@cli.command("install-tools")
@click.option("--dry-run", is_flag=True, help="Print exactly what would be done, and change nothing.")
@click.option("--yes", "assume_yes", is_flag=True, help="Do not ask for confirmation.")
def install_tools(dry_run: bool, assume_yes: bool) -> None:
    """Install or verify nmap, subfinder, nuclei and the pinned nuclei template pack.

    Shows the plan and asks before doing anything. Downloads are pinned and
    checked against a checksum; administrator rights are needed only where the
    system package manager needs them (nmap on Linux)."""
    code = run_install_tools(dry_run=dry_run, assume_yes=assume_yes, echo=click.echo, confirm=click.confirm)
    if code != 0:
        raise SystemExit(code)


@cli.command("test-scan")
@click.option("--target", default=TEST_SCAN_TARGET, show_default=True, help="Approved test-lab target to scan.")
@_scanner_option
def test_scan(target: str, scanner_key: str | None) -> None:
    """Run a real, safe scan against an approved target and report the result."""
    credentials = _require_credentials(scanner_key)
    client = ScannerApiClient(credentials.base_url, credentials.activation_token)
    try:
        result = _run_test_scan(client, target)
    except (NmapNotAvailableError, NmapScanError, ScannerApiError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Reported to Risklence — instance status: {result['status']}.")


def _run_test_scan(client: ScannerApiClient, target: str = TEST_SCAN_TARGET) -> dict:
    """The controlled test scan, reported to Risklence either way. Used by `test-scan` and, when Risklence asks for
    it, by `run` (2026-10-28), so the owner neither opens a terminal nor records the result themselves."""
    try:
        scan_result = run_safe_test_scan(target)
    except (NmapNotAvailableError, NmapScanError):
        try:
            client.report_test_scan(status="failed", connection_verified=False)
        except ScannerApiError:
            pass
        raise
    click.echo(f"Scanned {target} — open ports: {scan_result.open_ports or 'none'}")
    return client.report_test_scan(status="completed", connection_verified=True)


def _fingerprinting_approved(command: dict) -> bool:
    """Whether this command's own profile snapshot authorises service
    fingerprinting (CA-07.1 slice 1).

    Read from the envelope rather than configured on the Collector, because the
    authorisation is the organisation's and it already travels with every
    command: `profile` is `run.profile_snapshot`, built by
    `build_profile_snapshot` from the approved `ScannerProfile`'s capabilities.
    A Collector-side setting would be a second, local answer to a question the
    organisation has already approved — and could widen a scan beyond what was
    approved without anyone recording that it happened.

    Absent or malformed means False. A missing authorisation is not a permissive
    one, and an older server that sends no `profile` must get the old scan
    depth, not a deeper one nobody approved.
    """
    profile = command.get("profile")
    if not isinstance(profile, dict):
        return False
    return profile.get("allowsFingerprinting") is True


def _handle_command(client: ScannerApiClient, command: dict, credentials: ScannerCredentials) -> None:
    """CA-04.1 — verify, then (only if it verifies) actually execute nmap
    against the command's own approved targets and report a real result.
    A command that fails verification is never executed — it is rejected
    with the specific CommandRejectionCode that explains why, not silently
    dropped or unconditionally accepted like the old placeholder."""
    click.echo(f"Command {command['command_id']} ({command['command_type']}) for discovery run {command['discovery_run_id']}")
    click.echo(f"  Profile: {command['profile'].get('profileType')}")
    click.echo(f"  Targets: {len(command['targets'])}")
    click.echo(f"  Expires at: {command['expires_at']}")

    try:
        verify_command(
            command,
            raw_activation_token=credentials.activation_token,
            local_scanner_instance_id=credentials.scanner_instance_id,
        )
    except CommandVerificationError as exc:
        click.echo(f"Rejecting command ({exc.code}): {exc}")
        try:
            client.acknowledge_command(
                command["command_id"], accepted=False, rejection_code=exc.code, rejection_message=str(exc)
            )
        except ScannerApiError as ack_exc:
            click.echo(f"  (could not report rejection to Risklence: {ack_exc})")
        return

    # ScannerApiError propagates from here on. Under the one-shot `poll`
    # command its caller turns it into a ClickException and a non-zero exit,
    # which is correct for a CLI invocation. Under the persistent `run` loop
    # its caller logs and continues — raising ClickException here killed the
    # agent outright on a single transient network failure.
    result = client.acknowledge_command(command["command_id"], accepted=True, scanner_runtime_version=installed_collector_version())
    click.echo(f"Acknowledged — discovery run status: {result['status']}.")

    targets = [target["approvedValue"] for target in command["targets"] if target.get("approvedValue")]
    if command.get("provider_execution_id") is not None:
        _execute_delegated_job(client, command, targets)
    else:
        _execute_whole_run(client, command, targets)


def _nuclei_target_scopes(command: dict) -> list[tuple[str, list[str] | None, str]]:
    """Each nuclei target with its template scope and the reason for it.

    ``templateTrees`` absent means no scope was sent — an older server — and the
    whole pack runs, which is why the missing case is ``None`` rather than an
    empty list. An empty list would mean "scoped to nothing", and the server
    never sends that: it drops such a host from the command entirely.

    The reason is echoed to the console rather than kept internal. A scan that
    silently skipped 82% of its templates would look exactly like one that ran
    them all and matched nothing, which is the same defect class as a timeout
    reported as a clean scan.
    """
    scopes = []
    for target in command.get("targets", []):
        value = target.get("approvedValue")
        if not value:
            continue
        trees = target.get("templateTrees")
        scopes.append(
            (
                value,
                trees if isinstance(trees, list) else None,
                str(target.get("templateScopeReason") or ""),
            )
        )
    return scopes


def _nuclei_scoped_targets(command: dict) -> list[tuple[str, list[str] | None]]:
    return [(value, trees) for value, trees, _reason in _nuclei_target_scopes(command)]


def _execute_whole_run(client: ScannerApiClient, command: dict, targets: list[str]) -> None:
    """CA-04.1 — Step 4.1's original whole-run command path. Disclosed
    finding (CA-04.3): a real approved discovery run no longer takes this
    path in production at all — discovery_run.py's own
    _advance_if_approved comment states the execution-pipeline
    (_execute_delegated_job, below) is what every approved run actually
    triggers today, and create_command_for_run is kept only for backward
    compatibility, not deleted. This function stays correct for whatever
    still creates a command this way, but it is not the path real traffic
    exercises — see _execute_delegated_job for that."""
    discovery_run_id = command["discovery_run_id"]
    try:
        client.report_discovery_run_status(discovery_run_id, status="running")
    except ScannerApiError as exc:
        click.echo(f"  (could not report running status: {exc})")

    try:
        scan_results = run_discovery_scan(targets, fingerprint=_fingerprinting_approved(command))
    except NmapNotAvailableError as exc:
        click.echo(f"Scan failed: {exc}")
        try:
            client.report_discovery_run_status(discovery_run_id, status="failed")
        except ScannerApiError as report_exc:
            click.echo(f"  (could not report failure: {report_exc})")
        return

    total_open_ports = sum(len(scan.open_ports) for scan in scan_results)
    click.echo(f"Scanned {len(scan_results)} target(s) — {total_open_ports} open port(s) total.")
    report = client.report_discovery_run_status(discovery_run_id, status="completed")
    click.echo(f"Reported real result — discovery run status: {report['status']}.")


#: What one target gets when the command carries no usable budget of its own —
#: nuclei_runner's own default, named here rather than restated as a literal.
_NUCLEI_FALLBACK_TARGET_TIMEOUT_SECONDS = 180.0

#: Reserve on the command's budget, so reporting the result still happens inside
#: the window the platform is willing to wait. Spending the whole budget on the
#: scan and none on the upload turns a good scan into an expired command.
_REPORTING_RESERVE_SECONDS = 30.0

#: No target gets less than this. A command with many targets and a short window
#: would otherwise divide its way down to a budget nuclei cannot do anything
#: useful in, and a scan too short to find anything reports the same clean,
#: empty result this whole path exists to stop being a lie.
_MIN_TARGET_TIMEOUT_SECONDS = 30.0


def _target_timeout_seconds(command: dict, target_count: int) -> float:
    """Split the command's own duration budget across its targets.

    The platform already states how long it will wait — ``maximumDurationSeconds``
    on the command's execution policy — and the Collector used to ignore it,
    hardcoding 180s per target regardless. That is the hardcoding rule broken in
    the one place where the correct value was already on the wire.

    Floored rather than divided blindly: a target is given a budget it can do
    something with, and if the command cannot afford that for every target, the
    later ones report as truncated — which is now a truthful outcome rather than
    a silent one.
    """
    policy = command.get("execution_policy")
    budget = policy.get("maximumDurationSeconds") if isinstance(policy, dict) else None
    if not isinstance(budget, (int, float)) or budget <= 0:
        return _NUCLEI_FALLBACK_TARGET_TIMEOUT_SECONDS
    usable = max(float(budget) - _REPORTING_RESERVE_SECONDS, _MIN_TARGET_TIMEOUT_SECONDS)
    return max(usable / max(target_count, 1), _MIN_TARGET_TIMEOUT_SECONDS)


def _per_target_budget_seconds(command: dict, target_count: int) -> float | None:
    """What the platform said it will wait, split across the command's targets; None when it did not say."""
    policy = command.get("execution_policy")
    budget = policy.get("maximumDurationSeconds") if isinstance(policy, dict) else None
    if not isinstance(budget, (int, float)) or budget <= 0:
        return None
    return max(float(budget) - _REPORTING_RESERVE_SECONDS, _MIN_TARGET_TIMEOUT_SECONDS) / max(target_count, 1)


def _execute_delegated_job(client: ScannerApiClient, command: dict, targets: list[str]) -> None:
    """CA-04.3 — Step 4.2's real per-job command path, the one every
    approved discovery run actually takes in production today (see
    _execute_whole_run's docstring). Reports back through the per-job
    result route (discovery_execution_agent.py), never the whole-run
    status route — CA-04.1 never distinguished the two, so a delegated
    command was previously reported to the wrong endpoint entirely; this
    is the fix, not just Subfinder's own addition."""
    command_id = command["command_id"]
    check_key = command.get("check_key")

    if check_key == "subfinder":
        try:
            scan_results = run_subfinder_discovery(targets)
        except SubfinderNotAvailableError as exc:
            click.echo(f"Scan failed: {exc}")
            try:
                client.report_provider_execution_result(
                    command_id, status="failed", failure_code="provider_error", failure_message=str(exc)
                )
            except ScannerApiError as report_exc:
                click.echo(f"  (could not report failure: {report_exc})")
            return
        all_subdomains = sorted({subdomain for scan in scan_results for subdomain in scan.subdomains})
        click.echo(f"Discovered {len(all_subdomains)} subdomain(s) across {len(scan_results)} target(s).")
        raw_payload = "\n".join(all_subdomains)
        report = client.report_provider_execution_result(
            command_id, status="completed", evidence_format="text", raw_evidence_payload=raw_payload
        )
        click.echo(f"Reported real result — job status: {report['status']}.")
        return

    if check_key == "nmap":
        # nmap_runner now runs with -oX -, so raw_output is the NMAP_XML the
        # server's evidence adapter parses. Previously the scan ran for real,
        # found real open ports, and attached nothing — the job reported
        # completed while its results were discarded, so no discovery ever
        # produced an asset.
        fingerprint = _fingerprinting_approved(command)
        if fingerprint:
            # Said out loud because it changes what the scan does to the
            # customer's network, and an operator watching the Collector should
            # be able to see that from the console rather than infer it.
            click.echo("Profile approves service fingerprinting — running version detection.")
        try:
            scan_results = run_discovery_scan(
                targets, fingerprint=fingerprint, budget_seconds=_per_target_budget_seconds(command, len(targets))
            )
        except NmapNotAvailableError as exc:
            click.echo(f"Scan failed: {exc}")
            try:
                client.report_provider_execution_result(
                    command_id, status="failed", failure_code="provider_error", failure_message=str(exc)
                )
            except ScannerApiError as report_exc:
                click.echo(f"  (could not report failure: {report_exc})")
            return
        total_open_ports = sum(len(scan.open_ports) for scan in scan_results)
        # A target that ran out of time or failed is **not** a target that had nothing open: calling both "completed"
        # recorded a /24 that took longer than its limit as scanned and empty ("0 open ports"). Said as partial, with
        # whatever did complete still attached.
        unfinished = [scan.target for scan in scan_results if not scan.completed]
        status = "partially_completed" if unfinished else "completed"
        # Merged into one valid document — a command may carry several targets
        # but produces a single evidence package, and concatenated XML is
        # unparseable. A single-target command uploads nmap's XML unmodified.
        raw_payload = merge_scan_xml(scan_results)
        click.echo(f"Scanned {len(scan_results)} target(s) — {total_open_ports} open port(s) total.")
        if unfinished:
            click.echo(
                f"  {len(unfinished)} target(s) did not finish within their time limit, so nothing is known about "
                f"them: {', '.join(unfinished)}"
            )
        report = client.report_provider_execution_result(
            command_id,
            status=status,
            evidence_format="nmap_xml",
            raw_evidence_payload=raw_payload,
            failure_code="scan_time_budget_exceeded" if unfinished else None,
            failure_message=(
                f"{len(unfinished)} of {len(scan_results)} target(s) did not finish within their time limit; "
                "the attached evidence covers only what completed."
                if unfinished
                else None
            ),
        )
        click.echo(f"Reported real result — job status: {report['status']}.")
        return

    if check_key == "nuclei":
        # nuclei runs against the pinned CA-03.2 template pack (never
        # -update-templates — see nuclei_runner.py) and its raw JSONL is now
        # attached: the server registers a (json, nuclei) parser as of
        # 2026-09-06. This branch previously ran the scan for real, found real
        # vulnerabilities and reported "completed" while discarding every one
        # of them — the same defect the nmap branch above describes, and the
        # reason the platform held 69 evidence packages and zero findings.
        if not targets:
            # A vulnerability command whose targets narrowed to nothing has not
            # scanned anything, and must not report the empty result that would
            # be read as "scanned, found nothing" (see the timeout note below).
            click.echo("No targets to scan with nuclei — reporting no coverage rather than an empty scan.")
            try:
                client.report_provider_execution_result(
                    command_id,
                    status="failed",
                    failure_code="no_targets_in_scope",
                    failure_message=(
                        "No discovered host fell inside this command's approved scope, so nuclei "
                        "scanned nothing. Run discovery first."
                    ),
                )
            except ScannerApiError as report_exc:
                click.echo(f"  (could not report failure: {report_exc})")
            return
        # Each target carries the template trees the server scoped it to, and
        # why. Narrowing to discovered hosts was not enough on its own: the
        # 2026-09-07 07:12 run still took 606s because the organisation holds an
        # artefact per address across a whole /24, so 258 of 269 "discovered"
        # hosts had no open port at all. A target with no scope on the wire is
        # an older server and still gets the whole pack.
        scoped_targets = _nuclei_scoped_targets(command)
        for _target, _trees, reason in _nuclei_target_scopes(command):
            if reason:
                click.echo(f"  {_target}: {reason}")
        try:
            scan_results = run_nuclei_discovery(
                scoped_targets, timeout=_target_timeout_seconds(command, len(scoped_targets))
            )
        except NucleiNotAvailableError as exc:
            click.echo(f"Scan failed: {exc}")
            try:
                client.report_provider_execution_result(
                    command_id, status="failed", failure_code="provider_error", failure_message=str(exc)
                )
            except ScannerApiError as report_exc:
                click.echo(f"  (could not report failure: {report_exc})")
            return
        # JSONL concatenates safely — unlike nmap's XML, which had to be merged
        # into one valid document. A target that matched nothing contributes no
        # lines, which is a real result and not an absence of evidence.
        raw_payload = "\n".join(
            scan.raw_output.strip() for scan in scan_results if scan.raw_output.strip()
        )
        finding_lines = sum(1 for line in raw_payload.splitlines() if line.strip())
        # 🐞 A target killed at the time budget is **not** a target that came
        # back clean, and reporting both as "completed" is what let ten days of
        # truncated scans be recorded as clean empty ones. The platform's own
        # resolution rule — a later scan finding nothing is what proves a
        # finding resolved — makes that mislabel able to discharge real risk.
        # PARTIALLY_COMPLETED already exists for exactly this; whatever nuclei
        # did write is still attached, because partial evidence is real.
        # Hosts, not invocations. One invocation now covers every host sharing a
        # template scope, so a group's own label would name one host and hide
        # the rest — and these are exactly the hosts a reader must be told were
        # not fully examined.
        scanned_hosts = [host for scan in scan_results for host in scan.targets]
        truncated = [
            host for scan in scan_results if not scan.completed for host in scan.targets
        ]
        status = "partially_completed" if truncated else "completed"
        click.echo(
            f"Scanned {len(scanned_hosts)} host(s) in {len(scan_results)} nuclei run(s) against "
            f"the pinned template pack — {finding_lines} finding(s)."
        )
        if truncated:
            click.echo(
                f"  {len(truncated)} host(s) hit the time budget and were not fully scanned: "
                f"{', '.join(truncated)}"
            )
        report = client.report_provider_execution_result(
            command_id,
            status=status,
            evidence_format="json",
            raw_evidence_payload=raw_payload,
            failure_code="scan_time_budget_exceeded" if truncated else None,
            failure_message=(
                f"{len(truncated)} of {len(scanned_hosts)} host(s) hit the time budget and were "
                "not fully scanned; the attached evidence covers only what completed."
                if truncated
                else None
            ),
        )
        click.echo(f"Reported real result — job status: {report['status']}.")
        return

    click.echo(f"Unrecognised check key {check_key!r} for a delegated job — rejecting rather than guessing.")
    try:
        client.report_provider_execution_result(
            command_id,
            status="failed",
            failure_code="check_key_unknown",
            failure_message=f"Unrecognised check key: {check_key!r}",
        )
    except ScannerApiError as report_exc:
        click.echo(f"  (could not report failure: {report_exc})")


def _handle_inspection(client: ScannerApiClient, inspection: dict, credentials: ScannerCredentials) -> None:
    """Run one deep-verification inspection and report the facts.

    Deliberately short. Everything that decides *whether* this may run already
    happened — on the platform, when it was authorised and signed, and in
    ``run_inspection``, which verifies that signature before anything executes.
    Nothing here interprets the result: the Collector collects, the engine reads
    (Søren, 2026-08-24).
    """
    command_id = inspection["command_id"]
    try:
        credential = load_host_credential(inspection["connector_id"])
    except HostCredentialError as exc:
        # A missing credential is a setup fact, and reporting it as a rejection
        # is what lets somebody see it — a Collector that silently skipped would
        # leave the run waiting forever with nothing to look at.
        click.echo(f"  {exc}")
        client.report_inspection(command_id, rejection_reason=str(exc))
        return

    try:
        result = run_inspection(
            inspection,
            credential=credential,
            raw_activation_token=credentials.activation_token,
            local_scanner_instance_id=credentials.scanner_instance_id,
        )
    except CommandVerificationError as exc:
        click.echo(f"  Refused: {exc}")
        client.report_inspection(command_id, rejection_reason=f"{exc.code}: {exc}")
        return
    except SshNotAvailableError as exc:
        click.echo(f"  {exc}")
        client.report_inspection(command_id, rejection_reason=str(exc))
        return

    report = client.report_inspection(
        command_id,
        exit_code=result.exit_code,
        stderr=result.stderr,
        stdout=result.stdout,
        credential_findings=list(result.credential_findings),
        timed_out=result.timed_out,
    )
    established = report.get("identity_name")
    click.echo(
        f"  Inspected {inspection['capability']} — exit {result.exit_code}, "
        f"platform read it as: {report.get('outcome')}"
    )
    # "It ran" and "it learned something" are different facts, and the second is
    # the one this epic exists for.
    if established:
        click.echo(f"  Identified as: {established} (via {report.get('identity_basis')})")
    # #296 — worth saying out loud on the operator's own console, because it is
    # a finding about their estate rather than a detail of the run.
    if result.credential_findings:
        count = len(result.credential_findings)
        click.echo(
            f"  {count} stored credential{'s' if count != 1 else ''} found in configuration "
            f"— redacted here, reported as a finding."
        )


@cli.command()
@_scanner_option
def poll(scanner_key: str | None) -> None:
    """Fetch the next pending discovery command, verify it, execute a real
    Nmap scan against its approved targets, and report a real result back.

    CA-04.1 (Step 4.1's Scoped Job Protocol, whole-run command path) — a
    verified command is genuinely executed; an unverified one is rejected
    with a real CommandRejectionCode, never blindly acknowledged. Subfinder/
    Nuclei execution (delegated per-job path) is handled by
    _execute_delegated_job, not this whole-run docstring's own scan.
    """
    credentials = _require_credentials(scanner_key)
    client = ScannerApiClient(credentials.base_url, credentials.activation_token)
    try:
        kind, work = client.fetch_next_work()
    except ScannerApiError as exc:
        raise click.ClickException(str(exc)) from exc

    if kind is None:
        click.echo("No pending work.")
        return

    # CA-08.2 — the same poll returns two kinds of work. Which table it came
    # from is the platform's business; this only has to know what to do with it.
    if kind == "inspection":
        try:
            _handle_inspection(client, work, credentials)
        except ScannerApiError as exc:
            raise click.ClickException(str(exc)) from exc
        return

    command = work

    # One-shot invocation: a failure is the command's result, so it exits
    # non-zero. The persistent `run` loop deliberately does the opposite.
    try:
        _handle_command(client, command, credentials)
    except ScannerApiError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command()
@click.option(
    "--interval",
    default=DEFAULT_RUN_INTERVAL_SECONDS,
    show_default=True,
    help="Seconds between heartbeat/poll cycles.",
)
@_scanner_option
def run(interval: int, scanner_key: str | None) -> None:
    """Run as a persistent process: heartbeat and poll on a loop until
    stopped. This is what a systemd unit (`install`) or a Docker
    container's own long-running process actually executes — the
    one-shot commands above stay available for manual/scripted use."""
    folder = _credentials_folder(scanner_key)
    credentials = _require_credentials(scanner_key)
    # The scanner whose service this may be, so an update notice restarts that one.
    service_key = folder.name if folder.parent.name == SCANNERS_DIRNAME else None
    client = ScannerApiClient(credentials.base_url, credentials.activation_token)

    def _reload_credentials() -> None:
        """Pick up a rotated credential without being reinstalled.

        Søren, 2026-08-25: *"If the scanner exists then just update the token"*.

        Rotating a credential invalidates the old one immediately — the platform
        answers 401 — but this loop read its token once at startup, so a running
        Collector went on presenting a dead credential until somebody removed
        and recreated the container. Re-running `activate` wrote the new token
        to the same file and the running process never looked at it again.

        It looks now, every cycle. The file is small, local, and rewritten only
        by `activate`, so re-reading it is cheaper than the request that
        follows. A missing or unreadable file keeps whatever is already in hand:
        a transient read failure must not disarm a working Collector.
        """
        nonlocal credentials, client
        try:
            latest = load_credentials(folder)
        except (FileNotFoundError, ValueError, OSError):
            return
        if (
            latest.activation_token == credentials.activation_token
            and latest.base_url == credentials.base_url
        ):
            return
        credentials = latest
        client = ScannerApiClient(latest.base_url, latest.activation_token)
        click.echo("Credential changed on disk — reconnecting with the new one.")

    stop_requested = False

    def _handle_stop(signum: int, _frame: object) -> None:
        nonlocal stop_requested
        click.echo(f"Received signal {signum}, stopping after this cycle...")
        stop_requested = True

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    click.echo(COLLECTOR_ATTRIBUTION_LINE)
    click.echo(f"Starting Risklence Scanner agent loop (interval: {interval}s). Ctrl+C or SIGTERM to stop.")

    # CA-02.3 — the platform treats this Collector's own self-check as the only
    # authoritative statement about whether it can work, so the loop has to
    # produce one. It used to run only when a person typed `validate-tools`,
    # which meant an unattended Collector never reported readiness at all and
    # its setup could never complete.
    cycles_since_self_check = SELF_CHECK_EVERY_CYCLES
    link = LinkStability()
    # What the platform last said the newest Collector is. One notice per
    # start-up (the first heartbeat that answers) and one per self-check, so a
    # long-running Collector is not nagged every cycle.
    latest_collector_version: str | None = None
    collector_container_name: str | None = None
    startup_notice_given = False

    while not stop_requested:
        requested_self_check = False
        requested_test_scan = False
        # Before anything is sent: a credential rotated since the last cycle is
        # the difference between working and 401ing forever.
        _reload_credentials()
        try:
            result = _send_heartbeat(client)
            click.echo(_heartbeat_line(result, credentials))
            # CA-02.3 slice 3 — the platform cannot push, so an operational
            # instruction rides back on the message we already send most often.
            # `.get` rather than `[...]`: an older platform sends no such field,
            # and an agent must not break against one.
            requested_self_check = result.get("pending_instruction") == INSTRUCTION_SELF_CHECK
            requested_test_scan = result.get("pending_instruction") == INSTRUCTION_TEST_SCAN
            link.record(ok=True)
            # `.get` for the same reason: an older platform sends no latest version.
            latest_collector_version = result.get("latest_collector_version") or latest_collector_version
            collector_container_name = result.get("collector_container_name") or collector_container_name
            if not startup_notice_given:
                startup_notice_given = True
                notice = update_notice(
                    installed_collector_version(),
                    latest_collector_version,
                    collector_container_name,
                    restart=_restart_for(service_key),
                    scanner_key=service_key,
                )
                if notice:
                    click.echo(notice)
        except ScannerApiError as exc:
            # A paused/revoked credential, or a transient network issue,
            # must not crash the loop — the whole point of a persistent
            # service is that it keeps trying rather than needing a human
            # to notice and restart it.
            click.echo(f"Heartbeat failed, will retry next cycle: {exc}")
            link.record(ok=False)

        if stop_requested:
            break

        # After the heartbeat, never before it: a self-check runs local
        # subprocesses and is far more expensive, so putting it first would make
        # the platform wait on probes before learning this Collector is alive.
        # Once on start (a freshly installed Collector reports within one cycle),
        # then periodically.
        # A person waiting on a screen takes priority over the schedule: an
        # explicit request runs now, and resets the periodic clock so it does
        # not immediately run a second time for no reason.
        if requested_self_check or cycles_since_self_check >= SELF_CHECK_EVERY_CYCLES:
            trigger = (
                READINESS_TRIGGER_REQUESTED if requested_self_check else READINESS_TRIGGER_PERIODIC
            )
            try:
                _run_self_check(client, echo=False, trigger=trigger, link=link)
                _echo_collector_version(latest_collector_version, collector_container_name, service_key)
                click.echo(
                    "Self-check reported (requested)." if requested_self_check else "Self-check reported."
                )
                cycles_since_self_check = 0
            except ScannerApiError as exc:
                # Deliberately not cleared platform-side on failure: the
                # instruction stays pending so the next cycle tries again,
                # rather than the request silently evaporating.
                click.echo(f"Self-check failed, will retry: {exc}")
        cycles_since_self_check += 1

        if requested_test_scan and not stop_requested:
            # Its result clears the request on Risklence's side; a failure to report leaves it pending for next time.
            try:
                _run_test_scan(client)
                click.echo("Test scan reported (requested).")
            except (NmapNotAvailableError, NmapScanError) as exc:
                click.echo(f"Test scan failed, reported: {exc}")
            except ScannerApiError as exc:
                click.echo(f"Test scan could not be reported, will retry: {exc}")

        if stop_requested:
            break

        try:
            command = client.fetch_next_command()
        except ScannerApiError as exc:
            click.echo(f"Poll failed, will retry next cycle: {exc}")
            command = None

        if command is not None:
            try:
                # The lease is renewed by heartbeats, and this call blocks for
                # the whole scan — so without a beat from inside it, a healthy
                # Collector loses its own job partway through every long run.
                with heartbeat_while_working(
                    lambda: _send_heartbeat(client),
                    on_error=lambda exc: click.echo(
                        f"Heartbeat during scan failed, continuing: {exc}"
                    ),
                ):
                    _handle_command(client, command, credentials)
            except ScannerApiError as exc:
                # Reported separately from a poll failure because the remedy
                # differs: the scan itself may well have succeeded and only the
                # report back failed, which is why the message names the
                # command. The platform reissues an unacknowledged command, so
                # losing a cycle is recoverable — losing the agent is not, and
                # that is exactly what raising here used to do.
                click.echo(
                    f"Command {command.get('command_id')} could not be completed, "
                    f"will retry next cycle: {exc}"
                )

        for _ in range(interval):
            if stop_requested:
                break
            time.sleep(1)

    click.echo("Stopped.")


@cli.command("add-host-credential")
@click.option("--connector-id", required=True, help="The connector this credential is for.")
@click.option("--host", required=True, help="Hostname or address to reach the artefact on.")
@click.option("--username", required=True, help="Account to log in as.")
@click.option("--identity-file", default=None, help="Path to the private key. The key is never read or copied — only its path is stored.")
@click.option("--port", default=22, show_default=True, type=int)
def add_host_credential(
    connector_id: str, host: str, username: str, identity_file: str | None, port: int
) -> None:
    """Record how this Collector logs in to a host, on this machine only.

    The platform cannot supply this and has nowhere to put it (CA-07.2). The key
    itself is never read here — only the path to it is stored, so this file
    discloses nothing that owning the machine did not already disclose.
    """
    path = save_host_credential(
        HostCredential(
            connector_id=connector_id,
            host=host,
            username=username,
            identity_file=identity_file,
            port=port,
        )
    )
    click.echo(f"Stored host credential for connector {connector_id} at {path}.")
    if identity_file is None:
        click.echo("No identity file given — ssh will use its own configuration to authenticate.")
    if is_world_readable():
        click.echo(
            "Warning: this file is readable beyond its owner. It holds no key material, "
            "but it does list which accounts on which hosts this Collector can reach."
        )


@cli.command()
@click.option(
    "--enable-linger",
    is_flag=True,
    help="Linux only: also run `loginctl enable-linger` so it starts at boot and survives logout.",
)
@_scanner_option
def install(enable_linger: bool, scanner_key: str | None) -> None:
    """Install and start this agent so it runs at boot or logon, as a user-level
    service: systemd --user (Linux), a LaunchAgent (macOS) or a Task Scheduler
    task (Windows). No administrator rights are needed. Docker installs don't
    need this: the container's own restart policy already covers it."""
    try:
        # Its scanner's Collector must be here first, so the service never starts one nobody connected.
        scanner_key = _service_scanner(scanner_key)
        credentials = _require_credentials(scanner_key)
        replaced = _retire_earlier_service(credentials) if scanner_key else False
        result = install_service(
            InstallOptions(enable_linger=enable_linger), current_service_manager(scanner_key=scanner_key)
        )
    except ServiceError as exc:
        raise click.ClickException(str(exc)) from exc
    if replaced:
        click.echo("The background service it ran in before is replaced by this scanner's own.")
    # Said plainly: the install command now ends here, and the person may wonder whether to keep the window open.
    click.echo(
        f"The Collector for {_for_scanner(credentials.scanner_name)} now runs in the background. It starts when you "
        "log in and restarts if it stops. You can close this window."
    )
    click.echo(f"Installed and started as a {result.kind} ({result.location}).")
    for note in result.notes:
        click.echo(f"  {note}")


@cli.command()
@_scanner_option
def uninstall(scanner_key: str | None) -> None:
    """Stop and remove the service installed by `install`."""
    try:
        uninstall_service(current_service_manager(scanner_key=_named(scanner_key)))
    except ServiceError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("Service stopped and removed.")


@cli.command("service-status")
@_scanner_option
def service_status_command(scanner_key: str | None) -> None:
    """Say whether the service installed by `install` is installed and running."""
    try:
        status = service_status(current_service_manager(scanner_key=_named(scanner_key)))
    except ServiceError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Service: {status.detail}.")
    if status.hint:
        click.echo(f"  {status.hint}")


def _retire_earlier_service(credentials: ScannerCredentials) -> bool:
    """A scanner's own service replaces the unnamed one its Collector ran in before folders existed, so the same
    Collector never runs twice (2026-10-28). Only when that earlier Collector is this one: the same credential."""
    try:
        earlier = load_credentials(folder_for_earlier())
    except (FileNotFoundError, ValueError, OSError):
        return False
    if earlier.activation_token != credentials.activation_token:
        return False
    unnamed = current_service_manager(scanner_key=None)
    if not unnamed.status().installed:
        return False
    uninstall_service(unnamed)
    return True


def _named(scanner_key: str | None) -> str | None:
    try:
        return scanner_folder(scanner_key).name if scanner_key else None
    except CollectorHomeError as exc:
        raise click.ClickException(str(exc)) from exc


def _service_scanner(scanner_key: str | None) -> str | None:
    """The scanner a service is installed for: the named one, once its Collector is here; else the one this
    computer has. A Collector set up before folders existed keeps the unnamed service it always had."""
    folder = _credentials_folder(scanner_key)
    if folder.parent.name == SCANNERS_DIRNAME:
        return folder.name
    return None


def _ask_whose(credentials: ScannerCredentials) -> dict:
    try:
        return _send_heartbeat(ScannerApiClient(credentials.base_url, credentials.activation_token))
    except ScannerApiError as exc:
        raise CollectorHomeError(
            f"Could not ask Risklence which scanner the Collector already on this computer is for: {exc}"
        ) from exc


def _credentials_folder(scanner_key: str | None):
    """The folder of the scanner this command is for (``collector_home``)."""
    try:
        if scanner_key:
            return adopt_earlier(scanner_key, _ask_whose)
        return folder_for(None)
    except CollectorHomeError as exc:
        raise click.ClickException(str(exc)) from exc


def _require_credentials(scanner_key: str | None = None) -> ScannerCredentials:
    try:
        return load_credentials(_credentials_folder(scanner_key))
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc


if __name__ == "__main__":
    cli()
