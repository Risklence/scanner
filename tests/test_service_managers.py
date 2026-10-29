"""Service managers, with a fake command runner and a temp home: no real
systemctl, launchctl or schtasks is ever started, and nothing is written outside
the temp directory."""

import plistlib
from pathlib import Path

import pytest

from scanner_agent.command_runner import CommandResult
from scanner_agent.service import current_service_manager, restart_commands
from scanner_agent.service_contracts import InstallOptions, ServiceError
from scanner_agent.service_executable import resolve_collector_executable
from scanner_agent.service_launchd import LaunchdServiceManager, render_plist
from scanner_agent.service_systemd import SystemdServiceManager, render_unit
from scanner_agent.service_windows import (
    WindowsTaskServiceManager,
    render_command_arguments,
    render_task_xml,
)


class FakeRunner:
    def __init__(self, results: dict[str, CommandResult] | None = None):
        self.calls: list[list[str]] = []
        self._results = results or {}

    def __call__(self, argv):
        self.calls.append(list(argv))
        for prefix, result in self._results.items():
            if " ".join(argv).startswith(prefix):
                return result
        return CommandResult(0)


OK = CommandResult(0)


def fail(stderr="nope"):
    return CommandResult(1, "", stderr)


# --- systemd ---------------------------------------------------------------

EXPECTED_UNIT = """[Unit]
Description=Risklence Scanner Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/bin/risklence-scanner run --interval 60
Environment=PATH=/opt/bin:/home/u/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""


def systemd(tmp_path, runner, which="/usr/bin/systemctl"):
    return SystemdServiceManager(
        runner,
        home=tmp_path,
        which=lambda _name: which,
        resolve_executable=lambda: "/opt/bin/risklence-scanner",
        username=lambda: "u",
    )


def test_unit_text_is_exact_and_has_no_secret():
    assert render_unit("/opt/bin/risklence-scanner", Path("/home/u")) == EXPECTED_UNIT
    assert "token" not in EXPECTED_UNIT.lower()


def test_unit_quotes_an_executable_path_with_spaces():
    assert 'ExecStart="/opt/my bin/risklence-scanner" run' in render_unit(
        "/opt/my bin/risklence-scanner", Path("/h")
    )


def test_systemd_install_writes_unit_enables_it_and_warns_about_linger(tmp_path):
    runner = FakeRunner({"loginctl show-user": CommandResult(0, "Linger=no\n")})
    result = systemd(tmp_path, runner).install(InstallOptions())

    path = tmp_path / ".config/systemd/user/risklence-scanner.service"
    assert result.location == str(path)
    assert path.read_text().startswith("[Unit]")
    assert ["systemctl", "--user", "daemon-reload"] in runner.calls
    assert [
        "systemctl",
        "--user",
        "enable",
        "--now",
        "risklence-scanner.service",
    ] in runner.calls
    assert any("loginctl enable-linger u" in note for note in result.notes)
    assert ["loginctl", "enable-linger", "u"] not in runner.calls


def test_systemd_install_enables_linger_when_asked(tmp_path):
    runner = FakeRunner({"loginctl show-user": CommandResult(0, "Linger=no\n")})
    result = systemd(tmp_path, runner).install(InstallOptions(enable_linger=True))
    assert ["loginctl", "enable-linger", "u"] in runner.calls
    assert any("Lingering is now enabled" in note for note in result.notes)


def test_systemd_install_says_so_when_lingering_already_on(tmp_path):
    runner = FakeRunner({"loginctl show-user": CommandResult(0, "Linger=yes\n")})
    result = systemd(tmp_path, runner).install(InstallOptions(enable_linger=True))
    assert ["loginctl", "enable-linger", "u"] not in runner.calls
    assert "already enabled" in result.notes[0]


def test_systemd_install_reports_a_failed_linger_without_failing(tmp_path):
    runner = FakeRunner(
        {
            "loginctl show-user": CommandResult(0, "Linger=no\n"),
            "loginctl enable-linger": fail("denied"),
        }
    )
    result = systemd(tmp_path, runner).install(InstallOptions(enable_linger=True))
    assert any("Could not enable lingering (denied)" in note for note in result.notes)


def test_systemd_install_writes_nothing_without_systemd(tmp_path):
    runner = FakeRunner()
    with pytest.raises(ServiceError, match="systemd host"):
        systemd(tmp_path, runner, which=None).install(InstallOptions())
    assert not (tmp_path / ".config").exists()
    assert runner.calls == []


def test_systemd_install_wraps_a_failing_systemctl(tmp_path):
    runner = FakeRunner({"systemctl --user enable": fail("unit not found")})
    with pytest.raises(ServiceError, match="unit not found"):
        systemd(tmp_path, runner).install(InstallOptions())


def test_systemd_uninstall_removes_unit_and_is_safe_when_absent(tmp_path):
    runner = FakeRunner()
    manager = systemd(tmp_path, runner)
    manager.uninstall()
    assert runner.calls == []

    manager.install(InstallOptions())
    runner.calls.clear()
    manager.uninstall()
    assert not manager.unit_path.exists()
    assert [
        "systemctl",
        "--user",
        "disable",
        "--now",
        "risklence-scanner.service",
    ] in runner.calls
    assert ["systemctl", "--user", "daemon-reload"] in runner.calls


def test_systemd_status(tmp_path):
    runner = FakeRunner({"systemctl --user is-active": CommandResult(0, "active\n")})
    manager = systemd(tmp_path, runner)
    assert manager.status().installed is False
    manager.install(InstallOptions())
    status = manager.status()
    assert (status.installed, status.running, status.detail) == (True, True, "active")
    assert "journalctl --user" in status.hint
    assert manager.restart_commands() == (
        "systemctl --user restart risklence-scanner.service",
    )


# --- launchd ---------------------------------------------------------------

EXPECTED_PLIST = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/opt/bin:/Users/u/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.risklence.scanner</string>
	<key>ProcessType</key>
	<string>Background</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/bin/risklence-scanner</string>
		<string>run</string>
		<string>--interval</string>
		<string>60</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/Users/u/Library/Logs/Risklence/scanner.log</string>
	<key>StandardOutPath</key>
	<string>/Users/u/Library/Logs/Risklence/scanner.log</string>
	<key>ThrottleInterval</key>
	<integer>10</integer>
</dict>
</plist>
"""


def launchd(tmp_path, runner):
    return LaunchdServiceManager(
        runner,
        home=tmp_path,
        uid=lambda: 501,
        resolve_executable=lambda: "/opt/bin/risklence-scanner",
    )


def test_plist_text_is_exact_and_has_no_secret():
    plist = render_plist(
        "/opt/bin/risklence-scanner",
        Path("/Users/u"),
        Path("/Users/u/Library/Logs/Risklence/scanner.log"),
    )
    assert plist == EXPECTED_PLIST
    assert plistlib.loads(plist)["KeepAlive"] is True


def test_launchd_install_writes_plist_and_bootstraps_after_booting_out(tmp_path):
    runner = FakeRunner()
    manager = launchd(tmp_path, runner)
    result = manager.install(InstallOptions())

    assert (
        manager.plist_path
        == tmp_path / "Library/LaunchAgents/com.risklence.scanner.plist"
    )
    assert (
        plistlib.loads(manager.plist_path.read_bytes())["Label"]
        == "com.risklence.scanner"
    )
    assert manager.log_path.parent.is_dir()
    assert runner.calls == [
        ["launchctl", "bootout", "gui/501/com.risklence.scanner"],
        ["launchctl", "bootstrap", "gui/501", str(manager.plist_path)],
    ]
    assert any("logged in" in note for note in result.notes)


def test_launchd_install_reports_bootstrap_failure(tmp_path):
    runner = FakeRunner({"launchctl bootstrap": fail("Bootstrap failed: 5")})
    with pytest.raises(ServiceError, match="Bootstrap failed: 5"):
        launchd(tmp_path, runner).install(InstallOptions())


def test_launchd_uninstall_boots_out_and_removes_and_is_safe_when_absent(tmp_path):
    runner = FakeRunner()
    manager = launchd(tmp_path, runner)
    manager.uninstall()
    assert runner.calls == []

    manager.install(InstallOptions())
    runner.calls.clear()
    manager.uninstall()
    assert runner.calls == [["launchctl", "bootout", "gui/501/com.risklence.scanner"]]
    assert not manager.plist_path.exists()


def test_launchd_status(tmp_path):
    runner = FakeRunner({"launchctl print": CommandResult(0, "state = running\n")})
    manager = launchd(tmp_path, runner)
    assert manager.status().installed is False
    manager.install(InstallOptions())
    assert manager.status().running is True
    runner._results = {"launchctl print": fail()}
    assert manager.status().detail == "installed but not loaded"
    assert manager.restart_commands() == (
        "launchctl kickstart -k gui/501/com.risklence.scanner",
    )


# --- windows ---------------------------------------------------------------

EXE = r"C:\Users\u\pipx\venvs\risklence-scanner\Scripts\risklence-scanner.exe"
LOG = r"C:\Users\u\AppData\Local\Risklence\Scanner\collector.log"


def test_windows_command_arguments_are_exact():
    assert render_command_arguments(EXE, LOG) == (
        r'/c ""C:\Users\u\pipx\venvs\risklence-scanner\Scripts\risklence-scanner.exe" run --interval 60 '
        r'>> "C:\Users\u\AppData\Local\Risklence\Scanner\collector.log" 2>&1"'
    )


def test_windows_task_xml_has_logon_trigger_restart_and_no_admin_or_secret():
    xml = render_task_xml(EXE, r"PC\u", LOG)
    assert "<LogonTrigger>" in xml and r"<UserId>PC\u</UserId>" in xml
    assert "<RunLevel>LeastPrivilege</RunLevel>" in xml
    assert "<LogonType>InteractiveToken</LogonType>" in xml
    assert (
        "<RestartOnFailure>\n      <Interval>PT1M</Interval>\n      <Count>999</Count>"
        in xml
    )
    assert "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in xml
    assert "<Command>cmd.exe</Command>" in xml
    assert "run --interval 60" in xml
    assert "activation" not in xml.lower() and "HighestAvailable" not in xml


def test_windows_task_xml_escapes_special_characters():
    xml = render_task_xml(r"C:\A&B\risklence-scanner.exe", r"PC\u", LOG)
    assert r"A&amp;B" in xml


def windows(tmp_path, runner):
    return WindowsTaskServiceManager(
        runner,
        user_id=lambda: r"PC\u",
        local_app_data=lambda: tmp_path / "Local",
        resolve_executable=lambda: EXE,
        temp_dir=tmp_path,
    )


def test_windows_install_creates_task_from_xml_then_runs_it_and_cleans_up(tmp_path):
    seen: dict[str, str] = {}

    def runner(argv):
        if argv[1] == "/Create":
            seen["argv"] = list(argv)
            seen["xml"] = Path(argv[argv.index("/XML") + 1]).read_text(
                encoding="utf-16"
            )
        seen.setdefault("order", "")
        seen["order"] += argv[1] + " "
        return OK

    result = windows(tmp_path, runner).install(InstallOptions())

    assert seen["argv"][:4] == ["schtasks", "/Create", "/TN", "Risklence Scanner"]
    assert seen["argv"][-1] == "/F"
    assert "<LogonTrigger>" in seen["xml"]
    assert seen["order"] == "/Create /Run "
    assert not list(tmp_path.glob("*.xml"))
    assert (tmp_path / "Local/Risklence/Scanner").is_dir()
    assert any("administrator" in note for note in result.notes)


def test_windows_install_names_administrator_when_access_is_denied(tmp_path):
    runner = FakeRunner({"schtasks /Create": fail("ERROR: Access is denied.")})
    with pytest.raises(ServiceError, match="Run as administrator"):
        windows(tmp_path, runner).install(InstallOptions())
    assert not list(tmp_path.glob("*.xml"))


def test_windows_install_reports_other_failures(tmp_path):
    runner = FakeRunner({"schtasks /Create": fail("bad xml")})
    with pytest.raises(ServiceError, match="bad xml"):
        windows(tmp_path, runner).install(InstallOptions())


def test_windows_install_notes_when_it_could_not_start_now(tmp_path):
    runner = FakeRunner({"schtasks /Run": fail("not now")})
    result = windows(tmp_path, runner).install(InstallOptions())
    assert "did not start now" in result.notes[0]


def test_windows_uninstall_ends_and_deletes_and_is_safe_when_absent(tmp_path):
    runner = FakeRunner({"schtasks /Query": fail()})
    windows(tmp_path, runner).uninstall()
    assert runner.calls == [["schtasks", "/Query", "/TN", "Risklence Scanner"]]

    runner = FakeRunner()
    windows(tmp_path, runner).uninstall()
    assert runner.calls[1:] == [
        ["schtasks", "/End", "/TN", "Risklence Scanner"],
        ["schtasks", "/Delete", "/TN", "Risklence Scanner", "/F"],
    ]


def test_windows_status_and_restart_commands(tmp_path):
    runner = FakeRunner(
        {"schtasks /Query": CommandResult(0, "TaskName: x\nStatus:       Running\n")}
    )
    manager = windows(tmp_path, runner)
    assert manager.status().running is True
    runner._results = {"schtasks /Query": CommandResult(0, "TaskName: x\n")}
    assert manager.status().running is None
    runner._results = {"schtasks /Query": fail()}
    assert manager.status().installed is False
    assert manager.restart_commands() == (
        'schtasks /End /TN "Risklence Scanner"',
        'schtasks /Run /TN "Risklence Scanner"',
    )


# --- selection and executable ----------------------------------------------


@pytest.mark.parametrize(
    "platform,expected",
    [
        ("linux", SystemdServiceManager),
        ("darwin", LaunchdServiceManager),
        ("win32", WindowsTaskServiceManager),
    ],
)
def test_the_manager_is_chosen_by_operating_system(platform, expected):
    assert isinstance(current_service_manager(platform), expected)


def test_an_unsupported_operating_system_is_refused_plainly():
    with pytest.raises(ServiceError, match="not supported"):
        current_service_manager("freebsd14")
    assert restart_commands() is not None


def test_executable_is_found_next_to_python_then_on_path(tmp_path):
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    exe = scripts / "risklence-scanner.exe"
    exe.write_text("")
    python = str(tmp_path / "python.exe")
    assert resolve_collector_executable(
        "risklence-scanner.exe", python_executable=python
    ) == str(exe)

    found = resolve_collector_executable(
        "risklence-scanner",
        python_executable=str(tmp_path / "bin" / "python"),
        which=lambda _n: "/usr/bin/risklence-scanner",
    )
    assert found == "/usr/bin/risklence-scanner"


def test_a_missing_executable_says_how_to_install_it(tmp_path):
    with pytest.raises(ServiceError, match="Install the Collector first") as excinfo:
        resolve_collector_executable(
            python_executable=str(tmp_path / "python"), which=lambda _n: None
        )
    message = str(excinfo.value)
    assert "~/.risklence-scanner-app/bin/pip install https://github.com/Risklence/scanner/archive/refs/heads/main.zip" in message
    assert "Scripts\\pip.exe install https://github.com/Risklence/scanner/archive/refs/heads/main.zip" in message
    assert "pipx" not in message


def test_a_windows_venv_install_points_the_task_at_the_scripts_exe(tmp_path):
    scripts = tmp_path / "scanner-app" / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "risklence-scanner.exe").write_text("")

    found = resolve_collector_executable(
        "risklence-scanner.exe",
        python_executable=str(scripts / "python.exe"),
        which=lambda _n: None,
    )

    assert found == str(scripts / "risklence-scanner.exe")


def test_a_venv_install_points_the_service_at_the_venv_script(tmp_path):
    venv_bin = tmp_path / ".risklence-scanner-app" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "risklence-scanner").write_text("")

    found = resolve_collector_executable(
        "risklence-scanner",
        python_executable=str(venv_bin / "python"),
        which=lambda _n: "/usr/local/bin/risklence-scanner",
    )

    assert found == str(venv_bin / "risklence-scanner")


def test_service_interval_matches_the_run_default():
    from scanner_agent.cli import DEFAULT_RUN_INTERVAL_SECONDS
    from scanner_agent.service_constants import SERVICE_RUN_INTERVAL_SECONDS

    assert SERVICE_RUN_INTERVAL_SECONDS == DEFAULT_RUN_INTERVAL_SECONDS


def test_each_scanner_gets_its_own_service_and_the_unnamed_one_keeps_its_names(tmp_path):
    from scanner_agent.service_constants import service_names

    plain = service_names()
    named = service_names("aaaaaaaa1111")
    assert (plain.launchd_label, plain.systemd_unit, plain.windows_task) == (
        "com.risklence.scanner",
        "risklence-scanner.service",
        "Risklence Scanner",
    )
    assert (named.launchd_label, named.systemd_unit, named.windows_task) == (
        "com.risklence.scanner.aaaaaaaa1111",
        "risklence-scanner-aaaaaaaa1111.service",
        "Risklence Scanner aaaaaaaa1111",
    )
    assert "run --interval 60 --scanner aaaaaaaa1111" in render_unit("/opt/rs", Path("/home/u"), named)
    manager = LaunchdServiceManager(home=tmp_path, scanner_key="aaaaaaaa1111", uid=lambda: 501)
    assert manager.plist_path.name == "com.risklence.scanner.aaaaaaaa1111.plist"
    assert manager.log_path.name == "scanner-aaaaaaaa1111.log"
    assert manager.restart_commands() == ("launchctl kickstart -k gui/501/com.risklence.scanner.aaaaaaaa1111",)
    windows = WindowsTaskServiceManager(scanner_key="aaaaaaaa1111", local_app_data=lambda: tmp_path)
    assert windows.log_path.name == "collector-aaaaaaaa1111.log"
    assert "--scanner aaaaaaaa1111 >>" in render_command_arguments("C:\\rs.exe", "C:\\log", named)
