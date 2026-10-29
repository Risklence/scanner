from scanner_agent.install_method_contracts import InstallMethod
from scanner_agent.update_notice import collector_version_line, update_notice

IN_CONTAINER = {"install_method": lambda: InstallMethod.CONTAINER}
RESTART = lambda: ("systemctl --user restart risklence-scanner.service",)  # noqa: E731
PIPX = {"install_method": lambda: InstallMethod.PIPX, "restart": RESTART}
VENV = {
    "install_method": lambda: InstallMethod.VENV,
    "restart": RESTART,
    "is_windows": lambda: False,
}
WINDOWS_VENV = {
    **VENV,
    "is_windows": lambda: True,
    "restart": lambda: ("schtasks /Run /TN x",),
}
LOCAL = {"install_method": lambda: InstallMethod.LOCAL, "restart": RESTART}


def test_notice_says_what_it_costs_and_how_to_update_without_losing_identity():
    notice = update_notice("0.1.0", "0.2.0", **IN_CONTAINER)
    assert notice is not None
    assert "newer Risklence Collector" in notice
    assert "Long scans may not finish" in notice
    assert "docker build -t" in notice
    assert "docker pull" not in notice
    assert "docker rm -f risklence-scanner" in notice
    assert "same `run` command" in notice and "same data volume" in notice
    assert "Never run `activate`" in notice


def test_notice_names_the_container_the_platform_gave_this_scanner():
    notice = update_notice(
        "0.1.0", "0.2.0", "risklence-scanner-aaaaaaaa1111", **IN_CONTAINER
    )
    assert "docker rm -f risklence-scanner-aaaaaaaa1111" in notice
    assert "docker rm -f risklence-scanner\n" not in notice


def test_a_venv_install_is_told_to_upgrade_with_its_own_pip_and_never_pipx():
    notice = update_notice("0.1.0", "0.2.0", **VENV)
    assert notice is not None
    assert (
        "~/.risklence-scanner-app/bin/pip install --disable-pip-version-check --upgrade https://github.com/Risklence/scanner/archive/refs/heads/main.zip" in notice
    )
    assert "pipx" not in notice
    assert "(`~/.risklence-scanner-app/bin/risklence-scanner install`)" in notice
    assert "`~/.risklence-scanner-app/bin/risklence-scanner run`" in notice
    assert "`systemctl --user restart risklence-scanner.service`" in notice
    assert "docker" not in notice.lower()
    assert "Never run `activate`" in notice


def test_a_windows_venv_install_is_told_to_use_the_scripts_pip_exe_never_pipx():
    notice = update_notice("0.1.0", "0.2.0", **WINDOWS_VENV)
    assert notice is not None
    assert 'Scripts\\pip.exe" install --disable-pip-version-check --upgrade https://github.com/Risklence/scanner/archive/refs/heads/main.zip' in notice
    assert "pipx" not in notice and "~/" not in notice
    assert 'Scripts\\risklence-scanner.exe" install`' in notice
    assert "Never run `activate`" in notice


def test_a_local_install_of_unknown_kind_gets_generic_advice_not_a_wrong_command():
    notice = update_notice("0.1.0", "0.2.0", **LOCAL)
    assert notice is not None
    assert "the tool you installed it with" in notice
    assert "Never run `activate`" in notice


def test_a_pipx_install_is_told_to_upgrade_with_pipx_and_restart_not_to_use_docker():
    notice = update_notice("0.1.0", "0.2.0", **PIPX)
    assert notice is not None
    assert "pipx upgrade risklence-scanner" in notice
    assert "`systemctl --user restart risklence-scanner.service`" in notice
    assert "stop it (Ctrl+C)" in notice
    assert "docker" not in notice.lower()
    assert "Never run `activate`" in notice


def test_a_local_install_with_no_known_service_still_says_to_restart():
    notice = update_notice(
        "0.1.0", "0.2.0", install_method=lambda: InstallMethod.VENV, restart=lambda: ()
    )
    assert "restart that service" in notice


def test_notice_is_silent_when_current_latest_or_unknown():
    assert update_notice("0.2.0", "0.2.0") is None
    assert update_notice("0.3.0", "0.2.0") is None
    assert update_notice(None, "0.2.0") is None
    assert update_notice("0.1.0", None) is None
    assert update_notice("dev", "0.2.0") is None
    assert update_notice("0.2.0", "0.2.0", **VENV) is None


def test_version_line_names_unknown_plainly():
    assert collector_version_line("0.2.0") == "Collector version: 0.2.0"
    assert collector_version_line(None) == "Collector version: unknown"


def test_on_a_computer_with_several_scanners_the_notice_restarts_this_ones():
    from scanner_agent.install_method_contracts import InstallMethod

    notice = update_notice(
        "0.1.0",
        "0.2.0",
        install_method=lambda: InstallMethod.VENV,
        restart=lambda: ("launchctl kickstart -k gui/501/com.risklence.scanner.aaaaaaaa1111",),
        is_windows=lambda: False,
        scanner_key="aaaaaaaa1111",
    )
    assert "risklence-scanner run --scanner aaaaaaaa1111`" in notice
    assert "com.risklence.scanner.aaaaaaaa1111" in notice
