from unittest.mock import patch

from click.testing import CliRunner
from scanner_agent.cli import cli
from scanner_agent.service_contracts import (
    InstallOptions,
    ServiceError,
    ServiceInstallResult,
    ServiceStatus,
)


def _connected_here():
    """A Collector already set up on this computer (in the test's own home): a service starts only one that is."""
    from scanner_agent.config import ScannerCredentials, save_credentials

    save_credentials(ScannerCredentials(base_url="https://x", activation_token="t", scanner_name="Office"))


def test_install_command_reports_success_and_notes():
    _connected_here()
    result = ServiceInstallResult("systemd --user service", "/home/u/unit", ("Log: x",))
    with patch("scanner_agent.cli.install_service", return_value=result) as install:
        out = CliRunner().invoke(cli, ["install"])

    assert out.exit_code == 0
    assert "Installed and started as a systemd --user service (/home/u/unit)." in out.output
    assert "Log: x" in out.output
    assert 'The Collector for "Office" now runs in the background' in out.output
    assert install.call_args.args[0] == InstallOptions(enable_linger=False)


def test_install_command_passes_enable_linger():
    _connected_here()
    result = ServiceInstallResult("k", "l")
    with patch("scanner_agent.cli.install_service", return_value=result) as install:
        CliRunner().invoke(cli, ["install", "--enable-linger"])
    assert install.call_args.args[0] == InstallOptions(enable_linger=True)


def test_install_command_reports_service_error():
    _connected_here()
    with patch("scanner_agent.cli.install_service", side_effect=ServiceError("no systemd")):
        result = CliRunner().invoke(cli, ["install"])

    assert result.exit_code != 0
    assert "no systemd" in result.output


def test_uninstall_command_reports_success():
    with patch("scanner_agent.cli.uninstall_service") as mock_uninstall:
        result = CliRunner().invoke(cli, ["uninstall"])

    mock_uninstall.assert_called_once()
    assert result.exit_code == 0
    assert "Service stopped and removed." in result.output


def test_uninstall_command_reports_service_error():
    with patch("scanner_agent.cli.uninstall_service", side_effect=ServiceError("boom")):
        result = CliRunner().invoke(cli, ["uninstall"])

    assert result.exit_code != 0
    assert "boom" in result.output


def test_service_status_command_prints_state_and_hint():
    with patch(
        "scanner_agent.cli.service_status",
        return_value=ServiceStatus(True, True, "running", "Log: /x"),
    ):
        result = CliRunner().invoke(cli, ["service-status"])
    assert result.exit_code == 0
    assert "Service: running." in result.output
    assert "Log: /x" in result.output


def test_service_status_command_reports_service_error():
    with patch("scanner_agent.cli.service_status", side_effect=ServiceError("unsupported")):
        result = CliRunner().invoke(cli, ["service-status"])
    assert result.exit_code != 0
    assert "unsupported" in result.output


def test_a_service_is_installed_for_its_own_scanner():
    """One service per scanner on a computer that runs several (2026-10-28)."""
    from scanner_agent.collector_home import scanner_folder
    from scanner_agent.config import ScannerCredentials, save_credentials

    save_credentials(ScannerCredentials(base_url="https://x", activation_token="t"), scanner_folder("aaaaaaaa1111"))
    with patch("scanner_agent.cli.install_service", return_value=ServiceInstallResult("k", "l")) as install:
        out = CliRunner().invoke(cli, ["install", "--scanner", "aaaaaaaa1111"])

    assert out.exit_code == 0, out.output
    manager = install.call_args.args[1]
    assert manager._names.run_arguments[-2:] == ("--scanner", "aaaaaaaa1111")


def test_no_service_is_installed_for_a_scanner_whose_collector_is_not_here():
    with patch("scanner_agent.cli.install_service") as install:
        out = CliRunner().invoke(cli, ["install", "--scanner", "bbbbbbbb2222"])

    assert out.exit_code != 0
    install.assert_not_called()


def test_no_service_is_installed_where_no_collector_is_set_up():
    with patch("scanner_agent.cli.install_service") as install:
        out = CliRunner().invoke(cli, ["install"])

    assert out.exit_code != 0
    install.assert_not_called()


def test_a_scanners_own_service_replaces_the_one_its_collector_ran_in_before(tmp_path):
    """Auth & Access ran in the unnamed service; after updating, `install --scanner` must not start it a second time."""
    from scanner_agent.collector_home import scanner_folder
    from scanner_agent.config import ScannerCredentials, save_credentials

    save_credentials(ScannerCredentials(base_url="https://x", activation_token="same"))
    save_credentials(ScannerCredentials(base_url="https://x", activation_token="same"), scanner_folder("aaaaaaaa1111"))
    unnamed = type("M", (), {})()
    unnamed.status = lambda: ServiceStatus(True, True, "running")
    managers = {}

    def manager(platform=None, scanner_key=None):
        return unnamed if scanner_key is None else managers.setdefault(scanner_key, object())

    with patch("scanner_agent.cli.current_service_manager", side_effect=manager), patch(
        "scanner_agent.cli.uninstall_service"
    ) as uninstall, patch("scanner_agent.cli.install_service", return_value=ServiceInstallResult("k", "l")):
        out = CliRunner().invoke(cli, ["install", "--scanner", "aaaaaaaa1111"])

    assert out.exit_code == 0, out.output
    uninstall.assert_called_once_with(unnamed)
    assert "replaced by this scanner's own" in out.output


def test_another_scanners_earlier_service_is_left_alone(tmp_path):
    from scanner_agent.collector_home import scanner_folder
    from scanner_agent.config import ScannerCredentials, save_credentials

    save_credentials(ScannerCredentials(base_url="https://x", activation_token="auth-and-access"))
    save_credentials(ScannerCredentials(base_url="https://x", activation_token="other"), scanner_folder("aaaaaaaa1111"))

    with patch("scanner_agent.cli.uninstall_service") as uninstall, patch(
        "scanner_agent.cli.install_service", return_value=ServiceInstallResult("k", "l")
    ):
        out = CliRunner().invoke(cli, ["install", "--scanner", "aaaaaaaa1111"])

    assert out.exit_code == 0, out.output
    uninstall.assert_not_called()
