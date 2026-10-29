from pathlib import Path

from scanner_agent.collector_version_constants import (
    COLLECTOR_PACKAGE_NAME,
    COLLECTOR_PACKAGE_SOURCE,
    COLLECTOR_UPGRADE_COMMAND,
    COLLECTOR_VENV_DIR,
    COLLECTOR_VENV_UPGRADE_COMMAND,
    COLLECTOR_WINDOWS_VENV_UPGRADE_COMMAND,
)
from scanner_agent.install_method import detect_install_method
from scanner_agent.install_method_contracts import InstallMethod


def detect(
    env=None,
    dockerenv=False,
    cgroup="",
    prefix="/usr/local",
    home="/home/u",
    local_app_data="",
):
    return detect_install_method(
        env or {},
        lambda: dockerenv,
        lambda: cgroup,
        prefix=prefix,
        home=Path(home),
        local_app_data=local_app_data,
    )


def test_a_plain_machine_is_a_local_install():
    assert detect() is InstallMethod.LOCAL
    assert (
        detect(cgroup="0::/user.slice/user-1000.slice/session-2.scope")
        is InstallMethod.LOCAL
    )


def test_the_dockerfile_marker_means_container():
    assert detect({"RISKLENCE_INSTALL_METHOD": "docker"}) is InstallMethod.CONTAINER


def test_dockerenv_file_means_container():
    assert detect(dockerenv=True) is InstallMethod.CONTAINER


def test_cgroup_naming_a_container_runtime_means_container():
    assert detect(cgroup="12:cpu:/docker/abc123") is InstallMethod.CONTAINER
    assert detect(cgroup="0::/kubepods/burstable/pod1") is InstallMethod.CONTAINER


def test_the_upgrade_command_names_the_package():
    assert COLLECTOR_UPGRADE_COMMAND == f"pipx upgrade {COLLECTOR_PACKAGE_NAME}"


def test_the_private_folder_means_a_venv_install(tmp_path):
    prefix = tmp_path / ".risklence-scanner-app"
    prefix.mkdir()
    assert detect(prefix=str(prefix), home=str(tmp_path)) is InstallMethod.VENV


def test_a_pipx_environment_means_pipx():
    assert (
        detect(prefix="/home/u/.local/pipx/venvs/risklence-scanner")
        is InstallMethod.PIPX
    )
    assert (
        detect(prefix="C:/Users/u/pipx/venvs/risklence-scanner") is InstallMethod.PIPX
    )


def test_some_other_environment_is_just_local(tmp_path):
    assert detect(prefix="/home/u/project/.venv") is InstallMethod.LOCAL
    assert detect(prefix="/home/u/.local/pipx/venvs/other-tool") is InstallMethod.LOCAL


def test_a_container_wins_over_the_folder_it_runs_in(tmp_path):
    prefix = tmp_path / ".risklence-scanner-app"
    assert (
        detect(
            {"RISKLENCE_INSTALL_METHOD": "docker"},
            prefix=str(prefix),
            home=str(tmp_path),
        )
        is InstallMethod.CONTAINER
    )


def test_the_venv_upgrade_command_uses_the_environments_own_pip_and_no_pipx():
    assert COLLECTOR_VENV_UPGRADE_COMMAND == (
        f"{COLLECTOR_VENV_DIR}/bin/pip install --disable-pip-version-check --upgrade {COLLECTOR_PACKAGE_SOURCE}"
    )
    assert "pipx" not in COLLECTOR_VENV_UPGRADE_COMMAND
    # never the folder that holds credentials.json
    assert COLLECTOR_VENV_DIR != "~/.risklence-scanner"


def test_the_windows_private_folder_under_local_app_data_means_a_venv_install(tmp_path):
    prefix = tmp_path / "Risklence" / "scanner-app"
    prefix.mkdir(parents=True)
    assert (
        detect(prefix=str(prefix), local_app_data=str(tmp_path)) is InstallMethod.VENV
    )
    assert detect(prefix=str(prefix)) is InstallMethod.LOCAL


def test_the_windows_upgrade_command_uses_the_environments_own_pip_exe_and_no_pipx():
    assert COLLECTOR_WINDOWS_VENV_UPGRADE_COMMAND == (
        '& "$env:LOCALAPPDATA\\Risklence\\scanner-app\\Scripts\\pip.exe" '
        "install --disable-pip-version-check --upgrade https://github.com/Risklence/scanner/archive/refs/heads/main.zip"
    )
    assert "pipx" not in COLLECTOR_WINDOWS_VENV_UPGRADE_COMMAND
