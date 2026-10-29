"""Constants for naming this Collector build and describing how to update it."""

#: Must equal ``name`` in ``apps/scanner/pyproject.toml``; a test pins it.
COLLECTOR_PACKAGE_NAME = "risklence-scanner"

#: Where pip installs the Collector from: the public mirror, the same source the Docker build uses (Søren,
#: 2026-10-27: the Local install gets it from GitHub, like Docker). Not PyPI, where it is not published.
#: Must equal the platform's ``SCANNER_PACKAGE_SOURCE``; a server test compares them.
COLLECTOR_PACKAGE_SOURCE = "https://github.com/Risklence/scanner/archive/refs/heads/main.zip"

#: Must match the platform's ``generate_pull_command`` output (a server test
#: compares them). The registry image is stale, so the update is a rebuild from
#: the public mirror, never a ``docker pull``.
COLLECTOR_REBUILD_COMMAND = (
    "docker build -t risklence-scanner:latest "
    "https://github.com/Risklence/scanner.git#main"
)
COLLECTOR_CONTAINER_NAME = "risklence-scanner"

#: How an older pipx install is upgraded (no longer what the guide installs). The package name is pinned
#: above. Not published to PyPI yet, so until it is this command finds no newer
#: version.
COLLECTOR_UPGRADE_COMMAND = f"pipx upgrade {COLLECTOR_PACKAGE_NAME}"

#: Mac and Linux install into one private virtual environment in this folder: plain
#: pip, no pipx. It is NOT ``~/.risklence-scanner``, which holds ``credentials.json``.
#: The platform writes the same folder into its install snippet and the guide shows
#: it; ``apps/server/tests/test_collector_command_generation.py`` compares all three.
COLLECTOR_VENV_DIR = "~/.risklence-scanner-app"
COLLECTOR_VENV_FOLDER_NAME = ".risklence-scanner-app"

#: What to type to run the Collector from that folder (it is not on PATH).
COLLECTOR_VENV_EXECUTABLE = f"{COLLECTOR_VENV_DIR}/bin/{COLLECTOR_PACKAGE_NAME}"

#: How that install is upgraded (the environment's own pip, so nothing needs PATH).
COLLECTOR_VENV_UPGRADE_COMMAND = (
    f"{COLLECTOR_VENV_DIR}/bin/pip install --disable-pip-version-check --upgrade {COLLECTOR_PACKAGE_SOURCE}"
)

#: Windows: the same private environment, under the user's local application data
#: (``%LOCALAPPDATA%``), made with ``python -m venv`` and plain pip. No pipx either
#: (Søren, 2026-10-07: nothing extra to install first). The relative part is written
#: once here and compared with the platform's snippet constant by a server test.
COLLECTOR_WINDOWS_VENV_RELATIVE_DIR = "Risklence\\scanner-app"
COLLECTOR_WINDOWS_VENV_DIR = f"$env:LOCALAPPDATA\\{COLLECTOR_WINDOWS_VENV_RELATIVE_DIR}"
COLLECTOR_WINDOWS_VENV_EXECUTABLE = (
    f'& "{COLLECTOR_WINDOWS_VENV_DIR}\\Scripts\\{COLLECTOR_PACKAGE_NAME}.exe"'
)
COLLECTOR_WINDOWS_VENV_UPGRADE_COMMAND = f'& "{COLLECTOR_WINDOWS_VENV_DIR}\\Scripts\\pip.exe" install --disable-pip-version-check --upgrade {COLLECTOR_PACKAGE_SOURCE}'

#: pipx keeps each program in ``<pipx home>/venvs/<package>``.
PIPX_VENVS_FOLDER_NAME = "venvs"
