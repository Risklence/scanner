"""The Collector tells whoever runs it that Risklence made it, and under which licence."""

from pathlib import Path

import tomllib
from click.testing import CliRunner

from scanner_agent.cli import cli
from scanner_agent.collector_attribution_constants import (
    COLLECTOR_ATTRIBUTION_LINE,
    COLLECTOR_LICENSE_SPDX,
)

SCANNER_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((SCANNER_ROOT / "pyproject.toml").read_text())["tool"]["poetry"]


def test_version_says_who_made_it_and_under_which_licence():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("risklence-scanner ")
    assert COLLECTOR_ATTRIBUTION_LINE in result.output
    assert "Apache License 2.0" in result.output
    assert "keep their own licences" in result.output


def test_help_names_the_maker():
    result = CliRunner().invoke(cli, ["--help"])
    assert "Made by Risklence" in result.output


def test_the_licence_stated_in_code_is_the_one_the_package_declares():
    assert PYPROJECT["license"] == COLLECTOR_LICENSE_SPDX
    licence = (SCANNER_ROOT / "LICENSE").read_text()
    assert "Apache License" in licence and "Version 2.0, January 2004" in licence


def test_the_notice_credits_risklence_and_the_third_party_tools():
    notice = (SCANNER_ROOT / "NOTICE").read_text()
    assert notice.startswith("Risklence Collector")
    for tool in ("nmap", "subfinder", "nuclei", "nuclei-templates", "NPSL"):
        assert tool in notice
