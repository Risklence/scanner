import importlib.metadata
import tomllib
from pathlib import Path

import pytest

from scanner_agent import collector_version as module
from scanner_agent.collector_version import (
    installed_collector_version,
    is_newer_collector_version,
    parse_collector_version,
)
from scanner_agent.collector_version_constants import COLLECTOR_PACKAGE_NAME

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_package_name_matches_pyproject():
    assert tomllib.loads(PYPROJECT.read_text())["tool"]["poetry"]["name"] == COLLECTOR_PACKAGE_NAME


def test_installed_version_reads_package_metadata(monkeypatch):
    monkeypatch.setattr(module, "version", lambda name: "9.8.7" if name == COLLECTOR_PACKAGE_NAME else "x")
    assert installed_collector_version() == "9.8.7"


def test_installed_version_is_none_when_not_installed(monkeypatch):
    def _missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(module, "version", _missing)
    assert installed_collector_version() is None


@pytest.mark.parametrize(
    ("candidate", "current", "expected"),
    [
        ("0.2.0", "0.1.0", True),
        ("0.10.0", "0.9.0", True),
        ("0.2.0", "0.2.0", False),
        ("0.1.0", "0.2.0", False),
        (None, "0.1.0", False),
        ("0.2.0", None, False),
        ("0.2.0", "dev", False),
        ("0.2.0", "0.1.0+local", False),
        ("not-a-version", "0.1.0", False),
    ],
)
def test_newer_only_when_both_parse(candidate, current, expected):
    assert is_newer_collector_version(candidate, current) is expected


def test_parse_is_strict():
    assert parse_collector_version("1.2.3") == (1, 2, 3)
    assert parse_collector_version("1.2") is None
    assert parse_collector_version("") is None
