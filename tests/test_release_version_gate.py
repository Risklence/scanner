"""The release gate that ships with the package and runs in Risklence/scanner.

It has to work from the package root alone: the public repository holds no platform
and no monorepo, so the gate compares the tag with pyproject.toml and nothing else.
"""

import importlib.util
from pathlib import Path

import pytest

SCANNER_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_release_version", SCANNER_ROOT / "scripts" / "check_release_version.py"
)
assert _spec and _spec.loader
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def test_a_real_and_a_test_tag_for_the_packaged_version_pass():
    version = gate.package_version()

    assert gate.main(["gate", f"scanner-v{version}"]) == 0
    assert gate.main(["gate", f"scanner-test-v{version}"]) == 0


@pytest.mark.parametrize("tag", ["scanner-v99.0.0", "scanner-test-v0.2.0.dev1", "v0.2.0", "latest"])
def test_any_other_tag_is_refused(tag: str):
    assert gate.main(["gate", tag]) == 1


def test_a_rehearsal_version_is_refused_for_real_pypi_even_when_pyproject_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.poetry]\nversion = "0.2.0.dev2"\n')
    monkeypatch.setattr(gate, "PYPROJECT", pyproject)
    monkeypatch.setattr(gate, "package_version", lambda: "0.2.0.dev2")

    assert gate.main(["gate", "scanner-test-v0.2.0.dev2"]) == 0
    assert gate.main(["gate", "scanner-v0.2.0.dev2"]) == 1
