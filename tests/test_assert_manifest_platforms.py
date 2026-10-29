"""The publish workflow refuses an image a customer's machine cannot run."""

import importlib.util
import io
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "assert_manifest_platforms.py"
_spec = importlib.util.spec_from_file_location("assert_manifest_platforms", _SCRIPT)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def _entry(os_name: str, architecture: str, variant: str | None = None) -> dict:
    platform = {"os": os_name, "architecture": architecture}
    if variant:
        platform["variant"] = variant
    return {"mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": platform}


ATTESTATION = _entry("unknown", "unknown")

# What ghcr.io/risklence/risklence-scanner:latest held on 2026-09-28: the
# manifest the Apple Silicon customer's Docker refused.
PUBLISHED_ON_2026_09_28 = {"manifests": [_entry("linux", "amd64"), ATTESTATION]}


def test_accepts_an_image_that_runs_on_intel_and_arm():
    index = {
        "manifests": [
            _entry("linux", "amd64"),
            _entry("linux", "arm64", "v8"),
            ATTESTATION,
            ATTESTATION,
        ]
    }

    assert guard.missing_platforms(index) == []


def test_refuses_the_image_customers_were_actually_given():
    assert guard.missing_platforms(PUBLISHED_ON_2026_09_28) == ["linux/arm64"]


def test_attestations_never_count_as_a_platform():
    assert guard.runnable_platforms(PUBLISHED_ON_2026_09_28) == {"linux/amd64"}


def test_refuses_a_single_platform_manifest_that_is_not_an_index():
    assert guard.missing_platforms({"config": {}}) == ["linux/amd64", "linux/arm64"]


def test_main_exits_nonzero_and_names_what_is_missing(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(PUBLISHED_ON_2026_09_28)))

    assert guard.main([]) == 1
    assert "linux/arm64" in capsys.readouterr().err


def test_main_passes_a_complete_image(monkeypatch, capsys):
    index = {"manifests": [_entry("linux", "amd64"), _entry("linux", "arm64", "v8")]}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(index)))

    assert guard.main([]) == 0
    assert "linux/amd64" in capsys.readouterr().out


def test_main_rejects_something_that_is_not_json(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))

    assert guard.main([]) == 2
