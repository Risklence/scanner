"""Fail unless a release tag names the version pyproject.toml declares.

One responsibility: the release gate that runs inside the public Risklence/scanner
repository, where the package is the repository root and there is no platform to
ask. The publish workflows run it before anything is uploaded; it is also
runnable by hand from the package root:

    python3 scripts/check_release_version.py scanner-v0.2.0        # real PyPI
    python3 scripts/check_release_version.py scanner-test-v0.2.0   # TestPyPI

The monorepo adds the third comparison, the platform's LATEST_COLLECTOR_VERSION, as
a test that runs before every sync (apps/server/tests/test_scanner_release_version.py),
so a version that reaches this repository already agrees with the platform.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
TAG_PREFIX = "scanner-v"
TEST_TAG_PREFIX = "scanner-test-v"
#: A TestPyPI rehearsal version (0.2.0.dev2). TestPyPI never accepts a version twice, so
#: a second attempt needs a new one; it must never be released to real PyPI.
_REHEARSAL_VERSION = re.compile(r"\.dev\d+$")


def is_test_tag(tag: str) -> bool:
    return tag.startswith(TEST_TAG_PREFIX)


def tag_version(tag: str) -> str:
    prefix = TEST_TAG_PREFIX if is_test_tag(tag) else TAG_PREFIX
    if not tag.startswith(prefix):
        raise ValueError(f"tag {tag!r} starts with neither {TAG_PREFIX!r} nor {TEST_TAG_PREFIX!r}")
    return tag[len(prefix) :]


def package_version(pyproject: Path = PYPROJECT) -> str:
    return str(tomllib.loads(pyproject.read_text())["tool"]["poetry"]["version"])


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        found = {"git tag": tag_version(argv[1]), "pyproject.toml": package_version()}
    except ValueError as error:
        print(f"Release refused: {error}", file=sys.stderr)
        return 1
    if not is_test_tag(argv[1]) and _REHEARSAL_VERSION.search(found["git tag"]):
        print(
            "Release refused: a .devN version is a TestPyPI rehearsal, never a real release.",
            file=sys.stderr,
        )
        return 1
    for name, value in found.items():
        print(f"{name:16} {value}")
    if len(set(found.values())) != 1:
        print(
            "Release refused: the tag and pyproject.toml must name one version.",
            file=sys.stderr,
        )
        return 1
    print("Versions agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
