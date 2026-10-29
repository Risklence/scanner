"""Which Collector build this is, and whether another is newer.

One responsibility: answer "what version am I" and "is that one newer than
mine". It decides nothing about what to say or do about it; ``update_notice``
does the saying, and nothing here ever blocks a Collector from working.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
import re

from scanner_agent.collector_version_constants import COLLECTOR_PACKAGE_NAME

_VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def installed_collector_version() -> str | None:
    """The version this Collector was installed as, or ``None`` when unknown.

    ``None`` means a checkout run straight from source or a dev image where the
    package was never installed. Unknown is never reported as a made-up number.
    """
    try:
        return version(COLLECTOR_PACKAGE_NAME)
    except PackageNotFoundError:
        return None


def parse_collector_version(raw: str | None) -> tuple[int, int, int] | None:
    """``MAJOR.MINOR.PATCH`` as a tuple, or ``None`` if it is anything else.

    Strict on purpose: a dev build, a pre-release or a blank value cannot be
    ranked against a release, so it is treated as unknown rather than guessed.
    """
    if not raw:
        return None
    match = _VERSION_PATTERN.match(raw.strip())
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def is_newer_collector_version(candidate: str | None, current: str | None) -> bool:
    """True only when both parse and ``candidate`` is strictly greater.

    Missing or unparseable on either side is unknown, and unknown is never newer.
    """
    candidate_parts = parse_collector_version(candidate)
    current_parts = parse_collector_version(current)
    if candidate_parts is None or current_parts is None:
        return False
    return candidate_parts > current_parts
