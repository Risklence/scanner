"""Explaining, per operating system, how to grant raw-packet access."""

from __future__ import annotations

import sys

from scanner_agent.privilege_guidance_constants import (
    RAW_PACKET_EXPLANATION,
    RAW_PACKET_STEPS,
    RAW_PACKET_STEPS_FALLBACK,
)
from scanner_agent.tool_checks import RAW_PACKET_CAPABILITY, ToolCheckResult


def raw_packet_guidance(platform: str | None = None) -> list[str]:
    """The explanation and the steps for this operating system."""
    name = platform or sys.platform
    steps = next(
        (lines for prefix, lines in RAW_PACKET_STEPS.items() if name.startswith(prefix)),
        RAW_PACKET_STEPS_FALLBACK,
    )
    return [RAW_PACKET_EXPLANATION, *steps]


def guidance_for_checks(checks: list[ToolCheckResult], platform: str | None = None) -> list[str]:
    """Guidance lines when, and only when, raw-packet access is unavailable."""
    unavailable = any(c.tool == RAW_PACKET_CAPABILITY and not c.available for c in checks)
    return raw_packet_guidance(platform) if unavailable else []
