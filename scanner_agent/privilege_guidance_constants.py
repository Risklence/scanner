"""Business-readable wording for "this Collector cannot send raw packets".

Wording only. What the Collector reports to the platform about this capability is
decided in ``tool_checks`` and is not touched here.
"""

from __future__ import annotations

RAW_PACKET_EXPLANATION = (
    "This Collector cannot send raw network packets. It still scans, but it cannot see the "
    "hardware (MAC) address or maker of devices on its own network, so it will find fewer "
    "devices that have nothing listening. This is a permission, not a missing program."
)

#: Keyed by the prefix of ``sys.platform``.
RAW_PACKET_STEPS: dict[str, tuple[str, ...]] = {
    "linux": (
        "To allow it on Linux, either:",
        '  - give nmap the capability once (needs sudo): sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v nmap)")"',
        "    and start the Collector with NMAP_PRIVILEGED=1 in its environment, or",
        "  - run the Collector as root (for example `sudo risklence-scanner run`), which is the simplest and the broadest permission.",
        "A systemd --user service installed by `risklence-scanner install` runs as you and has neither.",
    ),
    "darwin": (
        "On macOS, nmap needs root for raw scans, and there is no per-program capability to grant.",
        "  - Either accept connect scans (the Collector works without this), or",
        "  - run the Collector as root (`sudo risklence-scanner run`). A LaunchAgent installed by `install` runs as you.",
    ),
    "win32": (
        "On Windows, raw packets need Npcap and an administrator.",
        "  - Install Npcap (https://npcap.com; the nmap installer offers it), and",
        "  - run the Collector from a PowerShell opened with 'Run as administrator'. The task made by `install` runs without administrator rights.",
    ),
}

RAW_PACKET_STEPS_FALLBACK = (
    "Raw packets need elevated rights on this operating system; connect scans work without them.",
)
