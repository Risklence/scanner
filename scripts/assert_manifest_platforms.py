"""Fail unless a published image index carries every platform customers run.

Søren, 2026-09-28: a customer on an Apple Silicon Mac ran the activation command
we show them and got ``no matching manifest for linux/arm64/v8``. The published
``:latest`` held ``linux/amd64`` only — and the build's own smoke test could not
notice, because it tests each architecture as it is built and never looks at what
was pushed. The activation command is the product's front door; an image that
cannot start on a customer's machine is the product failing.

The publish workflow pipes ``docker buildx imagetools inspect --raw <ref>`` into
this after pushing. A missing platform fails the run before the image is signed.

Attestation entries (SBOM, provenance) are listed as ``unknown/unknown``; they
are not something a machine can run and never count.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Iterable

# The two architectures a customer's Docker host is: Intel/AMD servers and
# desktops, and Apple Silicon Macs, Raspberry Pis and Graviton.
REQUIRED_PLATFORMS: tuple[str, ...] = ("linux/amd64", "linux/arm64")


def runnable_platforms(index: dict[str, Any]) -> set[str]:
    """The ``os/architecture`` pairs an image index can actually run on."""
    found: set[str] = set()
    for entry in index.get("manifests") or []:
        platform = entry.get("platform") or {}
        os_name, architecture = platform.get("os"), platform.get("architecture")
        if not os_name or not architecture or "unknown" in (os_name, architecture):
            continue
        found.add(f"{os_name}/{architecture}")
    return found


def missing_platforms(
    index: dict[str, Any], required: Iterable[str] = REQUIRED_PLATFORMS
) -> list[str]:
    present = runnable_platforms(index)
    return [platform for platform in required if platform not in present]


def main(argv: list[str]) -> int:
    try:
        index = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"Not an image manifest: {exc}", file=sys.stderr)
        return 2
    missing = missing_platforms(index)
    if missing:
        print(
            f"Published image is missing {', '.join(missing)}. "
            f"Present: {', '.join(sorted(runnable_platforms(index))) or 'none'}.",
            file=sys.stderr,
        )
        return 1
    print(f"Published image runs on: {', '.join(sorted(runnable_platforms(index)))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
