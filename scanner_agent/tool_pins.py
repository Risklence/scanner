"""Reading the pinned versions from ``tool_pins.env``, the single source of truth
shared with the Dockerfile."""

from __future__ import annotations

from importlib import resources

PINS_FILE_NAME = "tool_pins.env"
NUCLEI_TEMPLATES_VERSION_KEY = "NUCLEI_TEMPLATES_VERSION"
SUBFINDER_VERSION_KEY = "SUBFINDER_VERSION"
NUCLEI_VERSION_KEY = "NUCLEI_VERSION"


def parse_pins(text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = value.strip().strip("'\"")
    return pins


def load_pins() -> dict[str, str]:
    return parse_pins(resources.files("scanner_agent").joinpath(PINS_FILE_NAME).read_text())


def pinned_template_version() -> str:
    return load_pins()[NUCLEI_TEMPLATES_VERSION_KEY]


def pinned_subfinder_version() -> str:
    return load_pins()[SUBFINDER_VERSION_KEY]


def pinned_nuclei_version() -> str:
    return load_pins()[NUCLEI_VERSION_KEY]
