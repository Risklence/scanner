"""The attribution the Collector states about itself (Apache-2.0, NOTICE)."""

#: Must equal the SPDX ``license`` in ``pyproject.toml``; a test pins it.
COLLECTOR_LICENSE_SPDX = "Apache-2.0"
COLLECTOR_LICENSE_NAME = "Apache License 2.0"
COLLECTOR_MAKER = "Risklence"
COLLECTOR_HOME_URL = "https://github.com/Risklence/scanner"

#: One line, shown by ``--version`` and when ``run`` starts.
COLLECTOR_ATTRIBUTION_LINE = (
    f"Made by {COLLECTOR_MAKER}. {COLLECTOR_LICENSE_NAME}. {COLLECTOR_HOME_URL}"
)
#: Said once, under ``--version``: what the licence does and does not cover.
COLLECTOR_THIRD_PARTY_LINE = (
    "The licence covers the Collector code only; nmap, subfinder, nuclei and the "
    "nuclei templates keep their own licences (see NOTICE)."
)
