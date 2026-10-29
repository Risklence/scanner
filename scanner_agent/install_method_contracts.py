"""How this Collector process was installed."""

from __future__ import annotations

from enum import Enum


class InstallMethod(str, Enum):
    #: Running inside a container (the Docker install method).
    CONTAINER = "container"
    #: Installed on the machine itself some other way (a clone, a pip of the
    #: user's own). The update advice is then generic.
    LOCAL = "local"
    #: pipx's own environment (the Windows install).
    PIPX = "pipx"
    #: The private environment the Mac and Linux install makes (``COLLECTOR_VENV_DIR``).
    VENV = "venv"
