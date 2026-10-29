"""Pinned versions, checksums, URLs and per-OS recipes for ``install-tools``.

Everything here was taken from the projects' own release pages on 2026-10-07.
Checksums are written down here, in this reviewed file, and not fetched next to
the archive: an archive and a checksum fetched from the same place prove only
that the download was not corrupted, not that it is the file that was reviewed.

Bumping a version means replacing its checksums too. A test fails until the
template pack pinned in ``tool_pins.env`` has a checksum here.
"""

from __future__ import annotations

from pathlib import Path

from scanner_agent.tool_installer_contracts import PackageRecipe
from scanner_agent.tool_pins import pinned_nuclei_version, pinned_subfinder_version

#: Read from tool_pins.env, the one place a version is written (shared with the Dockerfile).
SUBFINDER_VERSION = pinned_subfinder_version()
NUCLEI_VERSION = pinned_nuclei_version()

RELEASE_URL = (
    "https://github.com/projectdiscovery/{tool}/releases/download/v{version}/"
    "{tool}_{version}_{os}_{arch}.zip"
)
TOOL_VERSIONS = {"subfinder": SUBFINDER_VERSION, "nuclei": NUCLEI_VERSION}

#: sha256 of each release archive, keyed by (tool, asset OS, asset architecture).
#: A combination absent here (nuclei has no Windows arm64 build) is not offered.
RELEASE_SHA256: dict[tuple[str, str, str], str] = {
    (
        "subfinder",
        "linux",
        "amd64",
    ): "1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60",
    (
        "subfinder",
        "linux",
        "arm64",
    ): "c81d49559c0f630177be9e347e502e7a3d474aacc6ff78291ffcb4964367d63d",
    (
        "subfinder",
        "macOS",
        "amd64",
    ): "8300c4d98f75596b7e8460ba6f3322dfeda4674bc2bcbde14d61d098db260b50",
    (
        "subfinder",
        "macOS",
        "arm64",
    ): "af55827c9e6cdc530cca377ad459214ead16daf1b79d90e3dcefa387f644e057",
    (
        "subfinder",
        "windows",
        "amd64",
    ): "ef760f0a064c22811100c75a61da35ba73d71398cb99ae85d32d0eed44496ab8",
    (
        "subfinder",
        "windows",
        "arm64",
    ): "442ab5a802953035767cddafc05a988df9625249e5695af9ee3a4d731c7ff60b",
    (
        "nuclei",
        "linux",
        "amd64",
    ): "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    (
        "nuclei",
        "linux",
        "arm64",
    ): "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
    (
        "nuclei",
        "macOS",
        "amd64",
    ): "75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a",
    (
        "nuclei",
        "macOS",
        "arm64",
    ): "7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0",
    (
        "nuclei",
        "windows",
        "amd64",
    ): "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2",
}

#: ``platform.system()`` to the word the release archives use.
ASSET_OS = {"Darwin": "macOS", "Linux": "linux", "Windows": "windows"}
#: ``platform.machine()`` (lower-cased) to the archive's architecture word.
ASSET_ARCH = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}

TEMPLATE_PACK_URL = (
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{version}.tar.gz"
)
#: sha256 of the tag's source archive, keyed by the version in ``tool_pins.env``.
TEMPLATE_PACK_SHA256: dict[str, str] = {
    "v10.4.7": "e1e2b1acf375bb80c558c968f87ea8639de1914cd47099351b54b06afa8643c4",
}
TEMPLATE_VERSION_MARKER = ".risklence-template-version"

#: Refuse an archive larger than this: the real ones are 10 to 40 MB.
MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 60
ALLOWED_DOWNLOAD_HOST = "github.com"

#: Package-manager recipes for nmap, in the order they are preferred, per
#: ``platform.system()``. Nothing else is installed through a package manager:
#: subfinder and nuclei are pinned release downloads, so they need no manager and
#: no administrator rights.
NMAP_RECIPES: dict[str, tuple[PackageRecipe, ...]] = {
    "Darwin": (PackageRecipe("brew", ("brew", "install", "nmap")),),
    "Linux": (
        PackageRecipe("apt-get", ("apt-get", "install", "-y", "nmap"), needs_admin=True),
        PackageRecipe("dnf", ("dnf", "install", "-y", "nmap"), needs_admin=True),
    ),
    "Windows": (
        PackageRecipe(
            "winget",
            (
                "winget",
                "install",
                "--id",
                "Insecure.Nmap",
                "-e",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ),
            note="Windows may show a permission prompt; the nmap installer also offers Npcap.",
        ),
        PackageRecipe("choco", ("choco", "install", "nmap", "-y"), needs_admin=True),
        PackageRecipe("scoop", ("scoop", "install", "nmap")),
    ),
}

NMAP_MANUAL_DOWNLOAD = "https://nmap.org/download"

POSIX_BIN_DIR = Path(".local") / "bin"
WINDOWS_BIN_DIR = Path("AppData") / "Local" / "Risklence" / "bin"
