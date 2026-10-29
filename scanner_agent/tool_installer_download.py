"""Fetching and verifying downloads for ``install-tools``.

Security first: HTTPS only, only the hosts the pinned URLs use, a size cap, and a
sha256 compared against a checksum written down in this program before anything
is unpacked. A mismatch deletes the download and installs nothing.
"""

from __future__ import annotations

import hashlib
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from scanner_agent.tool_installer_constants import (
    ALLOWED_DOWNLOAD_HOST,
    DOWNLOAD_TIMEOUT_SECONDS,
    MAX_DOWNLOAD_BYTES,
)
from scanner_agent.tool_installer_contracts import ToolInstallError

_CHUNK = 1024 * 256
#: GitHub serves release and archive downloads from these hosts after a redirect.
_ALLOWED_HOST_SUFFIXES = (ALLOWED_DOWNLOAD_HOST, "githubusercontent.com")


def _check_url(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    trusted = any(host == name or host.endswith("." + name) for name in _ALLOWED_HOST_SUFFIXES)
    if parsed.scheme != "https" or not trusted:
        raise ToolInstallError(
            f"Refusing to download from {url}: only https downloads from GitHub are allowed."
        )


def download_file(url: str, destination: Path) -> None:
    """Stream ``url`` to ``destination`` (the real downloader)."""
    _check_url(url)
    request = Request(url, headers={"User-Agent": "risklence-scanner-install-tools"})  # noqa: S310
    written = 0
    with (
        urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response,
        destination.open("wb") as out,
    ):  # noqa: S310
        _check_url(response.geturl())
        while chunk := response.read(_CHUNK):
            written += len(chunk)
            if written > MAX_DOWNLOAD_BYTES:
                raise ToolInstallError(
                    f"Download from {url} is larger than {MAX_DOWNLOAD_BYTES} bytes; stopped."
                )
            out.write(chunk)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str) -> None:
    actual = sha256_of(path)
    if actual != expected.lower():
        path.unlink(missing_ok=True)
        raise ToolInstallError(
            f"Checksum mismatch: expected {expected} but the download is {actual}. "
            "It was deleted and nothing was installed."
        )


def read_zip_member(archive: Path, member: str) -> bytes:
    """One named file from a zip, by exact name; the archive picks no output path."""
    with zipfile.ZipFile(archive) as bundle:
        if member not in bundle.namelist():
            raise ToolInstallError(f"{member} is not in the downloaded archive.")
        return bundle.read(member)


def extract_tar_stripping_top_folder(archive: Path, destination: Path) -> None:
    """Unpack a GitHub source archive into ``destination``, without its single
    top-level folder. Only plain files and folders are written, and any path that
    would leave ``destination`` is refused."""
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        for entry in bundle:
            parts = PurePosixPath(entry.name).parts[1:]
            if not parts:
                continue
            if entry.name.startswith("/") or ".." in parts:
                raise ToolInstallError(f"Unsafe path in the template archive: {entry.name}")
            target = destination.joinpath(*parts)
            if root not in target.resolve().parents and target.resolve() != root:
                raise ToolInstallError(f"Unsafe path in the template archive: {entry.name}")
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif entry.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(entry)
                if source is None:
                    continue
                with source, target.open("wb") as out:
                    shutil.copyfileobj(source, out)
            # Links, devices and other special entries are skipped on purpose.
