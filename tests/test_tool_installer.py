"""``install-tools``: the plan, the safety checks and the execution, with a fake
downloader and a fake runner. No real package manager runs and nothing is
downloaded."""

import hashlib
import io
import re
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from scanner_agent import cli as cli_module
from scanner_agent.cli import cli
from scanner_agent.tool_installer import render_plan, run_install_tools
from scanner_agent.tool_installer_constants import (
    NMAP_RECIPES,
    NUCLEI_VERSION,
    RELEASE_SHA256,
    SUBFINDER_VERSION,
    TEMPLATE_PACK_SHA256,
    TOOL_VERSIONS,
)
from scanner_agent.tool_installer_contracts import (
    DownloadAsset,
    HostInfo,
    PlanStep,
    StepKind,
    ToolInstallError,
    ToolState,
)
from scanner_agent.tool_installer_download import (
    _check_url,
    extract_tar_stripping_top_folder,
    verify_sha256,
)
from scanner_agent.tool_installer_execute import StepExecutor
from scanner_agent.tool_installer_plan import build_install_plan
from scanner_agent.tool_pins import parse_pins, pinned_template_version

PINNED = "v10.4.7"


def host(tmp_path, system="Linux", machine="x86_64", is_root=False, path_dirs=()):
    return HostInfo(
        system=system,
        machine=machine,
        is_root=is_root,
        home=tmp_path,
        bin_dir=tmp_path / ".local" / "bin",
        templates_dir=tmp_path / "nuclei-templates",
        path_dirs=tuple(path_dirs),
    )


NOTHING = ToolState(frozenset(), None)


def which_of(*present):
    return lambda name: f"/usr/bin/{name}" if name in present else None


# --- single source of truth for the pin --------------------------------------


def test_the_dockerfile_reads_the_pin_from_the_shared_file_and_repeats_no_version():
    dockerfile = (Path(__file__).parent.parent / "Dockerfile").read_text()
    assert "tool_pins.env" in dockerfile
    assert not re.search(r"NUCLEI_TEMPLATES_VERSION\s*=\s*v\d", dockerfile)
    assert not re.search(r"\bv\d+\.\d+\.\d+\b.*nuclei-templates", dockerfile)


def test_the_dockerfile_installs_every_tool_at_its_pin_and_never_at_latest():
    dockerfile = (Path(__file__).parent.parent / "Dockerfile").read_text()
    assert "@latest" not in dockerfile
    assert "GOTOOLCHAIN=auto" in dockerfile
    for tool, module, key in (
        ("subfinder", "subfinder/v2", "SUBFINDER_VERSION"),
        ("nuclei", "nuclei/v3", "NUCLEI_VERSION"),
    ):
        assert f"projectdiscovery/{module}/cmd/{tool}@v${{{key}}}" in dockerfile
    assert not re.search(r"@v\d", dockerfile)


def test_every_pinned_version_is_in_the_pin_file_and_the_installer_uses_it():
    pins = parse_pins((Path(__file__).parent.parent / "scanner_agent" / "tool_pins.env").read_text())
    assert pins["SUBFINDER_VERSION"] == SUBFINDER_VERSION == TOOL_VERSIONS["subfinder"]
    assert pins["NUCLEI_VERSION"] == NUCLEI_VERSION == TOOL_VERSIONS["nuclei"]


def test_every_pinned_tool_version_has_a_checksum_for_each_offered_platform():
    for tool, version in TOOL_VERSIONS.items():
        offered = {(os_, arch) for (t, os_, arch) in RELEASE_SHA256 if t == tool}
        assert {("linux", "amd64"), ("linux", "arm64"), ("macOS", "arm64")} <= offered, tool
        assert re.fullmatch(r"\d+\.\d+\.\d+", version)


def test_the_helper_and_the_pin_file_agree_and_the_pin_has_a_checksum():
    pins_text = (Path(__file__).parent.parent / "scanner_agent" / "tool_pins.env").read_text()
    assert parse_pins(pins_text)["NUCLEI_TEMPLATES_VERSION"] == pinned_template_version() == PINNED
    assert pinned_template_version() in TEMPLATE_PACK_SHA256


def test_the_pin_file_is_safe_to_source_with_sh():
    for line in (
        (Path(__file__).parent.parent / "scanner_agent" / "tool_pins.env").read_text().splitlines()
    ):
        assert (
            not line.strip()
            or line.startswith("#")
            or re.fullmatch(r"[A-Z_]+=[A-Za-z0-9._-]+", line)
        )


def test_every_pinned_download_has_a_64_hex_checksum():
    for checksum in [*RELEASE_SHA256.values(), *TEMPLATE_PACK_SHA256.values()]:
        assert re.fullmatch(r"[0-9a-f]{64}", checksum)


# --- plan --------------------------------------------------------------------


def test_a_complete_machine_has_nothing_to_do(tmp_path):
    state = ToolState(frozenset({"nmap", "subfinder", "nuclei", "nuclei_templates"}), PINNED)
    plan = build_install_plan(host(tmp_path), state, PINNED, which_of())
    assert plan.steps == ()
    assert render_plan(plan)[-1] == "Nothing to install."


def test_a_template_pack_of_another_version_is_replaced(tmp_path):
    state = ToolState(frozenset({"nmap", "subfinder", "nuclei", "nuclei_templates"}), "v9.0.0")
    (tmp_path / "nuclei-templates").mkdir()
    plan = build_install_plan(host(tmp_path), state, PINNED, which_of())
    assert [s.tool for s in plan.steps] == ["nuclei_templates"]
    assert "moved aside" in " ".join(plan.steps[0].notes)


def test_linux_nmap_uses_sudo_apt_and_says_so(tmp_path):
    plan = build_install_plan(host(tmp_path), NOTHING, PINNED, which_of("apt-get", "sudo"))
    nmap = plan.steps[0]
    assert nmap.kind is StepKind.PACKAGE_MANAGER
    assert nmap.argv == ("sudo", "apt-get", "install", "-y", "nmap")
    assert nmap.needs_admin and "password" in " ".join(nmap.notes)


def test_root_needs_no_sudo_and_dnf_is_the_fallback(tmp_path):
    plan = build_install_plan(host(tmp_path, is_root=True), NOTHING, PINNED, which_of("dnf"))
    assert plan.steps[0].argv == ("dnf", "install", "-y", "nmap")


def test_without_sudo_a_non_root_user_is_told_to_run_it_as_root(tmp_path):
    plan = build_install_plan(host(tmp_path), NOTHING, PINNED, which_of("apt-get"))
    assert plan.steps[0].kind is StepKind.MANUAL
    assert "as root" in plan.steps[0].summary


def test_macos_uses_brew_without_admin(tmp_path):
    plan = build_install_plan(host(tmp_path, "Darwin", "arm64"), NOTHING, PINNED, which_of("brew"))
    assert plan.steps[0].argv == ("brew", "install", "nmap")
    assert not plan.steps[0].needs_admin


@pytest.mark.parametrize(
    "available,expected",
    [
        (("winget", "choco"), "winget"),
        (("choco", "scoop"), "choco"),
        (("scoop",), "scoop"),
    ],
)
def test_windows_prefers_winget_then_choco_then_scoop(tmp_path, available, expected):
    plan = build_install_plan(
        host(tmp_path, "Windows", "AMD64"), NOTHING, PINNED, which_of(*available)
    )
    assert plan.steps[0].argv[0] == expected
    if expected == "choco":
        assert "Run as administrator" in " ".join(plan.steps[0].notes)


def test_no_package_manager_gives_a_manual_step(tmp_path):
    plan = build_install_plan(host(tmp_path, "Windows", "AMD64"), NOTHING, PINNED, which_of())
    assert plan.steps[0].kind is StepKind.MANUAL
    assert "nmap.org/download" in plan.steps[0].summary


def test_binaries_are_pinned_downloads_with_the_right_archive_per_platform(tmp_path):
    plan = build_install_plan(host(tmp_path, "Darwin", "arm64"), NOTHING, PINNED, which_of("brew"))
    subfinder, nuclei = plan.steps[1], plan.steps[2]
    assert subfinder.asset.url == (
        "https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_macOS_arm64.zip"
    )
    assert subfinder.asset.sha256 == RELEASE_SHA256[("subfinder", "macOS", "arm64")]
    assert nuclei.asset.url.endswith("nuclei_3.11.1_macOS_arm64.zip")
    assert subfinder.destination == tmp_path / ".local" / "bin" / "subfinder"


def test_windows_binaries_are_exe_files(tmp_path):
    plan = build_install_plan(
        host(tmp_path, "Windows", "AMD64"), NOTHING, PINNED, which_of("winget")
    )
    assert plan.steps[1].asset.member == "subfinder.exe"
    assert plan.steps[1].asset.url.endswith("subfinder_2.16.0_windows_amd64.zip")


def test_a_platform_without_a_pinned_build_is_a_manual_step(tmp_path):
    plan = build_install_plan(
        host(tmp_path, "Windows", "ARM64"), NOTHING, PINNED, which_of("winget")
    )
    nuclei = next(s for s in plan.steps if s.tool == "nuclei")
    assert nuclei.kind is StepKind.MANUAL


def test_an_unpinned_template_version_is_never_downloaded(tmp_path):
    plan = build_install_plan(
        host(tmp_path),
        ToolState(frozenset({"nmap", "subfinder", "nuclei"}), None),
        "v99",
        which_of(),
    )
    assert plan.steps[0].kind is StepKind.MANUAL


def test_path_hint_appears_only_when_a_binary_lands_off_path(tmp_path):
    off = build_install_plan(host(tmp_path), NOTHING, PINNED, which_of("apt-get", "sudo"))
    assert "not on your PATH" in "\n".join(off.path_hint)
    on = build_install_plan(
        host(tmp_path, path_dirs=[str(tmp_path / ".local" / "bin")]),
        NOTHING,
        PINNED,
        which_of("apt-get", "sudo"),
    )
    assert on.path_hint == ()
    win = build_install_plan(
        host(tmp_path, "Windows", "AMD64"), NOTHING, PINNED, which_of("winget")
    )
    assert "SetEnvironmentVariable" in "\n".join(win.path_hint)


def test_the_plan_text_shows_the_urls_and_checksums(tmp_path):
    plan = build_install_plan(host(tmp_path), NOTHING, PINNED, which_of("apt-get", "sudo"))
    text = "\n".join(render_plan(plan))
    assert (
        "from:   https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.7.tar.gz"
        in text
    )
    assert f"sha256: {TEMPLATE_PACK_SHA256[PINNED]}" in text
    assert "nothing is changed until you confirm" in text


def test_every_recipe_is_a_plain_argument_list_with_no_shell():
    for recipes in NMAP_RECIPES.values():
        for recipe in recipes:
            assert isinstance(recipe.argv, tuple) and recipe.argv[0] == recipe.manager
            assert not any(c in " ".join(recipe.argv) for c in "|;&$`")


# --- download safety -----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/x.zip",
        "https://evil.example.com/x.zip",
        "https://evilgithub.com/x.zip",
        "ftp://github.com/x",
    ],
)
def test_only_https_github_downloads_are_allowed(url):
    with pytest.raises(ToolInstallError):
        _check_url(url)


def test_github_and_its_redirect_hosts_are_allowed():
    for url in (
        "https://github.com/a/b.zip",
        "https://codeload.github.com/a/b.tar.gz",
        "https://objects.githubusercontent.com/x",
    ):
        _check_url(url)


def test_checksum_mismatch_deletes_the_file(tmp_path):
    path = tmp_path / "x"
    path.write_bytes(b"abc")
    with pytest.raises(ToolInstallError, match="Checksum mismatch"):
        verify_sha256(path, "0" * 64)
    assert not path.exists()


def make_zip(member: str, content: bytes = b"binary") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr(member, content)
        bundle.writestr("README.md", "x")
    return buffer.getvalue()


def make_targz(entries: dict[str, bytes], extra=None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
        if extra:
            extra(bundle)
    return buffer.getvalue()


def fake_downloader(payload: bytes):
    def download(url, destination):
        destination.write_bytes(payload)

    return download


def test_a_traversing_archive_is_refused(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(make_targz({"top/../../escape.txt": b"x"}))
    with pytest.raises(ToolInstallError, match="Unsafe path"):
        extract_tar_stripping_top_folder(archive, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_links_in_an_archive_are_skipped(tmp_path):
    def add_link(bundle):
        link = tarfile.TarInfo("top/evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        bundle.addfile(link)

    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(make_targz({"top/ok.yaml": b"id: x"}, add_link))
    out = tmp_path / "out"
    out.mkdir()
    extract_tar_stripping_top_folder(archive, out)
    assert (out / "ok.yaml").read_text() == "id: x"
    assert not (out / "evil").exists() and not (out / "evil").is_symlink()


# --- execution -----------------------------------------------------------------


def executor(downloader, runner=lambda argv: 0):
    return StepExecutor(runner, downloader, PINNED, now=lambda: datetime(2026, 10, 7, 12, 0, 0))


def binary_step(tmp_path, payload: bytes, sha=None, member="subfinder"):
    return PlanStep(
        "subfinder",
        StepKind.DOWNLOAD_BINARY,
        "dl",
        asset=DownloadAsset(
            "https://github.com/x.zip", sha or hashlib.sha256(payload).hexdigest(), member
        ),
        destination=tmp_path / "bin" / member,
    )


def test_a_verified_binary_is_installed_executable_and_leaves_no_temp_files(tmp_path):
    payload = make_zip("subfinder", b"#!/bin/sh\n")
    step = binary_step(tmp_path, payload)
    executor(fake_downloader(payload)).execute(step)
    installed = tmp_path / "bin" / "subfinder"
    assert installed.read_bytes() == b"#!/bin/sh\n"
    assert installed.stat().st_mode & 0o111
    assert [p.name for p in (tmp_path / "bin").iterdir()] == ["subfinder"]


def test_a_tampered_binary_is_never_installed(tmp_path):
    payload = make_zip("subfinder", b"evil")
    step = binary_step(tmp_path, payload, sha="0" * 64)
    with pytest.raises(ToolInstallError, match="Checksum mismatch"):
        executor(fake_downloader(payload)).execute(step)
    assert not (tmp_path / "bin" / "subfinder").exists()


def test_a_missing_archive_member_is_refused(tmp_path):
    payload = make_zip("other")
    with pytest.raises(ToolInstallError, match="not in the downloaded archive"):
        executor(fake_downloader(payload)).execute(binary_step(tmp_path, payload))


def template_step(tmp_path, payload):
    return PlanStep(
        "nuclei_templates",
        StepKind.TEMPLATE_PACK,
        "pack",
        asset=DownloadAsset("https://github.com/t.tar.gz", hashlib.sha256(payload).hexdigest()),
        destination=tmp_path / "nuclei-templates",
    )


def test_the_template_pack_lands_where_validate_tools_looks_with_its_marker(tmp_path, monkeypatch):
    from scanner_agent.tool_checks import check_nuclei_templates

    payload = make_targz({"nuclei-templates-10.4.7/http/a.yaml": b"id: a"})
    executor(fake_downloader(payload)).execute(template_step(tmp_path, payload))
    result = check_nuclei_templates(tmp_path / "nuclei-templates")
    assert result.available and result.version == PINNED
    assert (tmp_path / "nuclei-templates" / "http" / "a.yaml").exists()


def test_an_existing_template_folder_is_moved_aside_not_deleted(tmp_path):
    old = tmp_path / "nuclei-templates"
    old.mkdir()
    (old / "mine.yaml").write_text("keep me")
    payload = make_targz({"top/a.yaml": b"id: a"})
    executor(fake_downloader(payload)).execute(template_step(tmp_path, payload))
    backup = tmp_path / "nuclei-templates.previous-20261007120000"
    assert (backup / "mine.yaml").read_text() == "keep me"
    assert (tmp_path / "nuclei-templates" / "a.yaml").exists()


def test_a_tampered_template_pack_leaves_the_existing_folder_untouched(tmp_path):
    old = tmp_path / "nuclei-templates"
    old.mkdir()
    (old / "mine.yaml").write_text("keep me")
    payload = make_targz({"top/a.yaml": b"id: a"})
    step = template_step(tmp_path, payload)
    with pytest.raises(ToolInstallError):
        executor(fake_downloader(b"different")).execute(step)
    assert (old / "mine.yaml").read_text() == "keep me"


def test_a_failing_package_manager_is_reported():
    step = PlanStep("nmap", StepKind.PACKAGE_MANAGER, "x", argv=("brew", "install", "nmap"))
    with pytest.raises(ToolInstallError, match="exited with code 3"):
        executor(None, runner=lambda argv: 3).execute(step)


# --- orchestration ----------------------------------------------------------------


def run(
    tmp_path,
    *,
    dry_run=False,
    assume_yes=False,
    answer=True,
    system="Linux",
    which=None,
    runner=None,
    downloader=None,
):
    lines: list[str] = []
    asked: list[str] = []

    def confirm(question):
        asked.append(question)
        return answer

    ran: list = []
    code = run_install_tools(
        dry_run=dry_run,
        assume_yes=assume_yes,
        echo=lines.append,
        confirm=confirm,
        host=host(tmp_path, system, "arm64" if system == "Darwin" else "x86_64"),
        state=NOTHING,
        which=which or which_of("apt-get", "sudo", "brew"),
        runner=runner or (lambda argv: ran.append(argv) or 0),
        downloader=downloader or fake_downloader(b""),
    )
    return code, lines, asked, ran


def test_dry_run_prints_the_plan_and_changes_nothing(tmp_path):
    code, lines, asked, ran = run(tmp_path, dry_run=True)
    assert code == 0 and asked == [] and ran == []
    assert "Dry run: nothing was changed." in lines
    assert not (tmp_path / ".local").exists()


def test_declining_changes_nothing(tmp_path):
    code, lines, asked, ran = run(tmp_path, answer=False)
    assert code == 1 and asked and ran == []
    assert "Cancelled. Nothing was changed." in lines


def test_yes_skips_the_question_and_runs_the_steps(tmp_path):
    payloads = {}

    def downloader(url, destination):
        if url.endswith(".zip"):
            tool = "subfinder" if "subfinder" in url else "nuclei"
            data = make_zip(tool)
        else:
            data = make_targz({"top/a.yaml": b"id: a"})
        payloads[url] = data
        destination.write_bytes(data)

    # Real checksums cannot match the fake payloads, so a checksum failure is the
    # expected, safe result: it proves the verification runs before install.
    code, lines, asked, ran = run(tmp_path, assume_yes=True, downloader=downloader)
    assert asked == []
    assert ran == [("sudo", "apt-get", "install", "-y", "nmap")]
    assert code == 1
    assert any("Checksum mismatch" in line for line in lines)
    assert not (tmp_path / ".local" / "bin" / "subfinder").exists()


def test_manual_steps_make_the_exit_non_zero_but_the_rest_still_run(tmp_path):
    code, lines, _asked, ran = run(
        tmp_path, assume_yes=True, which=which_of(), downloader=fake_downloader(b"")
    )
    assert code == 1
    assert any("These need you" in line for line in lines)


def test_install_tools_command_dry_run(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli_module,
        "run_install_tools",
        lambda **kw: 0 if kw["dry_run"] and not kw["assume_yes"] else 9,
    )
    result = CliRunner().invoke(cli, ["install-tools", "--dry-run"])
    assert result.exit_code == 0


def test_install_tools_command_passes_yes_and_propagates_the_exit_code(monkeypatch):
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return 1

    monkeypatch.setattr(cli_module, "run_install_tools", fake)
    result = CliRunner().invoke(cli, ["install-tools", "--yes"])
    assert result.exit_code == 1 and seen["assume_yes"] is True and seen["dry_run"] is False
    assert TOOL_VERSIONS["subfinder"] == "2.16.0"
