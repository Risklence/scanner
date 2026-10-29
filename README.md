# Risklence Collector

*Made by [Risklence](https://github.com/Risklence/scanner). Free to download and use under the [Apache License 2.0](LICENSE); see [Licence](#licence).*

The Risklence Collector is a small agent you run **inside your own network**. It
discovers what infrastructure you actually have, and reports that evidence back
to Risklence.

It is deliberately open. This is software you install inside your perimeter, so
you should be able to read exactly what it does before you trust it — what it
scans, what it sends, and what it never touches.

```bash
docker build -t risklence-scanner:latest https://github.com/Risklence/scanner.git#main
```

**Setting one up for the first time?** [`FIRST-SCAN.md`](FIRST-SCAN.md) walks the
whole path from a fresh organisation to a Collector that has actually scanned
something — the seven readiness gates, which are cleared on the machine and which
are decisions taken in Risklence, and the traps each one hides.

---

## What it does, and does not do

**It does:**

- Discover hosts and open services on networks **you have explicitly approved**
  in Risklence.
- Enumerate subdomains of domains **you have explicitly approved**.
- Optionally run vulnerability checks from a **pinned, bundled** check pack.
- Report its own health — which components work, whether it can store evidence,
  how stable its connection is.

**It does not:**

- Scan anything outside the boundary you approved. Every job it receives is
  cryptographically signed and names its own targets; a command that fails
  verification is rejected, not executed.
- Download checks from the internet at run time. The check pack is pinned into
  the image at build time, so what runs is exactly what was published.
- Send file contents, credentials, or user data. It reports hosts, ports,
  service banners and its own status.
- Make changes. It never remediates, reconfigures, or writes to anything it
  scans.

---

## Install

### Docker (recommended)

Build the Collector on the machine that will run it, straight from this
repository:

```bash
docker build -t risklence-scanner:latest https://github.com/Risklence/scanner.git#main
```

Prefer to download it first, or need to build somewhere without direct access to
GitHub? Get the repository (`git clone`, or **Code → Download ZIP**) and build
inside it:

```bash
git clone https://github.com/Risklence/scanner.git
cd scanner
docker build -t risklence-scanner:latest .
```

It is built on your machine, so it is right for its processor — Intel, Apple
Silicon, Raspberry Pi and ARM servers alike. The first build takes a few
minutes. It is tagged `risklence-scanner:latest` so the
commands below, and the ones Risklence shows you, find it; nothing is pulled
from a registry. (Earlier versions of this page tagged it
`ghcr.io/risklence/risklence-scanner:latest`. That was a local build wearing the
registry's name, so it is renamed. A Collector already running keeps working, since
a container holds its own image; the next update rebuilds under the new name.)

**One container and one data volume per scanner.** Every scanner has its own
`<ID>` (the twelve characters Risklence puts in the container and volume names
of the commands it shows you). Two scanners on one machine must never share a
volume, because the volume holds that scanner's credential and the last
`activate` would silently replace the other's. Copy `<ID>` from the command the
product gives you; a Collector installed before this change keeps the shared
names `risklence-scanner` and `risklence-scanner-data` until you reinstall it.

Activate it once with the token shown on the Risklence setup screen:

```bash
docker run --rm \
  -v risklence-scanner-data-<ID>:/root/.risklence-scanner \
  risklence-scanner:latest \
  activate --base-url https://api.risklence.com --token <YOUR_TOKEN>
```

Then leave it running:

```bash
docker run -d --name risklence-scanner-<ID> --restart unless-stopped \
  --cap-add=NET_RAW --network host \
  -v risklence-scanner-data-<ID>:/root/.risklence-scanner \
  risklence-scanner:latest \
  run --interval 60
```

**The snippet Risklence shows you is these steps in one block.** The Credentials tab
and the setup guide give you, in one paste: the build line, `activate` on this
scanner's own volume, removal of this scanner's old container (`docker rm -f`, so
the same snippet is right for a first install, an update and a rotated key), the
`run` command above. It does not follow the log (that never returns and holds your
terminal); the product shows a line beside it, `To watch it connect: docker logs
risklence-scanner-<ID>`, to run when you want it. The lines are chained with `&&`,
so a failed build stops the rest; without a successful build a plain `docker run`
of the image name would *pull* the stale registry image. The platform generates it
from one place (`generate_activation_command`), and a server test compares its
flags with this page.

**Windows PowerShell.** The product also gives you the same steps written for
Windows PowerShell (5.1 and 7), chosen in the setup guide's terminal step or on the
credential panel. PowerShell 5.1 has no `&&`, so the steps are one `& { ... }` block
that stops at the first failed step, and removing an old container that is not there
is not an error:

```powershell
& {
  docker build -t risklence-scanner:latest https://github.com/Risklence/scanner.git#main; if ($LASTEXITCODE -ne 0) { return }
  docker run --rm -v risklence-scanner-data-<ID>:/root/.risklence-scanner risklence-scanner:latest activate --base-url https://api.risklence.com --token <TOKEN>; if ($LASTEXITCODE -ne 0) { return }
  docker rm -f risklence-scanner-<ID> 2>$null
  docker run -d --name risklence-scanner-<ID> --restart unless-stopped --cap-add=NET_RAW --network host -v risklence-scanner-data-<ID>:/root/.risklence-scanner risklence-scanner:latest run --interval 60; if ($LASTEXITCODE -ne 0) { return }
}
```

On Windows the Collector runs in Docker Desktop, where `--network host` does not
give it your LAN (see the network note below): it installs and connects, but do not
trust its discovery. For scanning your network on Windows, use the Local install (below) instead; the product says the same beside this snippet when you choose Windows, and suggests Local at creation. Docker Desktop on a Mac has the same limit. Never run `activate` on another
scanner's data volume.

> Until the public mirror is synced with the current `apps/scanner`, the build
> yields the mirror's (older) Collector.

> **Why `--cap-add=NET_RAW`.** Without it the Collector cannot ARP the local
> segment, so it never sees a MAC address or a hardware vendor. That matters
> twice over: a hardware vendor is the only thing that can name a device with
> nothing listening — *"Ubiquiti device"* rather than a bare `192.168.1.1` —
> and a MAC is what tells a real device apart from an address that merely
> answered. Without it, "nothing is here" and "we could not look" arrive as the
> same observation.
>
> The Collector runs **without** it if you would rather not grant it. It scans
> exactly as before and simply learns less, and it reports the capability as
> unavailable so Risklence knows to read its silence as *"could not look"*
> rather than *"nothing there"*.

> **Network visibility matters.** By default a container sees the Docker
> network, not your LAN, and results will be wrong rather than merely
> incomplete. On Linux, use `--network host` so the Collector discovers what the
> machine itself can see. On Docker Desktop (macOS/Windows) there is no true
> host networking — the container sits behind a virtual network stack that can
> answer for addresses which do not exist, so **do not trust discovery results
> from Docker Desktop.** Run the Collector on the Linux host you actually want
> to scan from.

### Local install (without Docker)

Use this when you cannot run Docker. It installs the Collector as a normal command on
the machine, runs as you (no root needed for the Collector itself), and can start
itself at boot or logon.

**You need:** Python 3.11 or newer, and nothing else to install first (no pipx). Check with
`python3 --version` (Windows: `python --version`). A new Mac often has 3.9, which is too old: install
a current Python from python.org or with `brew install python`, open a new terminal window, and check
again. The install below puts the Collector in **its own private folder** (a Python virtual
environment made with plain `python3 -m venv` and plain pip), so it cannot clash with anything else
on the machine, and a "externally managed environment" error from a system or Homebrew Python does not
apply to it. Your credentials stay in `~/.risklence-scanner`; the program lives in a different folder.

1. **Install the Collector.** One line, which stops with a readable message if Python is too old.

   Mac and Linux (installs into `~/.risklence-scanner-app`):

   ```bash
   if python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then python3 -m venv ~/.risklence-scanner-app && ~/.risklence-scanner-app/bin/pip install https://github.com/Risklence/scanner/archive/refs/heads/main.zip; else echo "The Risklence Collector needs Python 3.11 or newer. Run python3 --version to see what this computer has." >&2; false; fi
   ```

   Windows PowerShell (installs into `%LOCALAPPDATA%\Risklence\scanner-app`):

   ```powershell
   if ((python -c 'import sys; print(int(sys.version_info >= (3, 11)))') -eq '1') { python -m venv "$env:LOCALAPPDATA\Risklence\scanner-app"; if ($LASTEXITCODE -eq 0) { & "$env:LOCALAPPDATA\Risklence\scanner-app\Scripts\pip.exe" install https://github.com/Risklence/scanner/archive/refs/heads/main.zip } } else { Write-Error "The Risklence Collector needs Python 3.11 or newer. Run python --version to see what this computer has." }
   ```

   The Collector is **not on `PATH`**, so the commands the product shows call it by its full path:
   `~/.risklence-scanner-app/bin/risklence-scanner` (Windows:
   `& "$env:LOCALAPPDATA\Risklence\scanner-app\Scripts\risklence-scanner.exe"`). Optional, Mac and
   Linux: `echo 'export PATH="$HOME/.risklence-scanner-app/bin:$PATH"' >> ~/.zshrc` (`~/.bashrc` for
   bash), then open a new terminal window, and the short `risklence-scanner ...` form used in the rest of
   this README works. Windows has no such shortcut in the guide; use the full path.

   > `risklence-scanner` is **not published to PyPI yet** (see
   > `tasks/active/collector-local-install-without-docker.md`). Until it is, the line above cannot
   > find the package. Install from a clone of this repository instead, after making the folder:
   > `python3 -m venv ~/.risklence-scanner-app && ~/.risklence-scanner-app/bin/pip install ./apps/scanner`
   > (Windows: `python -m venv "$env:LOCALAPPDATA\Risklence\scanner-app"; & "$env:LOCALAPPDATA\Risklence\scanner-app\Scripts\pip.exe" install .\apps\scanner`).
   > Until the mirror (`github.com/Risklence/scanner`) is synced with the current code, do not install from it.

2. **Install the scan tools.** The Collector drives nmap, subfinder and nuclei, plus a
   pinned nuclei template pack. This command installs what is missing:

   ```bash
   risklence-scanner install-tools --dry-run   # print the exact plan, change nothing
   risklence-scanner install-tools             # show the plan, ask, then do it (--yes skips the question)
   ```

   - nmap comes from your package manager: `brew` (macOS), `apt-get` or `dnf` through
     `sudo` (Linux; it asks for your password), `winget`, `choco` or `scoop` (Windows;
     `choco` needs an administrator PowerShell, `winget` may show a permission prompt).
   - subfinder and nuclei are **pinned release downloads** (subfinder 2.16.0, nuclei
     3.11.1) installed to `~/.local/bin` (Windows: `%LOCALAPPDATA%\Risklence\bin`), and the
     template pack is the **pinned** tag in `scanner_agent/tool_pins.env` (the same file
     the Docker build reads), installed to `~/nuclei-templates` with a
     `.risklence-template-version` marker. Each download is checked against a sha256
     written down in the program before anything is unpacked, and a mismatch installs
     nothing. None of this needs administrator rights. An existing `~/nuclei-templates`
     is moved aside to `~/nuclei-templates.previous-<time>`, not deleted.
   - It never pipes a download into a shell, and never runs anything before showing
     what it will do. If the folder it installs to is not on your `PATH`, it prints the
     line to add.
   - Prefer to do it yourself? Install nmap, subfinder and nuclei by any means and put
     the pack at `~/nuclei-templates` (write the pinned version, `cat
     scanner_agent/tool_pins.env`, into `~/nuclei-templates/.risklence-template-version`).

3. **Connect.** Use the command the platform shows for a command-line install. It pairs
   by a code (`risklence-scanner pair --base-url <URL> --scanner <NAME>`, see `pair`), or,
   with a key, `risklence-scanner activate --base-url <URL> --token <TOKEN> --scanner <NAME>`.
   The credential is stored in `~/.risklence-scanner/scanners/<NAME>/credentials.json`, never
   in a service definition (see "One computer, several scanners").

4. **Check.** `risklence-scanner validate-tools` lists what the Collector can see and
   reports it to Risklence. It **exits 1 when nmap is missing** (`--strict`: when any of
   nmap, subfinder, nuclei or the template pack is missing), after reporting as usual,
   so a script can tell. A missing raw-packet permission is explained but never fails it.

5. **Run.** The command Risklence shows ends in `risklence-scanner install --scanner <NAME>`: the Collector runs
   in the background as that scanner's own service, starts when you log in and restarts if it stops, so closing
   the Terminal does not stop it. Running the same command again restarts it. Risklence cannot start a stopped
   Collector (it never reaches into your computer), which is why it is never left running in a Terminal window.
   `risklence-scanner run --interval 60` still runs it in the foreground, for watching it work:

   ```bash
   risklence-scanner install          # start now and at boot/logon
   risklence-scanner service-status   # installed? running? where is the log?
   risklence-scanner uninstall
   ```

   `install` needs no administrator rights, and chooses by operating system:

   | OS | What it creates | Starts | Restarts if it stops | Log |
   |---|---|---|---|---|
   | Linux | `systemd --user` unit `~/.config/systemd/user/risklence-scanner.service` | at login; **at boot only with lingering** | `Restart=on-failure` | `journalctl --user -u risklence-scanner -f` |
   | macOS | LaunchAgent `~/Library/LaunchAgents/com.risklence.scanner.plist` (`launchctl bootstrap gui/<uid>`) | at login | `KeepAlive` | `~/Library/Logs/Risklence/scanner.log` |
   | Windows | Task Scheduler task "Risklence Scanner" at logon, limited rights | at logon | once a minute, up to 999 times | `%LOCALAPPDATA%\Risklence\Scanner\collector.log` (appended, never trimmed) |

   - **Linux:** a user service stops at logout unless lingering is on. `install` checks
     and tells you; `risklence-scanner install --enable-linger` also runs
     `loginctl enable-linger $USER` (some systems ask for `sudo`).
   - **macOS:** a LaunchAgent runs while you are logged in. A Mac that rebooted and has
     nobody logged in is not covered; that needs a system LaunchDaemon and root, which
     this command does not do. Homebrew's nmap is found because the plist sets a `PATH`.
   - **Windows:** the task runs when you log on. Running before anybody logs on needs
     administrator rights and a stored password, and is not done. If Windows refuses to
     create the task, `install` says to rerun it from PowerShell opened with **Run as
     administrator**. `risklence-scanner.exe` is looked up next to the Python that runs
     `risklence-scanner` (the private environment's `Scripts` folder), so it need not be on `PATH`. The same goes for the
     LaunchAgent and the systemd unit: they point at the Collector inside its own folder.

### Privileges: raw packets

Without raw-packet access the Collector still scans (connect scans), but nmap cannot ARP the
local network, so it learns no MAC addresses or hardware vendors and finds fewer devices that have
nothing listening. `validate-tools` reports `raw_packet_access` as MISSING and prints this:

- **Linux:** give nmap the capability once, `sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v nmap)")"`,
  and start the Collector with `NMAP_PRIVILEGED=1` in its environment; or run the Collector as root
  (`sudo risklence-scanner run`). The `systemd --user` service installed by `install` has neither.
- **macOS:** nmap needs root for raw scans and there is no per-program capability. Accept connect
  scans, or run the Collector as root (`sudo risklence-scanner run`).
- **Windows:** install [Npcap](https://npcap.com) (the nmap installer offers it) and run the
  Collector from a PowerShell opened with **Run as administrator**. The logon task runs without it.

The check itself opens a raw socket in the Collector's own process, so a capability granted only to
the nmap binary may still be reported as MISSING; what the Collector reports to Risklence is unchanged.

### Updating, and uninstalling, a local install

```bash
~/.risklence-scanner-app/bin/pip install --disable-pip-version-check --upgrade https://github.com/Risklence/scanner/archive/refs/heads/main.zip
```

(Windows: `& "$env:LOCALAPPDATA\Risklence\scanner-app\Scripts\pip.exe" install --disable-pip-version-check --upgrade https://github.com/Risklence/scanner/archive/refs/heads/main.zip`;
a Collector installed earlier with pipx keeps using `pipx upgrade risklence-scanner`.) Then restart the service so it runs the new code: `systemctl --user restart risklence-scanner.service`
(Linux), `launchctl kickstart -k gui/$(id -u)/com.risklence.scanner` (macOS), or
`schtasks /End /TN "Risklence Scanner"` then `schtasks /Run /TN "Risklence Scanner"` (Windows); if you
started `run` yourself, stop it (Ctrl+C) and start it again. Your credentials stay where they are:
**never run `activate` for an existing scanner.** The running Collector says all of this itself when a
newer version exists. To remove it: `risklence-scanner uninstall`, then delete the private folder (`~/.risklence-scanner-app`; Windows
`%LOCALAPPDATA%\Risklence\scanner-app`), and delete `~/.risklence-scanner` if you want to forget the credential.

### What was and was not tested

Tested on macOS (Darwin arm64, Python 3.11, non-root) on 2026-10-07: every subcommand against a fake
platform API, the test suite, and the `install-tools` download, checksum verification and extraction of
the pinned subfinder, nuclei and template pack into a scratch home directory. The service managers,
the generated systemd unit, LaunchAgent plist and Task Scheduler XML, and the install plan per OS are
covered by unit tests that check the exact text and command lines with a fake command runner.

**Not tested on a real system:** `schtasks` and the task XML on Windows (nothing here ran on Windows,
including `risklence-scanner.exe` paths and Npcap), `launchctl bootstrap` of the plist, a systemd
install and a reboot with lingering, apt/dnf/winget/choco/scoop installs, running the downloaded
nuclei and subfinder on Linux or Windows, a real scan and a real activation. Treat the first install on
each of those as a test and report what you see.

---

## Commands

Run `risklence-scanner --help`, or `--help` on any command, for the current
surface.

### `activate`

Binds this machine to a Collector in your Risklence organisation and stores the
credential locally. `activate` is only for a new scanner: never run it to update
or restart one that already exists.

```bash
risklence-scanner activate --base-url https://api.risklence.com --token <TOKEN>
```

| Option | Description |
| --- | --- |
| `--base-url` | Your Risklence API base URL. Required. |
| `--token` | The activation token from the setup screen. Required, shown once. |

The credential is written to `~/.risklence-scanner/credentials.json`
(override the directory with `RISKLENCE_SCANNER_HOME`). Keep it as you would any
credential: it authenticates this machine as your Collector.

### `pair`

Connects this machine with a code instead of a key (#647). The Collector shows a code; you type it in
Risklence (in the assistant, or in the scanner's install step), check the computer it names, and press
Connect. The Collector then collects its credential itself: no key is copied anywhere.

```bash
risklence-scanner pair --base-url https://api.risklence.com --scanner <NAME>
```

`--scanner` is the scanner the command is for, as Risklence's command names it. Risklence refuses the code
if it is typed for any other scanner.

### One computer, several scanners

A computer can run as many scanners' Collectors as needed. Each scanner's credential lives in its own
folder, `~/.risklence-scanner/scanners/<NAME>/credentials.json`, and every command Risklence shows ends in
`--scanner <NAME>` (the same short name Docker's container and volume end in), so starting, pairing or
updating one scanner's Collector never reaches another's.

- Every command takes `--scanner` (`run`, `heartbeat`, `validate-tools`, `test-scan`, `poll`, `activate`,
  `install`, `uninstall`, `service-status`).
- Without it, a command uses the Collector set up before folders existed (`~/.risklence-scanner` itself,
  as it always did), else the one scanner this computer has. With several, it lists them and starts none.
- Named, on a computer whose only Collector was set up before folders existed, the Collector asks Risklence
  which scanner that credential is for. The named scanner: it is copied into that scanner's folder (the
  original stays, so a service still reading it keeps working). Another scanner: it says which, and starts
  nothing.
- `activate --scanner <NAME>` refuses a key that belongs to another scanner, and saves nothing.
- `install --scanner <NAME>` installs that scanner's own service (`com.risklence.scanner.<NAME>`,
  `risklence-scanner-<NAME>.service`, task "Risklence Scanner <NAME>", log `scanner-<NAME>.log`), beside
  any other scanner's. Without a name it keeps the original service names.
- The output names the scanner: `Heartbeat OK — Auth & Access scanner: online.`

### `run`

The one you want for normal operation. Runs as a persistent process:
heartbeats, polls for approved work, executes it, reports results, and
periodically checks its own health.

```bash
risklence-scanner run --interval 60
```

| Option | Default | Description |
| --- | --- | --- |
| `--interval` | `60` | Seconds between heartbeat/poll cycles. Must stay **well below** the
platform's worker lease (300s): a command's lease starts when the platform issues it, so a
Collector that polls only once per lease window can lose the job before it has claimed it.
This was `300` — exactly the lease — and every long run retried (#322). |

A shorter interval means Risklence notices problems sooner and work starts
sooner; it does not make scans faster. `SIGTERM` and `SIGINT` both stop it
cleanly after the current cycle rather than killing work in flight.

Transient network failures are expected and survived: a failed heartbeat or
poll is retried on the next cycle, and a completed scan whose result cannot be
delivered is retried rather than discarded.

### `heartbeat`

Sends a single liveness ping and reports this machine's identity (kernel,
architecture, and — when not containerised — its operating system).

### `validate-tools`

Checks the bundled tools locally and reports the result to Risklence.

```bash
risklence-scanner validate-tools
```

Prints each component and whether it works. This is the same self-check the
`run` loop performs on its own, so you rarely need to invoke it by hand; it is
useful when diagnosing a Collector that reports a component as missing.

It reports to Risklence first, then exits **1 when nmap is missing** (`--strict`: when
any of nmap, subfinder, nuclei or the template pack is missing). A missing raw-packet
permission is explained in plain words (see "Privileges: raw packets") and never
changes the exit code.

### `install-tools`

Installs or verifies nmap, subfinder, nuclei and the pinned template pack on a local
install. `--dry-run` prints the exact plan and changes nothing; it asks before doing
anything unless `--yes`. See "Local install".

### `poll`

Fetches the next pending job, verifies its signature, executes it if it
verifies, and reports the result. One-shot equivalent of a single `run` cycle,
intended for scripted or manual use.

### `test-scan`

Runs a small, safe scan against one approved target and records the outcome —
used during setup to prove the Collector can genuinely reach and scan something.

```bash
risklence-scanner test-scan --target 127.0.0.1
```

### `install` / `uninstall` / `service-status`

Run the Collector at boot or logon as a **user-level** service (local installs only;
Docker installs do not need this, a container's own restart policy does the job): systemd
`--user` on Linux, a LaunchAgent on macOS, a Task Scheduler logon task on Windows. No root
and no administrator rights. `install --enable-linger` (Linux) also enables lingering.
`service-status` says whether it is installed and running. Details and limits are in
"Local install". The definitions contain no credential.

---

## How it decides what to scan

The Collector has no standing permission to scan anything. Every job arrives as
a signed command that names its own approved targets and carries an expiry. The
agent verifies the signature, the expiry, and that the command was issued to
*this* Collector before doing anything; a command failing any of those is
rejected with a reason, never executed.

This means approving a boundary in Risklence is what grants scanning authority,
and revoking it takes that authority away — the Collector cannot widen its own
scope.

---

## Diagnosing a Collector

```bash
# Is it running and reaching Risklence?
docker logs -f risklence-scanner-<ID>

# What does it think it can do?
docker exec risklence-scanner-<ID> risklence-scanner validate-tools
```

**"cannot do the approved vulnerability check pack"** — the Collector has the
`nuclei` binary but not its check pack. Nuclei without checks is an engine with
nothing to run. Either use the Docker image, which bundles a pinned pack, or
choose a scan profile that does not include vulnerability checks.

**Discovery finds implausibly many hosts** — almost always Docker Desktop. See
the network note under Install.

**Nothing happens after activation** — the Collector polls rather than being
pushed to, so work begins on the next cycle (up to `--interval` seconds).

---

## Updating and rolling back

This section is for a **Docker** install. A local install is updated with its own pip
(`pip install --disable-pip-version-check --upgrade https://github.com/Risklence/scanner/archive/refs/heads/main.zip` in its private folder) and a service restart: see "Updating, and uninstalling,
a local install" above.

```bash
docker build -t risklence-scanner:latest https://github.com/Risklence/scanner.git#main
docker rm -f risklence-scanner-<ID>
# then re-run the `run` command above
```

Your credential lives in this scanner's `risklence-scanner-data-<ID>` volume, so it survives
replacing the container — you do not re-activate. When a newer Collector exists,
the running Collector tells you in its log and in `validate-tools` ("A newer
Risklence Collector is available"), with these same steps; it is a notice only
and never stops the Collector working. To pin or roll back, build a
specific commit or tag instead of `main`:

```bash
docker build -t risklence-scanner:latest https://github.com/Risklence/scanner.git#<commit-or-tag>
```

---

## Updating tools

Subfinder, Nuclei and the Nuclei template pack are **pinned**, not "latest": the Docker image and
`risklence-scanner install-tools` install exactly the same versions, written in one file,
`scanner_agent/tool_pins.env`. A rebuild never picks up an upstream release nobody reviewed, and an
image and a local install cannot differ. The price is that a new detection or fix reaches you only
when someone bumps the pin on purpose. To bump one:

1. Read the upstream release notes, then edit the version in `scanner_agent/tool_pins.env`.
2. Replace its checksums in `scanner_agent/tool_installer_constants.py` (`RELEASE_SHA256` for each
   archive, `TEMPLATE_PACK_SHA256` for the pack), taken from the project's own release page.
3. Run the tests: they fail until every pinned version has a checksum and the Dockerfile still reads
   its versions from the pin file.
4. Build the image and check `subfinder -version` and `nuclei -version` print the new versions.

## Verifying what you are running

Building from source means you run exactly what you can read: name a commit
(`#<commit>` above) and the image is built from that code and nothing else.

Prebuilt images, where Risklence publishes them, are signed with
[cosign](https://docs.sigstore.dev/) using keyless signing, so the signature is
bound to the workflow that built it:

```bash
cosign verify ghcr.io/risklence/risklence-scanner:latest \
  --certificate-identity-regexp 'https://github.com/Risklence/scanner/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also publishes an SBOM and a component manifest recording the
bundled tool and check-pack versions, read from the built image itself rather
than from source, so it cannot drift from what actually shipped.

---

## Tests

```bash
poetry install
poetry run pytest
```

## Releasing

The Collector is published to PyPI from **this repository**, by tag, and not from the
Risklence monorepo where it is developed. Each release is a snapshot of the monorepo's
`apps/scanner`, mirrored here; the release workflows in `.github/workflows/` are mirrored
with it, so edit them in the monorepo, not here.

- `scanner-test-vX.Y.Z` runs `publish-scanner-testpypi.yml` (environment `testpypi`) and
  uploads to TestPyPI, as a rehearsal.
- `scanner-vX.Y.Z` runs `publish-scanner-pypi.yml` (environment `pypi`, which needs an
  approval) and uploads to PyPI.

Both first check that the tag equals the `version` in `pyproject.toml`
(`scripts/check_release_version.py`), then run the tests and build. No token is stored:
PyPI trusts this repository's workflow run (trusted publishing). A version can never be
uploaded twice, so a TestPyPI retry uses a new `X.Y.Z.devN` version.

---

## Licence

The Collector is free for anyone to download, use and modify, under the
[Apache License 2.0](LICENSE). If you redistribute it, keep the [`NOTICE`](NOTICE)
file, which says that Risklence made it. `risklence-scanner --version` shows the
same attribution.

The licence covers the **Collector code only**. The tools it runs are separate
programs under their own licences: nmap (Nmap Public Source License, which has
terms for redistributing nmap, for example inside an image you distribute),
subfinder and nuclei (MIT) and the nuclei templates (MIT). [`NOTICE`](NOTICE)
lists them.

## Reporting a problem

Security issues: please report privately to security@risklence.com rather than
opening a public issue.

Everything else: open an issue on this repository. Note that the Collector's
source is developed alongside the Risklence platform, so fixes are applied
there and mirrored here on release — a pull request may be applied rather than
merged directly, and you will be credited either way.
