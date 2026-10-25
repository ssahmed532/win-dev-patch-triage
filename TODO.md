# TODO: making the skill reusable across Windows 11 machines

Improvements found during the first runs on THINKPAD-E15 (v1.5 to v1.7.1, 23 October 2026, and v1.8.0, 25 October
2026), and not done yet.
They are ordered by priority within each section. Items marked **(seen)** came from a real run, not from analysis.

## 1. Machines other than this laptop

- [ ] **Manufacturer-specific vendor sources.** Read `Win32_ComputerSystem.Manufacturer` and `Win32_BIOS` in the
      inventory, and add the matching security bulletin pages to `vendor-sources.md`: Lenovo PSIRT, Dell DSA, HP
      security bulletins and Microsoft Surface. Lenovo System Update and Lenovo Service Bridge were installed here and
      never checked **(seen)**.
- [ ] **Firmware and drivers.** Inventory the BIOS/UEFI version, Intel ME/CSME, TPM firmware, and the Intel, AMD and
      NVIDIA graphics drivers, and compare them with the OEM and chip-vendor advisories. This is where laptops differ
      most, and none of it is covered today.
- [ ] **ARM64 laptops (Snapdragon).** Handle `Program Files (Arm)`, ARM64 .NET and Python, and x64 apps running under
      emulation. Check the browser and runtime paths in `collect_inventory.ps1` on an ARM64 machine.
- [ ] **Non-English Windows.** Force English output where tools allow it (`DOTNET_CLI_UI_LANGUAGE=en`), and prefer
      machine-readable output over parsing winget tables and `dotnet sdk check` text.
- [ ] **Managed and locked-down machines.**
      - In `setup_run.py`, detect Constrained Language Mode, AppLocker/WDAC policy and execution policy, and stop with
        a clear message.
      - Detect Intune/MDM enrolment and WSUS policy, and word actions for IT-managed apps as "ask IT to update to X"
        automatically, instead of relying on the user to say which apps IT manages.
      - Treat a missing winget (LTSC editions, or a fresh install before App Installer updates) as a gap to report,
        not a failure.
- [ ] **Windows Server and Windows 10.** Decide whether they are in scope. If they are, adjust the OS checks; if not,
      make `setup_run.py` say so and stop.
- [ ] **Remove the old `config.json` after migration.** Once `--init` has written `config-<HOSTNAME>.json`, offer to
      rename the pre-v1.7 `config.json` to `.bak`, so it stops appearing in later `CONFIG_REQUIRED` messages on other
      machines that share the roaming profile.

## 2. Coverage gaps

- [ ] **More lockfiles through OSV.** `Gemfile.lock` (RubyGems), `composer.lock` (Packagist), `pnpm-lock.yaml`,
      `yarn.lock` and `bun.lock` (npm). Today they are reported as not scanned. The Cargo code in
      `scan_dependencies.py` (`scan_cargo`) is the pattern to copy.
- [ ] **Vendor sources for the apps left unchecked (seen).** About 25 installed apps had no source: Discord, NordVPN,
      calibre, Google Drive, OneDrive (beyond MSRC), MarkText, µTorrent, balenaEtcher, TeraCopy, OneCommander,
      CrystalDiskInfo, Token Monitor, VLC, fzf, lazygit, bat, delta, eza, fd, ripgrep, zoxide, the Visual C++
      redistributables and the Visual Studio Installer. Add the ones that publish security notes, and list the rest
      under Limits automatically.
- [ ] **Docker images.** Scan local images with an SBOM/vulnerability tool when the engine is running, and check the
      `FROM` lines in Dockerfiles against the base images' advisories.
- [ ] **Non-apt WSL distros.** Inventory Fedora, openSUSE, Alpine and Arch packages (rpm, apk, pacman) and check
      them against OSV, as for Ubuntu.
- [ ] **Rust programs on PATH.** Read the dependency list that `cargo auditable` embeds in Rust binaries (bat, delta,
      eza, fd, ripgrep, zoxide) and check it against OSV, as the Go check does.
- [ ] **Go programs built before Go 1.18.** They are listed as not read. Parse the older pointer-based build-info
      layout, or keep listing them and say so on the page.
- [ ] **Microsoft Store and MSIX apps.** `installed_apps` reads only the uninstall registry. Add `Get-AppxPackage` for
      Store apps that handle untrusted content (for example the Raw Image Extension, whose CVE-2026-96202 could not
      be checked on the first run **(seen)**).
- [ ] **Repository-only advisories for the AI agent CLIs.** OSV missed two Claude Code advisories that are published
      only on the repository's advisory page (CVE-2026-103435 and CVE-2026-103012, against the bun copy 2.1.27), so
      they were added to the page by hand **(seen)**. In `scan_ai_clis`, also read
      `gh api repos/<owner>/<repo>/security-advisories` for anthropics/claude-code, openai/codex and
      anomalyco/opencode, and match each copy's version against `vulnerable_version_range`. Merge by GHSA ID with
      the OSV hits, and skip this check, recording it as not scanned, when `gh` is missing or signed out.
- [ ] **Electron version in Electron apps.** The Electron CA fix (CVE-2026-115570, fixed in 42.11.16, 43.8.1 and
      44.9.1) could not be checked against Claude Desktop, VS Code, Discord, balenaEtcher or MarkText, because the
      inventory does not record which Electron each app ships **(seen)**. Read it from the app's files without
      running the app (for example the Electron version string embedded in the main executable or `resources`), and
      check it against OSV under the npm package `electron`, as the Go check does for Go programs.
- [ ] **Browser extensions.** List Chrome, Edge and Firefox extensions with their versions; they handle untrusted
      content with the browser's privileges.

## 3. Hardening

- [ ] **Python manifests without a lockfile in trusted projects.** `uv pip compile` can still build packages from
      the indexes a repo names. Try `--no-build` first, and report the project as not scanned (with the reason) if
      resolution needs a build.
- [ ] **A repo's `.npmrc`, `nuget.config` and `uv.toml`.** These can point the scanners at another registry and leak
      package names to it. Report when a scanned project has one, and consider ignoring them during the scan.
- [ ] **Verify the scanners' downloads.** pip-audit and govulncheck are pinned by version. Pin them by hash as well.
- [ ] **The research agent's reach.** Give it an explicit allowlist of domains (from `vendor-sources.md`, GitHub
      advisories and OSV) instead of relying on the brief alone.

## 4. Less manual work, so runs don't depend on the model

- [ ] **Generate the research brief with a script.** Both runs filled `research-brief.md` by hand from the
      inventory **(seen)**. A `make_brief.py` would fill every slot, including the side-by-side copies and the Go
      programs.
- [ ] **Generate the page outline from `findings.json`.** Fill the counts, delta chips, tables, ranks, Already
      patched and Sources deterministically, and leave only the triage wording and band choices to Claude.
- [ ] **Carry the research forward.** Save the research table as `RUN/research.json` so the next run can show what
      changed upstream since the previous run, as it already does for findings and installed software.
- [ ] **Make the research agent read the whole release post.** On the second run the agent read only Bun's blog
      index and reported "no security fix", while the 1.4.4 post has a Security section **(seen)**. The brief should
      require reading each release post in full, past the first screen.
- [ ] **Fallback when the MSRC API is down.** The KB-to-build match came from news on the second run because the API
      returned 503 **(seen)**. Fall back to the Windows release health page.
- [ ] **Test runs must not become the baseline.** Runs made while testing the skill had to be deleted by hand so
      they would not become the next run's `previous_run` **(seen)**. Add a `--scratch` option that writes to a
      separate folder.

## 5. Digest and report quality

- [ ] **Go findings without a severity inflate the counts.** 51 of 68 findings were "unknown" on the second run,
      one per program per CVE **(seen)**. Group Go standard-library advisories per Go version instead of per program,
      and say in the digest that the Go database gives no severities.
- [ ] **"New" after a scan upgrade.** Findings that appear only because a newer skill version checks more were
      counted as "new" (53 of them) **(seen)**. Mark them "newly checked" when the previous run did not have that
      check.
- [ ] **The Microsoft Store alias is not a duplicate.** `pwsh` showed up under DUPLICATE INSTALLS because of the
      `WindowsApps` alias **(seen)**. Leave `WindowsApps` aliases out of `all_paths`.
- [ ] **Duplicate apps that are not duplicates.** .NET 6 and 8 Desktop Runtimes were listed as duplicates **(seen)**.
      Compare major versions too, and list side-by-side majors separately.
- [ ] **Python install manager vs runtime.** The research agent could not tell whether "Python install manager
      3.14.2" meant the manager or a runtime **(seen)**. Record the install manager's own version and the runtimes it
      manages separately in the inventory.

## 6. Tests and maintenance

- [ ] **Unit tests for the pure functions.** `go_build_info`, `rel` / `project_of`, `config_problems`,
      `root_problems`, `choose_fix` and the inventory shape check, run with `uv run --with pytest`. Today they are
      tested only by hand.
- [ ] **Inventory fixtures.** Saved `inventory.json` files covering one-item lists, no WSL, no winget, no npm, several
      roots and a missing root, fed to `scan_dependencies.py` and `build_findings.py`.
- [ ] **Evals for the new behaviour.** The first-run case exists. Add cases for an invalid config (exit 3 with
      `--force` offered), an untrusted project, and a run on a second machine with a roaming profile.
- [ ] **Line endings.** Add a `.gitattributes` so Python, PowerShell and Markdown files have fixed line endings,
      instead of the LF/CRLF warnings on every commit **(seen)**.
- [ ] **A CHANGELOG.** Versions are recorded only in commit messages. Keep a short changelog that the README links to.
