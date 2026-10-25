# win-dev-patch-triage

A Claude Code skill that runs a read-only security patch triage of a Windows 11 developer workstation and publishes a
ranked remediation page: what to update today, this week, and in the backlog, with a comparison against the previous run.

It checks:
- installed apps and browsers (winget, plus file versions for apps winget does not track)
- AI agent apps and CLIs: the Claude and ChatGPT desktop apps, and every copy of Claude Code, Codex and OpenCode (native, winget, npm or bun), with the CLIs checked against OSV
- language runtimes and toolchains: Node.js, CPython via uv, .NET, Go, PowerShell, Git and others on PATH, plus PHP, Java or Ruby found off PATH
- global npm, bun and uv tools, including the libraries bundled inside them (via OSV)
- Go-built programs on PATH (gh, lazygit, fzf, ...): the Go version and modules compiled into each, read from the file and checked against OSV
- every dependency lockfile under one or more projects folders: uv, pip/requirements, npm, NuGet, Go and Cargo
- old copies left installed next to new ones, and commands whose copy in a user folder shadows the system copy
- WSL distros (key package versions and how stale the apt lists are), listening ports, and the OS patch level
- vendor advisories released in the last N hours (24 by default)

The workflow and its rules are in [SKILL.md](SKILL.md). The triage rules are in [references/triage-rules.md](references/triage-rules.md), and the vendor pages checked on each run are in [references/vendor-sources.md](references/vendor-sources.md).

## Requirements

| Tool | Minimum | Used for |
|---|---|---|
| Windows 11, PowerShell 7 (`pwsh`) | PowerShell 7.4 (tested with 7.5) | the inventory script |
| [uv](https://docs.astral.sh/uv/) | a uv that has `uv audit` (0.13 or newer; tested with 0.13.5). The setup step checks for it and stops with an upgrade message if it is missing | runs the Python scripts and the Python audits (`uv audit`, `uvx pip-audit`) |
| Node.js / npm | any current LTS (tested with Node 24) | `npm audit` and global package checks |
| GitHub CLI (`gh`), signed in | any | advisory severity and publish dates from the GitHub Advisory Database. Without it, the scripts fall back to OSV |
| .NET SDK | 9.0.300 or newer, the first with `dotnet list package --vulnerable` (tested with 10.0.402). Older SDKs are noted at setup and .NET projects are not audited | only if projects use .NET |
| Go | any supported release | only if projects use Go; `govulncheck`. Not needed for checking Go-built programs |
| Claude Code | tested with 2.1.308. Needs background agents; the PowerShell tool is used when present, otherwise Bash | running the skill |
| Claude Code signed in to claude.ai | the Artifact tool | publishing the page. Without it every run is dry and the page is the local file |

## Install

Clone the repo wherever you keep tools, then run the installer from that folder:

```powershell
git clone https://github.com/ssahmed532/win-dev-patch-triage
cd win-dev-patch-triage
pwsh -ExecutionPolicy Bypass -File .\install.ps1
```

`install.ps1` links `~/.claude/skills/win-dev-patch-triage` to this folder with a directory junction, so the
repo is the only copy and edits are live. It creates no config; the first run does that. Restart Claude Code afterwards.

`-ExecutionPolicy Bypass` applies to that one command only. Without it, Windows PowerShell 5.1 blocks every script on
a client machine by default, and PowerShell 7 blocks scripts that carry the internet mark, which a ZIP download of this
repo has and a `git clone` does not. For a ZIP, running `Unblock-File` on the `.ps1` files is the alternative.

Alternatively, clone the repo straight into the folder where Claude Code keeps its skills. No installer and no junction
are needed, and the clone is then the only copy:

```powershell
cd ~/.claude/skills
git clone https://github.com/ssahmed532/win-dev-patch-triage
```

Keep the folder name `win-dev-patch-triage`, which `git clone` uses by default. If `install.ps1` already
linked that name, remove the junction first. Restart Claude Code afterwards.

## Configure

The first run on a machine configures the skill, and scans nothing until that is done. `setup_run.py` stops with
`CONFIG_REQUIRED` (exit code 3) and lists the folders on the machine that contain git repos. Claude then asks for
the mandatory settings and saves them with `setup_run.py --init`, which validates each value:

- **projects folders**: one or more, for example `D:\work` and `~/source/repos`;
- **the report page**: an existing claude.ai artifact link, a new page, or local-only.

The config is per machine: `%APPDATA%\win-dev-patch-triage\config-<HOSTNAME>.json`. `%APPDATA%` roams
between machines on a domain profile, and each machine has its own projects and its own page. A config written on
another machine, or a `config.json` from before v1.7, also triggers the first-run questions; the old values are
offered as answers. To change a setting later, run `--init` again with `--force`, the projects roots and the
page; every other option left out keeps its current value (`--clear-untrusted` empties the untrusted list). The old
file is kept as `.bak`. A projects root that is missing on a later run, such as an unplugged drive, is reported as
not scanned, and the run goes on with the other roots.

```powershell
uv run scripts/setup_run.py --init --projects-root D:\work --projects-root ~/source/repos `
    --artifact-url https://claude.ai/artifact/<id> --untrusted-project D:\work\vendor-clones
```

A `config.local.json` in the repo folder is used only when the per-machine file does not exist; git ignores it.

| Key | Meaning |
|---|---|
| `hostname` | the machine the config was written for; written by `--init` |
| `projects_roots` | folders searched for dependency manifests. A folder inside another is refused, and so are two with the same folder name |
| `runs_root` | where each run's folder is written (outside the repo; it holds machine inventory) |
| `artifact_url` | the private page to update on each run |
| `local_only` | `true` to write the page locally only; required when `artifact_url` is empty |
| `untrusted_projects` | folders of third-party code. Their .NET and Go projects, and Python manifests without a lockfile, are not scanned, because that would evaluate their build files; they are reported as not scanned. Their lockfiles (uv.lock, package-lock.json, Cargo.lock) are still checked |
| `window_hours` | default look-back window for "new" advisories |
| `timezone_label` | optional label for the time zone on the page, such as `PKT`; times always use the machine's time zone, and an empty label uses the Windows zone name |
| `exclude_dirs` | folder names skipped while searching for manifests |
| `risky_ports` | listening ports to flag for review. The triage rules then decide whether a flagged port is a finding: a loopback-only listener and the standard Windows services on 135, 139 and 445 are not |
| `runtime_search_roots` | folders searched for PHP, Java and Ruby installs that are not on PATH (default: the system drive). Other users' profiles and the Windows folder are always skipped |

## Use

In Claude Code:

```text
/win-dev-patch-triage
/win-dev-patch-triage 48
/win-dev-patch-triage dry-run
```

The skill also triggers on requests such as "what needs patching on my machine". For a narrower question, such as
"does the new OpenSSL CVE affect me", Claude asks before starting a full run.
A full run takes 10–35 minutes, depending on the model, and most of that is the upstream research. The skill must run on the machine it
scans, so a cloud-scheduled routine cannot run it. To repeat it on a schedule, use `/loop` in an open session.
On a dry run, open `patch-triage.local.html` from the run folder; it is the page wrapped as a complete document.

What a run costs, from the 22 October 2026 evals on one workstation with 16 scanned projects (the research agent's own
usage is not included in the token figures):

| Model | Wall time | Main session tokens |
|---|---|---|
| Haiku | 14 min | about 146k |
| Sonnet | 21 min | about 132k |
| Opus | 25 min | about 181k |

A run with more projects, or on a day with many advisories, costs more. On a Pro plan one Opus run is a large share of
a five-hour usage window.

Use Opus for this skill. If your usage limits do not allow Opus, use Sonnet. The skill also runs on Haiku, but that is
not advisable: its results are less accurate, and it can miss or skip important gaps and vulnerabilities.

## What a run changes

Nothing in your projects or installs. The side effects (each WSL distro is started, and the uv, npm and Go caches
download the scanner packages) are listed under "Side effects to report" in
[SKILL.md](SKILL.md#things-that-go-wrong). The dependency scanners that run as downloaded code, pip-audit and
govulncheck, are pinned to fixed versions in `scripts/scan_dependencies.py`. .NET's first-use setup, which would
create a development HTTPS certificate, is turned off.

Scanning a .NET or Go project evaluates its build files, and resolving a Python manifest without a lockfile can
build packages; both can run code from the repo. List folders of third-party code in `untrusted_projects` to skip
those scans for them. Go always runs with `GOTOOLCHAIN=local`,
so a repo's `go.mod` cannot make Go download and run a different toolchain.

## What leaves your machine

- **Package names and versions** of your dependencies go to OSV (`api.osv.dev`) for the global npm, bun and uv tools,
  the crates in each `Cargo.lock`, the Go modules compiled into programs on PATH, and the versions of the AI agent CLIs, and to the advisory sources behind `uv audit`, `pip-audit`, `npm audit`, `dotnet list package --vulnerable` and
  `govulncheck` for your projects. Advisory IDs go to the GitHub Advisory Database through `gh` when it is signed in.
- **Product names and versions** of installed software go into the research agent's web fetches and web searches,
  and the vendor pages it reads see those requests.
- **The published page** carries your OS edition and build, installed app and runtime versions, the names of your
  projects, and the ports that are listening. It is private by default; anyone you share it with sees all of that.
  The run folder under `runs_root` holds the same data plus the raw scanner output, so keep it outside any synced or
  shared folder.
- **Nothing else.** No source code, no file contents, no credentials. The scripts never open `.env` files or credential
  stores, and the research brief tells the agent to skip pages that show personal identifiers.

## Corporate and managed machines

The skill was built and tested on an unmanaged Windows 11 Pro workstation. On a machine managed by IT, expect these
differences and set the environment variables before the run:

- **A proxy that inspects TLS.** The scanners and advisory lookups need to trust the corporate root CA. uv reads the
  Windows certificate store with `UV_SYSTEM_CERTS=1` (or `--system-certs`); Node and npm need the CA file in
  `NODE_EXTRA_CA_CERTS` (npm also honours its `cafile` setting); the Python scripts and Go use the Windows store on
  their own; `gh` and the Python scripts honour `HTTPS_PROXY`.
- **A private package registry.** `npm audit` needs the registry's audit endpoint, which mirrors such as Artifactory
  do not always expose; those projects are then reported as not scanned. Set `GOPROXY` for Go if the public proxy is
  blocked.
- **winget disabled by policy.** The inventory's first two commands fail and the run continues without winget data;
  the vendor comparison still works from the registry and file versions.
- **EDR or application control** may block `govulncheck` (downloaded and built with `go run`) or `uvx pip-audit`. The
  affected projects are reported as not scanned.
- **Apps that IT updates** through Company Portal or Software Center get the action "ask IT to update", as the triage
  rules say. The triage cannot tell which apps those are; name them in the chat so the page says so.

## Layout

```text
SKILL.md                     workflow, ground rules, things that go wrong
scripts/setup_run.py         config, window, run folder, previous run
scripts/collect_inventory.ps1  Windows inventory
scripts/scan_dependencies.py   dependency scanners
scripts/build_findings.py      normalise, enrich, compare, digest
scripts/check_page.py          checks the filled page before it is published
scripts/skill_version.py       version read from SKILL.md
references/                  triage rules, vendor sources, research-agent brief
assets/report_template.html  page layout
config.example.json          configuration template
install.ps1                  junction install
evals/                       test cases, one folder each
LICENSE                      MIT
```

## Test

`evals/` holds four test cases in the layout that `claude plugin eval` and the skill-creator skill read: a first run
with no configuration that must ask before scanning, a 48-hour
dry run, a single-CVE question that must not start a run unasked, and a Windows Update question that must not load
this skill. Run them after changing the skill, once for each model your team uses (Haiku, Sonnet and Opus).

`claude plugin eval` can run only the two question cases. On native Windows it refuses any run that is granted Bash
or PowerShell, and its sandbox hides your home folder, so the dry-run case cannot run under it. The command also
needs a plugin root, so wrap a copy of the skill in one: put the skill in `<dir>/skills/win-dev-patch-triage/`,
the cases in `<dir>/evals/`, and `{"name": "patch-triage-eval"}` in `<dir>/.claude-plugin/plugin.json`. Then, from
`<dir>`:

```powershell
claude plugin eval . --case "*question*" --model haiku --judge-model sonnet --no-publish --allow-tools WebFetch WebSearch
```

Each case runs three times, with and without the skill, and each run is billed. Results go to `evals/results/`.
Pass `--judge-model sonnet`: the default Haiku judge voted FAIL on "no scan script ran" checks in runs where no
script ran at all, including the no-skill arm, so its scores were unusable. The checks are objective, so when in
doubt read the traces in the results folder.

Run the dry-run case in a Claude Code session with each model, against a copy of the skill whose
`config.local.json` has this machine's `hostname`, `"local_only": true` and its own `runs_root`, on a profile with no
per-machine config (which takes precedence). Run the first-run case on a Windows profile with no config at all. Check its graders against the run folder
and the session transcript.

To release a new version, change `version` and `updated` in the SKILL.md front matter, the only place the version is
stated; the scripts and the page footer read it from there. Bump the pinned scanner versions in
`scripts/scan_dependencies.py` in the same release, after reading their release notes.

## License

MIT. See [LICENSE](LICENSE).
