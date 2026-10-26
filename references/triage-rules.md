# Triage rules

These rules turn the inventory, `findings.json` and the upstream research into the ranked list on the page.
The aim is a list someone can work top to bottom without having to re-sort it.

## Bands

Decide an item's band by working down this list. Stop at the first rule that matches.

**Priority 1 · Today**
0. A malicious package version is installed (the digest's MALICIOUS PACKAGES section, or a compromised version from
   the research found in `package_index.json`). It goes first on the page, above every other item. See Malicious
   packages below.
1. It is exploited in the wild: the digest's KNOWN EXPLOITED section (CISA KEV), or the vendor or a security
   research report the research cites says so. KEV often lags exploitation by days, so a research report of
   exploitation is enough; name the source and say that KEV does not list it yet.
2. It is a browser, OS component, runtime or toolchain, or anything else that handles untrusted network input or files on this machine, and it is Critical, or it is High and published in the window.
3. A browser has no patch yet for a Chromium or Firefox security release. Report it with the mitigation.
4. It is unpatchable (no fixed version will ship, for example an obsolete branch) and has a High or Critical advisory. The action is to remove it.
5. It is a project or global-tool dependency that runs as a service or processes untrusted input, and it is Critical, or it is High and published in the window. To decide, look at what the project reads and from where. If you still cannot tell, it does not meet this rule: put it in This week, and say in the item what would move it to Today (for example "move to Today if this project opens images from users").

**Priority 2 · This week**
1. It is Critical or High but does not meet a Today rule. For example, a test-only or dev-only package, or a transitive dependency of tests.
2. It is Moderate or Low and published in the window.
3. It is an old version installed alongside a current one (any entry in the digest's DUPLICATE INSTALLS, such as .NET runtimes and SDKs, PowerShell or a media player) and that old version is vulnerable.
4. It is an out-of-support runtime.
5. The WSL apt lists are more than 30 days old.
6. A fix for a cross-cutting incident (such as a CA distrust) has not shipped yet for an installed tool.

**Priority 3 · Backlog**
- Everything else from the dependency scans, grouped by ecosystem.
- End-of-support dates in the next 60 days.

**Not listed**
- Advisories that cannot apply to this machine, such as "non-Windows only". Mention them in one line under Limits.

**No action**
- Installed software that is already on the fixed version for this window's advisories. Listing these tells the reader they were checked.

**Limits**
- Scans that did not complete (`not_scanned` in findings.json), and scan notes with a caveat (`SCAN NOTES` in the digest).
- Sources you could not verify, and conflicts between sources.
- What this run does not cover, and its side effects.

AI agent apps and CLIs (Claude Desktop, ChatGPT, Claude Code, Codex, OpenCode) read untrusted repositories, web
pages and MCP tool output, and can run commands as the user. They count as handling untrusted input under Today
rules 2 and 5, and rank with browsers below. Give each vulnerable copy of a CLI its own line in the item, with its
path and install method, because each copy updates separately. The action for a stale copy that is not the one that
runs is to uninstall it. A desktop app that is only behind winget's offered version, with no advisory, is Backlog:
say that no advisory was found.

Software that IT manages, such as a VPN client or EDR agent, gets the band its severity and exposure call for. The action is "ask IT to update to <version>".

## Malicious packages

A malicious version means the machine may already be compromised, not only that something needs updating:
- Say where it was found (the project lockfile or global install) and whether it is installed now: a version in a
  global tree is installed; a version in a lockfile was installed wherever someone ran an install in that project.
- The action is to stop and report it to the organisation's security team before changing anything, then remove the
  package and reinstall from a clean lockfile. Credentials on the machine (npm, GitHub and cloud tokens, SSH keys)
  should be treated as exposed. Follow the order of steps in the vendor's or researcher's advisory: some worms
  delete data when a stolen token is revoked before their persistence is removed.
- Name the advisory and the indicators the research reported, and say which of them were checked and what was found.

## Node.js, PHP and Bun copies

- Each copy in NODE.JS, PHP AND BUN COPIES is its own item when it is vulnerable, with its path and where it came
  from (PATH, off PATH, nvm, fnm, Volta). An old version kept by a version manager is an old copy under the
  duplicate rules below; the action is to uninstall that version from the manager, or to update it.
- A `runtime` row from a release feed ("N security releases since ...") has no severity or CVE of its own: take them
  from the vendor's release notes in the research. If the research has none, write "not stated" and band it by the
  rules above, treating the runtime as handling untrusted input.
- An out-of-support Node.js or PHP line is This week (rule 4), unless an advisory for a supported line is exploited
  and the vendor says older lines are affected too; then it is Today.
- PHP that a local web server runs (mod_php, PHP-FPM, XAMPP, Laragon) handles network input. PHP used only as a CLI,
  for example by Composer, handles the files of the projects it runs in.

## Listening ports

`inventory.listening[]` flags ports from the config's `risky_ports` list. A flag is a prompt to look, not a finding:
- A listener bound to `127.0.0.1` or `::1` only is reachable from this machine alone. It is not listed.
- Ports 135, 139 and 445 owned by the System process are Windows RPC and file sharing, present on every Windows client. List them once in Backlog only if the machine is used on networks the user does not control, with the action of setting those networks to Public in Windows.
- A port owned by a developer service (a database, a cache, a web server) bound to all addresses is a Backlog item: say which process, and that the fix is binding it to localhost.
- A port owned by a remote-access or management service (3389, 5985, 5986, 22, 23) bound to all addresses on a non-managed machine is a This-week item.

## Duplicate installs

The digest's DUPLICATE INSTALLS section lists apps registered with more than one version, and commands found in
several PATH folders. Like a flagged port, an entry is a prompt to look, not a finding:
- An old copy with a known advisory goes in This week (rule 3), with the action of uninstalling that copy.
- An old copy with no known advisory, or a second copy of a command that is not the one that runs, is a Backlog
  item: name each copy and its path, and say which one runs.
- Major versions installed side by side on purpose (.NET 8 and 9, Python 3.13 and 3.14) are not duplicates. Judge
  each one on its own support status.
- A command marked as shadowing a system copy is a This-week item when the user did not put that folder first on
  PATH themselves: anything that can write to the user folder decides which program runs. The Microsoft Store
  alias folder (`WindowsApps`) listed after the real install is normal, and not a finding.

Within a band, rank by exposure first and severity second:
1. Browsers, AI agent apps and CLIs, and anything else that handles untrusted network input.
2. Language runtimes and toolchains (everything built or run with them inherits the flaw).
3. Libraries in projects that run as services or process untrusted files.
4. Global CLI tools and MCP servers.
5. Dev-only and test-only packages.

## Grouping

The digest lists one row per project, package and version. Merge rows so the page stays readable:
- Merge one package across several projects into one item, and list the projects (for example certifi in four uv projects).
- Merge one package across the projects of a .NET solution into one item per solution.
- Merge several advisories for one package into one item. Give the count, the worst severity, and the two or three advisories that matter most (RCE, memory corruption, Windows-specific).
- A flaw in a library bundled inside a global tool belongs to that tool. Say whether the tool's newest release still pins the vulnerable version (`npm view <pkg>@<version> dependencies`).

## Each item

- Product, and where it is installed (machine-wide, the project path, or the global install that bundles it).
- Installed version → fixed version. Use the minimum fixed version on the same major line. Say "uninstall" or "pending" when no fixed version applies.
- Severity chip, with CVSS when known. Mark "Windows-specific" or "reachable from your code" when the scan says so.
- Release date of the fix or advisory, in the configured time zone.
- One or two plain sentences on why it matters on this machine.
- The exact action.
  - Use a command only if it ran during this scan or you checked it with `--help`. This covers `uv lock --upgrade-package <pkg>`, `uv sync`, `uv python upgrade`, `npm install <pkg>@<version>`, `npm audit fix`, `winget uninstall --id <id>`, and `sudo apt update && sudo apt full-upgrade` inside WSL.
  - For .NET package bumps, give the package and version to set in the project file.
  - For apps, give the UI path or the vendor download page.
  - Link only to pages in `vendor-sources.md`, the GitHub Advisory Database or OSV. A download link found on any
    other page or in a search result is not used.
- Delta chip when a previous run exists: **New**, **Still open** or (in its own list) **Resolved**.

## Wording

Write for an engineering executive who will act on the page or forward it. Use literal, plain sentences with no metaphors. Use active voice. Name things by what people recognise ("Microsoft Edge", "the Python CA bundle"), not by scanner output. Put CVE and GHSA IDs in the item. Never invent a severity, version or date: if a source does not give one, say "not stated".
