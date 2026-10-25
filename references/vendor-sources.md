# Upstream sources to check on every run

Search indexes lag by a day or more, so read these pages directly instead of relying on a web search.
Check only what the inventory shows is installed, plus the cross-cutting incidents at the end.
Prefer the vendor's page. When a news site or aggregator disagrees with it, go with the vendor and record the conflict.

## Runtimes and toolchains

| Product | Page | What to read |
|---|---|---|
| Node.js | https://nodejs.org/en/blog/vulnerability | The newest security-release post: fixed version per release line, CVEs, dependency updates (undici, OpenSSL, c-ares, CA certificates) |
| Go | https://go.dev/doc/devel/release | Minor releases for the installed line that mention "security fixes"; compare with the reachable flaws from govulncheck |
| CPython | https://www.python.org/downloads/ and the release page of the newest patch for the installed minor line | Security content; bundled pip/certifi/OpenSSL changes |
| uv | https://github.com/astral-sh/uv/releases | Security notes; uv bundles its own CA roots |
| .NET | https://github.com/dotnet/core/tree/main/release-notes and https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core | Patch Tuesday (second Tuesday of the month) runtime and SDK versions; end-of-support dates |
| PowerShell | https://github.com/PowerShell/PowerShell/releases | Security releases; old side-by-side versions stay vulnerable |
| PHP, Java, Ruby | php.net, Oracle CPU / Adoptium, ruby-lang.org | Only if the inventory found them, on PATH or off it |
| Rust | https://blog.rust-lang.org/ (security announcements) and https://github.com/rust-lang/rustup/blob/master/CHANGELOG.md | Security point releases of rustc and Cargo, and rustup releases. Crate advisories (RustSec) come through OSV in the Cargo.lock scan |

## Applications

| Product | Page |
|---|---|
| Chrome | Version: https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions (JSON, newest first). The release blog (chromereleases.googleblog.com) lists bug reporters by name, so do not use it. Take CVE IDs and severities from NVD or CVE.org for "Google Chrome", and from Microsoft's Edge security notes, which list the Chromium CVEs they include |
| Edge | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security. Edge often trails Chrome by days. If Microsoft's newest note says a fix is pending, report Edge as "no patch yet" with the mitigation |
| Firefox | https://www.mozilla.org/en-US/security/advisories/ |
| Git for Windows | https://github.com/git-for-windows/git/releases. The `.windows.N` suffix matters, because a `.windows.2` build can carry an OpenSSL or curl security update that `.windows.1` lacks |
| GitHub CLI | https://github.com/cli/cli/releases |
| Docker Desktop | https://docs.docker.com/desktop/release-notes/ |
| VS Code | https://code.visualstudio.com/updates and MSRC |
| Visual Studio | https://learn.microsoft.com/en-us/visualstudio/releases/2026/release-notes (check whether a newer build has a security advisory table or only bug fixes) |
| 7-Zip | https://www.7-zip.org/history.txt |
| Notepad++ | https://github.com/notepad-plus-plus/notepad-plus-plus/releases |
| KeePass | https://keepass.info/news/news_all.html |
| Zoom | https://www.zoom.com/en/trust/security-bulletin/ |
| FortiClient | https://www.fortiguard.com/psirt (filter by FortiClient; usually IT-managed) |
| ISC BIND | https://kb.isc.org/docs/aa-00913. There are no Windows builds after 9.17, so an installed Windows BIND cannot be patched |
| WSL | https://github.com/microsoft/WSL/releases |
| Adobe Acrobat | https://www.adobe.com/trust/security/bulletins-and-advisories.html (Adobe's Trust Center, where bulletins are published from October 2026). The older APSB bulletins remain at https://helpx.adobe.com/security/products/acrobat.html, which sometimes returns 403 to automated fetches |
| Microsoft 365 Apps | https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates. Compare with the installed build, and say which update channel it is on if the build number shows it |
| OneDrive, Teams and other Microsoft apps | MSRC (https://msrc.microsoft.com/update-guide), filtered by product |
| Zed | https://zed.dev/releases/stable and https://github.com/zed-industries/zed/security/advisories |
| Slack | https://slack.com/release-notes/windows |
| Bun | https://bun.com/blog (release posts). The GitHub releases page can embed signed download URLs, so do not use it |
| Windows | https://msrc.microsoft.com/update-guide and the current month's Patch Tuesday; compare with the OS build and UBR from the inventory |

## AI agent apps and CLIs

Check every entry in `inventory.ai_apps` and `inventory.ai_clis`, one row per copy. `scan_dependencies.py` already
matches CLI copies against OSV, and those hits show in the digest. The research adds the latest version, advisories
OSV does not carry yet, and the desktop apps, which have no advisory feed a scanner can query.

| Product | Page | What to read |
|---|---|---|
| Claude Code | https://github.com/anthropics/claude-code/security/advisories, https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md and https://github.com/advisories?query=%40anthropic-ai%2Fclaude-code | Advisories (filed under the npm package `@anthropic-ai/claude-code`, which applies to the native and winget builds too, since they share version numbers) and the newest version. The native installer updates itself; winget and bun copies do not |
| Claude Desktop | https://nvd.nist.gov/vuln/search (keyword "Claude Desktop"), the Claude Code advisories above (some cover "Claude Code and Claude Desktop"), and https://support.claude.com/en/articles/12138966-release-notes | Anthropic publishes no version-numbered security notes for the desktop app: its release notes name features, not builds. Take CVEs and affected versions from NVD and the GitHub advisories; take the newest build from `winget_available` in the inventory and say that it comes from winget |
| ChatGPT desktop | https://help.openai.com/en/articles/10003026-chatgpt-windows-app-release-notes and https://nvd.nist.gov/vuln/search (keyword "ChatGPT") | Its MSIX package is named `OpenAI.Codex`, and the inventory reports it under its display name. The help page often returns 403 to automated fetches; when it does, take the newest build from `winget_available` and record the gap under Limits. OpenAI publishes no security bulletin for the app |
| Codex CLI | https://github.com/openai/codex/security/advisories, https://github.com/openai/codex/releases and https://github.com/advisories?query=%40openai%2Fcodex | Advisories (npm package `@openai/codex`) and the newest `rust-v*` release. The ChatGPT app bundles its own Codex runtime, which updates with the app |
| OpenCode | https://github.com/anomalyco/opencode/security/advisories and https://github.com/anomalyco/opencode/releases | Advisories (npm package `opencode-ai`) and the newest release. The project moved from `sst/opencode`; links to the old repository redirect |

## Feeds that catch everything else

- CISA alerts and the Known Exploited Vulnerabilities catalog: https://www.cisa.gov/news-events/cybersecurity-advisories and https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- GitHub Advisory Database, reviewed advisories sorted by newest: https://github.com/advisories
- One extended web search for "critical vulnerability security update <today's date>" to find anything not listed here.

## Cross-cutting incidents

When a certificate authority is compromised or distrusted, tools that ship their own CA bundle need their own updates even after the OS and browsers have blocked it. Check certifi in every Python project, uv, CPython's bundled pip, Docker Desktop, Git for Windows' bundled OpenSSL, and Node.js' bundled CA store.
