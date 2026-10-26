# /// script
# requires-python = ">=3.12"
# dependencies = ["packaging>=24"]
# ///
"""Run every dependency scanner over the manifests in RUN/inventory.json and save raw results to RUN/deps/.

Usage: uv run scan_dependencies.py --run RUN

Read-only for the projects: lockfiles are audited as they are, and projects without a lockfile are
resolved in a copy under RUN/work/, never in the repo. Each scan's outcome is recorded in
RUN/deps/scan_status.json so the report can say what was not scanned and why.
Side effects outside RUN: the uv, npm and Go caches download what they need. `dotnet list` never restores, so the
projects themselves are not touched.
The .NET and Go scans evaluate a project's build files, which can run code from the repo; folders listed in
untrusted_projects are skipped, and Go never downloads the toolchain a go.mod asks for (GOTOOLCHAIN=local).
Cargo, Composer, pnpm, yarn, bun and npm lockfiles, the Go programs on PATH (their embedded build info) and the AI agent
CLIs are checked against OSV. Every Node.js, PHP and Bun copy is checked against the vendor's release feed or the
security advisories on its GitHub repository.
"""
import argparse
import functools
import json
import mmap
import operator
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

sys.dont_write_bytecode = True  # the skill folder may be read-only or replaced by an update; write nothing into it
from skill_version import SKILL_VERSION  # noqa: E402

# No .NET first-use setup (it creates a development HTTPS certificate), and no toolchain download chosen by a repo's go.mod
os.environ.update({"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
                   "DOTNET_NOLOGO": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "GOTOOLCHAIN": "local"})

OSV = "https://api.osv.dev/v1"
# inventory fields that must be JSON lists; PowerShell turns a one-element array into a bare value unless it is wrapped in @()
LIST_FIELDS = ("runtimes", "python_on_path", "uv_tools", "uv_pythons", "installed_apps", "duplicate_apps", "browsers",
               "off_path_runtimes", "wsl", "listening", "manifests", "ai_clis", "ai_apps", "runtime_copies")
# Scanner code that is downloaded and executed on every run. Pinned on purpose: bump these with a release, after
# reading the scanner's release notes, rather than running whatever is newest on the day.
PIP_AUDIT = "2.10.1"
GOVULNCHECK = "v1.9.0"
status = []
# every package version checked against OSV, and where it was found, so the triage can look up a malicious version that
# the research reports before OSV lists it: ecosystem -> name -> version -> places
INDEX = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))


def inside(path, folder):
    path, folder = os.path.normcase(path), os.path.normcase(folder).rstrip("\\/")
    return path == folder or path.startswith(folder + os.sep)


def rel(path, roots):
    """The path relative to the projects root that holds it; with several roots, prefixed by that root's folder name."""
    for r in roots:
        if inside(path, r):
            rp = os.path.relpath(path, r)
            return rp if len(roots) == 1 else os.path.join(os.path.basename(r.rstrip("\\/")) or r, rp)
    return path


def slug(path, roots):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", rel(path, roots)).strip("_") or "root"


def run(cmd, cwd=None, timeout=900):
    """Run a command and return (exit code, stdout, stderr). Never raises for a non-zero exit."""
    exe = shutil.which(cmd[0])
    if not exe:
        return 127, "", f"{cmd[0]} not found on PATH"
    try:
        p = subprocess.run([exe, *cmd[1:]], cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def record(kind, target, ok, out=None, note=""):
    status.append({"kind": kind, "target": target, "ok": ok, "output": out, "note": note.strip()[:500]})


def save(deps, name, text):
    path = os.path.join(deps, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return os.path.relpath(path, os.path.dirname(deps))


def is_json(text):
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


# ---------- per-ecosystem scanners ----------

def scan_uv(d, roots, deps):
    # uv audit exits non-zero when it finds vulnerabilities, so judge success by the JSON, not the exit code
    code, out, err = run(["uv", "audit", "--frozen", "--preview-features", "audit-command", "--output-format", "json"], cwd=d)
    ok = is_json(out)
    record("uv-audit", d, ok, save(deps, f"uv__{slug(d, roots)}.json", out) if ok else None, "" if ok else err or out)


def installed_pythons(inv):
    """Minor versions of the uv-managed CPythons in the inventory, newest first, as '3.14' strings."""
    found = {m.group(1) for p in inv.get("uv_pythons") or [] for m in [re.match(r"cpython-(\d+\.\d+)", p)] if m}
    return sorted(found, key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)


def pick_python(src, pythons):
    """The newest installed Python that the project's requires-python allows: (version, None) or (None, why)."""
    spec = None
    if os.path.basename(src).lower() == "pyproject.toml":
        try:
            with open(src, "rb") as f:
                spec = (tomllib.load(f).get("project") or {}).get("requires-python")
        except (OSError, ValueError):
            pass
    if not pythons:
        return None, "no uv-managed Python is installed (uv python install <version>)"
    if not spec:
        return pythons[0], None
    try:
        allowed = SpecifierSet(spec)
    except InvalidSpecifier:
        return pythons[0], None
    for v in pythons:
        if allowed.contains(v):
            return v, None
    return None, f"no installed uv Python satisfies requires-python {spec} (installed: {', '.join(pythons)})"


def scan_unlocked_python(src, roots, deps, work, pythons):
    """pyproject without uv.lock, or a requirements file: resolve a copy in RUN/work, then pip-audit the pins."""
    name = slug(src, roots)
    py, why = pick_python(src, pythons)
    if not py:
        record("pip-audit", src, False, None, why)
        return
    wd = os.path.join(work, name)
    os.makedirs(wd, exist_ok=True)
    copy = os.path.join(wd, os.path.basename(src))
    shutil.copy2(src, copy)
    pinned = os.path.join(wd, "pinned.txt")
    # --no-python-downloads: a read-only scan must never install an interpreter
    code, out, err = run(["uv", "pip", "compile", copy, "--python", py, "--no-python-downloads", "--quiet", "--no-header",
                          "-o", pinned], cwd=wd)
    if code != 0 or not os.path.exists(pinned):
        record("pip-audit", src, False, None, f"uv pip compile with Python {py} failed: " + err)
        return
    outfile = os.path.join(deps, f"pipaudit__{name}.json")
    code, out, err = run(["uvx", f"pip-audit@{PIP_AUDIT}", "-r", pinned, "--no-deps", "--disable-pip",
                          "--progress-spinner", "off", "-f", "json", "-o", outfile], cwd=wd)
    ok = os.path.exists(outfile)
    # no lockfile means nothing pins what is actually installed: this shows what a fresh install would get today
    record("pip-audit", src, ok, os.path.relpath(outfile, os.path.dirname(deps)) if ok else None,
           f"resolved fresh from the manifest with Python {py} (no lockfile): reflects a new install today, "
           "not an existing venv" if ok else err)


def scan_npm(d, roots, deps):
    code, out, err = run(["npm", "audit", "--package-lock-only", "--json"], cwd=d)
    ok = is_json(out)
    record("npm-audit", d, ok, save(deps, f"npm__{slug(d, roots)}.json", out) if ok else None, "" if ok else err)


@functools.cache
def dotnet_no_restore():
    """['--no-restore'] where the SDK has the option. SDK 9 rejects it, and its `dotnet list package` never restores."""
    code, out, err = run(["dotnet", "list", "package", "--help"])
    return ["--no-restore"] if "--no-restore" in out + err else []


def scan_dotnet(target, roots, deps):
    # never restore, so the projects stay untouched; a project that was never restored is reported, not restored
    code, out, err = run(["dotnet", "list", target, "package", "--vulnerable", "--include-transitive", *dotnet_no_restore(),
                          "--format", "json", "--output-version", "1"], timeout=1200)
    ok = is_json(out) and '"problems"' not in out
    note = "" if ok else ("no restore output (obj/project.assets.json); run `dotnet restore` yourself, then re-run "
                          "the scan. " + (err or out)[:300])
    if is_json(out) and '"problems"' in out:  # partial result: keep it, but say which projects had problems
        ok, note = True, "some projects reported problems, usually missing restore output: " + out[out.find('"problems"'):][:300]
    record("dotnet-vulnerable", target, ok, save(deps, f"dotnet__{slug(target, roots)}.json", out) if is_json(out) else None, note)


def parse_govulncheck(text):
    """Turn govulncheck's `-show verbose` text report into records, keeping which section each one came from:
    Symbol Results = your code calls it, Package Results = imported but not called, Module Results = required only."""
    sections = {"Symbol": "reachable", "Package": "imported", "Module": "required"}
    vulns, cur, scope = [], None, "reachable"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = re.match(r"^=== (\w+) Results ===", line)
        if s:
            scope = sections.get(s.group(1), scope)
            continue
        m = re.match(r"^Vulnerability #\d+: (GO-\d{4}-\d+)", line)
        if m:
            cur = {"id": m.group(1), "title": lines[i + 1].strip() if i + 1 < len(lines) else "", "found": [], "fixed": [],
                   "scope": scope}
            vulns.append(cur)
        elif cur and "Found in:" in line:
            cur["found"].append(line.split("Found in:")[1].strip())
        elif cur and "Fixed in:" in line:
            cur["fixed"].append(line.split("Fixed in:")[1].strip())
    summary = [l.strip() for l in lines if l.startswith(("Your code is affected", "This scan also found", "vulnerabilities in modules"))]
    return {"vulns": vulns, "summary": " ".join(summary)}


def scan_go(d, roots, deps):
    code, out, err = run(["go", "run", f"golang.org/x/vuln/cmd/govulncheck@{GOVULNCHECK}", "-show", "verbose", "./..."],
                         cwd=d, timeout=1200)
    text = out + err
    ok = "Vulnerability #" in text or "Your code is affected by" in text or "No vulnerabilities found" in text
    parsed = parse_govulncheck(text)
    parsed["raw"] = save(deps, f"go__{slug(d, roots)}.txt", text)
    record("govulncheck", d, ok, save(deps, f"go__{slug(d, roots)}.json", json.dumps(parsed, indent=2)) if ok else None,
           "" if ok else text[-500:])


# ---------- global installs (no lockfile): enumerate bundled packages and ask OSV ----------

def bundled_npm_packages(root_dir):
    """Every name@version found in package.json files under a global node_modules tree."""
    found = defaultdict(set)
    if not root_dir or not os.path.isdir(root_dir):
        return found
    for cur, dirs, files in os.walk(root_dir):
        dirs[:] = [x for x in dirs if x not in (".bin", "test", "tests", "__tests__", "fixtures", "example", "examples")]
        parent = os.path.dirname(cur)
        is_package_dir = os.path.basename(parent) == "node_modules" or (
            os.path.basename(parent).startswith("@") and os.path.basename(os.path.dirname(parent)) == "node_modules")
        if is_package_dir and "package.json" in files:
            try:
                with open(os.path.join(cur, "package.json"), encoding="utf-8") as f:
                    pj = json.load(f)
            except (OSError, ValueError):
                continue
            if isinstance(pj.get("name"), str) and isinstance(pj.get("version"), str):
                top = os.path.relpath(cur, root_dir).split(os.sep)
                owner = "/".join(top[:2]) if top[0].startswith("@") else top[0]
                found[(pj["name"], pj["version"])].add(owner)
    return found


def osv_request(req, timeout):
    """One OSV call, tried three times: with many lockfiles a run sends hundreds, and single connections time out."""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.URLError:
            if attempt == 2:
                raise


def osv_post(path, body):
    return osv_request(urllib.request.Request(f"{OSV}/{path}", data=json.dumps(body).encode(),
                                              headers={"Content-Type": "application/json"}), 120)


OSV_RECORDS = {}  # shared by every scan in the run: lockfiles often have the same advisories


def osv_get(vid):
    if vid not in OSV_RECORDS:
        OSV_RECORDS[vid] = osv_request(f"{OSV}/vulns/{vid}", 60)
    return OSV_RECORDS[vid]


def osv_scan(packages, ecosystem, label=None):
    """packages: {(name, version): owners}. Returns OSV records joined to the packages they affect. OSV also lists
    malicious package versions, under MAL- IDs."""
    for (n, v), owners in packages.items():
        INDEX[ecosystem][n][v].update(f"{label}: {o}" if label else o for o in owners)
    keys = sorted(packages)
    hits = []
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        res = osv_post("querybatch", {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk]})
        for (n, v), r in zip(chunk, res.get("results", [])):
            for vuln in r.get("vulns", []) or []:
                hits.append({"name": n, "version": v, "owners": sorted(packages[(n, v)]), "id": vuln["id"]})
    for h in hits:
        h["osv"] = osv_get(h["id"])
    return hits


def scan_globals(inv, deps):
    trees = [("npm-global", inv.get("npm_global_root"), "bundled in a global install"),
             ("bun-global", inv.get("bun_global_root"), "bundled in a global install")]
    # the npm and corepack that ship inside each Node.js copy; `npm root -g` does not cover them
    trees += [("node-bundled", os.path.join(os.path.dirname(c["path"]), "node_modules"), f"ships with Node.js at {c['path']}")
              for c in inv.get("runtime_copies") or [] if c["name"] == "node"]
    for i, (label, root_dir, scope) in enumerate(trees):
        try:
            pk = bundled_npm_packages(root_dir)
            hits = osv_scan(pk, "npm", label) if pk else []
            out = save(deps, f"osv__{label}_{i}.json", json.dumps({"ecosystem": "npm", "root": root_dir, "scope_note": scope,
                                                                   "packages_checked": len(pk), "hits": hits}, indent=2))
            record("osv-" + label, root_dir or "(none)", True, out, f"{len(pk)} bundled packages checked")
        except Exception as e:  # network or parse failure: report it, keep scanning the rest
            record("osv-" + label, root_dir or "(none)", False, None, repr(e))
    tools = {(t["name"], t["version"]): {"uv tool"} for t in inv.get("uv_tools") or []}
    try:
        hits = osv_scan(tools, "PyPI") if tools else []
        out = save(deps, "osv__uv-tools.json", json.dumps({"ecosystem": "PyPI", "packages_checked": len(tools), "hits": hits}, indent=2))
        record("osv-uv-tools", "uv tool list", True, out, f"{len(tools)} tools checked")
    except Exception as e:
        record("osv-uv-tools", "uv tool list", False, None, repr(e))


def scan_ai_clis(inv, deps):
    """AI agent CLIs installed outside npm and bun (native installer, winget, scoop): each copy's version checked
    against OSV under the npm package its vendor files advisories for, since these builds share its version numbers.
    npm and bun copies are left to scan_globals, which reads the same package from node_modules."""
    pk = defaultdict(set)
    for c in inv.get("ai_clis") or []:
        if c["method"] in ("npm", "bun"):
            continue
        if not c.get("version"):
            record("osv-ai-clis", c["path"], False, None, f"no version in `{c['name']} --version` output: {c.get('version_output')}")
            continue
        pk[(c["npm_package"], c["version"])].add(f"{c['name']} ({c['method']}) {c['path']}")
    try:
        hits = osv_scan(pk, "npm") if pk else []
        out = save(deps, "osv__ai-clis.json", json.dumps({"ecosystem": "npm", "scope_note": "AI agent CLI, matched by its npm version",
                                                          "packages_checked": len(pk), "hits": hits}, indent=2))
        record("osv-ai-clis", "AI agent CLIs", True, out, f"{len(pk)} copies outside npm and bun checked")
    except Exception as e:
        record("osv-ai-clis", "AI agent CLIs", False, None, repr(e))


# ---------- lockfiles checked against OSV: the (name, version) pairs are read from the file; nothing is installed or run ----------

def parse_cargo(path):
    """crates.io crates only: path and git dependencies, and crates from other registries, are not in OSV."""
    with open(path, "rb") as f:
        lock = tomllib.load(f)
    return {(p["name"], p["version"]) for p in lock.get("package", []) if "crates.io" in str(p.get("source", ""))}


def parse_composer(path):
    with open(path, encoding="utf-8") as f:
        lock = json.load(f)
    # a branch such as dev-main has no release to match
    return {(p["name"], p["version"]) for p in (lock.get("packages") or []) + (lock.get("packages-dev") or [])
            if re.match(r"v?\d", p.get("version") or "")}


def parse_package_lock(path):
    """package-lock.json v2 and v3. A v1 file has no "packages" section and is left to npm audit."""
    with open(path, encoding="utf-8") as f:
        lock = json.load(f)
    return {(p.get("name") or key.rpartition("node_modules/")[2], p["version"])  # "name" is set for an aliased package
            for key, p in (lock.get("packages") or {}).items()
            if "node_modules/" in key and not p.get("link") and re.match(r"\d", p.get("version") or "")}


# keys under packages: and snapshots:, such as 'name@1.2.3' (v9), /@scope/name@1.2.3(peer@1.0.0) (v6), /name/1.2.3_peer@1.0.0 (v5)
PNPM_KEY = re.compile(r"^  '?/?((?:@[^/@\s']+/)?[^/@\s'(]+)[@/](\d[^\s:'(_]*)")


def parse_pnpm(path):
    found, section = set(), None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line[0].isspace():
                section = line.split(":")[0]
            elif section in ("packages", "snapshots") and (m := PNPM_KEY.match(line)):
                found.add(m.groups())
    return found


def parse_yarn(path):
    """yarn.lock: an unindented entry line ("name@^1.0.0", name@~1.1:) followed by its version, written as
    `version "1.2.3"` (classic) or `version: 1.2.3` (Berry)."""
    found, name = set(), None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip() and line[0] not in " #":
                m = re.match(r'"?(@?[^@"\s]+)@', line)
                name = m.group(1) if m else None
            elif name and (m := re.match(r'  version:? "?(\d[^"\s]*)', line)):
                found.add((name, m.group(1)))
                name = None
    return found


def parse_bun(path):
    """bun.lock (text; Bun 1.2 and later): each package entry is an array whose first item is "name@version".
    Workspace, git and file entries have no registry version and do not match."""
    with open(path, encoding="utf-8") as f:
        return set(re.findall(r'\[\s*"(@?[^@"\s]+)@(\d[^"]*)"', f.read()))


LOCKFILES = {"cargo.lock": ("crates.io", parse_cargo), "composer.lock": ("Packagist", parse_composer),
             "package-lock.json": ("npm", parse_package_lock), "pnpm-lock.yaml": ("npm", parse_pnpm),
             "yarn.lock": ("npm", parse_yarn), "bun.lock": ("npm", parse_bun)}


def scan_lockfile(path, roots, deps):
    """A lockfile's packages checked against OSV (which carries the GitHub, RustSec and PHP advisories and the
    malicious-package reports). package-lock.json also gets npm audit; the two are merged by advisory ID later."""
    name = os.path.basename(path)
    eco, parse = LOCKFILES[name.lower()]
    try:
        pk = {k: {rel(path, roots)} for k in parse(path)}
        hits = osv_scan(pk, eco) if pk else []
        out = save(deps, f"osv__lock__{slug(path, roots)}.json",
                   json.dumps({"ecosystem": eco, "scope_note": None, "packages_checked": len(pk), "hits": hits}, indent=2))
        record("osv-lockfile", os.path.dirname(path), True, out)
    except Exception as e:  # unreadable lockfile or network failure
        record("osv-lockfile", os.path.dirname(path), False, None, f"{name}: {e!r}")


# ---------- Node.js, PHP, Bun, Composer and pnpm themselves ----------

NODE_DIST = "https://nodejs.org/dist/index.json"
NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
PHP_RELEASES = "https://www.php.net/releases/index.php?json&max=200&version={}"
PHP_STATES = "https://www.php.net/releases/states.php"
# Vendors that publish advisories on their GitHub repository, where OSV may not have them (it had none of Bun's 1.4.4
# advisories). Each is checked against every copy in runtime_copies, or else the version its command reports.
REPO_ADVISORIES = {"php": "php/php-src", "bun": "oven-sh/bun", "composer": "composer/composer", "pnpm": "pnpm/pnpm"}
CMP = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "=": operator.eq}


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "win-dev-patch-triage", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def github_api(path):
    """GitHub's REST API through gh when it is signed in, otherwise unauthenticated (60 requests an hour)."""
    code, out, err = run(["gh", "api", path])
    return json.loads(out) if code == 0 else get_json(f"https://api.github.com/{path}")


def in_range(version, rng):
    """Whether a version is inside a GitHub vulnerable_version_range: '< 8.3.36', '>= 1.3.14, < 1.4.4', '>=11.0.0 <11.11.0'."""
    pairs = re.findall(r"(<=|>=|<|>|=)\s*([0-9][\w.+-]*)", rng or "")
    try:
        return bool(pairs) and all(CMP[op](Version(version), Version(v)) for op, v in pairs)
    except InvalidVersion:
        return False


def first_version(text):
    m = re.search(r"\d[\w.+-]*", text or "")
    try:
        return Version(m.group(0)) if m else None
    except InvalidVersion:
        return None


def matching_entries(version, entries):
    """The entries of one advisory that cover a version. PHP files one entry per release line with only an upper bound
    ('< 8.4.24' next to '< 8.3.33'), so such an entry counts only for a version on its own line. The line is cut at the
    first version part where the advisory's fixed versions differ: 8.3 against 8.4 for PHP, 10 against 11 for pnpm."""
    fixed = [f.release for e in entries if (f := first_version(e.get("patched_versions")))]
    cut = min((next((i for i, (a, b) in enumerate(zip(r, fixed[0])) if a != b), None) for r in fixed[1:]),
              key=lambda i: 99 if i is None else i, default=None)
    matched = []
    for e in entries:
        rng = e.get("vulnerable_version_range") or ""
        fix = first_version(e.get("patched_versions"))
        if not in_range(version, rng):
            continue
        if ">" not in rng and cut is not None and fix and Version(version).release[:cut + 1] != fix.release[:cut + 1]:
            continue  # an upper bound only, for another release line
        matched.append(e)
    return matched


def scan_runtime_releases(inv, deps):
    """Each Node.js and PHP copy against the vendor's release feed, which marks every security release and gives each
    line's end of support. One finding per copy, not per CVE; the CVEs are in the vendor's release notes."""
    copies = [c for c in inv.get("runtime_copies") or [] if c["name"] in ("node", "php")]
    if not copies:
        return
    hits, today = [], datetime.now(timezone.utc).date().isoformat()
    try:
        node = (get_json(NODE_DIST), get_json(NODE_SCHEDULE)) if any(c["name"] == "node" for c in copies) else None
        php_states = get_json(PHP_STATES) if any(c["name"] == "php" for c in copies) else None
        for c in copies:
            m = re.match(r"\d+\.\d+\.\d+", c.get("version") or "")
            if not m:
                record("runtime-releases", c["path"], False, None, f"no version in the file's version resource: {c.get('version')}")
                continue
            v = m.group(0)
            if c["name"] == "node":
                line = v.split(".")[0]
                releases = [(r["version"][1:], r["date"], r["security"]) for r in node[0] if r["version"][1:].split(".")[0] == line]
                end = (node[1].get(f"v{line}") or {}).get("end")
                url = "https://nodejs.org/en/blog/vulnerability"
            else:
                line = ".".join(v.split(".")[:2])
                releases = [(k, datetime.strptime(r["date"], "%d %b %Y").date().isoformat(), "security" in (r.get("tags") or []))
                            for k, r in get_json(PHP_RELEASES.format(line)).items() if isinstance(r, dict) and "date" in r]
                state = (php_states.get(line.split(".")[0]) or {}).get(line)
                end = state["security_support_end"][:10] if state else "1970-01-01"  # php.net lists supported lines only
                url = f"https://www.php.net/ChangeLog-{line.split('.')[0]}.php"
            security = sorted((r for r in releases if r[2] and Version(r[0]) > Version(v)), key=lambda r: Version(r[0]))
            latest = max((r[0] for r in releases), key=Version, default=None)
            base = {"product": c["name"], "copy": f"{c['path']} ({c['source']})", "installed": v, "url": url}
            if security:
                hits.append({**base, "ids": [f"{c['name']}-{security[-1][0]}-security-release"], "published": security[-1][1],
                             "fixed": [latest], "title": f"{len(security)} security release(s) on the {line} line since {v}: "
                                                         + ", ".join(f"{r[0]} ({r[1]})" for r in security)})
            if end and end < today:
                hits.append({**base, "ids": [f"{c['name']}-{line}-end-of-life"], "published": None, "fixed": [],
                             "title": f"the {line} line is out of support" + ("" if end.startswith("1970") else f" since {end}")
                                      + ": it gets no more security fixes"})
        out = save(deps, "runtime__releases.json", json.dumps({"hits": hits}, indent=2))
        record("runtime-releases", "Node.js and PHP copies", True, out)
    except Exception as e:  # a feed that cannot be read or has changed shape
        record("runtime-releases", "Node.js and PHP copies", False, None, repr(e))


def scan_repo_advisories(inv, deps):
    """PHP, Bun, Composer and pnpm against the security advisories published on their GitHub repositories."""
    copies = defaultdict(list)  # product -> [(version, where)]
    for c in inv.get("runtime_copies") or []:
        copies[c["name"]].append((c.get("version"), f"{c['path']} ({c['source']})"))
    for r in inv.get("runtimes") or []:
        if r["name"] in REPO_ADVISORIES and r["name"] not in copies and r.get("version"):
            m = re.search(r"\d+\.\d+\.\d+", r["version"])
            copies[r["name"]].append((m and m.group(0), r.get("path")))
    for product, repo in REPO_ADVISORIES.items():
        if not copies.get(product):
            continue
        try:
            advisories = [a for a in github_api(f"repos/{repo}/security-advisories?per_page=100") if not a.get("withdrawn_at")]
        except Exception as e:
            record("repo-advisories", repo, False, None, repr(e))
            continue
        hits = []
        for version, where in copies[product]:
            if not version:
                record("repo-advisories", where, False, None, f"the {product} version could not be read")
                continue
            for a in advisories:
                matched = matching_entries(version, a.get("vulnerabilities") or [])
                if matched:
                    cvss = a.get("cvss_severities") or {}
                    hits.append({"product": product, "copy": where, "installed": version,
                                 "ids": [a["ghsa_id"]] + ([a["cve_id"]] if a.get("cve_id") else []),
                                 "severity": a.get("severity"), "published": a.get("published_at"), "title": a.get("summary"),
                                 "cvss": (cvss.get("cvss_v4") or {}).get("score") or (cvss.get("cvss_v3") or {}).get("score"),
                                 "url": a.get("html_url"),
                                 "fixed": [m.group(0) for x in matched if (m := re.search(r"\d[\w.+-]*", x.get("patched_versions") or ""))]})
        out = save(deps, f"repo__{repo.replace('/', '_')}.json", json.dumps({"repo": repo, "hits": hits}, indent=2))
        record("repo-advisories", repo, True, out)


# ---------- Go programs on PATH: Go version and modules read from the build info the Go linker embeds ----------

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def read_uvarint(buf, i):
    n = shift = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, i
        shift += 7


def go_build_info(path):
    """(Go version, [(module, version)]) from a Go program; None if it is not one, and False if it is one in the
    layout from before Go 1.18, which is not read. The file is read, never run. Go 1.18 and later write a 32-byte
    header (magic, pointer size, and a flags byte whose value 2 means "inline"), then the version string and the
    module info, each prefixed by its length."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        at = m.find(GO_BUILDINFO_MAGIC)
        if at == -1:
            return None
        while at != -1:  # the same bytes appear as a string literal in programs that read build info themselves
            if m[at + 14] in (4, 8) and m[at + 15] & 2:
                n, i = read_uvarint(m, at + 32)
                version = m[i:i + n].decode(errors="replace")
                if version.startswith("go"):
                    n, i = read_uvarint(m, i + n)
                    raw = m[i:i + n]
                    if len(raw) >= 33 and raw[-17] == ord("\n"):  # the module info sits between two 16-byte sentinels
                        raw = raw[16:-16]
                    modinfo = raw.decode(errors="replace")
                    break
            at = m.find(GO_BUILDINFO_MAGIC, at + 1)
        else:
            return False
    mods = []
    for line in modinfo.splitlines():
        parts = line.split("\t")
        if parts[0] in ("mod", "dep") and len(parts) >= 3:
            mods.append((parts[1], parts[2]))
        elif parts[0] == "=>" and len(parts) >= 3 and mods:  # a replace directive: the replacement is what was compiled
            mods[-1] = (parts[1], parts[2])
    return version.split()[0], mods


def path_executables():
    """Every .exe in the folders on PATH, outside the Windows folder, once per real file (WinGet links resolved)."""
    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    found = {}
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d or not os.path.isdir(d) or inside(os.path.abspath(d), windir):
            continue
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if e.name.lower().endswith(".exe"):
                real = os.path.realpath(e.path)
                found.setdefault(os.path.normcase(real), (e.name, real))
    return list(found.values())


def scan_go_binaries(deps):
    """Go-built programs on PATH (gh, lazygit, fzf, ...): their Go standard library and modules, checked against OSV.
    Needs no Go install. Unlike govulncheck it cannot tell whether the program calls the vulnerable code."""
    pk, programs, old_layout = defaultdict(set), [], []
    try:
        executables = path_executables()
    except Exception as e:  # an unreadable PATH entry must not stop the rest of the scan
        record("osv-go-binaries", "programs on PATH", False, None, repr(e))
        return
    for name, path in executables:
        try:
            if not 0 < os.path.getsize(path) < 400_000_000:
                continue
            info = go_build_info(path)
        except (OSError, ValueError, IndexError):
            continue
        if info is False:
            old_layout.append(name)
        if not info:
            continue
        go, mods = info
        programs.append({"program": name, "path": path, "go": go, "modules": len(mods)})
        pk[("stdlib", go[2:])].add(name)  # OSV names the Go standard library "stdlib", with versions like 1.27.1
        for mod, ver in mods:
            if ver.startswith("v"):  # "(devel)" and local paths have no published version
                pk[(mod, ver)].add(name)
    try:
        hits = osv_scan(pk, "Go") if pk else []
        out = save(deps, "osv__go-binaries.json", json.dumps({"ecosystem": "Go", "scope_note": "compiled into a program on PATH",
                                                              "programs": programs, "packages_checked": len(pk), "hits": hits}, indent=2))
        record("osv-go-binaries", "programs on PATH", True, out,
               f"{len(programs)} Go programs, {len(pk)} modules checked; reachability not analysed" +
               (f"; built before Go 1.18, not read: {', '.join(old_layout)}" if old_layout else ""))
    except Exception as e:
        record("osv-go-binaries", "programs on PATH", False, None, repr(e))


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    a = ap.parse_args()
    run_dir = a.run
    with open(os.path.join(run_dir, "run.json"), encoding="utf-8-sig") as f:
        cfg = json.load(f)
    with open(os.path.join(run_dir, "inventory.json"), encoding="utf-8-sig") as f:
        inv = json.load(f)
    not_lists = [k for k in LIST_FIELDS if not isinstance(inv.get(k, []), list)]
    if not_lists:
        sys.exit(f"inventory.json: {', '.join(not_lists)} should be lists. collect_inventory.ps1 must wrap each in @(...), "
                 "or PowerShell writes a one-element list as a bare value.")
    roots = cfg.get("projects_roots") or [cfg["projects_root"]]  # a run folder set up by v1.6 has one root
    for r in cfg.get("missing_roots") or []:
        record("projects-root", r, False, None, "this projects root does not exist now (an unplugged or unmapped drive?)")
    untrusted = cfg.get("untrusted_projects") or []

    def trusted(path, kind, folder=None):
        """False, with the reason recorded, when the path is in an untrusted folder, or when its folder (a solution's
        or a Go module's) contains one, since evaluating it would evaluate the untrusted projects too."""
        hit = next((u for u in untrusted if inside(path, u) or inside(u, folder or path)), None)
        if hit:
            record(kind, path, False, None, f"untrusted_projects lists {hit}: build files there are not evaluated")
        return not hit

    deps = os.path.join(run_dir, "deps")
    work = os.path.join(run_dir, "work")
    os.makedirs(deps, exist_ok=True)

    by_dir = defaultdict(set)
    for m in inv.get("manifests") or []:
        by_dir[os.path.dirname(m)].add(os.path.basename(m))

    solutions = [os.path.join(d, f) for d, fs in by_dir.items() for f in fs if f.endswith((".sln", ".slnx"))]
    # only solutions that will be scanned count below, so a project listed only in a skipped solution is scanned on its own
    solutions = [s for s in sorted(solutions) if trusted(s, "dotnet-vulnerable", os.path.dirname(s))]
    sln_text = {}
    for s in solutions:
        with open(s, encoding="utf-8-sig", errors="replace") as fh:
            sln_text[s] = fh.read().lower()

    def in_a_solution(csproj):
        """True when a solution in this folder or above lists the project; otherwise it is scanned on its own."""
        name = os.path.basename(csproj).lower()
        return any(csproj.lower().startswith(os.path.dirname(s).lower() + os.sep) and name in t for s, t in sln_text.items())

    dockerfiles = []
    pythons = installed_pythons(inv)

    for d, files in sorted(by_dir.items()):
        lower = {f.lower() for f in files}
        if "uv.lock" in lower:
            scan_uv(d, roots, deps)
        # resolving a manifest without a lockfile can build packages and use the indexes the repo names
        elif "pyproject.toml" in lower and trusted(os.path.join(d, "pyproject.toml"), "pip-audit"):
            scan_unlocked_python(os.path.join(d, "pyproject.toml"), roots, deps, work, pythons)
        for f in sorted(files):
            if re.match(r"requirements.*\.txt$", f, re.I) and trusted(os.path.join(d, f), "pip-audit"):
                scan_unlocked_python(os.path.join(d, f), roots, deps, work, pythons)
        if "package-lock.json" in lower:
            scan_npm(d, roots, deps)
        for f in sorted(files):
            if f.lower() in LOCKFILES:
                scan_lockfile(os.path.join(d, f), roots, deps)
        if "bun.lockb" in lower and "bun.lock" not in lower:
            record("osv-lockfile", d, False, None, "bun.lockb is Bun's binary lockfile format, which is not read; "
                                                   "Bun 1.2 and later write the text format, bun.lock")
        for f in files:
            if f.endswith(".csproj") and not in_a_solution(os.path.join(d, f)) and trusted(os.path.join(d, f), "dotnet-vulnerable", d):
                scan_dotnet(os.path.join(d, f), roots, deps)
        if "go.mod" in lower and trusted(d, "govulncheck"):  # ./... loads every package below, untrusted folders included
            scan_go(d, roots, deps)
        for f in sorted(files):  # Dockerfile, Dockerfile.cli, api.Dockerfile, ...
            if re.search(r"^dockerfile(\..+)?$|\.dockerfile$", f, re.I):
                with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
                    dockerfiles.append({"path": os.path.join(d, f),
                                        "from": [l.strip() for l in fh if l.strip().upper().startswith("FROM ")]})
        if "gemfile.lock" in lower:
            record("other-lockfile", d, False, None, "Gemfile.lock files are not scanned by this skill")

    for s in solutions:
        scan_dotnet(s, roots, deps)
    if inv.get("composer_global_lock"):
        scan_lockfile(inv["composer_global_lock"], roots, deps)
    scan_globals(inv, deps)
    scan_ai_clis(inv, deps)
    scan_go_binaries(deps)
    scan_runtime_releases(inv, deps)
    scan_repo_advisories(inv, deps)
    save(deps, "dockerfiles.json", json.dumps(dockerfiles, indent=2))
    save(deps, "package_index.json", json.dumps({eco: {n: {v: sorted(w) for v, w in vs.items()} for n, vs in names.items()}
                                                 for eco, names in INDEX.items()}, indent=1))

    with open(os.path.join(deps, "scan_status.json"), "w", encoding="utf-8") as f:
        json.dump({"skill_version": SKILL_VERSION, "scans": status}, f, indent=2)
    failed = [s for s in status if not s["ok"]]
    print(f"scans: {len(status)} run, {len(failed)} not completed")
    for s in failed:
        print(f"  NOT SCANNED  {s['kind']:<18} {s['target']}  {s['note'][:160]}")


if __name__ == "__main__":
    main()
