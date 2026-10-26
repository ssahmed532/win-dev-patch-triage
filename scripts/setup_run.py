# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Create the run folder, resolve the window and the previous run, and write RUN/run.json.

Usage: uv run setup_run.py [--window-hours N] [--dry-run]
       uv run setup_run.py --init --projects-root DIR [--projects-root DIR ...] (--artifact-url URL | --local-only) [...]
Prints the run folder path on the last line so the caller can pick it up.
Stops before creating anything if PowerShell 7 is missing, and notes the optional tools that are missing.
Exits with code 3 and a CONFIG_REQUIRED block when this machine has no valid configuration yet; nothing runs until
the operator's answers are saved with --init.
"""
import argparse
import ctypes
import json
import os
import re
import shutil
import string
import subprocess
import sys
from datetime import datetime, timedelta, timezone

sys.dont_write_bytecode = True  # the skill folder may be read-only or replaced by an update; write nothing into it
from skill_version import SKILL_VERSION  # noqa: E402

# `dotnet --version` below would otherwise run .NET's first-use setup, which creates a development HTTPS certificate
os.environ.update({"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
                   "DOTNET_NOLOGO": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})

SKILL_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HOSTNAME = (os.environ.get("COMPUTERNAME") or "").upper()
CONFIG_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "win-dev-patch-triage")
# One file per machine: %APPDATA% roams between machines on a domain profile, and each machine has its own projects and page
HOST_CONFIG = os.path.join(CONFIG_DIR, f"config-{HOSTNAME}.json")
LEGACY_CONFIG = os.path.join(CONFIG_DIR, "config.json")
LOCAL_CONFIG = os.path.join(SKILL_DIR, "config.local.json")
EXAMPLE_CONFIG = os.path.join(SKILL_DIR, "config.example.json")
REQUIRED = {"hostname": str, "projects_roots": list, "runs_root": str}
OPTIONAL = {"artifact_url": str, "local_only": bool, "window_hours": int, "timezone_label": str, "exclude_dirs": list,
            "risky_ports": list, "runtime_search_roots": list, "untrusted_projects": list}
ARTIFACT_URL = re.compile(r"^https://claude\.ai/(code/)?artifact/[A-Za-z0-9_-]+$")
MIN_DOTNET_SDK = (9, 0, 300)  # first SDK with `dotnet list package --vulnerable`
CONFIG_REQUIRED_EXIT = 3


def expand(path):
    return os.path.normpath(os.path.expandvars(os.path.expanduser(path)))


def read_json(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except ValueError as e:
        sys.exit(f"{path} is not valid JSON: {e}")


def read_old_json(path):
    """An older config to take answers from, or {} when it is missing or not valid JSON: it only supplies suggestions."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError):
        return {}


def root_problems(roots):
    """Roots that cannot be scanned as a set: one inside another scans the same projects twice, and two with the same
    folder name give their projects the same names, so one root's results would overwrite the other's."""
    problems = []
    for x in roots:
        for y in roots:
            if x != y and inside(x, y):
                problems.append(f"projects root '{x}' is inside '{y}'; list only '{y}'")
    names = [os.path.basename(r.rstrip("\\/")).lower() for r in roots]
    for n in sorted({n for n in names if names.count(n) > 1}):
        problems.append(f"several projects roots share the folder name '{n}'; projects are named after their root's "
                        "folder, so use roots with different folder names")
    return problems


def inside(path, folder):
    path, folder = os.path.normcase(path), os.path.normcase(folder).rstrip("\\/")
    return path == folder or path.startswith(folder + os.sep)


def config_problems(cfg):
    """Everything wrong with a config, as sentences; empty when it is complete for this machine.
    A projects root that is missing today (an unplugged drive) is not a problem as long as one root exists: the run
    reports it as not scanned."""
    problems = []
    if str(cfg.get("hostname") or "").upper() != HOSTNAME:
        problems.append(f"it was written for machine '{cfg.get('hostname') or 'unknown'}', and this machine is '{HOSTNAME}'")
    for key, typ in REQUIRED.items():
        if not isinstance(cfg.get(key), typ) or not cfg.get(key):
            problems.append(f"'{key}' is missing or not a {'list' if typ is list else typ.__name__}")
    for key, typ in OPTIONAL.items():
        if key in cfg and not isinstance(cfg[key], typ):
            problems.append(f"'{key}' should be a {typ.__name__}")
    roots = cfg.get("projects_roots") if isinstance(cfg.get("projects_roots"), list) else []
    if any(not isinstance(r, str) for r in roots):
        problems.append("every entry of projects_roots must be a folder path")
    elif roots:
        if not any(os.path.isdir(expand(r)) for r in roots):
            problems.append(f"none of the projects roots exists: {', '.join(roots)}")
        problems += root_problems([expand(r) for r in roots])
    url = cfg.get("artifact_url") or ""
    if url and not ARTIFACT_URL.match(url):
        problems.append(f"artifact_url '{url}' is not a claude.ai artifact link")
    if not url and cfg.get("local_only") is not True:
        problems.append("there is no artifact_url, and local_only is not set: choose a report page or local-only")
    return problems


def suggest_roots():
    """Folders whose subfolders are git work trees, with the count, so the operator can pick one or more roots."""
    def subdirs(d):
        try:
            return [e.path for e in os.scandir(d) if e.is_dir(follow_symlinks=False) and not e.name.startswith(("$", "."))
                    and e.name.lower() not in ("windows", "program files", "program files (x86)", "programdata", "appdata")]
        except OSError:
            return []
    bases = [os.path.expanduser("~")]
    if os.name == "nt":
        bases += [f"{d}:\\" for d in string.ascii_uppercase if ctypes.windll.kernel32.GetDriveTypeW(f"{d}:\\") == 3]  # fixed disks
    found = {}
    for base in bases:
        for cand in [base, *(c for child in subdirs(base) for c in [child, *subdirs(child)])]:
            n = sum(os.path.isdir(os.path.join(c, ".git")) for c in subdirs(cand))
            if n:
                found[os.path.normpath(cand)] = n
    return sorted(found.items(), key=lambda kv: -kv[1])


def require_config(reason, previous=None):
    """Print what the operator must supply, then stop: a run never starts on a guessed configuration."""
    example = read_json(EXAMPLE_CONFIG)
    tz = datetime.now().astimezone().tzname()
    exists = os.path.exists(HOST_CONFIG)
    print(f"CONFIG_REQUIRED: {reason}")
    print(f"machine: {HOSTNAME}")
    print(f"config file to {'replace' if exists else 'create'}: {HOST_CONFIG}")
    print("mandatory, from the operator:")
    print("  1. projects_roots: one or more folders that hold the git work trees in active use")
    print("  2. the report page: an existing claude.ai artifact link, a new page to create, or local-only (no page)")
    if previous:
        print(f"values in the old config ({previous['_file']}), to offer as answers:")
        for key in ("projects_root", "projects_roots", "artifact_url", "runs_root", "window_hours", "timezone_label"):
            if key in previous:
                print(f"  {key}: {previous[key]}")
    roots = suggest_roots()
    print("folders that hold git work trees on this machine (folder: repos):")
    for path, n in roots[:12] or [("none found", 0)]:
        print(f"  {path}: {n}" if n else f"  {path}")
    print("defaults the operator can accept or change:")
    print(f"  runs_root: {example['runs_root']}   window_hours: {example['window_hours']}   timezone_label: {tz}")
    print("  untrusted_projects: none (folders of third-party code whose build files must not be evaluated)")
    print("next: uv run setup_run.py --init" + (" --force" if exists else "") +
          " --projects-root <folder> [--projects-root <folder> ...] (--artifact-url <url> | --local-only)"
          " [--runs-root <folder>] [--window-hours N] [--timezone-label <label>] [--untrusted-project <folder> ...]")
    if exists:
        print("  options left out keep their values from the current file")
    sys.exit(CONFIG_REQUIRED_EXIT)


def load_config():
    """This machine's config, then the one next to SKILL.md. Anything missing or invalid stops the run."""
    for path in (HOST_CONFIG, LOCAL_CONFIG):
        if os.path.exists(path):
            cfg = read_json(path)
            if not isinstance(cfg, dict):
                sys.exit(f"{path} must hold a JSON object.")
            problems = config_problems(cfg)
            if problems:
                cfg["_file"] = path
                require_config(f"{path} is incomplete: " + "; ".join(problems), cfg)
            for key in sorted(set(cfg) - set(REQUIRED) - set(OPTIONAL)):
                print(f"note: {path}: '{key}' is not a setting this version reads; it is ignored.", file=sys.stderr)
            cfg["_config_file"] = path
            return cfg
    if os.path.exists(LEGACY_CONFIG):
        old = read_old_json(LEGACY_CONFIG)
        old["_file"] = LEGACY_CONFIG
        require_config(f"{LEGACY_CONFIG} is from before v1.7 and is not tied to this machine; confirm its values", old)
    require_config("this machine has no configuration yet")


def init_config(a):
    """Validate the operator's answers and write this machine's config. Starts no run.
    The projects roots and the report page are always given; every other option left out keeps its value from this
    machine's current config, then from a pre-v1.7 config.json, then from config.example.json."""
    roots = []
    for r in a.projects_root:
        p = expand(r)
        if not os.path.isdir(p):
            sys.exit(f"projects root '{r}' is not an existing folder.")
        if p.lower() not in (x.lower() for x in roots):
            roots.append(p)
    problems = root_problems(roots)
    if problems:
        sys.exit("; ".join(problems) + ".")
    if a.artifact_url and not ARTIFACT_URL.match(a.artifact_url):
        sys.exit(f"'{a.artifact_url}' is not a claude.ai artifact link (https://claude.ai/artifact/<id>).")
    for u in a.untrusted_project or []:  # a mistyped folder would silently leave the real one trusted
        if not os.path.isdir(expand(u)):
            sys.exit(f"untrusted project '{u}' is not an existing folder.")
    if os.path.exists(HOST_CONFIG) and not a.force:
        sys.exit(f"{HOST_CONFIG} already exists. Pass --force to replace it; the old file is kept as .bak.")
    example = read_json(EXAMPLE_CONFIG)
    prior = read_old_json(HOST_CONFIG) or read_old_json(LEGACY_CONFIG)

    def keep(key, given, typ):
        return given if given is not None else prior[key] if isinstance(prior.get(key), typ) else example[key]
    cfg = {
        "hostname": HOSTNAME,
        "projects_roots": roots,
        "runs_root": keep("runs_root", a.runs_root, str),
        "artifact_url": a.artifact_url or "",
        "local_only": a.local_only,
        "window_hours": keep("window_hours", a.window_hours, int),
        "timezone_label": keep("timezone_label", a.timezone_label, str) or datetime.now().astimezone().tzname(),
        "untrusted_projects": [] if a.clear_untrusted else keep(
            "untrusted_projects", [expand(u) for u in a.untrusted_project] if a.untrusted_project else None, list),
        **{k: keep(k, None, list) for k in ("exclude_dirs", "risky_ports", "runtime_search_roots")},
    }
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(HOST_CONFIG):
        shutil.copy2(HOST_CONFIG, HOST_CONFIG + ".bak")
    with open(HOST_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"wrote {HOST_CONFIG}")
    print(json.dumps(cfg, indent=2))


def previous_run(runs_root, current):
    if not os.path.isdir(runs_root):
        return None
    runs = sorted(
        d for d in os.listdir(runs_root)
        if d != os.path.basename(current) and os.path.exists(os.path.join(runs_root, d, "findings.json"))
    )
    return os.path.join(runs_root, runs[-1]) if runs else None


# tool -> what a run loses without it (scan_dependencies.py records the affected projects as NOT SCANNED)
OPTIONAL_TOOLS = {
    "gh": "severity and publish dates come from OSV only (sign in with `gh auth login` for the GitHub Advisory Database), "
          "and the PHP, Bun, Composer and pnpm repository advisories are read through GitHub's unauthenticated API",
    "npm": "npm projects and global npm packages are not audited",
    "dotnet": ".NET projects are not audited",
    "go": "Go projects are not audited (Go-built programs on PATH are still checked, from their embedded build info)",
}


def version_tuple(text):
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def check_tools():
    if not shutil.which("pwsh"):
        sys.exit("PowerShell 7 (pwsh) is not on PATH, and the inventory step needs it. "
                 "Install it with `winget install --id Microsoft.PowerShell`, then run again.")
    # `uv audit` is what scans uv projects; older uv builds do not have it
    probe = subprocess.run([shutil.which("uv") or "uv", "audit", "--help"], capture_output=True, text=True)
    if probe.returncode != 0:
        sys.exit("This uv has no `uv audit` command, which the dependency scan needs. "
                 "Upgrade uv (`uv self update`), then run again.")
    for tool, loss in OPTIONAL_TOOLS.items():
        if not shutil.which(tool):
            print(f"note: {tool} is not on PATH: {loss}.", file=sys.stderr)
    dotnet = shutil.which("dotnet")
    if dotnet:
        v = subprocess.run([dotnet, "--version"], capture_output=True, text=True).stdout.strip()
        if v and version_tuple(v) < MIN_DOTNET_SDK:
            print(f"note: .NET SDK {v} is older than {'.'.join(map(str, MIN_DOTNET_SDK))}, which is the first with "
                  "`dotnet list package --vulnerable`: .NET projects are not audited.", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-hours", type=int)
    ap.add_argument("--dry-run", action="store_true", help="write the report locally, do not publish")
    ap.add_argument("--init", action="store_true", help="save the operator's answers as this machine's config, then stop")
    ap.add_argument("--projects-root", action="append", help="with --init: a folder of git work trees; repeat for each")
    page = ap.add_mutually_exclusive_group()
    page.add_argument("--artifact-url", help="with --init: the claude.ai artifact link the report updates")
    page.add_argument("--local-only", action="store_true", help="with --init: write the report locally, never publish")
    ap.add_argument("--runs-root")
    ap.add_argument("--timezone-label")
    untrusted = ap.add_mutually_exclusive_group()
    untrusted.add_argument("--untrusted-project", action="append",
                           help="with --init: a folder whose build files are not evaluated; repeat for each")
    untrusted.add_argument("--clear-untrusted", action="store_true", help="with --init: trust every project again")
    ap.add_argument("--force", action="store_true", help="with --init: replace this machine's existing config")
    a = ap.parse_args()

    if a.init:
        if not a.projects_root or not (a.artifact_url or a.local_only):
            ap.error("--init needs at least one --projects-root, and --artifact-url or --local-only")
        init_config(a)
        return

    check_tools()
    cfg = load_config()
    print(f"config: {cfg['_config_file']}", file=sys.stderr)
    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone()  # the machine's time zone, so daylight saving time is handled
    window = a.window_hours or cfg.get("window_hours", 24)

    runs_root = expand(cfg["runs_root"])
    # a later run on the same day, or in the same minute, never reuses an earlier run's folder
    run_dir = next(d for d in (os.path.join(runs_root, now_local.strftime(f)) for f in ("%Y-%m-%d", "%Y-%m-%d-%H%M", "%Y-%m-%d-%H%M%S"))
                   if not os.path.exists(d))
    os.makedirs(os.path.join(run_dir, "raw"))
    os.makedirs(os.path.join(run_dir, "deps"))

    artifact_url = cfg.get("artifact_url") or ""
    run = {
        "skill_version": SKILL_VERSION,
        "config_file": cfg["_config_file"],
        "hostname": HOSTNAME,
        "started_utc": now_utc.isoformat(timespec="seconds"),
        "started_local": now_local.strftime("%Y-%m-%d %H:%M"),
        "timezone_label": cfg.get("timezone_label") or now_local.tzname(),
        "window_hours": window,
        "since_utc": (now_utc - timedelta(hours=window)).isoformat(timespec="seconds"),
        "recent_cutoff_utc": (now_utc - timedelta(hours=max(window, 72))).isoformat(timespec="seconds"),
        # all configured roots, so project names do not change while one is missing; the inventory skips missing ones.
        # A root that is missing today (an unplugged or unmapped drive) is reported as not scanned, not fatal.
        "projects_roots": [expand(r) for r in cfg["projects_roots"]],
        "missing_roots": [expand(r) for r in cfg["projects_roots"] if not os.path.isdir(expand(r))],
        "untrusted_projects": [expand(u) for u in cfg.get("untrusted_projects") or []],
        "exclude_dirs": cfg.get("exclude_dirs", []),
        "risky_ports": cfg.get("risky_ports", []),
        "runtime_search_roots": [expand(p) for p in cfg.get("runtime_search_roots") or ["%SystemDrive%\\"]],
        "artifact_url": artifact_url,
        "dry_run": a.dry_run or not artifact_url,
        "previous_run": previous_run(runs_root, run_dir),
        "run_dir": run_dir,
    }
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as f:
        json.dump(run, f, indent=2)

    print(json.dumps({k: run[k] for k in ("skill_version", "config_file", "window_hours", "since_utc", "dry_run", "previous_run")}))
    if not artifact_url:
        print("local_only is set in config: this run writes the report locally only.", file=sys.stderr)
    for r in run["missing_roots"]:
        print(f"note: projects root {r} does not exist now; its projects are not scanned this run.", file=sys.stderr)
    prev_json = os.path.join(run["previous_run"] or "", "run.json")
    if run["previous_run"] and os.path.exists(prev_json):
        with open(prev_json, encoding="utf-8-sig") as f:
            prev = json.load(f)
        prev_roots = prev.get("projects_roots") or [prev.get("projects_root")]  # runs before v1.7 had one root
        for key, old, new in (("config_file", prev.get("config_file"), run["config_file"]),
                              ("projects_roots", prev_roots, run["projects_roots"])):
            if old != new:
                print(f"note: {key} differs from the previous run ({old} -> {new}); "
                      "the delta may include changes caused by that.", file=sys.stderr)
    print(run_dir)


if __name__ == "__main__":
    main()
