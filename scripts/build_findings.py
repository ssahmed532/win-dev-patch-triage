# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Normalise every scanner output in RUN/deps into one findings list, fill in severity and publish
dates from the GitHub Advisory Database (OSV as fallback), compare with the previous run, and print a digest.

Usage: uv run build_findings.py --run RUN
Writes RUN/findings.json. The digest on stdout is what the triage step reads; the JSON is what the
next run compares against.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.dont_write_bytecode = True  # the skill folder may be read-only or replaced by an update; write nothing into it
from skill_version import SKILL_VERSION  # noqa: E402

RANK = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}
# IDs an advisory database can look up; the release-feed findings use made-up IDs such as node-26.12.1-security-release
ADVISORY_ID = re.compile(r"(GHSA|CVE|PYSEC|GO|RUSTSEC|MAL|OSV)-")
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def norm_sev(s):
    s = (s or "").lower()
    return {"medium": "moderate", "important": "high"}.get(s, s if s in RANK else "unknown")


def vkey(v):
    """Sortable key for loose version strings like 2026.10.19, 10.0.13, go1.27.3, 13.0.0rc1."""
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


def choose_fix(installed, candidates):
    """The smallest fixed version above the installed one, preferring the same major line."""
    cands = sorted({c for c in candidates if c}, key=vkey)
    above = [c for c in cands if vkey(c) > vkey(installed)]
    same = [c for c in above if vkey(c)[:1] == vkey(installed)[:1]]
    return (same or above or cands or [None])[0]


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def project_of(target, roots):
    """The target relative to the projects root that holds it; with several roots, prefixed by that root's folder name."""
    for root in roots:
        try:
            rel = os.path.relpath(target, root)
        except ValueError:  # another drive
            continue
        if not rel.startswith(".."):
            return rel if len(roots) == 1 else os.path.join(os.path.basename(root.rstrip("\\/")) or root, rel)
    return target


# ---------- advisory lookups (cached per run) ----------

class Advisories:
    def __init__(self, cache_file):
        self.file = cache_file
        self.cache = load(cache_file) if os.path.exists(cache_file) else {}
        self.gh = shutil.which("gh")

    def _gh(self, ghsa):
        """One advisory from the GitHub Advisory Database, or None so the caller falls back to OSV."""
        try:
            p = subprocess.run([self.gh, "api", f"/advisories/{ghsa}"], capture_output=True, text=True, encoding="utf-8", timeout=60)
            if p.returncode != 0:
                return None
            a = json.loads(p.stdout)
        except (subprocess.TimeoutExpired, OSError, ValueError):  # a timeout, a missing gh, or a non-JSON reply
            return None
        cvss = (a.get("cvss_severities") or {})
        score = ((cvss.get("cvss_v4") or {}).get("score") or (cvss.get("cvss_v3") or {}).get("score") or None)
        return {"severity": norm_sev(a.get("severity")), "cvss": score, "published": a.get("published_at"), "type": a.get("type"),
                "cve": a.get("cve_id"), "summary": a.get("summary"), "url": a.get("html_url"),
                "patched": [{"package": (v.get("package") or {}).get("name"), "fixed": v.get("first_patched_version")}
                            for v in a.get("vulnerabilities") or []]}

    def _osv(self, vid):
        try:
            with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=60) as r:
                o = json.load(r)
        except Exception:
            return None
        fixed = [e["fixed"] for af in o.get("affected", []) for rg in af.get("ranges", []) for e in rg.get("events", []) if "fixed" in e]
        return {"severity": norm_sev((o.get("database_specific") or {}).get("severity")), "cvss": None,
                "published": o.get("published"), "cve": next((x for x in o.get("aliases", []) if x.startswith("CVE-")), None),
                "summary": o.get("summary"), "url": f"https://osv.dev/vulnerability/{vid}",
                "patched": [{"package": None, "fixed": f} for f in fixed]}

    def get(self, vid):
        if vid not in self.cache:
            rec = self._gh(vid) if (self.gh and vid.startswith("GHSA-")) else None
            self.cache[vid] = rec or self._osv(vid)
        return self.cache[vid]

    def prefetch(self, ids):
        todo = sorted({i for i in ids if i and i not in self.cache})
        with ThreadPoolExecutor(max_workers=8) as ex:
            for vid, rec in zip(todo, ex.map(lambda i: (self._gh(i) if (self.gh and i.startswith("GHSA-")) else None) or self._osv(i), todo)):
                self.cache[vid] = rec

    def save(self):
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.cache, f, indent=1)


# ---------- normalisers: each yields raw finding dicts ----------

def from_uv(doc, project):
    for v in doc.get("vulnerabilities", []):
        ids = [v.get("id")] + list(v.get("aliases") or [])
        yield {"ecosystem": "pypi", "project": project, "package": v["dependency"]["name"], "installed": v["dependency"]["version"],
               "ids": ids, "title": v.get("summary"), "fixed_candidates": v.get("fix_versions") or [],
               "published": v.get("published"), "url": v.get("link")}


def from_pip_audit(doc, project):
    for dep in doc.get("dependencies", []):
        for v in dep.get("vulns", []) or []:
            yield {"ecosystem": "pypi", "project": project, "package": dep["name"], "installed": dep.get("version"),
                   "ids": [v.get("id")] + list(v.get("aliases") or []), "title": (v.get("description") or "")[:200],
                   "fixed_candidates": v.get("fix_versions") or []}


def from_npm(doc, project, lock):
    """npm audit reports the vulnerable *range*; the installed version comes from package-lock.json."""
    packages = (lock or {}).get("packages", {})
    for name, entry in (doc.get("vulnerabilities") or {}).items():
        nodes = entry.get("nodes") or []
        installed = next((packages[n]["version"] for n in nodes if n in packages and "version" in packages[n]), None)
        for via in entry.get("via", []):
            if isinstance(via, str):  # a pointer to another entry; that entry is counted itself
                continue
            ghsa = (via.get("url") or "").rstrip("/").split("/")[-1]
            yield {"ecosystem": "npm", "project": project, "package": via.get("name") or name,
                   "installed": installed or entry.get("range"), "installed_is_range": not installed,
                   "ids": [ghsa], "title": via.get("title"), "severity": via.get("severity"),
                   "cvss": (via.get("cvss") or {}).get("score") or None, "url": via.get("url"),
                   "fix_note": "npm audit fix" if entry.get("fixAvailable") is True else
                   (f"{entry['fixAvailable'].get('name')}@{entry['fixAvailable'].get('version')}" if isinstance(entry.get("fixAvailable"), dict) else None)}


def from_dotnet(doc, roots):
    for pr in doc.get("projects", []):
        project = project_of(pr.get("path", ""), roots)
        for fw in pr.get("frameworks", []) or []:
            for kind in ("topLevelPackages", "transitivePackages"):
                for pk in fw.get(kind, []) or []:
                    for v in pk.get("vulnerabilities", []) or []:
                        ghsa = (v.get("advisoryurl") or "").rstrip("/").split("/")[-1]
                        yield {"ecosystem": "nuget", "project": project, "package": pk["id"], "installed": pk.get("resolvedVersion"),
                               "ids": [ghsa], "severity": v.get("severity"), "url": v.get("advisoryurl"),
                               "scope_note": "transitive" if kind == "transitivePackages" else "direct"}


GO_SCOPE = {"reachable": "reachable from your code", "imported": "imported, not called",
            "required": "in a required module, not imported"}


def from_go(doc, project):
    for v in doc.get("vulns", []):
        for found, fixed in zip(v.get("found") or [""], v.get("fixed") or [""]):
            pkg, _, inst = found.partition("@")
            yield {"ecosystem": "go", "project": project, "package": pkg, "installed": inst, "ids": [v["id"]],
                   "title": v.get("title"), "fixed_candidates": [fixed.partition("@")[2]],
                   "scope_note": GO_SCOPE.get(v.get("scope"), v.get("scope"))}


OSV_ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "Go": "go", "Packagist": "composer"}


def from_osv_hits(doc, label, project=None):
    """OSV results saved by scan_dependencies.py. With a project (a Cargo.lock), every hit belongs to it; otherwise each
    hit is listed under the global install or program that bundles it."""
    for h in doc.get("hits", []):
        o = h.get("osv") or {}
        fixed = [e["fixed"] for af in o.get("affected", []) if (af.get("package") or {}).get("name") == h["name"]
                 for rg in af.get("ranges", []) for e in rg.get("events", []) if "fixed" in e]
        for owner in [project] if project else h.get("owners") or [label]:
            yield {"ecosystem": OSV_ECOSYSTEMS[doc["ecosystem"]], "project": project or f"{label}: {owner}",
                   "package": h["name"], "installed": h["version"], "ids": [h["id"]] + list(o.get("aliases") or []),
                   "title": o.get("summary"), "severity": (o.get("database_specific") or {}).get("severity"),
                   "published": o.get("published"), "fixed_candidates": fixed,
                   "scope_note": doc.get("scope_note", "bundled in a global install")}


def from_runtime(doc):
    """Node.js, PHP, Bun, Composer and pnpm copies: vendor release-feed hits and GitHub repository advisories."""
    for h in doc.get("hits", []):
        yield {"ecosystem": "runtime", "project": f"{h['product']}: {h['copy']}", "package": h["product"],
               "installed": h["installed"], "ids": h["ids"], "title": h.get("title"), "severity": h.get("severity"),
               "cvss": h.get("cvss"), "published": h.get("published"), "fixed_candidates": h.get("fixed") or [],
               "url": h.get("url")}


def kev_catalog():
    """{CVE: date added} from CISA's Known Exploited Vulnerabilities catalog, or None when it cannot be read."""
    try:
        with urllib.request.urlopen(KEV_FEED, timeout=120) as r:
            return {v["cveID"]: v["dateAdded"] for v in json.load(r)["vulnerabilities"]}
    except Exception:
        return None


def inventory_delta(old, new):
    """Lines describing version changes between two inventory.json files: runtimes, browsers, OS, apps, tools, WSL."""
    # a field only one run has (for example after a skill upgrade) would show every entry as added; skip it
    shared = set(old) & set(new)

    def flat(inv):
        inv = {k: v for k, v in inv.items() if k in shared}
        d = {}
        for r in inv.get("runtimes") or []:
            if r.get("version"):
                d[f"runtime {r['name']}"] = r["version"]
        for b in inv.get("browsers") or []:
            d[f"browser {os.path.basename(b['path'])}"] = b["version"]
        os_ = inv.get("os") or {}
        d["os build"] = os_.get("build")
        for a in inv.get("installed_apps") or []:
            d.setdefault(f"app {a['name']}", a["version"])
        for p in inv.get("uv_pythons") or []:
            d[f"uv python {p}"] = "installed"
        for t in inv.get("uv_tools") or []:
            d[f"uv tool {t['name']}"] = t["version"]
        for k, v in ((inv.get("npm_global") or {}).get("dependencies") or {}).items():
            d[f"npm global {k}"] = v.get("version")
        for line in (inv.get("dotnet") or {}).get("runtimes") or []:
            d[f"dotnet {line.split(' [')[0]}"] = "installed"
        for line in (inv.get("dotnet") or {}).get("sdks") or []:
            d[f"dotnet sdk {line.split(' [')[0]}"] = "installed"
        for c in inv.get("ai_clis") or []:
            d[f"ai cli {c['name']} ({c['method']}) {c['path']}"] = c.get("version")
        for c in inv.get("runtime_copies") or []:
            d[f"{c['name']} copy {c['path']}"] = c.get("version")
        for p in inv.get("ai_apps") or []:
            d[f"ai app {p['name']} ({p['source']})"] = p.get("version")
        for w in inv.get("wsl") or []:
            for kp in w.get("key_packages") or []:
                name, _, ver = kp.partition(" ")
                d[f"wsl {w['distro']} {name}"] = ver
        return {k: v for k, v in d.items() if v}
    a, b = flat(old), flat(new)
    lines = []
    for k in sorted(set(a) | set(b)):
        if k not in a:
            lines.append(f"  added    {k} {b[k] if b[k] != 'installed' else ''}".rstrip())
        elif k not in b:
            lines.append(f"  removed  {k} {a[k] if a[k] != 'installed' else ''}".rstrip())
        elif a[k] != b[k]:
            lines.append(f"  changed  {k}: {a[k]} -> {b[k]}")
    return lines


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    a = ap.parse_args()
    run_dir = a.run
    cfg = load(os.path.join(run_dir, "run.json"))
    roots = cfg.get("projects_roots") or [cfg["projects_root"]]  # a run folder set up by v1.6 has one root
    deps = os.path.join(run_dir, "deps")
    status = load(os.path.join(deps, "scan_status.json"))["scans"]

    raw = []
    for s in status:
        if not s["ok"] or not s.get("output"):
            continue
        path = os.path.join(run_dir, s["output"])
        doc = load(path)
        project = project_of(s["target"], roots)
        kind = s["kind"]
        if kind == "uv-audit":
            raw += from_uv(doc, project)
        elif kind == "pip-audit":
            raw += from_pip_audit(doc, project)
        elif kind == "npm-audit":
            lock_path = os.path.join(s["target"], "package-lock.json")
            raw += from_npm(doc, project, load(lock_path) if os.path.exists(lock_path) else None)
        elif kind == "dotnet-vulnerable":
            raw += from_dotnet(doc, roots)
        elif kind == "govulncheck":
            raw += from_go(doc, project)
        elif kind == "osv-lockfile":
            raw += from_osv_hits(doc, kind[4:], project)
        elif kind.startswith("osv-"):
            raw += from_osv_hits(doc, kind[4:])
        elif kind in ("runtime-releases", "repo-advisories"):
            raw += from_runtime(doc)

    def lookup_id(ids):
        ids = [i for i in ids if i]
        return next((i for i in ids if i.startswith("GHSA-")), ids[0] if ids and ADVISORY_ID.match(ids[0]) else None)

    adv = Advisories(os.path.join(run_dir, "advisories_cache.json"))
    prev_cache = os.path.join(cfg.get("previous_run") or "", "advisories_cache.json")
    if cfg.get("previous_run") and os.path.exists(prev_cache):  # advisories rarely change; saves most of the lookups
        adv.cache = {**load(prev_cache), **adv.cache}
    adv.prefetch(lookup_id(r["ids"]) for r in raw)
    kev = kev_catalog()

    findings = {}
    for r in raw:
        ids = [i for i in r["ids"] if i]
        lookup = lookup_id(ids)
        info = adv.get(lookup) if lookup else None
        info = info or {}
        cve = next((i for i in ids if i.startswith("CVE-")), None) or info.get("cve")
        key_id = cve or lookup or (ids[0] if ids else None)  # a release-feed finding has its own ID
        patched = [p["fixed"] for p in info.get("patched", []) if p.get("fixed") and p.get("package") in (None, r["package"])]
        # for a bare range such as "8.0.0 - 8.1.5", its upper bound stands in for the installed version
        installed = r.get("installed") or ""
        if r.get("installed_is_range"):
            installed = (re.findall(r"\d+(?:\.\d+)+", installed) or [""])[-1]
        fix = choose_fix(installed, (r.get("fixed_candidates") or []) + patched)
        f = {
            "ecosystem": r["ecosystem"], "project": r["project"], "package": r["package"], "installed": r.get("installed"),
            "advisory": key_id, "ids": sorted(set(ids + ([cve] if cve else []))),
            "severity": norm_sev(r.get("severity") or info.get("severity")),
            "cvss": r.get("cvss") or info.get("cvss"), "title": r.get("title") or info.get("summary"),
            "published": r.get("published") or info.get("published"), "fixed": fix or r.get("fix_note"),
            "url": info.get("url") or r.get("url"), "scope_note": r.get("scope_note"),
            # an installed malicious version: OSV lists those under MAL- IDs, GitHub as advisories of type malware
            "malicious": any(i.startswith("MAL-") for i in ids) or info.get("type") == "malware",
            "kev": next((kev[i] for i in ids + [cve] if i in (kev or {})), None),  # date CISA added it to KEV
        }
        k = "|".join([f["ecosystem"], f["project"], f["package"], str(f["installed"]), str(key_id)])
        old = findings.get(k)
        if old:  # two records (GHSA and PYSEC) for the same flaw: keep the worse severity and the earlier date
            old["severity"] = max(f["severity"], old["severity"], key=RANK.get)
            old["malicious"], old["kev"] = old["malicious"] or f["malicious"], old["kev"] or f["kev"]
            if f["published"] and (not old["published"] or f["published"] < old["published"]):
                old["published"] = f["published"]
        else:
            findings[k] = f
    adv.save()

    # ---- compare with the previous run
    prev_keys, resolved = set(), []
    if cfg.get("previous_run") and os.path.exists(os.path.join(cfg["previous_run"], "findings.json")):
        prev = load(os.path.join(cfg["previous_run"], "findings.json"))
        prev_map = {x["key"]: x for x in prev.get("findings", [])}
        prev_keys = set(prev_map)
        resolved = [prev_map[k] for k in prev_keys - set(findings)]
    for k, f in findings.items():
        f["key"] = k
        f["delta"] = ("still_open" if k in prev_keys else "new") if cfg.get("previous_run") else "first_run"
        f["in_window"] = bool(f["published"] and f["published"] >= cfg["since_utc"][:19])
        f["recent"] = bool(f["published"] and f["published"] >= cfg["recent_cutoff_utc"][:19])

    out = {"skill_version": SKILL_VERSION, "generated_from": run_dir, "since_utc": cfg["since_utc"],
           "findings": sorted(findings.values(), key=lambda x: (-RANK[x["severity"]], x["project"], x["package"])),
           "resolved_since_previous": resolved, "not_scanned": [s for s in status if not s["ok"]], "kev_checked": kev is not None}
    with open(os.path.join(run_dir, "findings.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    # ---- digest (times in the configured zone)
    tz = cfg.get("timezone_label") or "local time"

    def local(ts):
        if not ts:
            return "not stated"
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:  # advisory dates without a zone are UTC
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%d %b %H:%M")

    fl = out["findings"]
    sev = defaultdict(int)
    for f in fl:
        sev[f["severity"]] += 1
    print(f"findings: {len(fl)} unique advisories  " + "  ".join(f"{k}={sev[k]}" for k in RANK if sev[k]) + f"   (times in {tz})")
    if cfg.get("previous_run"):
        print(f"delta vs {os.path.basename(cfg['previous_run'])}: new={sum(f['delta'] == 'new' for f in fl)} "
              f"still_open={sum(f['delta'] == 'still_open' for f in fl)} resolved={len(resolved)}")

    groups = defaultdict(list)
    for f in fl:
        groups[(f["ecosystem"], f["project"], f["package"], f["installed"])].append(f)
    print("\nPER PACKAGE, worst first: eco | project | package installed -> minimum fix | advisories (crit/high/mod/low) "
          "| in window / last 72h | newest | top advisories")
    rows = []
    for (eco, proj, pkg, inst), g in groups.items():
        g = sorted(g, key=lambda x: (-RANK[x["severity"]], -(x["cvss"] or 0)))
        fixes = [x["fixed"] for x in g if x["fixed"]]
        fix = max(fixes, key=vkey) if fixes and all(re.search(r"\d", x) for x in fixes) else (fixes[0] if fixes else "not stated")
        counts = "/".join(str(sum(x["severity"] == s for x in g)) for s in ("critical", "high", "moderate", "low"))
        top = "; ".join(f"{x['advisory']} {x['severity']}{' ' + str(x['cvss']) if x['cvss'] else ''}" for x in g[:3])
        scope = {x["scope_note"] for x in g if x.get("scope_note")}
        rows.append((RANK[g[0]["severity"]], sum(x["in_window"] for x in g), eco, proj, pkg, inst, fix, counts,
                     sum(x["recent"] for x in g), local(max(x["published"] or "" for x in g) or None), top,
                     f" [{', '.join(sorted(scope))}]" if scope else ""))
    for r in sorted(rows, key=lambda r: (-r[0], -r[1], r[3])):
        print(f"  {r[2]:<6}| {r[3]} | {r[4]} {r[5]} -> {r[6]} | {r[7]} | {r[1]} / {r[8]} | {r[9]} | {r[10]}{r[11]}")

    def listing(title, items):
        print(f"\n{title}")
        for f in items:
            print(f"  {f['severity']:<9}{f['ecosystem']:<9}{f['project']} | {f['package']} {f['installed']} -> {f['fixed']} | "
                  f"{f['advisory']}{' CVSS ' + str(f['cvss']) if f['cvss'] else ''} | {local(f['published'])} | {(f['title'] or '')[:90]}")
    listing(f"IN WINDOW (published since {local(cfg['since_utc'])})", [f for f in fl if f["in_window"]])
    listing("LAST 72 HOURS, outside the window (High and Critical)",
            [f for f in fl if f["recent"] and not f["in_window"] and RANK[f["severity"]] >= 3])
    listing("MALICIOUS PACKAGES (an installed version listed as malware: a possible compromise of this machine)",
            [f for f in fl if f["malicious"]])
    if kev is None:
        print(f"\nKNOWN EXPLOITED: the CISA KEV catalog could not be read ({KEV_FEED}); exploitation status comes from the research only")
    else:
        listing("KNOWN EXPLOITED (in the CISA KEV catalog)", [f for f in fl if f["kev"]])

    if resolved:
        print("\nRESOLVED SINCE PREVIOUS RUN")
        for f in resolved:
            print(f"  {f['ecosystem']:<9}{f['project']} | {f['package']} {f['installed']} | {f['advisory']}")

    # machine-level changes (apps, runtimes, OS) are not findings, so compare the two inventories directly
    if cfg.get("previous_run") and os.path.exists(os.path.join(cfg["previous_run"], "inventory.json")):
        changes = inventory_delta(load(os.path.join(cfg["previous_run"], "inventory.json")), load(os.path.join(run_dir, "inventory.json")))
        print(f"\nINSTALLED-SOFTWARE CHANGES SINCE PREVIOUS RUN ({len(changes)})")
        for c in changes or ["  none"]:
            print(c)

    # no scanner reports these: an old copy left next to a new one, and a command whose user-folder copy runs instead of the system one
    inv = load(os.path.join(run_dir, "inventory.json"))
    dup_apps = inv.get("duplicate_apps") or []
    dup_cmds = [r for r in inv.get("runtimes") or [] if len(r.get("all_paths") or []) > 1]
    if dup_apps or dup_cmds:
        print("\nDUPLICATE INSTALLS (an old copy stays exploitable until it is removed)")
        for d in dup_apps:
            print(f"  app      {' | '.join(d['versions'])}")
        for r in dup_cmds:
            flag = "  [SHADOWS A SYSTEM COPY: a user-writable folder comes first on PATH]" if r.get("shadows_system_copy") else ""
            print(f"  command  {r['name']}: {' | '.join(r['all_paths'])} (the first one runs){flag}")

    copies = inv.get("runtime_copies") or []
    if copies:
        print("\nNODE.JS, PHP AND BUN COPIES (each is updated on its own; findings are in the rows above, under runtime)")
        for c in copies:
            print(f"  {c['name']:<5}{c.get('version') or 'version not read'} ({c['source']}) {c['path']}")

    # the desktop apps have no advisory feed a scanner can query, so the research agent checks them against the vendor;
    # winget's offer is a hint that a newer build exists, not proof that the installed one is vulnerable
    ai_apps, ai_clis = inv.get("ai_apps") or [], inv.get("ai_clis") or []
    if ai_apps or ai_clis or inv.get("ai_apps_error"):
        print("\nAI AGENT APPS AND CLIS (every copy; OSV hits for the CLIs are in the rows above, under ai-clis, npm-global or bun-global)")
        for p in ai_apps:
            print(f"  app  {p['name']} {p['version']} ({p['source']}{', package ' + p['package'] if p.get('package') else ''})"
                  f"{' | winget offers ' + p['winget_available'] if p.get('winget_available') else ''}")
        for c in ai_clis:
            print(f"  cli  {c['name']} {c.get('version') or 'version not read'} ({c['method']}) {c['path']}"
                  f"{' | winget offers ' + c['winget_available'] if c.get('winget_available') else ''}")
        if inv.get("ai_apps_error"):
            print(f"  {inv['ai_apps_error'][:200]}")

    if out["not_scanned"]:
        print("\nNOT SCANNED")
        for s in out["not_scanned"]:
            print(f"  {s['kind']:<18} {s['target']}  {s['note'][:160]}")
    notes = [s for s in status if s["ok"] and s.get("note")]
    if notes:
        print("\nSCAN NOTES (scanned, with a caveat)")
        for s in notes:
            print(f"  {s['kind']:<18} {s['target']}  {s['note'][:160]}")


if __name__ == "__main__":
    main()
