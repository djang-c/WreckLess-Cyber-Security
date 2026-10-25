"""Purple's intel feeds: poll, normalise, match the dependency inventory, store in the IntelDB.

Feeds (live mode only; every host must be in Settings.live_intel_hosts):
  osv      api.osv.dev   /v1/querybatch: exact package@version matching, no key needed
  github   api.github.com /advisories?affects=pkg@version, token from GITHUB_TOKEN or `gh auth token`
  kev      www.cisa.gov  known-exploited list: flags matches so they jump the queue
Each feed fails independently; a dead feed is reported, never fatal.
"""
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from wreckless.config import Settings
from wreckless.kb import IntelDB

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_COMMIT = re.compile(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def load_inventory(path: Path) -> dict:
    inv = json.loads(path.read_text())
    return {"ecosystem": inv.get("ecosystem", "PyPI"), "packages": inv["packages"]}


def _get(url: str, s: Settings, data: dict | None = None, headers: dict | None = None,
         timeout: float = 20):
    host = urllib.parse.urlsplit(url).hostname
    if s.mode != "live" or host not in s.live_intel_hosts:
        raise PermissionError(f"{host} not allowed in {s.mode} mode")
    req = urllib.request.Request(url, json.dumps(data).encode() if data is not None else None,
                                 {"Accept": "application/json", "User-Agent": "wreckless-purple",
                                  **({"Content-Type": "application/json"} if data is not None else {}),
                                  **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def github_token() -> str | None:
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _commits(refs: list[str]) -> list[str]:
    return list(dict.fromkeys(m.group(1) for r in refs for m in [_COMMIT.search(r)] if m))


def normalize_osv(v: dict, package: str) -> dict:
    aliases = [a for a in v.get("aliases", []) if a != v["id"]]
    cve = next((a for a in [v["id"], *aliases] if _CVE.match(a)), None)
    ghsa = next((a for a in [v["id"], *aliases] if a.startswith("GHSA-")), None)
    refs = [r["url"] for r in v.get("references", [])]
    ranges = []
    for aff in v.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rg in aff.get("ranges", []):
            if rg.get("type") == "GIT":     # commit ranges are not package versions
                continue
            for ev in rg.get("events", []):
                if "fixed" in ev:
                    ranges.append(f"< {ev['fixed']}")
                elif "last_affected" in ev:
                    ranges.append(f"<= {ev['last_affected']}")
    db = v.get("database_specific", {})
    return {"id": cve or v["id"], "cve": cve, "ghsa_id": ghsa, "aliases": aliases, "package": package,
            "vulnerable_versions": ", ".join(dict.fromkeys(ranges)) or None,
            "severity": (db.get("severity") or "").lower() or None,
            "summary": v.get("summary") or (v.get("details") or "")[:160],
            "description": v.get("details") or "", "cwe": db.get("cwe_ids", []),
            "references": refs, "fix_commits": _commits(refs),
            "published": v.get("published"), "modified": v.get("modified")}


def normalize_github(a: dict, package: str) -> dict:
    refs = a.get("references") or []
    vulns = [x for x in a.get("vulnerabilities", [])
             if (x.get("package") or {}).get("name", "").lower() == package.lower()]
    cve = a.get("cve_id")
    return {"id": cve or a["ghsa_id"], "cve": cve, "ghsa_id": a["ghsa_id"],
            "aliases": [i["value"] for i in a.get("identifiers", []) if i["value"] != (cve or a["ghsa_id"])],
            "package": package,
            "vulnerable_versions": ", ".join(x["vulnerable_version_range"] for x in vulns
                                             if x.get("vulnerable_version_range")) or None,
            "severity": a.get("severity"), "summary": a.get("summary"),
            "description": a.get("description") or "", "cwe": [c["cwe_id"] for c in a.get("cwes", [])],
            "references": refs, "fix_commits": _commits(refs),
            "published": a.get("published_at"), "modified": a.get("updated_at")}


def poll_osv(db: IntelDB, inv: dict, s: Settings) -> list[tuple[str, dict]]:
    pkgs = list(inv["packages"].items())
    res = _get("https://api.osv.dev/v1/querybatch", s, data={"queries": [
        {"package": {"name": n, "ecosystem": inv["ecosystem"]}, "version": ver} for n, ver in pkgs]})
    out = []
    for (name, _), r in zip(pkgs, res.get("results", [])):
        for hit in r.get("vulns", []):
            known = db.get(hit["id"])
            if known and (known["modified"] or "") >= hit.get("modified", "") and known["matched"]:
                continue  # unchanged since last poll: skip the detail fetch
            out.append((name, normalize_osv(_get(f"https://api.osv.dev/v1/vulns/{hit['id']}", s), name)))
    return out


def poll_github(db: IntelDB, inv: dict, s: Settings) -> list[tuple[str, dict]]:
    token = github_token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    out = []
    for name, ver in inv["packages"].items():
        q = urllib.parse.urlencode({"ecosystem": "pip", "affects": f"{name}@{ver}", "per_page": 100})
        for a in _get(f"https://api.github.com/advisories?{q}", s, headers=headers):
            if not a.get("withdrawn_at"):
                out.append((name, normalize_github(a, name)))
    return out


def poll_kev(s: Settings) -> set[str]:
    return {v["cveID"] for v in _get(KEV_URL, s, timeout=60).get("vulnerabilities", [])}


@dataclass
class SyncReport:
    new: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    kev: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def line(self) -> str:
        err = f" · feed errors: {', '.join(f'{k}: {v}' for k, v in self.errors.items())}" if self.errors else ""
        return (f"{len(self.new)} new · {len(self.updated)} updated · {len(self.kev)} newly KEV-flagged"
                + err)


def sync(db: IntelDB, inv: dict, s: Settings, feeds: tuple = ("osv", "github", "kev")) -> SyncReport:
    """One poll of every feed. Everything a feed returns already matched the inventory server-side
    (OSV and GitHub both match package@version), so it is stored as matched."""
    rep = SyncReport()
    for feed, poll in (("osv", poll_osv), ("github", poll_github)):
        if feed not in feeds:
            continue
        try:
            for _, adv in poll(db, inv, s):
                status = db.upsert(adv, feed, matched=True)
                if status == "new":
                    rep.new.append(adv["id"])
                elif status == "updated" and adv["id"] not in rep.new:
                    rep.updated.append(adv["id"])
            db.set_cursor(feed, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))  # last good poll
        except Exception as e:
            rep.errors[feed] = f"{type(e).__name__}: {e}"[:120]
    if "kev" in feeds:
        try:
            rep.kev = db.mark_kev(poll_kev(s))
        except Exception as e:
            rep.errors["kev"] = f"{type(e).__name__}: {e}"[:120]
    rep.updated = [k for k in dict.fromkeys(rep.updated) if k not in rep.new]
    return rep
