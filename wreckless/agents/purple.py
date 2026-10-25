"""Purple / Detective Fedora: threat-intel ingestion."""
import json
import urllib.parse
import urllib.request
from pathlib import Path

from wreckless import llm, ui
from wreckless.config import BENCHMARKS, Settings
from wreckless.kb import IntelDB

HYPOTHESIS_SYS = (
    "You are a vulnerability researcher. Given an advisory, reply with JSON only: "
    '{"attack_surface": str, "sink": str, "entry_point": str, "exploit_strategy": str}. '
    'If a list of repo files is given, also include "affected_file": the one path from that list '
    "most likely to contain the vulnerable code."
)
PROMPT_FIELDS = ("id", "ghsa_id", "severity", "package", "vulnerable_versions", "summary", "description",
                 "cwe", "affected_file", "affected_symbols", "entry_point", "kev")


def _fetch_live(cve: str, s: Settings) -> dict:
    host = "api.github.com"
    assert host in s.live_intel_hosts
    url = f"https://{host}/advisories?cve_id={urllib.parse.quote(cve)}"
    with urllib.request.urlopen(url, timeout=15) as r:
        adv = json.load(r)[0]
    return {"id": cve, "ghsa_id": adv["ghsa_id"], "severity": adv["severity"],
            "summary": adv["summary"], "description": adv["description"],
            "references": adv["references"]}


def ingest(cve: str, s: Settings, db: IntelDB | None = None, repo: Path | None = None) -> dict:
    """Curated benchmark bundle if there is one (it names the affected file), else the intel DB
    record the feeds stored. ``repo`` lets the LLM point Red at a file for feed-only advisories."""
    bundle = BENCHMARKS / cve / "advisory.json"
    stored = db.get(cve) if db else None
    if bundle.exists():
        intel = json.loads(bundle.read_text())
        if stored:
            intel["kev"] = bool(stored["kev"])
    elif stored:
        intel = {k: v for k, v in stored.items() if k not in ("key", "matched", "fetched")}
        intel["kev"] = bool(stored["kev"])
    else:
        raise KeyError(f"no intel for {cve}: not a benchmark bundle and not in the intel DB")
    if s.mode == "live" and bundle.exists():
        ui.say("purple", f"Live Watchdog: pulling {cve} from whitelisted feed {s.live_intel_hosts}")
        try:
            intel |= _fetch_live(cve, s)
        except Exception as e:
            ui.say("purple", f"live feed unavailable ({e}); using local cache")
    else:
        where = "local intel cache" if bundle.exists() else f"intel DB ({stored['sources']})"
        ui.say("purple", f"Air-Gapped Forensic: loading {cve} from {where}"
               if s.mode != "live" else f"loading {cve} from {where}")
    kev = " · \033[1;31mKNOWN EXPLOITED (CISA KEV)\033[0m" if intel.get("kev") else ""
    ui.detail("purple", f"{intel['id']} [{intel.get('severity') or '?'}] {intel.get('summary') or ''}{kev}")

    if s.use_llm and llm.reachable(s.red):
        client = llm.OpenAI(base_url=s.red.url, api_key="local", timeout=300)
        brief = {k: intel[k] for k in PROMPT_FIELDS if intel.get(k) not in (None, "", [])}
        brief["description"] = str(brief.get("description", ""))[:4000]
        if repo and not intel.get("affected_file"):
            brief["repo_files"] = sorted(str(p.relative_to(repo)) for p in repo.rglob("*.py")
                                         if ".git" not in p.parts)[:200]
        try:
            out = client.chat.completions.create(
                model=s.red.model, temperature=0, max_tokens=600,
                messages=[{"role": "system", "content": HYPOTHESIS_SYS},
                          {"role": "user", "content": json.dumps(brief)}])
            text = out.choices[0].message.content or ""
        except Exception as e:  # the hypothesis is optional; a dead model must not lose the item
            ui.say("purple", f"no hypothesis — LLM error: {type(e).__name__}: {str(e)[:200]}")
            return intel
        try:
            intel["hypothesis"] = json.loads(text[text.find("{"): text.rfind("}") + 1])
        except ValueError:
            intel["hypothesis"] = {"raw": text}
        guess = intel["hypothesis"].get("affected_file")
        if not intel.get("affected_file") and guess in brief.get("repo_files", []):
            intel["affected_file"] = guess
        ui.detail("purple", json.dumps(intel["hypothesis"], indent=1))
    return intel
