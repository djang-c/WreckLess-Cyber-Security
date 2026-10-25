"""Purple / Detective Fedora: threat-intel ingestion."""
import json
import urllib.parse
import urllib.request

from wreckless import llm, ui
from wreckless.config import BENCHMARKS, Settings

HYPOTHESIS_SYS = (
    "You are a vulnerability researcher. Given an advisory, reply with JSON only: "
    '{"attack_surface": str, "sink": str, "entry_point": str, "exploit_strategy": str}'
)


def _fetch_live(cve: str, s: Settings) -> dict:
    host = "api.github.com"
    assert host in s.live_intel_hosts
    url = f"https://{host}/advisories?cve_id={urllib.parse.quote(cve)}"
    with urllib.request.urlopen(url, timeout=15) as r:
        adv = json.load(r)[0]
    return {"id": cve, "ghsa_id": adv["ghsa_id"], "severity": adv["severity"],
            "summary": adv["summary"], "description": adv["description"],
            "references": adv["references"]}


def ingest(cve: str, s: Settings) -> dict:
    cached = json.loads((BENCHMARKS / cve / "advisory.json").read_text())
    if s.mode == "live":
        ui.say("purple", f"Live Watchdog: pulling {cve} from whitelisted feed {s.live_intel_hosts}")
        try:
            cached |= _fetch_live(cve, s)
        except Exception as e:
            ui.say("purple", f"live feed unavailable ({e}); using local cache")
    else:
        ui.say("purple", f"Air-Gapped Forensic: loading {cve} from local intel cache")
    ui.detail("purple", f"{cached['id']} [{cached['severity']}] {cached['summary']}")

    if s.use_llm and llm.reachable(s.red):
        client = llm.OpenAI(base_url=s.red.url, api_key="local", timeout=300)
        out = client.chat.completions.create(
            model=s.red.model, temperature=0, max_tokens=600,
            messages=[{"role": "system", "content": HYPOTHESIS_SYS},
                      {"role": "user", "content": json.dumps(cached)}])
        text = out.choices[0].message.content or ""
        try:
            cached["hypothesis"] = json.loads(text[text.find("{"): text.rfind("}") + 1])
        except ValueError:
            cached["hypothesis"] = {"raw": text}
        ui.detail("purple", json.dumps(cached["hypothesis"], indent=1))
    return cached
