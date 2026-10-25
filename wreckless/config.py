"""Runtime configuration. Every endpoint is loopback: inference never leaves the box."""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# benchmarks/, targets/ and runs/ live in the checkout; a non-editable install must point here
ROOT = Path(os.environ.get("WRECKLESS_ROOT") or Path(__file__).resolve().parent.parent)
BENCHMARKS = ROOT / "benchmarks"
TARGETS = ROOT / "targets"
RUNS = ROOT / "runs"
# advisories Purple has seen; shared by every swarm home so a live sync can feed an airgapped run
INTEL_DB = Path(os.environ.get("WRECKLESS_INTEL_DB", RUNS / "intel.db"))


def load_env(path: Path | None = None) -> list[str]:
    """Load KEY=VALUE lines from ``.env`` (``export`` prefix and quotes allowed) into the process
    environment. Variables already set win, so a shell override still works. Returns the names
    it set, never the values."""
    path = path or Path(os.environ.get("WRECKLESS_ENV_FILE") or ROOT / ".env")
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    names = []
    for line in lines:
        line = line.strip().removeprefix("export ").strip()
        key, sep, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if line.startswith("#") or not sep or not key.isidentifier() or key in os.environ:
            continue
        if len(val) > 1 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        elif " #" in val or "\t#" in val:  # unquoted: a whitespace-led # starts a comment, as in sh
            val = val.split(" #", 1)[0].split("\t#", 1)[0].rstrip()
        os.environ[key] = val
        names.append(key)
    return names


@dataclass(frozen=True)
class ModelEndpoint:
    url: str
    model: str


def routes_path() -> Path:
    """The TUI Models tab's choices: {"red": {"url", "model"}, ...}. Env vars still win."""
    return Path(os.environ.get("WRECKLESS_MODEL_ROUTES") or RUNS / "model_routes.json")


def routes() -> dict:
    try:
        data = json.loads(routes_path().read_text())
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict) and v.get("url") and v.get("model")} \
        if isinstance(data, dict) else {}


def _ep(role: str, port: int, name: str) -> ModelEndpoint:
    """WRECKLESS_<ROLE>_URL/_MODEL > the routes file > the GB10 default port and served name."""
    r = routes().get(role.lower(), {})
    url_k, model_k = f"WRECKLESS_{role}_URL", f"WRECKLESS_{role}_MODEL"
    return ModelEndpoint(
        url=os.environ[url_k] if url_k in os.environ else r.get("url", f"http://127.0.0.1:{port}/v1"),
        model=os.environ[model_k] if model_k in os.environ else r.get("model", name),
    )


ROUTED = {"red": ("RED", 8000, "red"), "blue": ("BLUE", 8001, "blue"), "victim": ("VICTIM", 8002, "victim")}


def rerouted(s: "Settings") -> "Settings":
    """`s` with each role that has a routes-file entry re-read, so a long-running daemon picks up a
    model switched in the TUI at its next item. Roles without an entry are left exactly as they are."""
    from dataclasses import replace
    r = routes()
    return replace(s, **{k: _ep(*ROUTED[k]) for k in ROUTED if k in r}) if r else s


@dataclass
class Settings:
    # Purple and Red share one 30B-A3B server; Blue gets the 80B-A3B; victim is the 7B.
    red: ModelEndpoint = field(default_factory=lambda: _ep("RED", 8000, "red"))
    blue: ModelEndpoint = field(default_factory=lambda: _ep("BLUE", 8001, "blue"))
    blue_fallback: ModelEndpoint = field(default_factory=lambda: _ep("BLUE_FALLBACK", 8001, "blue-fallback"))
    victim: ModelEndpoint = field(default_factory=lambda: _ep("VICTIM", 8002, "victim"))
    mode: str = "airgap"            # airgap | live
    demo_mode: bool = False         # N=1, temperature 0, cached fallback on failure
    use_llm: bool = True
    agentic_exploit: bool = False   # drive the exploit through the victim LLM (prompt injection)
    max_agent_steps: int = 12
    target: str = "victim_app"      # targets/<name>/target.json: victim_app | langchain (real upstream)
    live_intel_hosts: tuple = ("api.github.com", "api.osv.dev", "www.cisa.gov", "services.nvd.nist.gov")
