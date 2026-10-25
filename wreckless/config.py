"""Runtime configuration. Every endpoint is loopback: inference never leaves the box."""
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
        os.environ[key] = val
        names.append(key)
    return names


@dataclass(frozen=True)
class ModelEndpoint:
    url: str
    model: str


def _ep(role: str, port: int, name: str) -> ModelEndpoint:
    return ModelEndpoint(
        url=os.environ.get(f"WRECKLESS_{role}_URL", f"http://127.0.0.1:{port}/v1"),
        model=os.environ.get(f"WRECKLESS_{role}_MODEL", name),
    )


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
