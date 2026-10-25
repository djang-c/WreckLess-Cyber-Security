"""Runtime configuration. Every endpoint is loopback: inference never leaves the box."""
import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = ROOT / "benchmarks"
TARGETS = ROOT / "targets"
RUNS = ROOT / "runs"
# advisories Purple has seen; shared by every swarm home so a live sync can feed an airgapped run
INTEL_DB = Path(os.environ.get("WRECKLESS_INTEL_DB", RUNS / "intel.db"))
INVENTORY = TARGETS / "victim_app" / "inventory.json"


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
    live_intel_hosts: tuple = ("api.github.com", "api.osv.dev", "www.cisa.gov", "services.nvd.nist.gov")
