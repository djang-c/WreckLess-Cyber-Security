"""GB10 memory + per-port throughput, scraped from each vLLM server's Prometheus `/metrics`.

nvidia-smi reports memory as [N/A] on the GB10 (unified memory), so the box total comes from
/proc/meminfo and each port's share from the `gpu_memory_utilization` vLLM reports in
`cache_config_info`. Tokens/sec is the delta of the generation-token counter between two samples.
Stdlib only; a down port is reported as down, never raised (nor is a missing /proc/meminfo).
"""
import json
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from wreckless.config import ROOT, Settings

_LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)')
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
# vLLM renamed a few metrics across versions; first name present wins.
GEN_TOKENS = ("vllm:generation_tokens_total", "vllm:generation_tokens")
PROMPT_TOKENS = ("vllm:prompt_tokens_total", "vllm:prompt_tokens")
KV_USAGE = ("vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc")
RUNNING, WAITING = ("vllm:num_requests_running",), ("vllm:num_requests_waiting",)


def parse(text: str) -> dict[str, list[tuple[dict, float]]]:
    """Prometheus text format -> {name: [(labels, value), ...]}. Comments and junk are skipped."""
    out: dict[str, list[tuple[dict, float]]] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m or line.startswith("#"):
            continue
        try:
            value = float(m.group(3))
        except ValueError:
            continue
        out.setdefault(m.group(1), []).append((dict(_LABEL.findall(m.group(2) or "")), value))
    return out


def _sum(metrics: dict, names: tuple) -> float | None:
    for n in names:
        if n in metrics:
            return sum(v for _, v in metrics[n])
    return None


@dataclass
class PortStats:
    role: str
    port: int
    up: bool = False
    model: str | None = None
    running: float = 0
    waiting: float = 0
    kv_usage: float | None = None        # 0..1
    mem_util: float | None = None        # --gpu-memory-utilization share of unified memory
    gen_tokens: float = 0
    prompt_tokens: float = 0
    tok_s: float | None = None           # generation tokens/sec since the previous sample
    ckpt: str | None = None              # served checkpoint, e.g. Qwen3-Coder-Next-AWQ-4bit@c92cabf
    ctx: int | None = None               # --max-model-len
    error: str | None = None


@dataclass
class Snapshot:
    t: float
    mem_total_gb: float
    mem_used_gb: float
    ports: list[PortStats] = field(default_factory=list)

    @property
    def budget_gb(self) -> float:
        return sum((p.mem_util or 0) * self.mem_total_gb for p in self.ports if p.up)


def revisions(tsv: Path = ROOT / "scripts" / "models.tsv") -> dict[str, str]:
    """Pinned revision (7 chars) per checkpoint directory name, from the one model manifest."""
    out = {}
    try:
        lines = tsv.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        f = line.split()
        if line.startswith("#") or len(f) < 7:
            continue
        out[f[5].rsplit("/", 1)[-1]] = f[6][:7]
    return out


def _checkpoint(root: str, timeout: float) -> tuple[str | None, int | None]:
    """(checkpoint@rev, max_model_len) from the server's /v1/models; (None, None) if unavailable."""
    try:
        with urllib.request.urlopen(f"{root}/v1/models", timeout=timeout) as r:
            d = json.loads(r.read())["data"][0]
        name = str(d["root"]).rstrip("/").rsplit("/", 1)[-1]
        rev = revisions().get(name)
        return (f"{name}@{rev}" if rev else name), d.get("max_model_len")
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None, None


def port_stats(role: str, base_url: str, timeout: float = 2.0) -> PortStats:
    """`base_url` is the OpenAI-style endpoint (http://host:port/v1); /metrics lives at the root."""
    root = base_url.rstrip("/").removesuffix("/v1")
    port = int(root.rsplit(":", 1)[-1]) if root.rsplit(":", 1)[-1].isdigit() else 0
    st = PortStats(role, port)
    try:
        with urllib.request.urlopen(f"{root}/metrics", timeout=timeout) as r:
            m = parse(r.read().decode(errors="replace"))
    except Exception as e:  # down, still loading, or refused: the panel shows it, the swarm goes on
        st.error = type(e).__name__
        return st
    st.up = True
    st.running = _sum(m, RUNNING) or 0
    st.waiting = _sum(m, WAITING) or 0
    st.kv_usage = _sum(m, KV_USAGE)
    st.gen_tokens = _sum(m, GEN_TOKENS) or 0
    st.prompt_tokens = _sum(m, PROMPT_TOKENS) or 0
    for labels, _ in m.get("vllm:cache_config_info", []):
        try:
            st.mem_util = float(labels["gpu_memory_utilization"])
        except (KeyError, ValueError):
            pass
    for name in RUNNING + GEN_TOKENS:
        for labels, _ in m.get(name, []):
            st.model = st.model or labels.get("model_name")
    st.ckpt, st.ctx = _checkpoint(root, timeout)
    return st


def meminfo(path: Path = Path("/proc/meminfo")) -> tuple[float, float]:
    """(total_gb, used_gb) of the unified pool: used = MemTotal - MemAvailable.
    (0, 0) when /proc/meminfo is missing or unreadable (non-Linux, sandboxed /proc)."""
    kb = {}
    try:
        text = path.read_text()
    except OSError:
        return 0.0, 0.0
    for line in text.splitlines():
        k, _, rest = line.partition(":")
        try:
            kb[k] = int(rest.split()[0]) if rest.split() else 0
        except ValueError:
            continue
    total = kb.get("MemTotal", 0) / 2**20
    return total, total - kb.get("MemAvailable", 0) / 2**20


class Monitor:
    """Call `sample()` periodically; tokens/sec needs two samples, so the first one shows None."""

    def __init__(self, s: Settings | None = None, endpoints: dict[str, str] | None = None,
                 clock=time.time):
        s = s or Settings()
        self.clock = clock
        # Scout (Purple) and Ralph (Red) share :8000, so it is listed once, as "scout+ralph"
        self.endpoints = endpoints or {"felix": s.blue.url, "scout+ralph": s.red.url,
                                       "victim": s.victim.url}
        self._prev: dict[str, tuple[float, float]] = {}

    def sample(self) -> Snapshot:
        now = self.clock()
        total, used = meminfo()
        snap = Snapshot(now, total, used)
        roles = list(self.endpoints)
        # probed concurrently: three down ports cost one timeout, not three
        with ThreadPoolExecutor(max_workers=max(1, len(roles))) as pool:
            stats = list(pool.map(lambda r: port_stats(r, self.endpoints[r]), roles))
        for role, st in zip(roles, stats):
            prev = self._prev.get(role)
            # a counter that went backwards means the server restarted: no rate this sample
            if st.up and prev and now > prev[0] and st.gen_tokens >= prev[1]:
                st.tok_s = (st.gen_tokens - prev[1]) / (now - prev[0])
            if st.up:
                self._prev[role] = (now, st.gen_tokens)
            else:
                self._prev.pop(role, None)
            snap.ports.append(st)
        return snap
