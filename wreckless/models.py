"""Model picker: which model each role (red = Scout+Ralph, blue = Felix, victim) talks to.

Two moves, one list of options per role:
- switch: point the role at a model that is already loaded (any of our vLLM ports, or a resident
  Ollama model). Instant. Saved in the routes file (config.routes_path()); env vars still win.
- swap:   unload the model on the role's own port and load another one from disk, on the same port
  and served name, so nothing else changes. vLLM: `scripts/serve_models.sh swap` (minutes; the
  role is offline meanwhile; a failed load restores the old model). Ollama: unload + preload.

Every probe is short and never raises: a down port is just an option that is not offered.
"""
import json
import os
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from wreckless.config import ROOT, ROUTED, Settings, routes, routes_path

PORTS = {"red": 8000, "blue": 8001, "victim": 8002}
OLLAMA = os.environ.get("WRECKLESS_OLLAMA_URL", "http://127.0.0.1:11434")


@dataclass
class Option:
    label: str
    backend: str          # "vllm" | "ollama"
    url: str              # OpenAI-style base URL the role would use
    model: str            # model name sent in requests
    status: str           # "ready" (switch, instant) | "swap" (reload the role's port)
    detail: str = ""
    dir: str | None = None   # vLLM checkpoint dir (swap)
    ckpt: str = ""           # checkpoint (vLLM dir name or Ollama tag): what `friendly()` names

    @property
    def name(self) -> str:
        return friendly(self.ckpt or self.model)[0]

    @property
    def blurb(self) -> str:
        return friendly(self.ckpt or self.model)[1]


# Plain names for people watching (the ad, the stage); unknown models fall back to their own id.
FRIENDLY = {
    "Qwen3-Coder-30B-A3B-Instruct-AWQ-4bit": ("Qwen3 Coder 30B", "fast coding model"),
    "Qwen3-Coder-Next-AWQ-4bit": ("Qwen3 Coder Next 80B", "the strongest coding model here"),
    "Qwen2.5-Coder-32B-Instruct-AWQ": ("Qwen2.5 Coder 32B", "backup coding model"),
    "Qwen2.5-Coder-7B-Instruct-AWQ": ("Qwen2.5 Coder 7B", "small model, plays the target app's AI"),
    "NVIDIA-Nemotron-3.5-Lightning-30B-A3B-FP8": ("NVIDIA Nemotron 3.5 Lightning 30B", "NVIDIA reasoning model"),
}


def friendly(ckpt: str) -> tuple[str, str]:
    base = Path(ckpt).name
    if base in FRIENDLY:
        return FRIENDLY[base]
    if ":" in base:   # Ollama tag, e.g. qwen3:8b
        fam, size = base.split(":", 1)
        return f"{fam.replace('-', ' ').title()} {size.upper()}", "runs in Ollama on this machine"
    return base, ""


def _get(url: str, timeout: float = 1.5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except Exception:  # noqa: BLE001  down, refused, not JSON: not an option right now
        return None


def _post(url: str, payload: dict, timeout: float = 600):
    req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def catalog(tsv: Path = ROOT / "scripts" / "models.tsv") -> list[dict]:
    """Rows of the model manifest that can be served: dir, util, parser, extra, role ('-' = swap-in)."""
    rows = []
    try:
        lines = tsv.read_text().splitlines()
    except OSError:
        return rows
    for line in lines:
        f = line.split()
        if line.startswith("#") or len(f) < 7 or f[3] == "-" or f[4] == "-":
            continue
        rows.append({"role": f[0], "dir": f[5].rsplit("/", 1)[-1], "repo": f[5], "util": f[3],
                     "parser": f[4], "extra": f[7] if len(f) > 7 else ""})
    return rows


def current(s: Settings | None = None) -> dict:
    s = s or Settings()
    return {"red": s.red, "blue": s.blue, "victim": s.victim}


def vllm_options(role: str, host: str = "127.0.0.1", models_dir: Path = ROOT / "models") -> list[Option]:
    out, loaded = [], set()
    for r, port in PORTS.items():
        d = _get(f"http://{host}:{port}/v1/models")
        for m in (d or {}).get("data", []):
            ckpt = Path(m.get("root") or m["id"]).name
            loaded.add(ckpt)
            out.append(Option(f"{m['id']} on :{port} ({ckpt})", "vllm", f"http://{host}:{port}/v1", m["id"],
                              "ready", f"loaded on {r}'s port", ckpt=ckpt))
    own = PORTS.get(role)
    for row in catalog():
        if row["dir"] in loaded or own is None:
            continue
        on_disk = (models_dir / row["dir"]).is_dir()
        out.append(Option(row["dir"], "vllm", f"http://{host}:{own}/v1", ROUTED[role][2],
                          "swap" if on_disk else "missing",
                          f"load on :{own} (util {row['util']}, parser {row['parser']})"
                          + ("" if on_disk else " · not downloaded"), row["dir"], ckpt=row["dir"]))
    return out


def ollama_options(base: str = OLLAMA) -> list[Option]:
    tags = _get(f"{base}/api/tags")
    if not tags:
        return []
    resident = {m.get("name") for m in (_get(f"{base}/api/ps") or {}).get("models", [])}
    out = []
    for m in tags.get("models", []):
        name = m["name"]
        size = f"{m.get('size', 0) / 2**30:.1f} GB"
        out.append(Option(name, "ollama", f"{base}/v1", name, "ready" if name in resident else "swap",
                          f"ollama · {size} · " + ("in memory" if name in resident else "on disk"), ckpt=name))
    return out


def options(role: str) -> list[Option]:
    """Everything the role could use right now: loaded first (instant), then swap-ins."""
    opts = vllm_options(role) + ollama_options()
    return sorted(opts, key=lambda o: {"ready": 0, "swap": 1, "missing": 2}[o.status])


def serving(ep) -> tuple[bool, str]:
    """(up, checkpoint) for an endpoint: what a role is really talking to right now."""
    d = _get(ep.url.rstrip("/") + "/models")
    if not d:   # down: name what that role's port normally serves (e.g. "red" -> Qwen3 Coder 30B)
        row = next((r for r in catalog() if r["role"] == ep.model), None)
        return False, row["dir"] if row else ep.model
    for m in d.get("data", []):
        if m.get("id") == ep.model:
            return True, Path(m.get("root") or m["id"]).name
    return True, ep.model


def _save(data: dict) -> None:
    p = routes_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".routes-")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, p)


def switch(role: str, url: str, model: str) -> None:
    if role not in ROUTED:
        raise ValueError(f"unknown role {role!r}")
    data = routes()
    data[role] = {"url": url, "model": model}
    _save(data)


def reset(role: str) -> None:
    """Back to the GB10 default port + served name (written out, so a running daemon follows)."""
    _, port, name = ROUTED[role]
    switch(role, f"http://127.0.0.1:{port}/v1", name)


def swap(role: str, opt: Option, log=print, script: Path = ROOT / "scripts" / "serve_models.sh") -> bool:
    """Unload what the role's port serves and load `opt` there. True when the new model answers."""
    if opt.status == "missing":
        log(f"{opt.label} is not downloaded (scripts/download_models.sh)")
        return False
    if opt.backend == "ollama":
        cur = current()[role]
        try:
            if cur.url.startswith(OLLAMA) and cur.model != opt.model:
                log(f"unloading {cur.model}")
                _post(f"{OLLAMA}/api/generate", {"model": cur.model, "keep_alive": 0}, timeout=60)
            log(f"loading {opt.model} into memory")
            _post(f"{OLLAMA}/api/generate", {"model": opt.model, "prompt": "", "keep_alive": "30m"})
        except Exception as e:  # noqa: BLE001
            log(f"ollama swap failed: {e}")
            return False
        switch(role, opt.url, opt.model)
        log(f"SWAPPED {role} → {opt.model}")
        return True
    p = subprocess.Popen(["bash", str(script), "swap", role, opt.dir], cwd=ROOT, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        log(line.rstrip())
    ok = p.wait() == 0
    if ok:
        reset(role)   # same port + served name as before: the role's default route now hits the new model
    return ok
