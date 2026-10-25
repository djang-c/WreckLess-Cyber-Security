"""Model picker (wreckless/models.py): switch = re-point a role, swap = reload a role's port."""
import http.server
import json
import threading

import pytest

from wreckless import config, models
from wreckless.config import Settings, rerouted


def serve(routes: dict):
    """Tiny JSON server: {path: payload}; POSTs are recorded."""
    posts = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(routes.get(self.path, {})).encode()
            self.send_response(200 if self.path in routes else 404)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            posts.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", posts


@pytest.fixture(autouse=True)
def no_env(monkeypatch):
    for r in ("RED", "BLUE", "VICTIM"):
        monkeypatch.delenv(f"WRECKLESS_{r}_URL", raising=False)
        monkeypatch.delenv(f"WRECKLESS_{r}_MODEL", raising=False)


def test_switch_is_saved_and_env_still_wins(monkeypatch):
    assert Settings().blue.url.endswith(":8001/v1")
    models.switch("blue", "http://127.0.0.1:8000/v1", "red")
    assert Settings().blue == config.ModelEndpoint("http://127.0.0.1:8000/v1", "red")
    monkeypatch.setenv("WRECKLESS_BLUE_MODEL", "pinned")
    assert Settings().blue.model == "pinned" and Settings().blue.url.endswith(":8000/v1")
    models.reset("blue")
    monkeypatch.delenv("WRECKLESS_BLUE_MODEL")
    assert Settings().blue == config.ModelEndpoint("http://127.0.0.1:8001/v1", "blue")


def test_running_daemon_follows_a_switch_at_its_next_item():
    s = Settings()
    assert rerouted(s) is s                           # no routes file: untouched
    models.switch("red", "http://127.0.0.1:11434/v1", "qwen3:8b")
    s2 = rerouted(s)
    assert s2.red.model == "qwen3:8b" and s2.blue == s.blue   # only routed roles change


def test_switch_rejects_unknown_role():
    with pytest.raises(ValueError):
        models.switch("purple-ish", "http://x/v1", "m")


def test_catalog_includes_nemotron_with_its_card_flags():
    rows = {r["dir"]: r for r in models.catalog()}
    nemo = rows["NVIDIA-Nemotron-3.5-Lightning-30B-A3B-FP8"]
    assert nemo["role"] == "-" and nemo["parser"] == "qwen3_coder" and "nemotron_v3" in nemo["extra"]


def test_vllm_options_offer_loaded_models_then_swap_ins(monkeypatch, tmp_path):
    srv, base, _ = serve({"/v1/models": {"data": [{"id": "red", "root": "/models/Qwen3-Coder-30B-A3B-Instruct-AWQ-4bit"}]}})
    port = srv.server_address[1]
    monkeypatch.setattr(models, "PORTS", {"red": port, "blue": 1, "victim": 2})
    (tmp_path / "NVIDIA-Nemotron-3.5-Lightning-30B-A3B-FP8").mkdir()
    opts = models.vllm_options("red", models_dir=tmp_path)
    srv.shutdown()
    ready = [o for o in opts if o.status == "ready"]
    assert [(o.model, o.url) for o in ready] == [("red", f"http://127.0.0.1:{port}/v1")]
    nemo = next(o for o in opts if o.dir == "NVIDIA-Nemotron-3.5-Lightning-30B-A3B-FP8")
    assert nemo.status == "swap" and nemo.model == "red"    # same served name on red's own port
    assert all(o.dir != "Qwen3-Coder-30B-A3B-Instruct-AWQ-4bit" for o in opts if o.status != "ready")
    assert any(o.status == "missing" for o in opts)          # in the manifest, not on disk


def test_ollama_swap_unloads_then_loads_then_routes(monkeypatch):
    srv, base, posts = serve({"/api/tags": {"models": [{"name": "qwen3:8b", "size": 5e9},
                                                       {"name": "qwen2.5-coder:7b", "size": 4e9}]},
                              "/api/ps": {"models": [{"name": "qwen3:8b"}]}})
    monkeypatch.setattr(models, "OLLAMA", base)
    opts = {o.model: o for o in models.ollama_options(base)}
    assert opts["qwen3:8b"].status == "ready" and opts["qwen2.5-coder:7b"].status == "swap"
    models.switch("blue", f"{base}/v1", "qwen3:8b")
    assert models.swap("blue", opts["qwen2.5-coder:7b"], log=lambda m: None)
    srv.shutdown()
    assert [p[1].get("keep_alive") for p in posts] == [0, "30m"]
    assert posts[0][1]["model"] == "qwen3:8b" and posts[1][1]["model"] == "qwen2.5-coder:7b"
    assert Settings().blue.model == "qwen2.5-coder:7b"


def test_missing_model_is_never_swapped(monkeypatch):
    called = []
    monkeypatch.setattr(models.subprocess, "Popen", lambda *a, **k: called.append(a))
    opt = models.Option("X", "vllm", "http://127.0.0.1:8000/v1", "red", "missing", dir="X")
    assert not models.swap("red", opt, log=lambda m: None) and not called
