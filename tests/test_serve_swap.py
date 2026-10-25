"""scripts/serve_models.sh swap: unload one role's model, load another on the same port + names.

Runs the real script on a copy of scripts/ with a fake `vllm` (a tiny HTTP server answering
/v1/models), so the stop/start/restore logic is tested without a GPU."""
import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
FAKE_VLLM = r'''#!PY
import http.server, json, sys
a = sys.argv[1:]
model = a[1]
if "broken" in model:
    sys.exit(3)
port = int(a[a.index("--port") + 1])
names = a[a.index("--served-model-name") + 1: a.index("--host")]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"data": [{"id": n, "root": model} for n in names]}).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def box(tmp_path):
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "serve_models.sh", tmp_path / "scripts")
    port = _port()
    (tmp_path / "scripts" / "models.tsv").write_text(
        f"red  {port}  red  0.20  qwen3_coder  org/Qwen-A  aaa\n"
        f"-    -       -    0.30  qwen3_coder  org/Nemo-B  bbb  --reasoning-parser,nemotron_v3\n"
        f"-    -       -    0.30  qwen3_coder  org/broken-C  ccc\n"
        f"-    -       -    -     -            org/NoServe-D  ddd\n")
    for d in ("Qwen-A", "Nemo-B", "broken-C", "NoServe-D"):
        (tmp_path / "models" / d).mkdir(parents=True)
    fake = tmp_path / "vllm"
    fake.write_text(FAKE_VLLM.replace("#!PY", "#!" + sys.executable))
    fake.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "VLLM_RUNTIME": "pip", "VLLM": str(fake),
           "READY_SLEEP": "0.2", "READY_TRIES": "50", "HOME": str(tmp_path)}
    run = lambda *a: subprocess.run(["bash", "scripts/serve_models.sh", *a], cwd=tmp_path, env=env,
                                    capture_output=True, text=True, timeout=60)
    yield tmp_path, port, run
    run("stop")


def served(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/models", timeout=2) as r:
        d = json.load(r)["data"]
    return [m["id"] for m in d], d[0]["root"]


def test_swap_loads_another_model_on_the_same_port_and_names(box):
    tmp, port, run = box
    assert run("red").returncode == 0
    assert served(port) == (["red"], "models/Qwen-A")
    p = run("swap", "red", "Nemo-B")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "SWAPPED red → Nemo-B" in p.stdout
    time.sleep(0.3)
    assert served(port) == (["red"], "models/Nemo-B")      # same port, same served name


def test_failed_swap_restores_the_original(box):
    tmp, port, run = box
    assert run("red").returncode == 0
    p = run("swap", "red", "broken-C")
    assert p.returncode == 1 and "restoring Qwen-A" in p.stdout
    assert served(port) == (["red"], "models/Qwen-A")


@pytest.mark.parametrize("want,msg", [("missing-E", "no model missing-E"), ("NoServe-D", "no util/tool_parser")])
def test_swap_refuses_unknown_or_unconfigured_models(box, want, msg):
    tmp, port, run = box
    assert run("red").returncode == 0
    p = run("swap", "red", want)
    assert p.returncode == 1 and msg in p.stderr
    assert served(port)[1] == "models/Qwen-A"               # untouched
