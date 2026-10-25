"""metrics.py against a fake vLLM /metrics endpoint (format as served by vLLM v0.1x)."""
import http.server
import threading

import pytest

from wreckless import metrics, ui

BODY = """# HELP vllm:num_requests_running Number of requests in model execution batches.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{{engine="0",model_name="blue"}} 2.0
vllm:num_requests_waiting{{engine="0",model_name="blue"}} 1.0
vllm:kv_cache_usage_perc{{engine="0",model_name="blue"}} 0.25
vllm:generation_tokens_total{{engine="0",model_name="blue"}} {gen}
vllm:prompt_tokens_total{{engine="0",model_name="blue"}} 500.0
vllm:cache_config_info{{block_size="16",cache_dtype="fp8",gpu_memory_utilization="0.45",num_gpu_blocks="9000"}} 1.0
"""


@pytest.fixture
def fake_vllm():
    state = {"gen": 1000.0}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = BODY.format(gen=state["gen"]).encode()
            self.send_response(200 if self.path == "/metrics" else 404)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1", state
    srv.shutdown()


def test_parse_labels_and_skips_junk():
    m = metrics.parse('# HELP x\nfoo{a="1",b="x\\"y"} 3\nbar 2.5\nbroken line\nbaz{a="1"} NaNx\n')
    assert m["foo"] == [({"a": "1", "b": 'x\\"y'}, 3.0)]
    assert m["bar"] == [({}, 2.5)]
    assert "baz" not in m


def test_port_stats_reads_vllm_fields(fake_vllm):
    url, _ = fake_vllm
    st = metrics.port_stats("blue", url)
    assert st.up and st.model == "blue"
    assert (st.running, st.waiting, st.kv_usage, st.mem_util) == (2, 1, 0.25, 0.45)
    assert st.gen_tokens == 1000 and st.prompt_tokens == 500


def test_monitor_tokens_per_second_and_down_port(fake_vllm, tmp_path, monkeypatch):
    url, state = fake_vllm
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal: 125829120 kB\nMemFree: 1 kB\nMemAvailable: 62914560 kB\n")
    real = metrics.meminfo
    monkeypatch.setattr(metrics, "meminfo", lambda: real(meminfo))

    times = iter([100.0, 110.0])
    mon = metrics.Monitor(endpoints={"blue": url, "victim": "http://127.0.0.1:1/v1"},
                          clock=lambda: next(times))
    first = mon.sample()
    assert first.ports[0].tok_s is None            # needs two samples
    assert not first.ports[1].up and first.ports[1].error
    assert (first.mem_total_gb, first.mem_used_gb) == (120.0, 60.0)
    state["gen"] = 1500.0
    second = mon.sample()
    assert second.ports[0].tok_s == pytest.approx(50.0)
    assert second.budget_gb == pytest.approx(0.45 * 120)


def test_panel_renders_up_and_down(capsys, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    ui.gb10_panel(120.0, 60.0, [
        {"role": "blue", "port": 8001, "up": True, "mem_util": 0.45, "tok_s": 31.2,
         "kv_usage": 0.12, "running": 1, "waiting": 0},
        {"role": "victim", "port": 8002, "up": False, "error": "URLError"}], _record=False)
    out = capsys.readouterr().out
    assert "54 GB" in out and "31.2 tok/s" in out and "DOWN URLError" in out
    assert "1/2 up" in out
    widths = {len(line) for line in out.splitlines()[:-1]}
    assert len(widths) == 1                         # borders line up
