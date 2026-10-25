"""cli.py: metrics exit codes / JSON shape / watch priming, status home check, backend choice."""
import json
import os

import pytest

from wreckless import cli, metrics, sandbox


class FakeMonitor:
    def __init__(self, up=True, interrupt_after=None):
        self.up, self.calls, self.interrupt_after = up, 0, interrupt_after

    def sample(self):
        self.calls += 1
        if self.interrupt_after is not None and self.calls > self.interrupt_after:
            raise KeyboardInterrupt
        tok = None if self.calls == 1 else 12.5   # a rate needs two samples
        return metrics.Snapshot(float(self.calls), 120.0, 60.0, [
            metrics.PortStats("blue", 8001, up=self.up, tok_s=tok if self.up else None,
                              error=None if self.up else "URLError")])


@pytest.fixture(autouse=True)
def plain(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.mark.parametrize("up,code", [(True, 0), (False, 1)])
def test_metrics_single_shot_exit_code(capsys, up, code):
    assert cli._metrics(None, False, mon=FakeMonitor(up)) == code
    assert ("tok/s" if up else "DOWN URLError") in capsys.readouterr().out


def test_metrics_json_shape(capsys):
    assert cli._metrics(None, True, mon=FakeMonitor()) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert set(rec) == {"t", "mem_total_gb", "mem_used_gb", "ports"}
    assert rec["mem_total_gb"] == 120.0 and rec["ports"][0]["role"] == "blue"
    assert set(rec["ports"][0]) >= {"role", "port", "up", "tok_s", "kv_usage", "mem_util", "error"}


def test_metrics_watch_primes_counters_and_ctrl_c_exits_130(capsys):
    mon, sleeps = FakeMonitor(interrupt_after=2), []
    assert cli._metrics(5.0, False, mon=mon, sleep=sleeps.append) == 130
    cap = capsys.readouterr()
    assert cap.out.count("GB10") == 1 and "12.5 tok/s" in cap.out   # first panel shown has a rate
    assert sleeps == [2, 5.0]
    assert "Traceback" not in cap.err


def test_metrics_watch_json_ctrl_c(capsys):
    mon = FakeMonitor(interrupt_after=3)
    assert cli._metrics(1.0, True, mon=mon, sleep=lambda s: None) == 130
    assert len(capsys.readouterr().out.strip().splitlines()) == 3   # no priming in JSON mode


@pytest.mark.parametrize("bad", ["0", "-1", "nan", "inf", "x"])
def test_metrics_watch_rejects_non_positive(bad, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["metrics", "--watch", bad])
    assert e.value.code == 2 and "--watch" in capsys.readouterr().err


def test_status_refuses_missing_home(tmp_path, capsys):
    home = tmp_path / "typo"
    assert cli.main(["status", "--home", str(home)]) == 2
    assert not home.exists()
    assert "no queue" in capsys.readouterr().err


@pytest.mark.parametrize("env,available,expected", [
    ("userland", True, "userland-guard"), ("openshell", False, "openshell"),
    ("auto", True, "openshell"), ("auto", False, "userland-guard"), (None, False, "userland-guard")])
def test_backend_honours_wreckless_sandbox(monkeypatch, env, available, expected):
    if env is None:
        monkeypatch.delenv("WRECKLESS_SANDBOX", raising=False)
    else:
        monkeypatch.setenv("WRECKLESS_SANDBOX", env)
    monkeypatch.setattr(sandbox, "openshell_available", lambda: available)
    assert cli._backend() == expected


def test_load_env_sets_missing_names_only(tmp_path, monkeypatch):
    from wreckless.config import load_env
    f = tmp_path / ".env"
    f.write_text("# c\nexport A_TOKEN=abc\nB_QUOTED='x y'\nC_KEEP=new\nbad line\n=nokey\n")
    monkeypatch.setenv("C_KEEP", "shell")
    for k in ("A_TOKEN", "B_QUOTED"):
        monkeypatch.delenv(k, raising=False)
    assert load_env(f) == ["A_TOKEN", "B_QUOTED"]
    assert os.environ["A_TOKEN"] == "abc" and os.environ["B_QUOTED"] == "x y" and os.environ["C_KEEP"] == "shell"
    for k in ("A_TOKEN", "B_QUOTED"):
        monkeypatch.delenv(k)
    assert load_env(tmp_path / "missing") == []
