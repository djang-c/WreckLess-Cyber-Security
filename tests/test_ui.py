import io
import json
import time
import re

import pytest

from wreckless import ui

ESC = "\x1b"


class _TTY(io.StringIO):
    def isatty(self):
        return True


def _render_all():
    ui.banner("WreckLess · test")
    for role in ui.ROLES:
        ui.mascot(role)
        ui.say(role, "hello \x1b[41m embedded escape \x1b[0m")
        ui.detail(role, "line1\nline2")
    ui.transition("CVE-X#1", "queued", "verifying", "gate")
    ui.intrusion("CVE-X#1", "repro_exploit.py", "llm")
    ui.diff("blue", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-eval(x)\n+ast.literal_eval(x)\n ctx")
    ui.scoreboard(True, True, True)
    ui.patch_validated("CVE-X#1", "wreckless/fix-X", "deadbeef" * 5, "llm")
    ui.notified("CVE-X#1", "outbox")
    ui.replay_tag("run-1", 1.0)


def test_non_tty_has_no_escape_codes(capsys, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    _render_all()
    out = capsys.readouterr().out
    assert ESC not in out
    assert "INTRUSION" in out and "PATCH VALIDATED" in out


def test_no_color_wins_even_on_tty(monkeypatch):
    buf = _TTY()
    monkeypatch.setattr("sys.stdout", buf)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    _render_all()
    assert ESC not in buf.getvalue()


def test_tty_gets_colour(monkeypatch):
    buf = _TTY()
    monkeypatch.setattr("sys.stdout", buf)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("WRECKLESS_NO_ANIM", "1")
    ui.diff("blue", "-old\n+new")
    out = buf.getvalue()
    assert ui.GREEN + "+new" in out and ui.RED + "-old" in out


@pytest.mark.parametrize("checks", [(False, True, True), (True, False, True),
                                    (True, True, False)])
def test_scoreboard_fails_when_any_check_false(capsys, checks):
    assert ui.scoreboard(*checks) is False
    out = capsys.readouterr().out
    board = out.split("\n", 1)[1]  # skip the summary say-line
    assert "FAIL" in board and "ALL PASS" not in out
    assert len(re.findall(r"\bPASS\b", board)) == 2
    assert "2/3" in board


def test_scoreboard_all_pass(capsys):
    assert ui.scoreboard(True, True, True) is True
    out = capsys.readouterr().out
    assert "3/3 passed · ALL PASS" in out and "FAIL" not in out


def test_missing_held_out_test_is_na_not_fail(capsys):
    """Red-hunt findings have no held-out test: shown n/a, not counted (blue.Validation.ok)."""
    assert ui.scoreboard(None, True, True) is True
    out = capsys.readouterr().out
    assert "n/a" in out and "2/2 passed · ALL PASS" in out and "FAIL" not in out
    assert ui.scoreboard(None, True, False) is False


def test_untrusted_escapes_never_reach_the_terminal(monkeypatch):
    """Exploit/LLM output can carry OSC (title, clipboard) or cursor codes; only colour survives."""
    buf = _TTY()
    monkeypatch.setattr("sys.stdout", buf)
    monkeypatch.delenv("NO_COLOR", raising=False)
    ui.detail("red", "a\x1b]0;PWNED\x07b\x1b]52;c;aGk=\x07c\x1b[2J\x1b[1A\x07d\x1b[31mred")
    out = buf.getvalue()
    assert "PWNED" not in out and "]52;" not in out and "\x1b[2J" not in out and "\x1b[1A" not in out
    assert "\x07" not in out and "abcd" in out and "\x1b[31m" in out


@pytest.mark.parametrize("animate", [False, True])
def test_intrusion_banner_sanitizes_untrusted_fields(monkeypatch, animate):
    buf = _TTY()
    monkeypatch.setattr("sys.stdout", buf)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(ui, "_animate", lambda: animate)
    monkeypatch.setattr(ui.time, "sleep", lambda s: None)
    ui.intrusion("CVE-X#1\x1b]0;PWNED\x07", "x.py\x1b[2J", "llm\x1b]52;c;aGk=\x07", _record=False)
    out = buf.getvalue()
    assert "PWNED" not in out and "]52;" not in out and "\x1b[2J" not in out and "\x07" not in out
    assert "INTRUSION" in out and ui.ON_RED in out


def test_replay_renders_recorded_beats(tmp_path, capsys, monkeypatch):
    from wreckless.events import EventLog, replay
    monkeypatch.setattr(ui, "SINK", None)
    log = EventLog(tmp_path / "events.jsonl").attach()
    log.emit("gate", "transition", "CVE-X#1", frm="verifying", to="verified")
    ui.intrusion("CVE-X#1", "repro_exploit.py", "llm")
    ui.scoreboard(True, True, False)
    ui.patch_validated("CVE-X#1", "wreckless/fix-X", "f" * 40, "cached")
    ui.SINK = None
    live = capsys.readouterr().out
    replay(tmp_path / "events.jsonl", speed=0)
    out = capsys.readouterr().out
    assert out.count("REPLAY of") == 2 and "verifying → verified" in out
    for beat in ("INTRUSION", "2/3 passed · FAILED", "PATCH VALIDATED"):
        assert beat in live and beat in out


def test_public_api_unchanged():
    assert set(ui.ROLES) == {"purple", "red", "blue", "gate", "core", "porter"}
    assert all(len(v) == 3 for v in ui.ROLES.values())
    for fn in ("say", "detail", "banner", "mascot", "scoreboard"):
        assert callable(getattr(ui, fn))


def _record_one(tmp_path, monkeypatch):
    from wreckless.events import EventLog
    monkeypatch.setattr(ui, "SINK", None)
    log = EventLog(tmp_path / "events.jsonl").attach()
    ui.say("red", "crafting exploit")
    log.emit("gate", "transition", "CVE-X#1", frm="verifying", to="verified")
    ui.say("blue", "patch applied")
    ui.SINK = None
    return tmp_path / "events.jsonl"


def test_every_replayed_trace_line_is_marked_replay(tmp_path, capsys, monkeypatch):
    """A judge glancing mid-run must see REPLAY, not just in the first/last line."""
    from wreckless.events import replay
    path = _record_one(tmp_path, monkeypatch)
    live = capsys.readouterr().out
    replay(path, speed=0)
    out = ui.strip_ansi(capsys.readouterr().out)
    stamped = [ln for ln in out.splitlines() if re.match(r"^\S*\s*\d\d:\d\d:\d\d ", ln)]
    assert len(stamped) == 3 and all(ln.startswith("REPLAY ") for ln in stamped)
    assert "REPLAY" not in live


def test_replay_banner_shows_recording_date_and_age(tmp_path, capsys, monkeypatch):
    from wreckless.events import replay
    path = _record_one(tmp_path, monkeypatch)
    lines = path.read_text().splitlines()
    old = [json.dumps(json.loads(ln) | {"t": json.loads(ln)["t"] - 86400 * 2}) for ln in lines]
    path.write_text("\n".join(old) + "\n")
    capsys.readouterr()
    replay(path, speed=0)
    out = ui.strip_ansi(capsys.readouterr().out)
    day = time.strftime("%Y-%m-%d", time.localtime(json.loads(old[0])["t"]))
    assert out.count(f"recorded {day}") == 2 and "2 d ago" in out


def test_replay_mode_is_reset_even_if_replay_crashes(tmp_path, capsys, monkeypatch):
    from wreckless import events
    path = _record_one(tmp_path, monkeypatch)
    # bad lines are skipped now, so crash the renderer itself
    monkeypatch.setattr(events, "_render", lambda ev: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        events.replay(path, speed=0)
    capsys.readouterr()
    ui.say("core", "live again")
    assert "REPLAY" not in capsys.readouterr().out


def test_mascot_and_tool_calls_record_the_task(capsys):
    seen = []
    ui.SINK = lambda role, kind, **data: seen.append((role, kind, data))
    try:
        ui.mascot("red")
        ui.mascot("blue", "test")
        ui.tool_call("red", "sandbox_exec", {"script_path": "x.py"})
        ui.tool_call("red", "unknown_tool", "")
    finally:
        ui.SINK = None
    assert ("red", "mascot", {"task": "exploit"}) in seen
    assert ("blue", "mascot", {"task": "test"}) in seen
    assert ("red", "task", {"task": "sandbox"}) in seen
    assert sum(k == "task" for _, k, _ in seen) == 1
    out = capsys.readouterr().out
    assert "building exploit" in out and "RUN" in out and "sandbox_exec" in out and "x.py" in out


def test_each_tool_class_renders_its_own_way(capsys, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    ui.tool_call("red", "read_file", {"path": "victim/a.py"})
    ui.tool_result("red", "read_file", "l1\nl2\nl3")
    ui.tool_call("red", "write_file", {"path": "repro_exploit.py", "content": "import os\nprint(1)"})
    ui.tool_result("red", "write_file", "wrote repro_exploit.py (18 bytes)")
    ui.tool_call("blue", "edit_file", {"path": "v.py", "old": "eval(x)", "new": "ast.literal_eval(x)"})
    ui.tool_call("blue", "git_apply_patch", {"diff": "--- a/x\n+++ b/x\n-a\n+b"})
    ui.tool_call("blue", "run_pytest", {"test_file": "tests"})
    ui.tool_result("blue", "run_pytest", "x\n12 passed in 0.1s")
    ui.tool_call("red", "sandbox_exec", {"script_path": "repro_exploit.py"})
    ui.tool_result("red", "sandbox_exec", "[openshell] VERIFIED-ELIGIBLE (oracle written via victim code)\nout")
    ui.tool_call("red", "mystery", {"a": 1})
    ui.think("red", "I should read the file first")
    out = capsys.readouterr().out
    for want in ("READ", "3 lines", "WRITE", "import os", "EDIT", "- eval(x)", "+ ast.literal_eval(x)", "PATCH",
                 "+b", "TEST", "12 passed", "RUN", "VERIFIED-ELIGIBLE", "TOOL", "mystery", "I should read"):
        assert want in out, want


def test_failing_pytest_and_errors_are_red(monkeypatch):
    buf = _TTY()
    monkeypatch.setattr("sys.stdout", buf)
    monkeypatch.delenv("NO_COLOR", raising=False)
    ui.tool_result("blue", "run_pytest", "FAILED t\n1 failed, 3 passed in 0.2s")
    ui.tool_result("red", "read_file", "ERROR: path escapes worktree")
    out = buf.getvalue()
    assert ui.RED + "1 failed, 3 passed" in out and ui.RED + "ERROR: path escapes" in out


def test_tool_events_replay_through_the_same_renderer(tmp_path, capsys):
    from wreckless.events import EventLog, replay
    EventLog(tmp_path / "events.jsonl").attach()
    capsys.readouterr()
    try:
        ui.tool_call("red", "write_file", {"path": "p.py", "content": "print(1)"})
        ui.tool_result("red", "write_file", "wrote p.py (8 bytes)")
        ui.think("red", "done thinking")
    finally:
        ui.SINK = None
    live = capsys.readouterr().out
    replay(tmp_path / "events.jsonl", speed=0)
    out = capsys.readouterr().out
    assert "WRITE" in live and "WRITE" in out and "print(1)" in out and "done thinking" in out


def test_step_line_shows_model_context_fill_and_rate(capsys, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    ui.step("blue", "blue", 5200, 120, 4.0, 16384)
    out = capsys.readouterr().out
    assert "blue · ctx 5.2k/16k · 120 out · 30 tok/s" in out
    buf = _TTY()
    monkeypatch.setattr("sys.stdout", buf)
    monkeypatch.delenv("NO_COLOR")
    ui.step("blue", "blue", 15000, 10, 0.0, 16384)       # 92% full, too quick to give a rate
    assert ui.RED + "ctx 15.0k/16k" in buf.getvalue()


def test_log_tags_use_their_birds_colour(monkeypatch):
    """Each role's name tag in the log is drawn in its bird's colour (e.g. VERIFIER yellow)."""
    from wreckless import mascots, ui
    monkeypatch.setenv("COLORTERM", "truecolor")
    for role, (body, _) in mascots.ROLE_COLORS.items():
        assert ui.role_color(role) == "\033[1;38;2;%d;%d;%dm" % body
    monkeypatch.setenv("COLORTERM", "")
    assert ui.role_color("gate").startswith("\033[1;38;5;")    # 256-colour terminals: nearest match
