import io
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
    ui.transition("IDLE", "INTEL_READY", "purple")
    ui.intrusion("repro_exploit.py", "llm")
    ui.diff("blue", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-eval(x)\n+ast.literal_eval(x)\n ctx")
    ui.scoreboard(True, True, True)
    ui.patch_validated("wreckless/fix-X", "deadbeef" * 5, "llm")
    ui.notified("outbox")
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
                                    (True, True, False), (None, True, True)])
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
    assert "3/3 ALL PASS" in out and "FAIL" not in out


def test_public_api_unchanged():
    assert set(ui.ROLES) == {"purple", "red", "blue", "core"}
    assert all(len(v) == 3 for v in ui.ROLES.values())
    for fn in ("say", "detail", "banner", "mascot", "scoreboard"):
        assert callable(getattr(ui, fn))
