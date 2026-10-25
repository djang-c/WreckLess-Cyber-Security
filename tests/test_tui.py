"""`wreckless tui`: driven headless (Textual pilot) over a real recorded run."""
import asyncio
import json

import pytest
from textual.widgets import DataTable, RichLog, Static

from wreckless import tui
from wreckless.config import Settings
from wreckless.swarm import Swarm

CVE = "CVE-2024-21513"


@pytest.fixture(scope="module")
def home(tmp_path_factory):
    import os
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        os.environ.pop(k, None)
    h = tmp_path_factory.mktemp("home")
    assert Swarm(Settings(use_llm=False), h).run_hero(CVE) == "notified"
    return h


def events(home):
    return [json.loads(ln) for ln in (home / "events.jsonl").read_text().splitlines()]


def test_gate_event_is_recorded_with_every_run(home):
    [g] = [e for e in events(home) if e["kind"] == "gate_report"]
    assert g["passed"] and g["strength"] == "verified" and g["control"] == "reference-patched"
    assert sorted(r["copy"] for r in g["runs"]) == ["control", "vulnerable", "vulnerable"]
    assert all(r["hit"] == (r["copy"] == "vulnerable") for r in g["runs"])
    assert g["item"] == f"{CVE}#1"


def test_render_lines_reuses_the_terminal_renderers(home):
    g = next(e for e in events(home) if e["kind"] == "gate_report")
    lines = tui.render_lines(g, 100)
    assert "GATE · repro_exploit.py" in lines[0] and "VERIFIED" in lines[-1]
    assert tui.render_lines({"kind": "mascot", "actor": "red", "t": 0}) == []   # birds: flock panel only
    assert tui.render_lines({"kind": "say", "actor": "red", "t": 0}) == []      # bad record: skipped


def test_run_state_folds_a_whole_run(home):
    st = tui.RunState()
    for e in events(home):
        st.apply(e)
    assert st.item == f"{CVE}#1" and st.states[-1] == "notified"
    assert st.score == {"regression": True, "functional": True, "exploit_blocked": True, "hardening": st.score["hardening"]}
    assert st.gate["strength"] == "verified" and st.done == {"notified": 1}
    text = tui.item_panel(st).plain
    assert "VERIFIED" in text and "PASS  exploit blocked" in text


def test_slack_off_cannot_be_turned_back_on_by_dotenv(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-real")
    env = tui.run_env(slack=False)
    assert env["SLACK_BOT_TOKEN"] == "" and "SLACK_BOT_TOKEN" in env   # set-but-empty: load_env skips it
    assert tui.run_env(slack=True)["SLACK_BOT_TOKEN"] == "xoxb-real"


def test_queue_rows_read_only(home, tmp_path):
    rows = tui.queue_rows(home / "queue.db")
    assert rows[0][0] == f"{CVE}#1" and rows[0][3] == "notified"
    assert tui.queue_rows(tmp_path / "none.db") == [] and not (tmp_path / "none.db").exists()


def run_app(home, steps, size=(160, 48)):
    async def go():
        app = tui.WrecklessApp(home)
        async with app.run_test(size=size) as pilot:
            await pilot.pause(0.6)
            return await steps(app, pilot)
    return asyncio.run(go())


def test_app_shows_the_recorded_run(home):
    async def steps(app, pilot):
        log = app.query_one("#log", RichLog)
        text = "\n".join(s.text for s in log.lines)
        assert "GATE · repro_exploit.py" in text and "fix-branch card" in text
        assert "VERIFIED" in app.query_one("#item", Static).render().plain
        assert app.query_one("#gates", DataTable).row_count == 1
        await pilot.press("3")
        await pilot.pause(2.3)
        assert app.query_one("#queue_table", DataTable).row_count == 1
        await pilot.press("4")
        assert app.query_one("#roles", DataTable).row_count == 3
        return True
    assert run_app(home, steps)


def test_replay_key_replays_the_last_item_tagged(home):
    async def steps(app, pilot):
        await pilot.press("p")
        await pilot.pause(4.0)
        text = "\n".join(s.text for s in app.query_one("#log", RichLog).lines)
        assert text.startswith(" REPLAY of " + f"{CVE}#1") and "REPLAY " in text
        return True
    assert run_app(home, steps)


def test_cve_target_slack_keys_change_the_launch(home):
    async def steps(app, pilot):
        assert app.slack is False                       # never posts unless asked
        await pilot.press("c", "t", "s")
        assert (app.cve, app.target, app.slack) == ("CVE-2023-44467", "langchain", True)
        assert "Slack ON" in app.sub_title
        return True
    assert run_app(home, steps)


def test_nothing_reaches_the_real_terminal_while_captured(capsys):
    """Regression 2026-10-25: the INTRUSION flash printed past ui.OUT and scribbled over the TUI."""
    ev = {"kind": "intrusion", "actor": "red", "t": 0, "item": "X#1", "script": "e.py", "source": "llm",
          "strength": "verified"}
    lines = tui.render_lines(ev, 80)
    assert any("INTRUSION" in ln for ln in lines)
    assert capsys.readouterr().out == ""


def test_story_follows_the_run_in_plain_words(home):
    st = tui.RunState()
    assert "Press ▶ Run the demo" in tui.headline(st).plain
    seen = []
    for e in events(home):
        st.apply(e)
        if not seen or seen[-1] != st.phase:
            seen.append(st.phase)
    assert seen == ["find", "attack", "prove", "fix", "approve", "done"]
    assert "Nothing ships until a human clicks Approve" in tui.headline(st).plain
    assert tui.steps_bar(st).plain.count("✓") == 5


def test_rejected_run_says_so_and_marks_the_prove_step():
    st = tui.RunState()
    for e in ({"kind": "enqueue", "actor": "core", "t": 1, "item": "X#1"},
              {"kind": "mascot", "actor": "red", "t": 2},
              {"kind": "transition", "actor": "gate", "t": 3, "item": "X#1", "frm": "queued", "to": "verifying"},
              {"kind": "transition", "actor": "gate", "t": 9, "item": "X#1", "frm": "verifying", "to": "rejected"}):
        st.apply(e)
    assert st.phase == "rejected" and "No false alarms" in tui.headline(st).plain
    bar = tui.steps_bar(st).plain
    assert "✗ 3 Prove" in bar and bar.count("✓") == 2


def test_offline_card_names_the_model_not_the_port_alias():
    from wreckless import models
    from wreckless.config import ModelEndpoint
    up, ckpt = models.serving(ModelEndpoint("http://127.0.0.1:9/v1", "blue"))
    assert not up and models.friendly(ckpt)[0] == "Qwen3 Coder Next 80B"
