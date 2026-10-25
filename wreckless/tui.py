"""`wreckless tui`: one full-screen app for the whole swarm.

It tails the same events.jsonl the pipeline writes (a `run`, the 24/7 daemon, or a run it
launches itself), so it never changes what the pipeline does and shows only what was recorded.
Every event goes through the existing ``ui`` renderers (``ui.OUT`` captures their lines), so the
log looks exactly like the plain terminal UI.

Tabs: Live (flock, log, item, scoreboard, GB10), Gate (every verdict with its runs), Queue
(every candidate), Models (switch a role to a loaded model, or swap a model onto its port).
Keys: r scripted run · d demo-mode run (LLM) · c CVE · t target · s Slack on/off · p replay
last run · 1-4 tabs · q quit. Slack starts OFF: a launched run posts nothing unless you press s.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (Button, DataTable, Footer, Header, Label, OptionList, RichLog, Static,
                             TabbedContent, TabPane)
from textual.widgets.option_list import Option as ListOption

from wreckless import events as ev_mod
from wreckless import mascots, models, ui
from wreckless.config import ROOT, RUNS

CVES = ["CVE-2024-21513", "CVE-2023-44467"]
TARGETS = ["victim_app", "langchain"]
FINAL = {"rejected", "patch_failed", "notified", "failed"}
SLACK_VARS = ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_WEBHOOK_URL")


# ---------- pure helpers (tested without a terminal) ----------
def render_lines(ev: dict, width: int = 100) -> list[str]:
    """The lines the plain terminal UI would print for one recorded event (ANSI colour kept)."""
    if ev.get("kind") in ("mascot", "enqueue", "transition_only"):
        return []   # birds live in the flock panel; enqueue has no terminal line of its own
    out: list[str] = []
    prev_out, prev_w = ui.OUT, ui.WIDTH
    ui.OUT, ui.WIDTH = out.append, width
    try:
        ev_mod._render(ev)
    except (KeyError, TypeError, ValueError, AttributeError):
        pass   # a record from an older/newer schema: skip it, as replay does
    finally:
        ui.OUT, ui.WIDTH = prev_out, prev_w
    return [ln for chunk in out for ln in chunk.split("\n")]


@dataclass
class RunState:
    """What the side panels show, folded from events in order."""
    item: str | None = None
    states: list = field(default_factory=list)
    score: dict | None = None
    gate: dict | None = None
    notified: str | None = None
    done: dict = field(default_factory=dict)       # final state -> count
    gates: list = field(default_factory=list)      # every gate_report, with its item and time

    def apply(self, ev: dict) -> None:
        kind, item = ev.get("kind"), ev.get("item")
        if kind == "transition":
            if item != self.item and ev.get("frm") in ("queued", None):
                self.item, self.states, self.score, self.gate, self.notified = item, [], None, None, None
            if item == self.item:
                self.states.append(ev.get("to"))
            if ev.get("to") in FINAL:
                self.done[ev["to"]] = self.done.get(ev["to"], 0) + 1
        elif kind == "scoreboard" and item == self.item:
            self.score = {k: ev.get(k) for k in ("regression", "functional", "exploit_blocked", "hardening")}
        elif kind == "gate_report":
            rec = {**{k: v for k, v in ev.items() if k not in ("kind", "actor")}}
            self.gates.append(rec)
            if item == self.item:
                self.gate = rec
        elif kind == "notified" and item == self.item:
            self.notified = ev.get("channel")


def item_panel(st: RunState) -> Text:
    t = Text()
    t.append("ITEM  ", style="bold")
    t.append(f"{st.item or '—'}\n")
    for s in st.states:
        color = {"verified": "green", "patched": "green", "notified": "green", "rejected": "red",
                 "patch_failed": "red", "failed": "red"}.get(s, "yellow")
        t.append(f"  → {s}\n", style=color)
    if st.gate:
        word = ("VERIFIED" if st.gate.get("strength") == "verified" else "REACHABLE") \
            if st.gate.get("passed") else "REJECTED"
        t.append("\nGATE  ", style="bold")
        t.append(word + "\n", style="green" if st.gate.get("passed") else "red")
        t.append(f"  control: {st.gate.get('control')}\n", style="dim")
        if st.gate.get("flaw"):
            t.append(f"  flaw: {st.gate['flaw']}\n", style="dim")
    if st.score:
        t.append("\nCHECKS\n", style="bold")
        for label, k in (("held-out regression", "regression"), ("functional suite", "functional"),
                         ("exploit blocked", "exploit_blocked")):
            v = st.score.get(k)
            t.append(f"  {'PASS' if v else 'n/a ' if v is None else 'FAIL'}  ",
                     style="green" if v else "dim" if v is None else "bold red")
            t.append(label + "\n")
        if st.score.get("hardening"):
            t.append(f"  probes {st.score['hardening']}\n", style="dim")
    if st.notified:
        t.append("\nCARD  ", style="bold")
        t.append(f"{st.notified}\n")
    if st.done:
        t.append("\nTOTALS  ", style="bold")
        t.append(" · ".join(f"{k} {v}" for k, v in sorted(st.done.items())) + "\n", style="dim")
    return t


def gb10_text(snap) -> Text:
    t = Text()
    if snap is None:
        return Text("probing ports…", style="dim")
    if snap.mem_total_gb:
        frac = snap.mem_used_gb / snap.mem_total_gb
        t.append("MEMORY ", style="bold")
        t.append("█" * int(frac * 20), style="magenta")
        t.append("░" * (20 - int(frac * 20)), style="dim")
        t.append(f" {snap.mem_used_gb:.0f}/{snap.mem_total_gb:.0f} GB\n")
    else:
        t.append("MEMORY ", style="bold")
        t.append("n/a here (no /proc/meminfo: not the GB10)\n", style="dim")
    for p in snap.ports:
        t.append(f"{p.role:<12}", style="bold")
        if not p.up:
            t.append(f":{p.port} down\n", style="red")
            continue
        rate = f"{p.tok_s:5.1f} tok/s" if p.tok_s is not None else "  …   tok/s"
        t.append(f":{p.port} {rate}  run {p.running:.0f} wait {p.waiting:.0f}  {p.ckpt or p.model or ''}\n",
                 style="green")
    return t


def queue_rows(db: Path, limit: int = 300) -> list[tuple]:
    """Newest first, read-only (never creates or locks the daemon's queue)."""
    if not db.exists():
        return []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1)
        try:
            return con.execute("SELECT id, source, cve, state, label, title, updated FROM items "
                               "ORDER BY updated DESC LIMIT ?", (limit,)).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return []


def run_env(slack: bool) -> dict:
    """Environment for a launched run. Slack OFF: the vars are set empty, so load_env (which
    never overrides a set variable) cannot turn Slack back on from .env."""
    env = {**os.environ, "WRECKLESS_NO_ANIM": "1"}
    if not slack:
        env.update({k: "" for k in SLACK_VARS})
    return env


# ---------- the app ----------
class Confirm(ModalScreen[bool]):
    DEFAULT_CSS = """
    Confirm { align: center middle; }
    #box { width: 72; height: auto; border: thick $warning; background: $surface; padding: 1 2; }
    #box Horizontal { height: auto; margin-top: 1; }
    """

    def __init__(self, text: str):
        super().__init__()
        self.text = text

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(self.text)
            with Horizontal():
                yield Button("Swap", variant="warning", id="yes")
                yield Button("Cancel", id="no")

    def on_button_pressed(self, e: Button.Pressed) -> None:
        self.dismiss(e.button.id == "yes")


class WrecklessApp(App):
    TITLE = "WreckLess"
    CSS = """
    #flock { height: 11; content-align: center middle; }
    #log { width: 3fr; border: round $primary; }
    #side { width: 1fr; min-width: 34; }
    #item { border: round $secondary; height: 1fr; }
    #gb10 { border: round $accent; height: auto; min-height: 6; }
    #gates { width: 1fr; } #gate_detail { width: 1fr; border: round $warning; }
    #roles { height: 7; } #opts { height: 1fr; border: round $primary; } #swaplog { height: 12; border: round $warning; }
    """
    BINDINGS = [
        Binding("r", "launch(False)", "Scripted run"), Binding("d", "launch(True)", "Demo run (LLM)"),
        Binding("c", "cycle_cve", "CVE"), Binding("t", "cycle_target", "Target"),
        Binding("s", "toggle_slack", "Slack on/off"), Binding("p", "replay", "Replay last"),
        Binding("1", "tab('live')", "Live", show=False), Binding("2", "tab('gate')", "Gate", show=False),
        Binding("3", "tab('queue')", "Queue", show=False), Binding("4", "tab('models')", "Models", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, home: Path = RUNS / "swarm", replay: Path | None = None):
        super().__init__()
        self.home, self.events = Path(home), Path(home) / "events.jsonl"
        self.pos = 0
        self.flock, self.state = mascots.Flock(), RunState()
        self.cve, self.target, self.slack = CVES[0], TARGETS[0], False
        self.replay_q: list[dict] = []
        self.replay_t0 = None
        self.replay_from = replay
        self.proc = None
        self.role = "red"
        self.opts: list[models.Option] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="live"):
            with TabPane("Live [1]", id="live"):
                yield Static(id="flock")
                with Horizontal():
                    yield RichLog(id="log", wrap=False, markup=False, max_lines=4000)
                    with Vertical(id="side"):
                        yield Static(id="item")
                        yield Static(id="gb10")
            with TabPane("Gate [2]", id="gate"):
                with Horizontal():
                    yield DataTable(id="gates", cursor_type="row")
                    yield RichLog(id="gate_detail", wrap=True, markup=False)
            with TabPane("Queue [3]", id="queue"):
                yield DataTable(id="queue_table", cursor_type="row")
            with TabPane("Models [4]", id="models"):
                yield DataTable(id="roles", cursor_type="row")
                yield OptionList(id="opts")
                yield RichLog(id="swaplog", wrap=True, markup=False)
        yield Footer()

    # ----- lifecycle -----
    def on_mount(self) -> None:
        self.query_one("#gates", DataTable).add_columns("time", "item", "exploit", "control", "verdict")
        self.query_one("#queue_table", DataTable).add_columns("item", "source", "cve", "state", "label", "title")
        self.query_one("#roles", DataTable).add_columns("role", "uses model", "at")
        self.query_one("#item", Static).border_title = "item · gate · checks"
        self.query_one("#gb10", Static).border_title = "GB10"
        self.query_one("#log", RichLog).border_title = "swarm log"
        self.query_one("#gate_detail", RichLog).border_title = "gate evidence"
        self.query_one("#opts", OptionList).border_title = "options (Enter: ready = switch now, swap = reload port)"
        self.query_one("#swaplog", RichLog).border_title = "model swaps"
        self._subtitle()
        if self.replay_from:
            self._start_replay(self.replay_from)
        else:
            self._backfill()
        self.set_interval(0.25, self._poll)
        self.set_interval(1 / 8, self._draw_flock)
        self.set_interval(2.0, self._sample_gb10)
        self.set_interval(2.0, self._refresh_queue)
        if not self.state.gates:
            self.query_one("#gate_detail", RichLog).write(Text(
                "No gate verdicts recorded in this home yet. Press r for a scripted run: the verifier "
                "re-runs the exploit on 2 vulnerable copies and 1 control, in random order, each with a "
                "fresh nonce, and every run shows up here.", style="dim"))
        self._refresh_roles()
        self._sample_gb10()

    def _subtitle(self) -> None:
        run = " · RUNNING" if self.proc and self.proc.poll() is None else ""
        rep = " · REPLAY" if self.replay_q else ""
        self.sub_title = (f"{self.home} · {self.target} · {self.cve} · Slack "
                          f"{'ON' if self.slack else 'off'}{run}{rep}")

    def _backfill(self) -> None:
        """Fold the whole log into state, but only render the recent tail (fast on a long daemon log)."""
        evs = list(ev_mod._events(self.events)) if self.events.exists() else []
        self.pos = self.events.stat().st_size if self.events.exists() else 0
        for ev in evs[:-300]:
            self._fold(ev)
        for ev in evs[-300:]:
            self._handle(ev)

    def _poll(self) -> None:
        if self.replay_q:
            self._replay_tick()
        elif self.events.exists():
            with self.events.open("rb") as f:
                f.seek(self.pos)
                for raw in f:
                    if not raw.endswith(b"\n"):
                        break   # half-written: next poll
                    self.pos += len(raw)
                    try:
                        ev = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(ev, dict) and "kind" in ev:
                        self._handle(ev)
        self._subtitle()

    def _fold(self, ev: dict) -> None:
        self.flock.apply(ev)
        self.state.apply(ev)
        if ev.get("kind") == "gate_report":
            self._add_gate_row(self.state.gates[-1])

    def _handle(self, ev: dict, replay: bool = False) -> None:
        self._fold(ev)
        log = self.query_one("#log", RichLog)
        width = max(60, (log.size.width or 100) - 4)
        for ln in render_lines(ev, width):
            log.write(Text.from_ansi(("\033[1;7;33mREPLAY\033[0m " if replay else "") + ln))
        self.query_one("#item", Static).update(item_panel(self.state))

    # ----- panels -----
    def _draw_flock(self) -> None:
        w = self.query_one("#flock", Static)
        cols = max(40, w.size.width or 80)
        roles = list(mascots.ROLE_COLORS)
        label_w = max(mascots.W - 2, min(mascots.LABEL_W, (cols + 2) // len(roles) - 4))
        rows = mascots._row(self.flock.now(time.time()), time.time(), "truecolor", label_w)
        w.update(Text.from_ansi("\n".join(rows)))

    @work(thread=True, exclusive=True, group="gb10")
    def _sample_gb10(self) -> None:
        from wreckless.metrics import Monitor
        if not hasattr(self, "_mon"):
            self._mon = Monitor()
        snap = self._mon.sample()
        self.call_from_thread(self.query_one("#gb10", Static).update, gb10_text(snap))

    def _refresh_queue(self) -> None:
        t = self.query_one("#queue_table", DataTable)
        rows = queue_rows(self.home / "queue.db")
        t.clear()
        for r in rows:
            color = "green" if r[3] in ("verified", "patched", "notified") else \
                "red" if r[3] in ("rejected", "patch_failed", "failed") else "yellow"
            t.add_row(r[0], r[1], r[2] or "—", Text(r[3], style=color), r[4], (r[5] or "")[:70])

    def _add_gate_row(self, g: dict) -> None:
        word = ("VERIFIED" if g.get("strength") == "verified" else "REACHABLE") if g.get("passed") else "REJECTED"
        self.query_one("#gates", DataTable).add_row(
            time.strftime("%H:%M:%S", time.localtime(g.get("t", 0))), g.get("item") or "—", g.get("script"),
            g.get("control"), Text(word, style="green" if g.get("passed") else "bold red"),
            key=str(len(self.state.gates) - 1))

    def on_data_table_row_highlighted(self, e: DataTable.RowHighlighted) -> None:
        if e.data_table.id == "gates" and e.row_key.value is not None:
            g = self.state.gates[int(e.row_key.value)]
            out = self.query_one("#gate_detail", RichLog)
            out.clear()
            for ln in render_lines({"kind": "gate_report", "actor": "gate", "t": g.get("t", 0),
                                    **{k: g[k] for k in ("script", "control", "flaw", "runs", "passed",
                                                         "strength", "reason")}}, 90):
                out.write(Text.from_ansi(ln))
            out.write(Text(f"\nitem {g.get('item')} · each copy got a fresh nonce; the control must stay clean",
                           style="dim"))
        elif e.data_table.id == "roles" and e.row_key.value:
            self.role = e.row_key.value
            self._load_options(self.role)

    # ----- models -----
    def _refresh_roles(self) -> None:
        t = self.query_one("#roles", DataTable)
        t.clear()
        names = {"red": "red  (Scout + Ralph)", "blue": "blue (Felix)", "victim": "victim (target LLM)"}
        for role, ep in models.current().items():
            t.add_row(names[role], ep.model, ep.url, key=role)

    @work(thread=True, exclusive=True, group="opts")
    def _load_options(self, role: str) -> None:
        opts = models.options(role)
        self.call_from_thread(self._show_options, role, opts)

    def _show_options(self, role: str, opts: list) -> None:
        self.opts = opts
        ol = self.query_one("#opts", OptionList)
        ol.clear_options()
        tag = {"ready": ("READY", "green"), "swap": ("SWAP ", "yellow"), "missing": ("  —  ", "dim")}
        for i, o in enumerate(opts):
            word, color = tag[o.status]
            ol.add_option(ListOption(Text.assemble((f"[{word}] ", color), (o.label, "bold"), f"  {o.detail}"),
                                     id=str(i), disabled=o.status == "missing"))
        ol.border_title = f"options for {role} (Enter: READY = switch now, SWAP = unload + load on its port)"

    def on_option_list_option_selected(self, e: OptionList.OptionSelected) -> None:
        o = self.opts[int(e.option.id)]
        log = self.query_one("#swaplog", RichLog)
        if o.status == "ready":
            models.switch(self.role, o.url, o.model)
            log.write(Text(f"{time.strftime('%H:%M:%S')} {self.role} → {o.model} @ {o.url} (switch; next item)",
                           style="green"))
            self._refresh_roles()
            return

        def go(ok: bool | None) -> None:
            if ok:
                self._swap(self.role, o)
        self.push_screen(Confirm(f"Swap {self.role}: unload its current model and load\n{o.label}\n\n{o.detail}\n\n"
                                 "The role is offline until the new model answers (vLLM: minutes).\n"
                                 "If it fails to load, the old model is started again."), go)

    @work(thread=True, exclusive=True, group="swap")
    def _swap(self, role: str, o) -> None:
        log = self.query_one("#swaplog", RichLog)
        say = lambda m: self.call_from_thread(log.write, Text(f"{time.strftime('%H:%M:%S')} {m}"))  # noqa: E731
        say(f"swap {role} → {o.label} …")
        ok = models.swap(role, o, log=say)
        say("done" if ok else "FAILED (see above)")
        self.call_from_thread(self._refresh_roles)
        self.call_from_thread(self._load_options, role)

    # ----- actions -----
    def action_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    def action_cycle_cve(self) -> None:
        self.cve = CVES[(CVES.index(self.cve) + 1) % len(CVES)]
        self._subtitle()

    def action_cycle_target(self) -> None:
        self.target = TARGETS[(TARGETS.index(self.target) + 1) % len(TARGETS)]
        self._subtitle()

    def action_toggle_slack(self) -> None:
        self.slack = not self.slack
        self.notify(f"Slack {'ON: launched runs post cards' if self.slack else 'off: cards go to the outbox'}")
        self._subtitle()

    def action_launch(self, llm: bool) -> None:
        if self.proc and self.proc.poll() is None:
            self.notify("a run is already going", severity="warning")
            return
        cmd = [sys.executable, "-m", "wreckless", "run", "--cve", self.cve, "--target", self.target,
               "--home", str(self.home)] + (["--demo-mode"] if llm else ["--no-llm"])
        (ROOT / "logs").mkdir(exist_ok=True)
        with open(ROOT / "logs" / "tui_run.log", "ab") as logf:   # the child keeps its own copy of the fd
            self.proc = subprocess.Popen(cmd, cwd=ROOT, env=run_env(self.slack), stdout=logf, stderr=logf,
                                         stdin=subprocess.DEVNULL)
        self.query_one(TabbedContent).active = "live"
        self.notify(f"{'demo' if llm else 'scripted'} run: {self.cve} on {self.target}"
                    + (" · Slack ON" if self.slack else ""))

    def action_replay(self) -> None:
        self._start_replay(self.events)

    def _start_replay(self, path: Path) -> None:
        evs = list(ev_mod._events(path)) if path.exists() else []
        done = [e["item"] for e in evs if e.get("kind") == "transition" and e.get("to") in FINAL and e.get("item")]
        if not done:
            self.notify("nothing recorded to replay yet", severity="warning")
            return
        last = done[-1]
        self.replay_q = [e for e in evs if e.get("item") in (last, None) and e["t"] >= next(
            x["t"] for x in evs if x.get("item") == last)]
        self.replay_t0 = (time.time(), self.replay_q[0]["t"])
        self.flock, self.state = mascots.Flock(), RunState()
        self.query_one("#gates", DataTable).clear()   # its row keys index state.gates
        log = self.query_one("#log", RichLog)
        log.clear()
        log.write(Text.from_ansi(f"\033[1;7;33m REPLAY of {last} · recorded "
                                 f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.replay_q[0]['t']))} \033[0m"))
        self.query_one(TabbedContent).active = "live"

    def _replay_tick(self) -> None:
        wall0, rec0 = self.replay_t0
        while self.replay_q and self.replay_q[0]["t"] - rec0 <= (time.time() - wall0):
            self._handle(self.replay_q.pop(0), replay=True)
        if not self.replay_q:
            self.query_one("#log", RichLog).write(Text.from_ansi("\033[1;7;33m END OF REPLAY \033[0m"))


def main(home: Path, replay: Path | None = None) -> None:
    WrecklessApp(home, replay).run()
