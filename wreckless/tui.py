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
from textual.containers import Horizontal, Vertical, VerticalScroll
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
    phase: str = "idle"                            # plain-language step (STEPS / HEADLINES)
    t0: float | None = None
    t_end: float | None = None

    def apply(self, ev: dict) -> None:
        kind, item = ev.get("kind"), ev.get("item")
        self._phase(ev)
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


    PHASE_OF = {"purple": "find", "red": "attack", "gate": "prove", "blue": "fix", "core": "approve"}
    END_PHASE = {"rejected": "rejected", "patch_failed": "fix_failed", "notified": "done", "failed": "failed"}

    def _phase(self, ev: dict) -> None:
        kind = ev.get("kind")
        if kind == "enqueue" or (kind == "mascot" and ev.get("actor") == "purple"):
            self.phase, self.t0, self.t_end = "find", ev.get("t"), None
        elif kind == "mascot" and ev.get("actor") in self.PHASE_OF:
            if self.phase not in self.END_PHASE.values() or ev.get("actor") == "purple":
                self.phase = self.PHASE_OF[ev["actor"]]
        elif kind == "gate_report":
            self.phase = "prove"
        elif kind == "transition" and ev.get("to") in self.END_PHASE:
            self.phase, self.t_end = self.END_PHASE[ev["to"]], ev.get("t")


# The five steps a viewer follows, and one plain sentence for each moment.
STEPS = [("find", "Find", "Scout"), ("attack", "Attack", "Ralph"), ("prove", "Prove", "Verifier"),
         ("fix", "Fix", "Felix"), ("approve", "Approve", "a human")]
STEP_AT = {"idle": -1, "find": 0, "attack": 1, "prove": 2, "fix": 3, "approve": 4, "done": 5,
           "rejected": 2, "fix_failed": 3, "failed": -1}
HEADLINES = {
    "idle": "Press ▶ Run the demo. Five AI agents find, prove and fix a real security bug, all on this machine.",
    "find": "Scout reads the security advisory and works out where the bug lives.",
    "attack": "Ralph writes a real attack and fires it inside a locked sandbox.",
    "prove": "The Verifier re-runs the attack on fresh copies: it must break the buggy code and fail on the "
             "fixed code, or it does not count.",
    "fix": "Felix writes a patch. Then it is tested: the attack must fail now, and nothing else may break.",
    "approve": "The fix is ready and goes to Slack. A human approves it from anywhere.",
    "done": "Fix ready for review in Slack. Nothing ships until a human clicks Approve.",
    "rejected": "Not proven: the Verifier rejected the attack, so nothing gets patched. No false alarms.",
    "fix_failed": "The patch did not pass every test, so it is held back for a human. Nothing broken ships.",
    "failed": "Something crashed. The item was stopped safely.",
}
CVE_NAMES = {"CVE-2024-21513": "LangChain SQL code injection", "CVE-2023-44467": "LangChain sandbox escape"}
TARGET_NAMES = {"victim_app": "mini replica", "langchain": "real LangChain code"}
ROLE_CARDS = {"red": ("Scout + Ralph", "investigate & attack"), "blue": ("Felix", "writes the fix"),
              "victim": ("Target app's AI", "the one being attacked")}


def steps_bar(st: RunState) -> Text:
    at, bad = STEP_AT.get(st.phase, -1), st.phase in ("rejected", "fix_failed")
    t = Text(justify="center")
    for i, (_, label, who) in enumerate(STEPS):
        if i:
            t.append("  ──  ", style="dim")
        if bad and i == at:
            t.append(f" ✗ {i + 1} {label} ", style="bold red")
        elif i < at or st.phase == "done":
            t.append(f" ✓ {i + 1} {label} ", style="")
        elif i == at:
            t.append(f" ▶ {i + 1} {label} ", style="bold underline")
        else:
            t.append(f"   {i + 1} {label} ", style="dim")
    t.append("\n")
    for i, (_, _, who) in enumerate(STEPS):
        if i:
            t.append("      ")
        t.append(f"{who:^{len(STEPS[i][1]) + 6}}", style="dim")
    return t


def headline(st: RunState, override: str | None = None) -> Text:
    if override:
        return Text(override, style="bold", justify="center")
    text = HEADLINES.get(st.phase, "")
    if st.phase in ("done", "rejected", "fix_failed") and st.t0 and st.t_end:
        text += f"  ({st.t_end - st.t0:.0f} s)"
    color = {"rejected": "bold red", "fix_failed": "bold red", "failed": "bold red"}
    return Text(text, style=color.get(st.phase, "bold"), justify="center")


def item_panel(st: RunState) -> Text:
    t = Text()
    t.append("ITEM  ", style="bold")
    t.append(f"{st.item or '—'}\n")
    for n, s in enumerate(st.states):
        bad = s in ("rejected", "patch_failed", "failed")
        t.append(f"  → {s}\n", style="red" if bad else "bold" if n == len(st.states) - 1 else "dim")
    if st.gate:
        word = ("VERIFIED" if st.gate.get("strength") == "verified" else "REACHABLE") \
            if st.gate.get("passed") else "REJECTED"
        t.append("\nGATE  ", style="bold")
        t.append(word + "\n", style="bold" if st.gate.get("passed") else "bold red")
        t.append(f"  control: {st.gate.get('control')}\n", style="dim")
        if st.gate.get("flaw"):
            t.append(f"  flaw: {st.gate['flaw']}\n", style="dim")
    if st.score:
        t.append("\nCHECKS\n", style="bold")
        for label, k in (("held-out regression", "regression"), ("functional suite", "functional"),
                         ("exploit blocked", "exploit_blocked")):
            v = st.score.get(k)
            t.append(f"  {'PASS' if v else 'n/a ' if v is None else 'FAIL'}  ",
                     style="bold" if v else "dim" if v is None else "bold red")
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
        t.append("█" * int(frac * 20))
        t.append("░" * (20 - int(frac * 20)), style="dim")
        t.append(f" {snap.mem_used_gb:.0f}/{snap.mem_total_gb:.0f} GB\n")
    else:
        t.append("MEMORY ", style="bold")
        t.append("n/a here (no /proc/meminfo: not the GB10)\n", style="dim")
    for p in snap.ports:
        t.append(f"{p.role:<12}", style="bold")
        if not p.up:
            t.append(f":{p.port} down\n", style="dim")
            continue
        rate = f"{p.tok_s:5.1f} tok/s" if p.tok_s is not None else "  …   tok/s"
        t.append(f":{p.port} {rate}  run {p.running:.0f} wait {p.waiting:.0f}  {p.ckpt or p.model or ''}\n")
    return t


def calm(line: str) -> Text:
    """An ANSI line as Text with foreground colour only: no background blocks, no reverse video."""
    from rich.style import Style
    text = Text.from_ansi(line)
    spans = []
    for sp in text.spans:
        st = sp.style if isinstance(sp.style, Style) else Style.parse(str(sp.style))
        # a coloured block (e.g. black on green) keeps its colour as the text colour instead
        color = st.bgcolor if st.bgcolor and not st.bgcolor.is_default else st.color
        spans.append(sp._replace(style=Style(color=color, bold=st.bold or bool(st.bgcolor), dim=st.dim,
                                             italic=st.italic)))
    text.spans = spans
    return text


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
    #box { width: 76; height: auto; border: round $foreground 40%; background: $surface; padding: 1 2; }
    #box Horizontal { height: auto; margin-top: 1; }
    """

    def __init__(self, text: str, yes: str = "Load it"):
        super().__init__()
        self.text, self.yes = text, yes

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(self.text)
            with Horizontal():
                yield Button(self.yes, variant="primary", id="yes")
                yield Button("Cancel", id="no")

    def on_button_pressed(self, e: Button.Pressed) -> None:
        self.dismiss(e.button.id == "yes")


class ModelPicker(ModalScreen):
    """Plain chooser for one agent's AI model. Returns ("switch"|"swap", Option) or None."""
    DEFAULT_CSS = """
    ModelPicker { align: center middle; }
    #pick { width: 96; height: 26; border: round $foreground 40%; background: $surface; padding: 1 2; }
    #pick OptionList { height: 1fr; margin: 1 0; }
    #pick Horizontal { height: auto; }
    """
    BINDINGS = [Binding("escape", "cancel", "Close")]

    def __init__(self, role: str):
        super().__init__()
        self.role, self.opts = role, []

    def compose(self) -> ComposeResult:
        who, job = ROLE_CARDS[self.role]
        with Vertical(id="pick"):
            yield Label(Text.assemble(("Choose the AI model for ", "bold"), (who, "bold underline"),
                                      (f"  ({job})", "dim")))
            yield Label(Text("ready: already running, switches instantly.  load: stored on disk, "
                             "loaded into memory in place of the current one (a few minutes).", style="dim"))
            yield OptionList(id="choices")
            with Horizontal():
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#choices", OptionList).add_option(ListOption("looking for models…", disabled=True))
        self._load()

    @work(thread=True, exclusive=True)
    def _load(self) -> None:
        opts = models.options(self.role)
        self.app.call_from_thread(self._show, opts)

    def _show(self, opts: list) -> None:
        self.opts = opts
        ol = self.query_one("#choices", OptionList)
        ol.clear_options()
        if not opts:
            ol.add_option(ListOption("no models found (is vLLM or Ollama running?)", disabled=True))
        for n, o in enumerate(opts):
            if o.status == "ready":
                tag, note = ("● ready  ", "bold"), "running, switch now"
            elif o.status == "swap":
                tag, note = ("○ load   ", ""), "on disk, load it in"
            else:
                tag, note = ("  absent ", "dim"), "not downloaded"
            ol.add_option(ListOption(Text.assemble(tag, (o.name, "bold"), f"  {o.blurb}", (f"  · {note}", "dim")),
                                     id=str(n), disabled=o.status == "missing"))

    def on_option_list_option_selected(self, e: OptionList.OptionSelected) -> None:
        o = self.opts[int(e.option.id)]
        self.dismiss(("switch" if o.status == "ready" else "swap", o))

    def on_button_pressed(self, e: Button.Pressed) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class BrainCard(Vertical):
    """One agent: which AI model it uses right now, whether it answers, and a Change button."""

    def __init__(self, role: str):
        super().__init__(id=f"card-{role}", classes="card")
        self.role = role

    def compose(self) -> ComposeResult:
        who, job = ROLE_CARDS[self.role]
        yield Static(Text.assemble((who, "bold"), (f" · {job}", "dim")), classes="who")
        yield Static("…", id=f"model-{self.role}", classes="model")
        yield Button("Change model", id=f"change-{self.role}", classes="change")

    def show(self, up: bool, ckpt: str) -> None:
        name, blurb = models.friendly(ckpt)
        self.query_one(f"#model-{self.role}", Static).update(Text.assemble(
            ("● " if up else "○ ", "" if up else "dim"), (name, "bold"),
            (f"  {'running' if up else 'offline'}", "dim")))


class WrecklessApp(App):
    TITLE = "WreckLess"
    SUB_TITLE = "local AI security team"
    CSS = """
    Screen { background: $background; }
    #hero { height: 16; }
    #stage { width: 3fr; }
    #steps { height: 3; margin-top: 1; content-align: center middle; }
    #headline { height: 2; padding: 0 2; }
    #flock { height: 10; content-align: center middle; }
    #gb10 { width: 1fr; min-width: 36; height: 100%; border: round $foreground 25%; padding: 0 1; }
    #main { height: 1fr; }
    #log { width: 3fr; min-height: 6; border: round $foreground 25%; }
    #item_box { width: 1fr; min-width: 36; border: round $foreground 25%; }
    #controls { height: 3; }
    #controls Button { width: 1fr; min-width: 12; }
    #set_title { height: 2; padding: 1 1 0 1; }
    #brains { height: 7; margin: 1 0; }
    .card { width: 1fr; border: round $foreground 25%; padding: 0 1; }
    .card .change { width: 100%; min-width: 16; height: 3; }
    #adv_title { height: 1; padding: 0 1; }
    #gates { width: 1fr; } #gate_detail { width: 1fr; border: round $foreground 25%; }
    #roles { height: 5; } #opts { height: 1fr; border: round $foreground 25%; }
    #swaplog { height: 8; border: round $foreground 25%; }
    """
    BINDINGS = [
        Binding("r", "launch(False)", "Run demo"), Binding("d", "launch(True)", "Run with AI"),
        Binding("m", "tab('models')", "Settings"), Binding("p", "replay", "Replay"),
        Binding("c", "cycle_cve", "Bug", show=False), Binding("t", "cycle_target", "Code", show=False),
        Binding("s", "toggle_slack", "Slack", show=False),
        Binding("1", "tab('live')", "Live", show=False), Binding("2", "tab('gate')", "Proof", show=False),
        Binding("3", "tab('queue')", "Findings", show=False), Binding("4", "tab('models')", "Settings", show=False),
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
        self.busy: str | None = None   # headline override while a model loads
        self.main = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="live"):
            with TabPane("Live [1]", id="live"):
                with Horizontal(id="hero"):
                    with Vertical(id="stage"):
                        yield Static(id="steps")
                        yield Static(id="headline")
                        yield Static(id="flock")
                    yield Static(id="gb10")
                with Horizontal(id="main"):
                    yield RichLog(id="log", wrap=False, markup=False, max_lines=4000)
                    with VerticalScroll(id="item_box"):
                        yield Static(id="item")
                with Horizontal(id="controls"):
                    yield Button("▶ Run the demo", id="run", variant="primary")
                    yield Button("Run with live AI", id="runai")
                    yield Button("⟲ Replay", id="replay")
                    yield Button("", id="cve")
                    yield Button("", id="target")
                    yield Button("", id="slack")
            with TabPane("Proof [2]", id="gate"):
                with Horizontal():
                    yield DataTable(id="gates", cursor_type="row")
                    yield RichLog(id="gate_detail", wrap=True, markup=False)
            with TabPane("Findings [3]", id="queue"):
                yield DataTable(id="queue_table", cursor_type="row")
            with TabPane("Settings [4]", id="models"):
                yield Static(Text.assemble(("AI models", "bold"), ("   Which local model each agent uses. "
                             "Change one here; it applies from the next finding on.", "dim")), id="set_title")
                with Horizontal(id="brains"):
                    for role in ("red", "blue", "victim"):
                        yield BrainCard(role)
                yield Static(Text("Advanced: every endpoint and option", style="dim"), id="adv_title")
                yield DataTable(id="roles", cursor_type="row")
                yield OptionList(id="opts")
                yield RichLog(id="swaplog", wrap=True, markup=False)
        yield Footer()

    # ----- lifecycle -----
    def on_mount(self) -> None:
        self.main = self.screen   # periodic refreshes must not query a popup that is on top
        self.main.query_one("#gates", DataTable).add_columns("time", "item", "exploit", "control", "verdict")
        self.main.query_one("#queue_table", DataTable).add_columns("item", "source", "cve", "state", "label", "title")
        self.main.query_one("#roles", DataTable).add_columns("role", "uses model", "at")
        self.main.query_one("#item_box").border_title = "this finding"
        self.main.query_one("#gb10", Static).border_title = "GB10 · memory and speed"
        self.main.query_one("#log", RichLog).border_title = "what the agents are doing"
        self.main.query_one("#gate_detail", RichLog).border_title = "the proof"
        self.main.query_one("#opts", OptionList).border_title = "options"
        self.main.query_one("#swaplog", RichLog).border_title = "model changes"
        self._labels()
        if self.replay_from:
            self._start_replay(self.replay_from)
        else:
            self._backfill()
        if not self.state.gates:
            self.main.query_one("#gate_detail", RichLog).write(Text(
                "No proofs recorded yet. Press ▶ Run the demo: the Verifier re-runs the attack on 2 buggy "
                "copies and 1 fixed copy, in random order, each with a fresh secret, and every run shows here.",
                style="dim"))
        self._story()
        self.set_interval(0.25, self._tick(self._poll))
        self.set_interval(1 / 8, self._tick(self._draw_flock))
        self.set_interval(2.0, self._tick(self._sample_gb10))
        self.set_interval(2.0, self._tick(self._refresh_queue))
        self.set_interval(3.0, self._tick(self._probe_brains))
        self._refresh_roles()
        self._sample_gb10()
        self._probe_brains()

    @staticmethod
    def _tick(fn):
        """A timer callback that is quiet while the app is shutting down (widgets already gone)."""
        from textual.css.query import NoMatches

        def run():
            try:
                fn()
            except NoMatches:
                pass
        return run

    def _labels(self) -> None:
        running = bool(self.proc and self.proc.poll() is None)
        self.main.query_one("#cve", Button).label = f"Bug: {CVE_NAMES.get(self.cve, self.cve)}"
        self.main.query_one("#target", Button).label = f"Code: {TARGET_NAMES[self.target]}"
        sl = self.main.query_one("#slack", Button)
        sl.label = "Slack: ON" if self.slack else "Slack: off"
        for b in ("run", "runai"):
            self.main.query_one(f"#{b}", Button).disabled = running
        rep = " · REPLAY" if self.replay_q else ""
        self.sub_title = (f"{self.home} · {self.target} · {self.cve} · Slack "
                          f"{'ON' if self.slack else 'off'}{' · RUNNING' if running else ''}{rep}")

    def _story(self) -> None:
        self.main.query_one("#steps", Static).update(steps_bar(self.state))
        self.main.query_one("#headline", Static).update(headline(self.state, self.busy))

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
        self._labels()
        self._story()

    def _fold(self, ev: dict) -> None:
        self.flock.apply(ev)
        self.state.apply(ev)
        if ev.get("kind") == "gate_report":
            self._add_gate_row(self.state.gates[-1])

    def _handle(self, ev: dict, replay: bool = False) -> None:
        self._fold(ev)
        log = self.main.query_one("#log", RichLog)
        width = max(60, (log.size.width or 100) - 4)
        for ln in render_lines(ev, width):
            log.write(calm(("\033[1mREPLAY\033[0m " if replay else "") + ln))
        self.main.query_one("#item", Static).update(item_panel(self.state))

    # ----- panels -----
    def _draw_flock(self) -> None:
        w = self.main.query_one("#flock", Static)
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
        self.call_from_thread(self.main.query_one("#gb10", Static).update, gb10_text(snap))

    @work(thread=True, exclusive=True, group="brains")
    def _probe_brains(self) -> None:
        for role, ep in models.current().items():
            up, ckpt = models.serving(ep)
            self.call_from_thread(self.main.query_one(f"#card-{role}", BrainCard).show, up, ckpt)

    def _refresh_queue(self) -> None:
        t = self.main.query_one("#queue_table", DataTable)
        rows = queue_rows(self.home / "queue.db")
        t.clear()
        for r in rows:
            color = "red" if r[3] in ("rejected", "patch_failed", "failed") else ""
            t.add_row(r[0], r[1], r[2] or "—", Text(r[3], style=color), r[4], (r[5] or "")[:70])

    def _add_gate_row(self, g: dict) -> None:
        word = ("VERIFIED" if g.get("strength") == "verified" else "REACHABLE") if g.get("passed") else "REJECTED"
        self.main.query_one("#gates", DataTable).add_row(
            time.strftime("%H:%M:%S", time.localtime(g.get("t", 0))), g.get("item") or "—", g.get("script"),
            g.get("control"), Text(word, style="bold" if g.get("passed") else "bold red"),
            key=str(len(self.state.gates) - 1))

    def on_data_table_row_highlighted(self, e: DataTable.RowHighlighted) -> None:
        if e.data_table.id == "gates" and e.row_key.value is not None:
            g = self.state.gates[int(e.row_key.value)]
            out = self.main.query_one("#gate_detail", RichLog)
            out.clear()
            for ln in render_lines({"kind": "gate_report", "actor": "gate", "t": g.get("t", 0),
                                    **{k: g[k] for k in ("script", "control", "flaw", "runs", "passed",
                                                         "strength", "reason")}}, 90):
                out.write(calm(ln))
            out.write(Text("\nHow to read this: the attack ran on two copies of the buggy code and one copy "
                           "with the fix, in random order, each with a fresh secret. It only counts if it "
                           "breaks both buggy copies through the flawed function and fails on the fixed one.",
                           style="dim"))
        elif e.data_table.id == "roles" and e.row_key.value:
            self.role = e.row_key.value
            self._load_options(self.role)

    # ----- models -----
    def _refresh_roles(self) -> None:
        t = self.main.query_one("#roles", DataTable)
        t.clear()
        for role, ep in models.current().items():
            t.add_row(f"{ROLE_CARDS[role][0]} ({role})", ep.model, ep.url, key=role)

    @work(thread=True, exclusive=True, group="opts")
    def _load_options(self, role: str) -> None:
        opts = models.options(role)
        self.call_from_thread(self._show_options, role, opts)

    def _show_options(self, role: str, opts: list) -> None:
        self.opts = opts
        ol = self.main.query_one("#opts", OptionList)
        ol.clear_options()
        tag = {"ready": ("READY", "bold"), "swap": ("LOAD ", ""), "missing": ("  —  ", "dim")}
        for i, o in enumerate(opts):
            word, color = tag[o.status]
            ol.add_option(ListOption(Text.assemble((f"[{word}] ", color), (o.name, "bold"),
                                                   f"  {o.label} · {o.detail}"),
                                     id=str(i), disabled=o.status == "missing"))
        ol.border_title = f"options for {role} (Enter: READY = switch now, LOAD = unload + load on its port)"

    def on_option_list_option_selected(self, e: OptionList.OptionSelected) -> None:
        if e.option_list.id != "opts":
            return
        o = self.opts[int(e.option.id)]
        self._choose(self.role, ("switch" if o.status == "ready" else "swap", o))

    def action_pick(self, role: str) -> None:
        self.push_screen(ModelPicker(role), lambda res: self._choose(role, res))

    def _choose(self, role: str, res) -> None:
        if not res:
            return
        how, o = res
        who = ROLE_CARDS[role][0]
        if how == "switch":
            models.switch(role, o.url, o.model)
            self._note(f"{who} now uses {o.name} (from the next finding on)")
            self.notify(f"{who} → {o.name}", title="Model switched")
            self._refresh_roles()
            self._probe_brains()
            return

        def go(ok: bool | None) -> None:
            if ok:
                self._swap(role, o)
        self.push_screen(Confirm(f"Load {o.name} for {who}?\n\n{o.blurb}\n\nThe model {who} uses now is "
                                 f"unloaded first, then {o.name} is loaded from disk into the same slot. {who} "
                                 "is offline until it answers (a few minutes on the GB10). If it fails to "
                                 "load, the old model comes back."), go)

    def _note(self, msg: str) -> None:
        self.main.query_one("#swaplog", RichLog).write(Text(f"{time.strftime('%H:%M:%S')} {msg}"))

    @work(thread=True, exclusive=True, group="swap")
    def _swap(self, role: str, o) -> None:
        who = ROLE_CARDS[role][0]
        say = lambda m: self.call_from_thread(self._note, m)  # noqa: E731
        self.busy = f"Loading {o.name} into {who}'s slot… {who} is offline until it answers."
        say(f"{who}: unloading, then loading {o.name}")
        ok = models.swap(role, o, log=say)
        self.busy = None
        say(f"{who} now runs {o.name}" if ok else f"{who}: loading {o.name} failed, old model restored")
        self.call_from_thread(self.notify, f"{who} → {o.name}" if ok else f"could not load {o.name}",
                              title="Model loaded" if ok else "Model change failed",
                              severity="information" if ok else "error")
        self.call_from_thread(self._refresh_roles)
        self.call_from_thread(self._probe_brains)

    # ----- buttons + actions -----
    def on_button_pressed(self, e: Button.Pressed) -> None:
        bid = e.button.id or ""
        if bid.startswith("change-"):
            self.action_pick(bid.removeprefix("change-"))
        elif bid in ("run", "runai"):
            self.action_launch(bid == "runai")
        elif bid == "replay":
            self.action_replay()
        elif bid == "cve":
            self.action_cycle_cve()
        elif bid == "target":
            self.action_cycle_target()
        elif bid == "slack":
            self.action_toggle_slack()

    def action_tab(self, tab: str) -> None:
        self.main.query_one(TabbedContent).active = tab

    def action_cycle_cve(self) -> None:
        self.cve = CVES[(CVES.index(self.cve) + 1) % len(CVES)]
        self._labels()

    def action_cycle_target(self) -> None:
        self.target = TARGETS[(TARGETS.index(self.target) + 1) % len(TARGETS)]
        self._labels()

    def action_toggle_slack(self) -> None:
        self.slack = not self.slack
        self.notify("runs now post their card to Slack" if self.slack else "cards stay on this machine (outbox)",
                    title=f"Slack {'ON' if self.slack else 'off'}")
        self._labels()

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
        self.state.phase, self.state.t0 = "find", time.time()
        self.main.query_one(TabbedContent).active = "live"
        self.notify(f"{CVE_NAMES.get(self.cve, self.cve)} · {TARGET_NAMES[self.target]}"
                    + (" · with live AI" if llm else " · scripted"), title="Run started")
        self._labels()

    def action_replay(self) -> None:
        self._start_replay(self.events)

    def _start_replay(self, path: Path) -> None:
        evs = list(ev_mod._events(path)) if path.exists() else []
        done = [e["item"] for e in evs if e.get("kind") == "transition" and e.get("to") in FINAL and e.get("item")]
        if not done:
            self.notify("nothing recorded to replay yet", severity="warning")
            return
        last = done[-1]
        start = next(x["t"] for x in evs if x.get("item") == last)
        self.replay_q = [e for e in evs if e.get("item") in (last, None) and e["t"] >= start - 1]
        self.replay_t0 = (time.time(), self.replay_q[0]["t"])
        self.flock, self.state = mascots.Flock(), RunState()
        self.main.query_one("#gates", DataTable).clear()   # its row keys index state.gates
        log = self.main.query_one("#log", RichLog)
        log.clear()
        log.write(calm(f"\033[1m REPLAY of {last} · recorded "
                                 f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.replay_q[0]['t']))} \033[0m"))
        self.main.query_one(TabbedContent).active = "live"

    def _replay_tick(self) -> None:
        wall0, rec0 = self.replay_t0
        while self.replay_q and self.replay_q[0]["t"] - rec0 <= (time.time() - wall0):
            self._handle(self.replay_q.pop(0), replay=True)
        if not self.replay_q:
            self.main.query_one("#log", RichLog).write(calm("\033[1m END OF REPLAY \033[0m"))


def main(home: Path, replay: Path | None = None) -> None:
    WrecklessApp(home, replay).run()
