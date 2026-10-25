"""Color-coded role mascots for terminal output. Every line is also sent to the event sink.

Colour policy (checked on every call, so tests and pipes behave):
  * ``NO_COLOR`` set (any non-empty value)  -> plain text, never an escape code
  * stdout not a TTY (CI, pipe, file)       -> plain text, unless ``FORCE_COLOR`` is set
Untrusted text (exploit output, LLM chatter) is sanitised on every write: colour codes
survive in colour mode, but OSC (title/clipboard), cursor movement and other control
characters never reach the terminal.

Honesty rule: these functions only *render* what the pipeline recorded. ``intrusion`` and
``patch_validated`` must be called only after the queue reached that state, and
``scoreboard`` shows the booleans it is given; ``False`` is a FAIL, ``None`` is n/a.

Replay: each display function records its arguments as an event of the same ``kind``;
``events.replay`` calls it again with ``_record=False`` (see ``REPLAYABLE``).
"""
import os
import re
import shutil
import sys
import threading
import time

RESET = "\033[0m"
ROLES = {
    "purple": ("\033[1;35m", "🕵️ ", "PURPLE/Fedora"),
    "red": ("\033[1;31m", "🎩", "RED/TopHat"),
    "blue": ("\033[1;34m", "👷", "BLUE/HardHat"),
    "gate": ("\033[1;33m", "🔒", "VERIFY-GATE"),
    "core": ("\033[1;37m", "⚙️ ", "NEMOCLAW"),
}

BOLD, DIM = "\033[1m", "\033[2m"
REVERSE = "\033[1;7;33m"   # replay marker: bold reverse-video yellow, hard to miss
GREEN, RED, CYAN = "\033[1;32m", "\033[1;31m", "\033[36m"
ON_RED, ON_GREEN = "\033[41;97;1m", "\033[42;30;1m"
PLAIN_WIDTH = 72
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# OSC (ESC ] ... BEL|ST), non-colour CSI, other ESC sequences, C0/C1 controls except \t \n
_UNSAFE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b\[[0-9;?]*[ -/]*[@-ln-~]"
                     r"|\x1b[^\[\]]|[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f\x80-\x9f]")
_LOCK = threading.RLock()  # worker threads share stdout; multi-line panels must not interleave

MASCOTS = {
    "purple": ("intel analyst · reads the advisory, forms the hypothesis", [
        r"     .-'''-.    ",
        r"   _/_______\_  ",
        r"     ( -_- )    ",
        r"     /|   |\o-- ",
        r"      /   \     ",
    ]),
    "red": ("exploit crafter · proves the bug is real, in the sandbox", [
        r"      _____     ",
        r"      |   |     ",
        r"    __|___|__   ",
        r"     ( >_< )    ",
        r"     /|   |\ /  ",
    ]),
    "blue": ("patch engineer · fixes it, then the orchestrator checks it", [
        r"      _____     ",
        r"    /_/___\_\   ",
        r"     ( ^_^ )    ",
        r"     /|   |\-[] ",
        r"      /   \     ",
    ]),
    "gate": ("verify gate · fresh nonce, oracle must be hit from victim code", [
        r"     .-----.    ",
        r"     | o o |    ",
        r"    _|_____|_   ",
        r"    |  [#]  |   ",
        r"    |_______|   ",
    ]),
    "core": ("orchestrator · candidate queue + per-item lifecycle", [
        r"    [=======]   ",
        r"    | (o o) |<> ",
        r"    |  \=/  |   ",
        r"    /|_____|\   ",
        r"     //   \\    ",
    ]),
}

# Set by EventLog so terminal output can be replayed later: (role, kind, **data) -> None.
SINK = None
REPLAYABLE = {"say", "detail", "banner", "mascot", "intrusion", "diff", "scoreboard",
              "patch_validated", "notified", "gb10_panel"}


def _emit(role: str, kind: str, **data) -> None:
    if SINK:
        SINK(role, kind, **data)


def color_enabled(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def strip_ansi(text: str) -> str:
    return _UNSAFE.sub("", _ANSI.sub("", text))


def sanitize(text: str) -> str:
    """Drop everything a terminal would act on except colour (SGR) codes."""
    return _UNSAFE.sub("", text)


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if color_enabled() else text


def _out(text: str) -> None:
    with _LOCK:
        print(sanitize(text) if color_enabled() else strip_ansi(text), flush=True)


def _width() -> int:
    if not color_enabled():
        return PLAIN_WIDTH
    return max(40, min(shutil.get_terminal_size((PLAIN_WIDTH, 24)).columns, 110))


def _animate() -> bool:
    return color_enabled() and sys.stdout.isatty() and not os.environ.get("WRECKLESS_NO_ANIM")


# True while `wreckless replay` renders: every trace line is marked, not just the banners.
REPLAYING = False


def say(role: str, msg: str, ts: float | None = None, _record: bool = True) -> None:
    """One trace line. ``ts`` lets replay print the original wall-clock time."""
    color, icon, tag = ROLES[role]
    stamp = time.strftime("%H:%M:%S", time.localtime(ts))
    mark = _c(REVERSE, "REPLAY") + " " if REPLAYING else ""
    _out(f"{mark}{_c(color, f'{stamp} {icon} [{tag}]')} {msg}")
    if _record:
        _emit(role, "say", text=msg)


def detail(role: str, msg: str, limit: int = 600, _record: bool = True) -> None:
    color = ROLES[role][0]
    if len(msg) > limit:
        msg = msg[:limit] + " …"
    with _LOCK:
        for line in msg.splitlines() or [""]:
            _out(f"{_c(color, '   │')} {line}")
    if _record:
        _emit(role, "detail", text=msg)


def banner(text: str, _record: bool = True) -> None:
    bar = "═" * (len(text) + 4)
    _out("\n" + _c(BOLD, f"╔{bar}╗\n║  {text}  ║\n╚{bar}╝") + "\n")
    if _record:
        _emit("core", "banner", text=text)


def mascot(role: str, _record: bool = True) -> None:
    """Role mascot, printed when the role enters the stage."""
    color, icon, tag = ROLES[role]
    caption, art = MASCOTS[role]
    side = {1: _c(color, f"{icon} {tag}"), 2: _c(DIM, caption)}
    with _LOCK:
        _out("")
        for i, line in enumerate(art):
            _out(f"{_c(color, line)}  {side.get(i, '')}".rstrip())
    if _record:
        _emit(role, "mascot")


def transition(item: str, frm: str, to: str, actor: str, ts: float | None = None) -> None:
    """Lifecycle line. The queue records the transition event itself, so nothing is emitted."""
    say("core", f"{item} {_c(DIM, 'state')} {frm} → {_c(BOLD, to)} {_c(DIM, f'(actor: {actor})')}",
        ts=ts, _record=False)


def intrusion(item: str, script: str, source: str, _record: bool = True) -> None:
    """Full-width red flash. Call only after the item reached ``verified``."""
    if _record:
        _emit("red", "intrusion", item=item, script=script, source=source)
    w = _width()
    title = " INTRUSION · EXPLOIT VERIFIED "
    body = f"{item} · {script} ({source}) · oracle hit from victim code"
    if not color_enabled():
        with _LOCK:
            _out("!" * w)
            _out(title.center(w, "!"))
            _out(body.center(w))
            _out("!" * w)
        return
    lines = [" " * w, title.center(w), body[:w].center(w), " " * w]
    with _LOCK:  # the flash moves the cursor up; no other thread may print in between
        for i in range(3 if _animate() else 0):
            style = ON_RED if i % 2 == 0 else "\033[7;31;1m"
            for ln in lines:
                print(f"{style}{ln}{RESET}", flush=True)
            time.sleep(0.12)
            print(f"\033[{len(lines)}F", end="", flush=True)
        for ln in lines:
            print(f"{ON_RED}{ln}{RESET}", flush=True)


def diff(role: str, text: str, limit: int = 1500, _record: bool = True) -> None:
    """Unified diff with +green / -red; same gutter as ``detail``."""
    if _record:
        _emit(role, "diff", text=text, limit=limit)
    color = ROLES[role][0]
    if len(text) > limit:
        text = text[:limit] + " …"
    with _LOCK:
        for line in text.splitlines() or [""]:
            if line.startswith(("+++", "---", "diff --git", "index ")):
                body = _c(BOLD, line)
            elif line.startswith("+"):
                body = _c(GREEN, line)
            elif line.startswith("-"):
                body = _c(RED, line)
            elif line.startswith("@@"):
                body = _c(CYAN, line)
            else:
                body = line
            _out(f"{_c(color, '   │')} {body}")


def scoreboard(regression, functional, exploit_blocked, hardening: str | None = None,
               _record: bool = True) -> bool:
    """Validation board. ``False`` is FAIL; a ``None`` regression (no held-out test exists,
    e.g. a Red-hunt finding) is n/a, matching ``blue.Validation.ok``. Returns the verdict."""
    if _record:
        _emit("blue", "scoreboard", regression=regression, functional=functional,
              exploit_blocked=exploit_blocked, hardening=hardening)
    checks = [("held-out regression (WreckLess)", regression, True),
              ("functional test suite (victim app)", functional, False),
              ("exploit replay blocked", exploit_blocked, False)]
    counted = [(name, v) for name, v, optional in checks if not (optional and v is None)]
    ok = all(v is True for _, v in counted)
    inner = 44
    head = " VALIDATION · run by orchestrator "
    with _LOCK:
        _out(f"   ┌{head.center(inner, '─')}┐")
        for name, v, optional in checks:
            mark = (_c(DIM, " n/a  ") if optional and v is None else
                    _c(GREEN, " PASS ") if v is True else _c(ON_RED, " FAIL "))
            _out(f"   │ {name:<{inner - 9}} {mark} │")
        if hardening:
            _out(f"   │ {'hardening probes (not gating)':<{inner - 9}} {hardening:^6} │")
        passed = sum(v is True for _, v in counted)
        verdict = f"{passed}/{len(counted)} passed · " + ("ALL PASS" if ok else "FAILED — needs a human")
        _out(f"   └{'─' * inner}┘  " + _c(GREEN if ok else RED, verdict))
    return ok


def patch_validated(item: str, branch: str, commit: str, source: str, _record: bool = True) -> None:
    """Green panel. Call only after the item reached ``patched``."""
    if _record:
        _emit("blue", "patch_validated", item=item, branch=branch, commit=commit, source=source)
    w = min(_width(), 72)
    rows = [" PATCH VALIDATED ", f"item    {item}", f"branch  {branch}", f"commit  {commit[:12]}",
            f"patch   {source}"]
    with _LOCK:
        if not color_enabled():
            _out("=" * w)
            for r in rows:
                _out(f"| {r.strip():<{w - 4}} |")
            _out("=" * w)
            return
        _out(f"{ON_GREEN}{' ' * w}{RESET}")
        _out(f"{ON_GREEN}{rows[0].center(w)}{RESET}")
        for r in rows[1:]:
            _out(f"{ON_GREEN}  {r:<{w - 2}}{RESET}")
        _out(f"{ON_GREEN}{' ' * w}{RESET}")


def notified(item: str, channel: str, ts: float | None = None, _record: bool = True) -> None:
    """Where the final fix-branch card actually went (outbox means Slack was NOT reached)."""
    if _record:
        _emit("core", "notified", item=item, channel=channel)
    where = ("Slack" if channel.startswith("slack") else
             "local outbox logs/slack_outbox.jsonl (Slack not configured / unreachable)")
    say("core", f"✅ {item} fix-branch card (local, pending review) → {where} [{channel}]", ts=ts, _record=False)


def _bar(frac: float, width: int) -> str:
    n = max(0, min(width, round(frac * width)))
    return "█" * n + "░" * (width - n)


def gb10_panel(mem_total_gb: float, mem_used_gb: float, ports: list[dict], _record: bool = True) -> None:
    """GB10 unified-memory + per-port throughput panel. ``ports`` are ``metrics.PortStats`` dicts;
    a down port is shown as DOWN, tokens/sec as '—' until there are two samples."""
    if _record:
        _emit("core", "gb10_panel", mem_total_gb=mem_total_gb, mem_used_gb=mem_used_gb, ports=ports)
    inner = 62
    used = mem_used_gb / mem_total_gb if mem_total_gb else 0
    up = [p for p in ports if p.get("up")]

    def row(text: str) -> None:  # pad by visible width so colour codes don't skew the border
        _out(f"   │ {text}{' ' * max(0, inner - 1 - len(strip_ansi(text)))}│")

    with _LOCK:
        _out(f"   ┌{' GB10 · unified memory · loopback only '.center(inner, '─')}┐")
        row(f"mem {_bar(used, 30)} {mem_used_gb:5.1f}/{mem_total_gb:.0f} GB {used:4.0%}")
        for p in ports:
            name = f"{p['role']} :{p['port']}"
            if not p.get("up"):
                row(f"{name:<17} {_c(RED, 'DOWN')} {p.get('error') or ''}")
                continue
            share = f"{p['mem_util'] * mem_total_gb:3.0f} GB" if p.get("mem_util") else "  ? GB"
            tok = f"{p['tok_s']:6.1f} tok/s" if p.get("tok_s") is not None else "     — tok/s"
            kv = f"kv {p['kv_usage']:4.0%}" if p.get("kv_usage") is not None else "kv    ?"
            row(f"{name:<17} {share} {_c(GREEN, tok)}  {kv}  "
                f"{p.get('running', 0):.0f} run {p.get('waiting', 0):.0f} wait")
        total_tok = sum(p.get("tok_s") or 0 for p in up)
        _out(f"   └{'─' * inner}┘  {len(up)}/{len(ports)} up · {total_tok:.1f} tok/s total")


def replay_tag(source: str, speed: float, recorded: float | None = None) -> None:
    when = ""
    if recorded is not None:
        age = max(0, time.time() - recorded)
        ago = (f"{age / 86400:.0f} d" if age >= 86400 else f"{age / 3600:.0f} h" if age >= 3600
               else f"{age / 60:.0f} min")
        when = f" · recorded {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(recorded))} ({ago} ago)"
    _out(_c(REVERSE, f"[REPLAY of {source} · recorded run, not live{when} · speed x{speed:g}]"))
