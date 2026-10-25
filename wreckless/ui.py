"""Color-coded role mascots for terminal output.

Colour policy (checked on every call, so tests and pipes behave):
  * ``NO_COLOR`` set (any non-empty value)  -> plain text, never an escape code
  * stdout not a TTY (CI, pipe, file)       -> plain text, unless ``FORCE_COLOR`` is set
Plain mode also strips escape codes that callers embed in messages (e.g. LLM output).

Honesty rule: these functions only *render* what the pipeline recorded. ``intrusion`` and
``patch_validated`` must be called only after the state machine reached that state, and
``scoreboard`` shows the booleans it is given; anything not ``True`` is a FAIL.
"""
import os
import re
import shutil
import sys
import time

RESET = "\033[0m"
ROLES = {
    "purple": ("\033[1;35m", "🕵️ ", "PURPLE/Fedora"),
    "red": ("\033[1;31m", "🎩", "RED/TopHat"),
    "blue": ("\033[1;34m", "👷", "BLUE/HardHat"),
    "core": ("\033[1;37m", "⚙️ ", "NEMOCLAW"),
}

BOLD, DIM = "\033[1m", "\033[2m"
GREEN, RED, CYAN = "\033[1;32m", "\033[1;31m", "\033[36m"
ON_RED, ON_GREEN = "\033[41;97;1m", "\033[42;30;1m"
PLAIN_WIDTH = 72
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

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
    "core": ("orchestrator · JSON state machine, owns validation", [
        r"    [=======]   ",
        r"    | (o o) |<> ",
        r"    |  \=/  |   ",
        r"    /|_____|\   ",
        r"     //   \\    ",
    ]),
}


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
    return _ANSI.sub("", text)


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if color_enabled() else text


def _out(text: str) -> None:
    print(text if color_enabled() else strip_ansi(text), flush=True)


def _width() -> int:
    if not color_enabled():
        return PLAIN_WIDTH
    return max(40, min(shutil.get_terminal_size((PLAIN_WIDTH, 24)).columns, 110))


def _animate() -> bool:
    return color_enabled() and sys.stdout.isatty() and not os.environ.get("WRECKLESS_NO_ANIM")


def say(role: str, msg: str, ts: float | None = None) -> None:
    """One trace line. ``ts`` lets replay print the original wall-clock time."""
    color, icon, tag = ROLES[role]
    stamp = time.strftime("%H:%M:%S", time.localtime(ts))
    _out(f"{_c(color, f'{stamp} {icon} [{tag}]')} {msg}")


def detail(role: str, msg: str, limit: int = 600) -> None:
    color = ROLES[role][0]
    if len(msg) > limit:
        msg = msg[:limit] + " …"
    for line in msg.splitlines() or [""]:
        _out(f"{_c(color, '   │')} {line}")


def banner(text: str) -> None:
    bar = "═" * (len(text) + 4)
    _out("\n" + _c(BOLD, f"╔{bar}╗\n║  {text}  ║\n╚{bar}╝") + "\n")


def mascot(role: str) -> None:
    """Role mascot, printed once when the role enters the stage."""
    color, icon, tag = ROLES[role]
    caption, art = MASCOTS[role]
    side = {1: _c(color, f"{icon} {tag}"), 2: _c(DIM, caption)}
    _out("")
    for i, line in enumerate(art):
        _out(f"{_c(color, line)}  {side.get(i, '')}".rstrip())


def transition(frm: str, to: str, actor: str, ts: float | None = None) -> None:
    """State-machine line; rendered from the persisted history entry, live or replayed."""
    say("core", f"{_c(DIM, 'state')} {frm} → {_c(BOLD, to)} {_c(DIM, f'(actor: {actor})')}", ts=ts)


def intrusion(script: str, source: str) -> None:
    """Full-width red flash. Call only after EXPLOIT_VERIFIED was recorded."""
    w = _width()
    title = " INTRUSION · EXPLOIT VERIFIED "
    body = f"{script} ({source}) · oracle hit inside the enclave"
    if not color_enabled():
        _out("!" * w)
        _out(title.center(w, "!"))
        _out(body.center(w))
        _out("!" * w)
        return
    lines = [" " * w, title.center(w), body[:w].center(w), " " * w]
    frames = 3 if _animate() else 0
    for i in range(frames):
        style = ON_RED if i % 2 == 0 else "\033[7;31;1m"
        for ln in lines:
            print(f"{style}{ln}{RESET}", flush=True)
        time.sleep(0.12)
        print(f"\033[{len(lines)}F", end="", flush=True)
    for ln in lines:
        print(f"{ON_RED}{ln}{RESET}", flush=True)


def diff(role: str, text: str, limit: int = 1500) -> None:
    """Unified diff with +green / -red; same gutter as ``detail``."""
    color = ROLES[role][0]
    if len(text) > limit:
        text = text[:limit] + " …"
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


def scoreboard(regression, functional, exploit_blocked, ts: float | None = None) -> bool:
    """3-check board. Anything other than True is a FAIL. Returns the overall verdict."""
    checks = [("held-out regression test (upstream)", regression is True),
              ("functional test suite (victim app)", functional is True),
              ("exploit replay blocked", exploit_blocked is True)]
    ok = all(p for _, p in checks)
    say("blue", f"held-out regression: {'PASS' if checks[0][1] else 'FAIL'} · "
                f"functional: {'PASS' if checks[1][1] else 'FAIL'} · "
                f"exploit blocked: {'YES' if checks[2][1] else 'NO'}", ts=ts)
    inner = 44
    head = " VALIDATION · run by orchestrator "
    _out(f"   ┌{head.center(inner, '─')}┐")
    for name, passed in checks:
        mark = _c(GREEN, " PASS ") if passed else _c(ON_RED, " FAIL ")
        _out(f"   │ {name:<{inner - 9}} {mark} │")
    verdict = f"{sum(p for _, p in checks)}/3 " + ("ALL PASS" if ok else "FAILED — needs a human")
    _out(f"   └{'─' * inner}┘  " + _c(GREEN if ok else RED, verdict))
    return ok


def patch_validated(branch: str, commit: str, source: str) -> None:
    """Green panel. Call only after PATCH_VALIDATED was recorded."""
    w = min(_width(), 72)
    rows = [" PATCH VALIDATED ", f"branch  {branch}", f"commit  {commit[:12]}",
            f"patch   {source}"]
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


def notified(channel: str, ts: float | None = None) -> None:
    """Where the 'Draft PR Ready' card actually went (outbox means Slack was NOT reached)."""
    where = ("Slack" if channel.startswith("slack") else
             "local outbox logs/slack_outbox.jsonl (Slack not configured / unreachable)")
    say("core", f"✅ Draft PR Ready card → {where} [{channel}]", ts=ts)


def replay_tag(run_id: str, speed: float) -> None:
    _out(_c(DIM, f"[REPLAY of {run_id} · recorded run, not live · speed x{speed:g}]"))
