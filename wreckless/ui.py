"""Color-coded role mascots for terminal output. Every line is also sent to the event sink."""
import sys
import time

RESET = "\033[0m"
ROLES = {
    "purple": ("\033[1;35m", "🕵️ ", "PURPLE/Fedora"),
    "red": ("\033[1;31m", "🎩", "RED/TopHat"),
    "blue": ("\033[1;34m", "👷", "BLUE/HardHat"),
    "gate": ("\033[1;33m", "🔒", "VERIFY-GATE"),
    "core": ("\033[1;37m", "⚙️ ", "NEMOCLAW"),
}

# Set by EventLog so terminal output can be replayed later (role, kind, text) -> None.
SINK = None


def _emit(role: str, kind: str, text: str) -> None:
    if SINK:
        SINK(role, kind, text)


def say(role: str, msg: str, _record: bool = True) -> None:
    color, icon, tag = ROLES[role]
    ts = time.strftime("%H:%M:%S")
    print(f"{color}{ts} {icon} [{tag}]{RESET} {msg}", flush=True)
    if _record:
        _emit(role, "say", msg)


def detail(role: str, msg: str, limit: int = 600, _record: bool = True) -> None:
    color = ROLES[role][0]
    if len(msg) > limit:
        msg = msg[:limit] + " …"
    for line in msg.splitlines() or [""]:
        print(f"{color}   │{RESET} {line}", flush=True)
    if _record:
        _emit(role, "detail", msg)


def banner(text: str, _record: bool = True) -> None:
    bar = "═" * (len(text) + 4)
    print(f"\n\033[1m╔{bar}╗\n║  {text}  ║\n╚{bar}╝{RESET}\n", file=sys.stdout, flush=True)
    if _record:
        _emit("core", "banner", text)
