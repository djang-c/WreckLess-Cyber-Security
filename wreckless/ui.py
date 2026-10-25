"""Color-coded role mascots for terminal output."""
import sys
import time

RESET = "\033[0m"
ROLES = {
    "purple": ("\033[1;35m", "🕵️ ", "PURPLE/Fedora"),
    "red": ("\033[1;31m", "🎩", "RED/TopHat"),
    "blue": ("\033[1;34m", "👷", "BLUE/HardHat"),
    "core": ("\033[1;37m", "⚙️ ", "NEMOCLAW"),
}


def say(role: str, msg: str) -> None:
    color, icon, tag = ROLES[role]
    ts = time.strftime("%H:%M:%S")
    print(f"{color}{ts} {icon} [{tag}]{RESET} {msg}", flush=True)


def detail(role: str, msg: str, limit: int = 600) -> None:
    color = ROLES[role][0]
    if len(msg) > limit:
        msg = msg[:limit] + " …"
    for line in msg.splitlines() or [""]:
        print(f"{color}   │{RESET} {line}", flush=True)


def banner(text: str) -> None:
    bar = "═" * (len(text) + 4)
    print(f"\n\033[1m╔{bar}╗\n║  {text}  ║\n╚{bar}╝{RESET}\n", file=sys.stdout, flush=True)
