"""Pixel mascots: a small flock, one bird per role, a hat per task, a few animation moods.

Sprites are tiny pixel grids drawn with half blocks (two pixels per terminal cell), so
they need no emoji or wide glyphs and stay aligned inside tmux panes at any font size.

    shape + colour = who (role)    hat + prop = what they're doing right now (task)
    eyes + motion  = mood (idle / think / work / happy / sad)

Deliberately minimal, like dots: flat colour, two pill eyes, a beak. Each role has its own
silhouette so the flock still reads in monochrome.

``frame(role, task, mood, t)`` returns the lines for one moment; the animation is just a
function of time, so a pane can redraw at any rate and replay looks identical.
"""
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

W = 14          # sprite width in pixels (= terminal columns): 10 bird + 4 prop
HAT_H = 3       # hat rows above the body (pixels)
BODY_H = 7

# Role palettes: body, shade (feet / tail).
ROLE_COLORS = {
    "purple": ((167, 139, 250), (91, 33, 182)),
    "red":    ((248, 113, 113), (153, 27, 27)),
    "blue":   ((96, 165, 250), (30, 64, 175)),
    "gate":   ((251, 191, 36), (146, 64, 14)),
    "core":   ((148, 163, 184), (51, 65, 85)),
    "porter": ((45, 212, 191), (17, 94, 89)),
}
INK = {
    "K": (100, 110, 135), "w": (248, 250, 252), "g": (148, 163, 184), "G": (71, 85, 105),
    "y": (250, 204, 21), "Y": (161, 98, 7), "r": (220, 38, 38), "n": (129, 140, 248),
    "N": (79, 70, 229), "f": (120, 90, 60), "c": (34, 211, 238),
    "C": (14, 116, 144), "o": (251, 146, 60), "p": (244, 114, 182), "e": (17, 24, 39),
    "O": (249, 115, 22), "b": (9, 9, 11), "v": (74, 222, 128), "s": (222, 184, 135),
}

# One silhouette per role (round, dart, egg, block, hen). B body, S shade (feet / tail),
# O beak, . transparent.
# eyes: top pixel of each 1x2 pill; hat: (body row of the head top, x of the 8-wide hat).
# Drawn 10 wide; the 4 columns right of the beak are for the prop.
SHAPES = {
    "purple": {"eyes": ((1, 4), (1, 6)), "hat": (0, 1), "body": [
        "...BBBB.......",
        ".BBBBBBBB.....",
        ".BBBBBBBB.....",
        "SBBBBBBBBO....",
        "SSBBBBBBB.....",
        "..BBBBBB......",
        "...S..S.......",
    ]},
    "red": {"eyes": ((1, 5), (1, 7)), "hat": (0, 2), "body": [
        "....BBBB......",
        "...BBBBBB.....",
        "SSBBBBBBBO....",
        ".SBBBBBBB.....",
        "...BBBBB......",
        "....S.S.......",
        "..............",
    ]},
    "blue": {"eyes": ((1, 4), (1, 6)), "hat": (0, 1), "body": [
        "...BBBB.......",
        "..BBBBBB......",
        "..BBBBBBO.....",
        "..BBBBBB......",
        ".SBBBBBB......",
        "SS.BBBB.......",
        "...S..S.......",
    ]},
    "gate": {"eyes": ((1, 3), (1, 6)), "hat": (0, 1), "body": [
        ".BBBBBBBB.....",
        ".BBBBBBBB.....",
        ".BBBBBBBBO....",
        "SBBBBBBBB.....",
        "SBBBBBBBB.....",
        ".BBBBBBBB.....",
        "..S....S......",
    ]},
    "porter": {"eyes": ((1, 4), (1, 7)), "hat": (0, 1), "body": [
        "..BBBBBB......",
        ".BBBBBBBB.....",
        ".BBBBBBBBO....",
        ".BBBBBBBB.....",
        "SBBBBBBBB.....",
        "SS.BBBBB......",
        "...S..S.......",
    ]},
    "core": {"eyes": ((2, 5), (2, 7)), "hat": (1, 1), "body": [
        "..............",
        "S.BBBBBB......",
        "SSBBBBBBB.....",
        "SBBBBBBBBO....",
        "BBBBBBBBBB....",
        ".BBBBBBBB.....",
        "..S....S......",
    ]},
}

# Wearables: 8 wide x HAT_H rows, placed on the head. "face" wearables are fitted to the
# shape instead (monocle and mask around the eyes, goggles over them, a sandbox round it all).
HATS = {
    "none":     {"rows": []},
    "nightcap": {"rows": [".....nw.",
                          "...nnn..",
                          ".nNnNnN."]},
    "cap":      {"rows": ["..NNN...",
                          ".NNyNN..",
                          ".NNNNNNN"]},
    "hardhat":  {"rows": ["...yy...",
                          "..yYyy..",
                          "yyyyyyyy"]},
    "party":    {"rows": ["...p....",
                          "...oo...",
                          "..pppp.."]},
    "monocle":  {"rows": [], "face": "monocle"},
    "mask":     {"rows": [], "face": "mask"},
    "goggles":  {"rows": [], "face": "goggles"},
    "sandbox":  {"rows": [], "face": "sandbox"},
}

# Props, drawn right of the beak so the task reads literally. Each is a list of frames
# (cycled at ``fps``); ``dy`` is the drawing's row that lines up with the beak.
PROPS = {
    "none":      {"dy": 0, "fps": 1, "frames": [[]]},
    "zzz":       {"dy": 5, "fps": 1.5, "frames": [["....", "wwww", "..w.", ".w..", "wwww"],
                                                  ["wwww", "..w.", ".w..", "wwww", "...."]]},
    "magnifier": {"dy": 4, "fps": 2, "frames": [[".gg.", "gwcg", "gccg", "fgg.", "f..."],
                                                [".gg.", "gccg", "gcwg", "fgg.", "f..."]]},
    "page":      {"dy": 1, "fps": 1, "frames": [["wwww", "wGGw", "wwww", "wGGw"]]},
    "bomb":      {"dy": 2, "fps": 8, "frames": [["...y", "..f.", ".KK.", "KwKK", ".KK."],
                                                ["..o.", "..f.", ".KK.", "KwKK", ".KK."],
                                                ["...r", "..f.", ".KK.", "KwKK", ".KK."]]},
    "boom":      {"dy": 2, "fps": 6, "frames": [[".y.", "yoy", ".r.", "yoy", ".y."],
                                                ["y.y", ".o.", "yry", ".o.", "y.y"]]},
    "clipboard": {"dy": 2, "fps": 1, "frames": [[".GG.", "wwww", "wwwv", "vwvw", "wvww"]]},
    "wrench":    {"dy": 2, "fps": 3, "frames": [[".g.g", ".ggg", "..g.", ".g..", "g..."],
                                                ["....", ".g.g", ".ggg", "..g.", ".g.."]]},
    "flask":     {"dy": 2, "fps": 3, "frames": [["...w", ".gg.", ".gg.", "gvvg", "gvvg"],
                                                ["..w.", ".gg.", ".gg.", "gvvg", "gvvg"]]},
    "envelope":  {"dy": 0, "fps": 2, "frames": [["GwwG", "wGGw", "wwww"],
                                                ["....", "GwwG", "wGGw", "wwww"]]},
    "confetti":  {"dy": 4, "fps": 4, "frames": [["p..y", "..c.", "y...", "..o.", "c..."],
                                                ["..p.", "y..c", "..o.", "c...", "..y."]]},
}

# What each task looks like: (wearable, prop, label). Tasks come from pipeline events /
# tool names (see TASK_OF).
TASKS = {  # labels fit LABEL_W
    "idle":     ("nightcap", "zzz", "asleep · waiting"),
    "intel":    ("none", "magnifier", "investigating"),
    "read":     ("monocle", "page", "reading source"),
    "exploit":  ("mask", "bomb", "building exploit"),
    "sandbox":  ("sandbox", "boom", "detonating (sandbox)"),
    "verify":   ("cap", "clipboard", "re-checking (nonce)"),
    "patch":    ("hardhat", "wrench", "patching"),
    "test":     ("goggles", "flask", "running tests"),
    "notify":   ("none", "envelope", "sending the card"),
    "done":     ("party", "confetti", "done!"),
    "outer":    ("none", "envelope", "at the Slack door"),
    "inner":    ("cap", "page", "at the agents' door"),
}
LABEL_W = 20
SHORT = {  # <= 12 chars: used when the pane is too narrow for the full labels (W-wide sprites)
    "idle": "asleep", "intel": "scouting", "read": "reading", "exploit": "exploiting", "sandbox": "detonating",
    "verify": "re-checking", "patch": "patching", "test": "testing", "notify": "sending", "done": "done!",
    "outer": "Slack door", "inner": "agents' door",
}
STAGE_TASK = {"purple": "intel", "red": "exploit", "gate": "verify", "blue": "patch", "core": "notify",
              "porter": "outer"}
TASK_OF = {  # agent tool name -> task
    "read_file": "read", "write_file": "exploit", "git_checkout": "read",
    "sandbox_exec": "sandbox", "edit_file": "patch", "git_apply_patch": "patch",
    "run_pytest": "test", "run_exploit": "test", "generate_openshell_egress_rule": "patch",
}
MOODS = ("idle", "think", "work", "happy", "sad")
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _eyes(role: str, mood: str, t: float) -> list[tuple[int, int]]:
    """Eye pixels as (body_row, col): 1x2 pills, like the dots."""
    (y, lx), (_, rx) = SHAPES[role]["eyes"]
    if mood == "think":                     # looking up
        return [(y - 1, lx), (y, lx), (y - 1, rx), (y, rx)]
    if mood == "work":                      # glancing at the work, to the side
        return [(y, lx + 1), (y + 1, lx + 1), (y, rx + 1), (y + 1, rx + 1)]
    if mood == "happy":                     # squeezed shut (cheeks added in pixels())
        return [(y, lx), (y, rx)]
    if mood == "sad" or (t % 3.2) < 0.18:   # closed / blink
        return [(y + 1, lx), (y + 1, rx)]
    return [(y, lx), (y + 1, lx), (y, rx), (y + 1, rx)]


def _span(row: str) -> tuple[int, int]:
    xs = [x for x, ch in enumerate(row) if ch == "B"]
    return xs[0], xs[-1]


def _find(rows: list[str], ch: str) -> tuple[int, int]:
    return next((y, x) for y, r in enumerate(rows) for x, c in enumerate(r) if c == ch)


def pixels(role: str, task: str = "idle", mood: str = "idle", t: float = 0.0) -> list[list]:
    """(HAT_H + BODY_H + 2) x W grid of RGB tuples or None; 2 spare rows let it hop/bob."""
    shape = SHAPES[role]
    rows = shape["body"]
    body, shade = ROLE_COLORS[role]
    if mood == "sad":  # wash the colour out a bit
        body = _mix(body, (100, 116, 139), .5)
    pal = {"B": body, "S": shade}
    wear, prop, _ = TASKS[task]
    hat, prop = HATS[wear], PROPS[prop]
    face = hat.get("face")
    grid = [[None] * W for _ in range(HAT_H + BODY_H)]

    def put(y, x, ink):
        if 0 <= x < W and 0 <= HAT_H + y < len(grid):
            grid[HAT_H + y][x] = INK[ink] if isinstance(ink, str) else ink

    wag = mood == "work" and int(t * 6) % 2  # tail feathers flick while working
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch != ".":
                tail = ch == "S" and x <= 1
                put(y - (wag and tail), x, pal.get(ch) or ch)
    (ey, lx), (_, rx) = shape["eyes"]
    top, hx = shape["hat"]
    for y, row in enumerate(hat["rows"]):
        for x, ch in enumerate(row):
            if ch != ".":
                put(top - HAT_H + y, hx + x, ch)
    if face == "mask":  # bandit mask across the eyes, knot tails behind
        a, b = _span(rows[ey])
        for y in (ey, ey + 1):
            for x in range(a, b + 1):
                put(y, x, "b")
        flap = int(t * 6) % 2
        put(ey, a - 1, "b")
        put(ey + 1 + flap, a - 2, "b")
    asleep = task == "idle" and mood == "idle"
    for y, x in _eyes(role, "sad" if asleep else mood, t):  # one flat colour, like the dots
        put(y, x, "w" if face == "mask" else "e")  # white only where the mask is black
    if mood == "happy":
        put(ey + 1, lx - 1, "p")
        put(ey + 1, rx + 1, "p")
    if face == "monocle":  # gold ring round the right eye (it follows the glance), chain below
        my = ey - 1 if mood == "think" else ey
        mx = rx + 1 if mood == "work" else rx
        put(my - 1, mx, "y")
        put(my + 2, mx, "y")
        for y in (my, my + 1):
            put(y, mx - 1, "y")
            put(y, mx + 1, "y")
        put(my + 3, mx + 1, "Y")
        put(my + 4, mx, "Y")
    if face == "goggles":  # strap across the eyes, two lenses
        a, b = _span(rows[ey])
        for x in range(a, b + 1):
            put(ey, x, "G")
        for x in (lx, rx):
            put(ey, x, "c")
            put(ey + 1, x, "C")
    by, bx = _find(rows, "O")
    frames = prop["frames"]
    for y, row in enumerate(frames[int(t * prop["fps"]) % len(frames)]):
        for x, ch in enumerate(row):
            if ch != ".":
                put(by - prop["dy"] + y, bx + 1 + x, ch)
    if face == "sandbox":  # a box with a sand floor round bird and prop: the blast stays inside
        cy = top - HAT_H
        for x in range(W):
            put(cy, x, "K")
            put(BODY_H - 1, x, "s")
        for x in (0, W - 1):
            for y in range(cy, BODY_H):
                put(y, x, "K")
    # motion: bob while working, hop when happy; 2 spare rows of headroom on top
    lift = 0
    if mood == "work":
        lift = int(t * 4) % 2
    elif mood == "happy":
        lift = (0, 1, 2, 1)[int(t * 6) % 4]
    blank = [[None] * W for _ in range(2)]
    return blank[lift:] + grid + blank[:lift] if lift else blank + grid


def _mix(a, b, k):
    return tuple(round(x + (y - x) * k) for x, y in zip(a, b))


def color_mode() -> str:
    """'truecolor', '256' or 'none' (NO_COLOR / not a tty, unless FORCE_COLOR)."""
    if os.environ.get("NO_COLOR"):
        return "none"
    if not (os.environ.get("FORCE_COLOR") or sys.stdout.isatty()):
        return "none"
    ct = os.environ.get("COLORTERM", "")
    return "truecolor" if ("truecolor" in ct or "24bit" in ct) else "256"


def _fg(c, mode):
    if mode == "truecolor":
        return f"38;2;{c[0]};{c[1]};{c[2]}"
    return f"38;5;{_to256(c)}"


def _bg(c, mode):
    if mode == "truecolor":
        return f"48;2;{c[0]};{c[1]};{c[2]}"
    return f"48;5;{_to256(c)}"


def _to256(c):
    r, g, b = (round(v / 255 * 5) for v in c)
    return 16 + 36 * r + 6 * g + b


def render(grid: list[list], mode: str | None = None) -> list[str]:
    """Pixel grid -> terminal lines (half blocks). Plain mode draws a monochrome silhouette."""
    mode = mode or color_mode()
    lines = []
    for y in range(0, len(grid), 2):
        top, bot = grid[y], grid[y + 1] if y + 1 < len(grid) else [None] * W
        out = []
        for a, b in zip(top, bot):
            if mode == "none":  # monochrome: eyes become holes so the face still reads
                a, b = (None if c == INK["e"] else c for c in (a, b))
                out.append("█" if a and b else "▀" if a else "▄" if b else " ")
            elif a and b:
                out.append(f"\033[{_fg(a, mode)};{_bg(b, mode)}m▀\033[0m")
            elif a:
                out.append(f"\033[{_fg(a, mode)}m▀\033[0m")
            elif b:
                out.append(f"\033[{_fg(b, mode)}m▄\033[0m")
            else:
                out.append(" ")
        lines.append("".join(out))
    return lines


def frame(role: str, task: str = "idle", mood: str = "idle", t: float | None = None,
          mode: str | None = None, label_w: int = LABEL_W) -> list[str]:
    """Sprite lines plus a status line, for time ``t`` (default: now)."""
    t = time.time() if t is None else t
    lines = render(pixels(role, task, mood, t), mode)
    spin = SPINNER[int(t * 10) % len(SPINNER)] if mood in ("work", "think") else " "
    label = TASKS[task][2] if label_w >= LABEL_W else SHORT[task]
    lines.append(f"{spin} {label}"[:label_w + 2])
    return lines


def side_by_side(blocks: list[list[str]], gap: int = 3, widths: list[int] | None = None) -> list[str]:
    """Join several multi-line blocks horizontally (ANSI-aware padding by visible width)."""
    vis = lambda s: len(re.sub(r"\x1b\[[0-9;]*m", "", s))  # noqa: E731
    widths = widths or [max(vis(l) for l in b) for b in blocks]
    h = max(len(b) for b in blocks)
    rows = []
    for i in range(h):
        parts = []
        for b, w in zip(blocks, widths):
            s = b[i] if i < len(b) else ""
            parts.append(s + " " * (w - vis(s)))
        rows.append((" " * gap).join(parts).rstrip())
    return rows


# A looping pipeline story for the preview: (task, mood, seconds) per role, in lockstep.
STORY = {
    "purple": [("intel", "work", 3), ("intel", "think", 2), ("done", "happy", 2), ("idle", "idle", 9)],
    "red":    [("idle", "idle", 3), ("read", "think", 2), ("exploit", "work", 2),
               ("sandbox", "work", 2), ("done", "happy", 2), ("idle", "idle", 5)],
    "gate":   [("idle", "idle", 9), ("verify", "work", 2), ("done", "happy", 1), ("idle", "idle", 4)],
    "blue":   [("idle", "idle", 10), ("patch", "work", 2), ("test", "work", 2), ("done", "happy", 2)],
    "core":   [("idle", "idle", 12), ("notify", "work", 2), ("done", "happy", 2)],
}
NAMES = {"purple": "SCOUT", "red": "RALPH", "gate": "VERIFIER", "blue": "FELIX", "core": "CONDUCTOR",
         "porter": "PORTER"}


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _at(story, t):
    t %= sum(d for *_, d in story)
    for task, mood, d in story:
        if t < d:
            return task, mood
        t -= d
    return story[-1][:2]


def _row(states: dict, t: float, mode: str, label_w: int = LABEL_W) -> list[str]:
    blocks = []
    for role, (task, mood) in states.items():
        b = frame(role, task, mood, t, mode, label_w)
        color = ROLE_COLORS[role][0]
        tag = NAMES[role] if mode == "none" else f"\033[1;{_fg(color, mode)}m{NAMES[role]}\033[0m"
        blocks.append([tag] + b)
    return side_by_side(blocks, gap=2, widths=[label_w + 2] * len(blocks))


def preview(animate: bool = False, seconds: float = 32, fps: int = 10) -> None:
    mode = color_mode()
    if not animate:
        for task in TASKS:
            print(f"\n{task}: {TASKS[task][2]}")
            for line in side_by_side([render(pixels(r, task, "idle", 1.0), mode) for r in ROLE_COLORS]):
                print(line)
        print("\nmoods:", " · ".join(MOODS))
        for line in side_by_side([render(pixels("red", "idle", m, 1.0), mode) for m in MOODS]):
            print(line)
        return
    if mode == "none":
        print("animation needs a colour terminal (unset NO_COLOR or set FORCE_COLOR)")
        return
    t0, h = time.time(), 0
    sys.stdout.write("\033[?25l")
    try:
        while (t := time.time() - t0) < seconds:
            lines = _row({r: _at(s, t) for r, s in STORY.items()}, t, mode)
            if h:
                sys.stdout.write(f"\033[{h}F")
            sys.stdout.write("".join(f"{ln}\033[K\n" for ln in lines))
            sys.stdout.flush()
            h = len(lines)
            time.sleep(1 / fps)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h")


# ---------- live view: the flock, driven by events.jsonl ----------
class Flock:
    """Each role's (task, mood), derived from pipeline events. Happy/sad wear off to idle."""
    CHEER, SULK = 4.0, 6.0
    AFTER = {  # transition target -> roles that react, and how
        "verified": [("red", "done", "happy"), ("gate", "done", "happy")],
        "rejected": [("red", "idle", "sad"), ("gate", "idle", "sad")],
        "patched": [("blue", "done", "happy")],
        "patch_failed": [("blue", "idle", "sad")],
        "notified": [("core", "done", "happy")],
    }
    FINAL = {"rejected", "patch_failed", "notified"}
    PRODUCER = {"purple": "purple", "red-hunt": "red"}  # enqueue source -> the bird that found it

    def __init__(self):
        self.state = {r: ("idle", "idle", None) for r in ROLE_COLORS}

    def apply(self, ev: dict) -> None:
        role, kind, t = ev.get("actor"), ev.get("kind"), ev.get("t", 0)
        if kind in ("mascot", "task") and role in self.state:
            self.state[role] = (ev.get("task") or STAGE_TASK[role], "work", None)
        elif kind == "enqueue" and ev.get("source") in self.PRODUCER:
            self.state[self.PRODUCER[ev["source"]]] = ("done", "happy", t + self.CHEER)
        elif kind == "transition":
            if ev.get("to") in self.FINAL:  # the item is over: whoever was working stands down
                for r, (_, mood, _) in self.state.items():
                    if mood == "work":
                        self.state[r] = ("idle", "idle", None)
            for r, task, mood in self.AFTER.get(ev.get("to"), []):
                self.state[r] = (task, mood, t + (self.CHEER if mood == "happy" else self.SULK))

    def now(self, t: float) -> dict:
        return {r: (("idle", "idle") if until and t > until else (task, mood))
                for r, (task, mood, until) in self.state.items()}


def watch(events, roles: list[str] | None = None, fps: int = 10) -> None:
    """Animate the flock from a growing events.jsonl (Ctrl-C to quit). Meant for a tmux pane."""
    mode = color_mode()
    if mode == "none":
        print("the flock view needs a colour terminal (unset NO_COLOR or set FORCE_COLOR)")
        return
    path, flock, pos = Path(events), Flock(), 0
    prev, prev_shape = [], None
    roles = roles or list(ROLE_COLORS)
    sys.stdout.write("\033[?1049h\033[?25l")  # alternate screen, hidden cursor
    try:
        while True:
            if path.exists():
                with path.open("rb") as f:
                    f.seek(pos)
                    for line in f:
                        if not line.endswith(b"\n"):
                            break  # half-written; pick it up next frame
                        pos += len(line)
                        try:
                            flock.apply(json.loads(line))
                        except ValueError:
                            pass
            t = time.time()
            states = flock.now(t)
            cols = shutil.get_terminal_size((80, 24)).columns
            # one row if every bird fits: shrink the label column down to the sprite width (W) first
            label_w = max(W - 2, min(LABEL_W, (cols + 2) // len(roles) - 4))
            per = max(1, (cols + 2) // (label_w + 4))
            lines = []
            for k in range(0, len(roles), per):
                row = _row({r: states[r] for r in roles[k:k + per]}, t, mode, label_w)
                pad = " " * max(0, (cols - max(len(_ANSI.sub("", ln)) for ln in row)) // 2)
                lines += [pad + ln for ln in row] + [""]
            # repaint only the lines that changed: rewriting the whole screen 10x a second makes
            # terminal hover widgets (tooltips, link detection) flicker
            if (cols, len(lines)) != prev_shape:
                out, prev = ["\033[2J"], []
            else:
                out = []
            for i, ln in enumerate(lines):
                if i >= len(prev) or prev[i] != ln:
                    out.append(f"\033[{i + 1};1H{ln}\033[K")
            if out:
                sys.stdout.write("".join(out))
                sys.stdout.flush()
            prev, prev_shape = lines, (cols, len(lines))
            time.sleep(1 / fps)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h\033[?1049l")
