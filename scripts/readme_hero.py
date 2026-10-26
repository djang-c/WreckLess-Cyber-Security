"""Render the README hero banner (docs/assets/hero.svg) straight from the mascot sprites.

    python3 scripts/readme_hero.py [out.svg]      # no dependencies beyond the repo itself
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wreckless import mascots as m  # noqa: E402

W, H, SCALE = 1200, 400, 8
FONT = "DejaVu Sans, Verdana, Helvetica, Arial, sans-serif"
ROLES = ["purple", "red", "gate", "blue", "core", "porter"]
JOBS = {"purple": "reads the advisory", "red": "writes the exploit", "gate": "re-runs it, fresh nonce",
        "blue": "patches the root cause", "core": "ships the fix",
        "porter": "talks to Slack"}


def rgb(c) -> str:
    return c if isinstance(c, str) else "rgb(%d,%d,%d)" % tuple(c[:3])


def bird(role: str, cx: int, top: int) -> str:
    grid = m.pixels(role, m.STAGE_TASK[role], "idle", 1.0)
    ox = cx - m.W * SCALE // 2
    cells = [f'<rect x="{ox + x * SCALE}" y="{top + y * SCALE}" width="{SCALE}" height="{SCALE}" fill="{rgb(c)}"/>'
             for y, row in enumerate(grid) for x, c in enumerate(row) if c]
    return "\n".join(cells)


def main(out: Path) -> None:
    margin = 120
    step = (W - 2 * margin) // (len(ROLES) - 1)
    xs = [margin + i * step for i in range(len(ROLES))]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
        f'aria-label="WreckLess: Scout, Ralph, Verifier, Felix, Conductor and Porter, the six agents of the swarm">',
        '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#181922"/><stop offset="1" stop-color="#0f1016"/></linearGradient></defs>',
        f'<rect width="{W}" height="{H}" rx="18" fill="url(#bg)"/>',
        f'<text x="{W // 2}" y="78" text-anchor="middle" font-family="{FONT}" font-size="54" font-weight="700" '
        f'fill="#f2f2f8" letter-spacing="1">WreckLess</text>',
        f'<text x="{W // 2}" y="116" text-anchor="middle" font-family="{FONT}" font-size="20" fill="#a4a4bb">'
        f'An always-on security swarm: it exploits, patches and proves the fix, all on one desk-side box.</text>',
    ]
    for role, cx in zip(ROLES, xs):
        parts.append(bird(role, cx, 150))
        parts.append(f'<text x="{cx}" y="290" text-anchor="middle" font-family="{FONT}" font-size="20" '
                     f'font-weight="700" fill="{rgb(m.ROLE_COLORS[role][0])}">{m.NAMES[role]}</text>')
        parts.append(f'<text x="{cx}" y="314" text-anchor="middle" font-family="{FONT}" font-size="14" '
                     f'fill="#9a9ab2">{JOBS[role]}</text>')
    for x in xs[:-1]:
        ax = x + step // 2
        parts.append(f'<path d="M{ax - 7} 208 L{ax + 5} 220 L{ax - 7} 232" fill="none" stroke="#5a5b72" '
                     f'stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')
    parts.append(f'<rect x="{W // 2 - 330}" y="344" width="660" height="34" rx="17" fill="#1f2a1c" stroke="#76b900"/>')
    parts.append(f'<text x="{W // 2}" y="367" text-anchor="middle" font-family="{FONT}" font-size="15" '
                 f'font-weight="700" fill="#a9e34b">100% local inference · Dell Pro Max GB10 · OpenShell sandbox</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "docs/assets/hero.svg"))
