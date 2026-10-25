"""Render the flock to a PNG character sheet (docs/assets/mascots.png), straight from the sprites.

    python3 scripts/mascot_sheet.py [out.png]      # needs Pillow (not a project dependency)
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wreckless import mascots as m  # noqa: E402

SCALE, PAD, CAPTION = 16, 40, 64
BG, FG, DIM = (24, 24, 31), (235, 235, 245), (150, 150, 170)
JOBS = {"purple": "Purple · intel", "red": "Red · exploit", "gate": "Gate · verify",
        "blue": "Blue · patch", "core": "Core · orchestrator"}


def font(size: int, bold: bool = False):
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    try:
        return ImageFont.truetype(f"/usr/share/fonts/truetype/dejavu/{name}", size)
    except OSError:
        return ImageFont.load_default()


def main(out: Path) -> None:
    roles = list(JOBS)
    h = m.HAT_H + m.BODY_H + 2
    cw = m.W * SCALE + PAD
    img = Image.new("RGB", (PAD + cw * len(roles), PAD + h * SCALE + CAPTION), BG)
    d = ImageDraw.Draw(img)
    for i, role in enumerate(roles):
        task = m.STAGE_TASK[role]
        ox = PAD + i * cw
        for y, row in enumerate(m.pixels(role, task, "idle", 1.0)):
            for x, c in enumerate(row):
                if c:
                    d.rectangle([ox + x * SCALE, PAD // 2 + y * SCALE,
                                 ox + (x + 1) * SCALE - 1, PAD // 2 + (y + 1) * SCALE - 1], fill=c)
        ty = PAD // 2 + h * SCALE + 6
        d.text((ox, ty), JOBS[role], fill=m.ROLE_COLORS[role][0], font=font(20, bold=True))
        d.text((ox, ty + 28), m.TASKS[task][2], fill=DIM, font=font(16))
    img.save(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "docs/assets/mascots.png"))
