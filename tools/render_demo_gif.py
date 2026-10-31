#!/usr/bin/env python3
"""
Record a terminal-style animated GIF of real kit commands for the README.

Runs each command, captures its actual output, and renders a typing-then-output animation with Pillow.
Nothing is faked: rerun after changing rules or data and commit the new GIF.

    pip install pillow
    python tools/render_demo_gif.py            # writes assets/demo-lab-tests.gif
"""
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "demo-lab-tests.gif"
COMMANDS = ["python tests/test_lab_detections.py", "python tests/test_repo_consistency.py"]
W, H, PAD, LINE = 980, 560, 22, 21
BG, FG, DIM, OK, BAD, PROMPT, BAR = "#0d1117", "#e6edf3", "#7d8590", "#3fb950", "#f85149", "#58a6ff", "#161b22"
FONT_PATHS = ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc",
              "C:/Windows/Fonts/consola.ttf"]


def font(size):
    for p in FONT_PATHS:
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


F = font(15)
ROWS = (H - 44 - 2 * PAD) // LINE


def colour(line):
    if line.startswith("$ "):
        return PROMPT
    if line.startswith("PASS"):
        return OK
    if line.startswith("FAIL") or "Error" in line:
        return BAD
    return FG


def frame(lines, cursor=False):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 34], fill=BAR)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse([16 + i * 22, 11, 28 + i * 22, 23], fill=c)
    d.text((W // 2, 17), "cti-hunt-loop-kit: Sigma rules vs. lab answer key", fill=DIM, font=F, anchor="mm")
    view = lines[-ROWS:]
    for i, ln in enumerate(view):
        d.text((PAD, 44 + PAD + i * LINE), ln[:104], fill=colour(ln), font=F)
    if cursor and view:
        x = PAD + d.textlength(view[-1][:104], font=F)
        y = 44 + PAD + (len(view) - 1) * LINE
        d.rectangle([x + 2, y + 2, x + 10, y + 18], fill=FG)
    return img


def main():
    frames, durations, screen = [], [], []

    def add(img, ms):
        frames.append(img.quantize(colors=32, method=Image.Quantize.MEDIANCUT))
        durations.append(ms)

    for cmd in COMMANDS:
        out = subprocess.run(cmd.split(), cwd=ROOT, capture_output=True, text=True)
        if out.returncode != 0:
            sys.exit(f"{cmd} failed; fix it before recording:\n{out.stdout}{out.stderr}")
        screen.append("$ ")
        for i in range(0, len(cmd) + 1, 3):
            screen[-1] = "$ " + cmd[:i]
            add(frame(screen, cursor=True), 45)
        screen[-1] = "$ " + cmd
        add(frame(screen, cursor=True), 400)
        for ln in out.stdout.splitlines():
            screen.append(ln.replace("benign look-alikes", "look-alikes"))
            add(frame(screen), 110)
        screen.append("")
        add(frame(screen), 900)
    screen.append("$ ")
    add(frame(screen, cursor=True), 3000)
    OUT.parent.mkdir(exist_ok=True)
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
