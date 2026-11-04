"""Generate the desktop app icon set (a plain shield with a small provenance graph inside).

Output (next to this script): icon.png (1024x1024), icon.icns (macOS), icon.ico (Windows), icons/<n>x<n>.png (Linux).
electron-builder picks them up from `directories.buildResources` (resources/). Regenerate with:
  docker run --rm -v "$PWD/desktop/resources:/out" -w /out python:3.12-slim \
    sh -c 'pip install -q pillow==10.4.0 && python make-icons.py'
"""
import math
import os

from PIL import Image, ImageDraw

OUT = os.path.dirname(os.path.abspath(__file__))
S = 4096  # supersampled canvas, downscaled to 1024 for smooth edges
BG, RIM, EDGE, NODE, HOT = (16, 33, 54, 255), (79, 163, 217, 255), (150, 200, 235, 255), (235, 244, 250, 255), (255, 170, 60, 255)


def shield(cx, top, w, h, n=200):
    """Outline: flat-ish top with rounded shoulders, straight-ish sides curving to a point at the bottom."""
    pts = []
    half = w / 2
    # top edge, slightly dipped in the middle
    for i in range(n + 1):
        x = cx - half + w * i / n
        pts.append((x, top + 0.04 * h * math.sin(math.pi * i / n)))
    # straight shoulders down 30 % of the height, then both sides curve in to the point at the bottom
    pts.append((cx + half, top + 0.30 * h))
    for i in range(1, n + 1):
        t = i / n
        pts.append((cx + half * (1 - t ** 2.2), top + h * (0.30 + 0.70 * t)))
    for i in range(n - 1, -1, -1):
        t = i / n
        pts.append((cx - half * (1 - t ** 2.2), top + h * (0.30 + 0.70 * t)))
    return pts


def draw():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx, top, w, h = S / 2, S * 0.08, S * 0.78, S * 0.86
    d.polygon(shield(cx, top, w, h), fill=RIM)
    inset = S * 0.045
    d.polygon(shield(cx, top + inset, w - 2 * inset * 1.25, h - 2.3 * inset), fill=BG)
    # a small directed provenance graph: process -> file -> process -> socket, with one side branch
    nodes = {"a": (0.50, 0.27), "b": (0.32, 0.45), "c": (0.68, 0.45), "d": (0.50, 0.63), "e": (0.50, 0.80)}
    nodes = {k: (x * S, y * S) for k, (x, y) in nodes.items()}
    lw = int(S * 0.022)
    for u, v in (("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("d", "e")):
        d.line([nodes[u], nodes[v]], fill=EDGE, width=lw)
    r = S * 0.055
    for k, (x, y) in nodes.items():
        d.ellipse([x - r, y - r, x + r, y + r], fill=HOT if k == "e" else NODE)
    return img.resize((1024, 1024), Image.LANCZOS)


def main():
    big = draw()
    big.save(os.path.join(OUT, "icon.png"))
    os.makedirs(os.path.join(OUT, "icons"), exist_ok=True)
    for n in (16, 32, 48, 64, 128, 256, 512, 1024):
        big.resize((n, n), Image.LANCZOS).save(os.path.join(OUT, "icons", f"{n}x{n}.png"))
    big.save(os.path.join(OUT, "icon.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    big.save(os.path.join(OUT, "icon.icns"))
    print("icons written to", OUT)


if __name__ == "__main__":
    main()
