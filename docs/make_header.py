"""Render the project header illustration (docs/header.png).

The same rows of data seen from both sides: readable by the key holder,
opaque to every machine that stores them. Sized 1920x1080 for article
covers and og:image previews.

  python3 docs/make_header.py
"""
import hashlib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
BG = "#0f1115"
PANEL = "#171a21"
LINE = "#262b36"
TXT = "#d7dce4"
DIM = "#8b93a1"
MUTE = "#6f7889"
CYAN = "#5cc8ff"
GOLD = "#e0b060"
GREEN = "#7fd18c"

MENLO = "/System/Library/Fonts/Menlo.ttc"


def font(size, bold=False):
    try:
        return ImageFont.truetype(MENLO, size, index=1 if bold else 0)
    except OSError:
        return ImageFont.load_default(size)


ROWS = [
    ("SO-2024-1008", "tidal ab", "$1,879.26", "paid"),
    ("SO-2024-1064", "salt bt", "$1,864.17", "pending"),
    ("SO-2024-1147", "apex ltd", "$1,618.43", "shipped"),
    ("SO-2024-1301", "delta ag", "$2,458.93", "refunded"),
    ("SO-2025-1005", "harbor plc", "$2,043.31", "shipped"),
    ("SO-2025-1162", "apex ltd", "$1,933.48", "paid"),
    ("SO-2026-1201", "sable zrt", "$1,022.94", "pending"),
]


def opaque_lines(n):
    """Deterministic pseudorandom key->blob pairs, shaped like the real ones."""
    out = []
    for i in range(n):
        h = hashlib.sha256(f"blindrange-header-{i}".encode()).hexdigest()
        key = "I:" + h[:22] + "…"
        blob = hashlib.sha256(h.encode()).hexdigest()[:10].upper() + "="
        out.append((key, blob))
    return out


def vtext(img, xy, text, fnt, fill):
    """Text rotated 90° (bottom-to-top), centered on xy."""
    w = int(ImageDraw.Draw(img).textlength(text, font=fnt)) + 8
    h = fnt.size + 12
    strip = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(strip).text((4, 4), text, font=fnt, fill=fill)
    strip = strip.rotate(90, expand=True)
    img.paste(strip, (xy[0] - strip.width // 2, xy[1] - strip.height // 2),
              strip)


def main():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # ---- wordmark and one-liner --------------------------------------
    f40 = font(40, True)
    d.text((96, 74), "blind", font=f40, fill=TXT)
    d.text((96 + d.textlength("blind", font=f40), 74), "range", font=f40,
           fill=CYAN)
    d.text((96, 138), "range queries on encrypted data, served by machines "
           "that cannot read it", font=font(27), fill=DIM)

    PY, PH = 236, 580

    # ---- left: what the key holder reads ------------------------------
    lx, lw = 96, 806
    d.rounded_rectangle((lx, PY, lx + lw, PY + PH), 18, fill=PANEL,
                        outline="#2b3a4a", width=2)
    d.text((lx + 34, PY + 32), "YOU", font=font(26, True), fill=CYAN)
    d.text((lx + 110, PY + 34), "— holding the key", font=font(24), fill=DIM)
    d.text((lx + 34, PY + 80), "amount BETWEEN $500 AND $2,500",
           font=font(23), fill=DIM)
    d.line((lx + 34, PY + 122, lx + lw - 34, PY + 122), fill=LINE)

    y = PY + 150
    for order, cust, amount, status in ROWS:
        d.text((lx + 34, y), order, font=font(24), fill=TXT)
        d.text((lx + 262, y), cust, font=font(24), fill=TXT)
        d.text((lx + 500, y), amount, font=font(24), fill=TXT)
        d.text((lx + 650, y), status, font=font(24),
               fill=GREEN if status == "paid" else DIM)
        y += 52
    d.text((lx + 34, y + 18), "77 rows — decrypted here and nowhere else",
           font=font(23), fill=DIM)

    # ---- the trust boundary -------------------------------------------
    mx = 960
    for yy in range(PY + 6, PY + PH - 6, 18):
        d.line((mx, yy, mx, yy + 9), fill="#3a4150", width=2)
    vtext(img, (mx, PY + PH // 2), "YOUR KEY STOPS HERE", font(22, True),
          "#7c8698")

    # ---- right: what every node stores --------------------------------
    rx, rw = 1018, 806
    d.rounded_rectangle((rx, PY, rx + rw, PY + PH), 18, fill=PANEL,
                        outline="#4a3d24", width=2)
    d.text((rx + 34, PY + 32), "EVERY MACHINE STORING IT",
           font=font(26, True), fill=GOLD)
    d.text((rx + 34, PY + 80),
           "no key · no order · no equality · no plaintext",
           font=font(22), fill=DIM)
    d.line((rx + 34, PY + 122, rx + rw - 34, PY + 122), fill=LINE)

    y = PY + 150
    for key, blob in opaque_lines(8):
        d.text((rx + 34, y), key, font=font(22), fill=MUTE)
        d.text((rx + 388, y), "→", font=font(22), fill="#4a5262")
        d.text((rx + 436, y), blob, font=font(22), fill=MUTE)
        y += 46
    d.text((rx + 34, y + 22), "this is everything the operator can see",
           font=font(23), fill=DIM)

    # ---- bottom facts and footer ---------------------------------------
    facts = [(CYAN, "no central infrastructure"),
             (GOLD, "no port forwarding, no trusted component"),
             (GREEN, "leakage measured and published")]
    x, fy = 96, 892
    f25 = font(25)
    for color, text in facts:
        d.ellipse((x, fy + 12, x + 12, fy + 24), fill=color)
        d.text((x + 26, fy), text, font=f25, fill=TXT)
        x += int(d.textlength(text, font=f25)) + 92

    d.text((96, 972), "blindrange.dev", font=f25, fill=DIM)
    tail = "open source · MIT"
    d.text((W - 96 - d.textlength(tail, font=f25), 972), tail, font=f25,
           fill=DIM)

    out = Path(__file__).parent / "header.png"
    img.save(out)
    print("wrote", out, img.size)


if __name__ == "__main__":
    main()
