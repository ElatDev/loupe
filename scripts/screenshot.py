#!/usr/bin/env python3
"""Render real Loupe output to an HTML page, for the README screenshot.

Runs Loupe with colour forced on, turns the ANSI escapes into HTML and
writes docs/screenshot.html. Nothing is typed by hand, so the picture in the
README always matches what the program actually prints.

    python scripts/screenshot.py C:\\Windows\\System32\\wer.dll --lines 46
    # then screenshot docs/screenshot.html (any browser, or Playwright)
"""
from __future__ import annotations

import argparse
import html
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_LOUPE = os.path.join(ROOT, "build", "loupe.exe" if os.name == "nt" else "loupe")

# The palette Loupe emits, mapped to the colours the page draws with.
COLORS = {
    "0": None,
    "1;97": "#f2f4f8",
    "1;36": "#4fc3d9",
    "90": "#7d8799",
    "97": "#e6e9ef",
    "1;33": "#e5b567",
    "36": "#63b1c4",
    "32": "#8cc265",
    "31": "#e06c6c",
    "1;35": "#d78adf",
    "2": "#6b7280",
}
BOLD = {"1;97", "1;36", "1;33", "1;35"}

ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_to_html(text: str) -> str:
    out, open_span = [], False
    for line in text.splitlines():
        pos = 0
        for m in ANSI.finditer(line):
            out.append(html.escape(line[pos:m.start()]))
            pos = m.end()
            code = m.group(1) or "0"
            if open_span:
                out.append("</span>")
                open_span = False
            color = COLORS.get(code)
            if color:
                weight = ";font-weight:600" if code in BOLD else ""
                out.append('<span style="color:%s%s">' % (color, weight))
                open_span = True
        out.append(html.escape(line[pos:]))
        if open_span:
            out.append("</span>")
            open_span = False
        out.append("\n")
    return "".join(out)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>loupe</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    margin: 0; padding: 40px; background: #12141a;
    font-family: "Cascadia Code", "JetBrains Mono", Consolas, "DejaVu Sans Mono", monospace;
  }}
  .window {{
    width: fit-content; min-width: 900px; margin: 0 auto; border-radius: 10px;
    overflow: hidden; background: #171a21;
    box-shadow: 0 18px 50px rgba(0,0,0,.55), 0 0 0 1px rgba(255,255,255,.06);
  }}
  .bar {{
    display: flex; align-items: center; gap: 8px; padding: 10px 14px;
    background: #1e222b; border-bottom: 1px solid rgba(255,255,255,.06);
  }}
  .dot {{ width: 11px; height: 11px; border-radius: 50%; }}
  .title {{
    margin-left: 10px; color: #9aa3b2; font-size: 12px; letter-spacing: .02em;
  }}
  pre {{
    margin: 0; padding: 18px 22px 22px; color: #c9cedb;
    font-size: 13px; line-height: 1.45; white-space: pre;
  }}
</style>
</head>
<body>
  <div class="window">
    <div class="bar">
      <div class="dot" style="background:#e06c6c"></div>
      <div class="dot" style="background:#e5b567"></div>
      <div class="dot" style="background:#8cc265"></div>
      <div class="title">{title}</div>
    </div>
<pre>{body}</pre>
  </div>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("args", nargs="*", default=[], help="arguments passed to loupe")
    ap.add_argument("--loupe", default=DEFAULT_LOUPE)
    ap.add_argument("--lines", type=int, default=0, help="keep only the first N lines")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "screenshot.html"))
    opts = ap.parse_args()

    cmd = [opts.loupe, "--color=always"] + opts.args
    text = subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout
    if not text.strip():
        return print("loupe produced no output") or 1
    if opts.lines:
        text = "\n".join(text.splitlines()[:opts.lines])

    shown = " ".join(["loupe"] + opts.args)
    page = PAGE.format(title=html.escape(shown), body=ansi_to_html(text))
    os.makedirs(os.path.dirname(opts.out), exist_ok=True)
    with open(opts.out, "w", encoding="utf-8") as f:
        f.write(page)
    print("wrote %s (%d lines)" % (opts.out, len(text.splitlines())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
