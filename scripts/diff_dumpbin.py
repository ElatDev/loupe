#!/usr/bin/env python3
"""Differential test: Loupe against Microsoft's dumpbin.

For every file given, runs `loupe --flat -i -e` and `dumpbin /imports
/exports`, parses both into sets of (module, symbol) and (ordinal, name,
target) records, and reports any difference. Two independent parsers
agreeing on thousands of binaries is a much stronger statement than a
hand-checked example.

    python scripts/diff_dumpbin.py C:\\Windows\\System32\\*.dll
    python scripts/diff_dumpbin.py --dir C:\\Windows\\System32 --limit 500

dumpbin is found through vswhere if it is not already on PATH.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOUPE = os.path.join(HERE, "..", "build", "loupe.exe")


def find_dumpbin() -> str:
    from shutil import which

    found = which("dumpbin")
    if found:
        return found
    vswhere = os.path.join(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if os.path.exists(vswhere):
        root = subprocess.run(
            [vswhere, "-latest", "-products", "*", "-property", "installationPath"],
            capture_output=True, text=True).stdout.strip()
        pattern = os.path.join(root, "VC", "Tools", "MSVC", "*", "bin", "Hostx64", "x64",
                               "dumpbin.exe")
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[-1]
    sys.exit("dumpbin not found; run from a Developer Command Prompt")


def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return p.stdout


MODULE_RE = re.compile(r"^ {4}(\S.*?)\s*$")
# "        158 wcscmp" and, in the delay-load section, the same line with the
# thunk address in front: "   0000000140002B34    EA DecryptFileW" - or with
# two addresses, when the delay IAT is bound.
IMPORT_RE = re.compile(r"^ {6,}(?:[0-9A-Fa-f]{8,16}\s+){0,2}([0-9A-Fa-f]{1,4})\s+(\S+)\s*$")
ORDINAL_RE = re.compile(r"^ {6,}(?:[0-9A-Fa-f]{8,16}\s+){0,2}Ordinal\s+(\d+)\s*$")
# The export table is laid out in fixed columns:
#   ordinal [0:11]  hint [11:16]  RVA [17:25]  name [26:]
EXPORT_RE = re.compile(r"^\s*\d+\s")


def parse_dumpbin(text: str):
    """-> (imports, exports). imports: {(module, symbol, delay)}."""
    imports, exports = set(), set()
    section = None
    module = None
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("section contains the following delay load imports"):
            section, module = "delay", None
            continue
        if low.startswith("section contains the following imports"):
            section, module = "imports", None
            continue
        if low.startswith("section contains the following exports"):
            section, module = "exports", None
            continue
        if low.startswith("section contains the following") or low.startswith("summary"):
            section = None
            continue

        if section in ("imports", "delay"):
            m = MODULE_RE.match(line)
            if m and not m.group(1)[0].isdigit():
                module = m.group(1).lower()
                continue
            m = ORDINAL_RE.match(line)
            if m and module:
                imports.add((module, "#" + m.group(1), section == "delay"))
                continue
            m = IMPORT_RE.match(line)
            if m and module:
                imports.add((module, m.group(2), section == "delay"))
                continue
        elif section == "exports":
            if "ordinal" in low and "hint" in low:
                continue
            if not EXPORT_RE.match(line) or len(line) < 27:
                continue
            ordinal, rva, rest = line[:11].strip(), line[17:25].strip(), line[26:].strip()
            if not rest or not re.fullmatch(r"[0-9A-Fa-f]*", rva):
                continue
            name, target = rest, ""
            fwd = re.match(r"(.*?)\s*\(forwarded to (.*)\)$", rest)
            if fwd:
                name, target = fwd.group(1), fwd.group(2)
            exports.add((int(ordinal), name, target.lower() if target else
                         ("0x%08x" % int(rva, 16) if rva else "")))
    return imports, exports


def parse_loupe(text: str):
    imports, exports = set(), set()
    for line in text.splitlines():
        f = line.split("\t")
        if f[0] in ("import", "delayimport") and len(f) >= 3:
            imports.add((f[1].lower(), f[2], f[0] == "delayimport"))
        elif f[0] == "export" and len(f) >= 4:
            target = f[3][3:].lower() if f[3].startswith("-> ") else f[3]
            exports.add((int(f[1]), f[2], target))
    return imports, exports


def compare(path: str, loupe: str, dumpbin: str, show: int):
    text = run([loupe, "--flat", "-i", "-e", path])
    if not text.startswith("format\tPE"):
        return path, "not a PE file", 0
    if "warning\t" in text:
        return path, "loupe reported warnings", 0
    li, le = parse_loupe(text)
    di, de = parse_dumpbin(run([dumpbin, "/nologo", "/imports", "/exports", path]))

    problems = []
    for what, ours, theirs in (("import", li, di), ("export", le, de)):
        only_ours = ours - theirs
        only_theirs = theirs - ours
        if only_ours or only_theirs:
            problems.append("%s: %d only in loupe, %d only in dumpbin %s" % (
                what, len(only_ours), len(only_theirs),
                sorted(only_ours)[:show] + sorted(only_theirs)[:show]))
    return path, "; ".join(problems), len(li) + len(le)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--dir", help="compare every file in this directory")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--loupe", default=DEFAULT_LOUPE)
    ap.add_argument("--jobs", type=int, default=min(16, (os.cpu_count() or 4)))
    ap.add_argument("--show", type=int, default=3, help="differing records to print")
    args = ap.parse_args()

    paths = list(args.files)
    for pattern in list(paths):
        if "*" in pattern:
            paths.remove(pattern)
            paths += glob.glob(pattern)
    if args.dir:
        paths += [os.path.join(args.dir, f) for f in sorted(os.listdir(args.dir))
                  if os.path.isfile(os.path.join(args.dir, f))]
    if args.limit:
        paths = paths[:args.limit]
    if not paths:
        return ap.print_usage() or 2

    dumpbin = find_dumpbin()
    os.environ["PATH"] = os.path.dirname(dumpbin) + os.pathsep + os.environ["PATH"]
    loupe = os.path.abspath(args.loupe)

    checked = mismatched = skipped = records = 0
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futures = [pool.submit(compare, p, loupe, dumpbin, args.show) for p in paths]
        for fut in concurrent.futures.as_completed(futures):
            path, problem, n = fut.result()
            records += n
            if problem in ("loupe reported warnings", "not a PE file"):
                skipped += 1
            elif problem:
                mismatched += 1
                print("MISMATCH %s\n         %s" % (path, problem))
            else:
                checked += 1
    print("\n%d files agree (%d import/export records), %d mismatched, %d skipped"
          % (checked, records, mismatched, skipped))
    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
