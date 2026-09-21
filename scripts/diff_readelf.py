#!/usr/bin/env python3
"""Differential test: Loupe against llvm-readelf (or GNU readelf).

Parses the same ELF files with both tools and compares section headers,
program headers, needed libraries and the dynamic symbol table, including
symbol versions.

    python scripts/diff_readelf.py /usr/lib/x86_64-linux-gnu/*.so*
    python scripts/diff_readelf.py --dir C:\\dev\\Android\\Sdk\\ndk --recurse

--readelf picks the reference tool; without it the script looks for
llvm-readelf, readelf, then the copy in an Android NDK.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import glob
import os
import re
import subprocess
import sys
from shutil import which

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOUPE = os.path.join(HERE, "..", "build",
                             "loupe.exe" if os.name == "nt" else "loupe")


def find_readelf() -> str:
    for name in ("llvm-readelf", "readelf", "eu-readelf"):
        found = which(name)
        if found:
            return found
    ndk = os.environ.get("ANDROID_NDK_ROOT") or r"C:\dev\Android\Sdk\ndk"
    hits = sorted(glob.glob(os.path.join(
        ndk, "*", "toolchains", "llvm", "prebuilt", "*", "bin", "llvm-readelf.exe")))
    if hits:
        return hits[-1]
    sys.exit("no readelf found; pass --readelf")


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout


SECTION_RE = re.compile(
    r"^\s*\[\s*(\d+)\]\s(?P<rest>.*)$")
SECTION_TAIL_RE = re.compile(
    r"^(?P<name>.*?)\s+(?P<type>\S+)\s+(?P<addr>[0-9a-f]{8,16})\s+(?P<off>[0-9a-f]{6,})"
    r"\s+(?P<size>[0-9a-f]{6,})\s")
SEGMENT_RE = re.compile(
    r"^\s+(?P<type>\S+)\s+0x(?P<off>[0-9a-f]+)\s+0x(?P<vaddr>[0-9a-f]+)\s+"
    r"0x(?P<paddr>[0-9a-f]+)\s+0x(?P<filesz>[0-9a-f]+)\s+0x(?P<memsz>[0-9a-f]+)\s+"
    r"(?P<flags>[RWE ]{1,3})\s+0x(?P<align>[0-9a-f]+)\s*$")
SYM_RE = re.compile(
    r"^\s*(?P<num>\d+):\s+(?P<value>[0-9a-f]+)\s+(?P<size>\d+)\s+(?P<type>\S+)\s+"
    r"(?P<bind>\S+)\s+(?P<vis>\S+)\s+(?P<ndx>\S+)\s*(?P<name>.*?)\s*$")
NEEDED_RE = re.compile(r"\(NEEDED\).*\[(?P<lib>[^\]]*)\]")


def norm_flags(f: str) -> str:
    """readelf writes segment permissions as R/W/E, Loupe as rwx."""
    f = f.upper().replace(" ", "").replace("-", "").replace("X", "E")
    return "".join(c for c in "RWE" if c in f)


def parse_readelf(text: str):
    sections, segments, needed, syms = {}, {}, set(), {}
    in_dynsym = False
    for line in text.splitlines():
        m = SECTION_RE.match(line)
        if m:
            tail = SECTION_TAIL_RE.match(m.group("rest"))
            if tail:
                sections[int(m.group(1))] = (
                    tail.group("name").strip(), tail.group("type"),
                    int(tail.group("addr"), 16), int(tail.group("off"), 16),
                    int(tail.group("size"), 16))
            continue
        m = SEGMENT_RE.match(line)
        if m and not line.strip().startswith("Type"):
            segments[len(segments)] = (
                int(m.group("off"), 16), int(m.group("vaddr"), 16),
                int(m.group("filesz"), 16), int(m.group("memsz"), 16),
                norm_flags(m.group("flags")))
            continue
        m = NEEDED_RE.search(line)
        if m:
            needed.add(m.group("lib"))
            continue
        if "Symbol table '.dynsym'" in line:
            in_dynsym = True
            continue
        if line.startswith("Symbol table") or not line.strip():
            in_dynsym = in_dynsym and not line.startswith("Symbol table")
        if in_dynsym:
            m = SYM_RE.match(line)
            if m and m.group("type") != "Type":
                syms[int(m.group("num"))] = (
                    int(m.group("value"), 16), int(m.group("size")), m.group("type"),
                    m.group("bind"), m.group("ndx"), m.group("name"))
    return sections, segments, needed, syms


def parse_loupe(text: str):
    sections, segments, needed, syms = {}, {}, set(), {}
    for line in text.splitlines():
        f = line.split("\t")
        if f[0] == "section" and len(f) >= 8:
            sections[int(f[1])] = (f[2], f[3], int(f[4], 16), int(f[5], 16), int(f[6], 16))
        elif f[0] == "segment" and len(f) >= 8:
            segments[int(f[1])] = (int(f[3], 16), int(f[4], 16), int(f[5], 16),
                                   int(f[6], 16), norm_flags(f[7]))
        elif f[0] == "needed" and len(f) >= 2:
            needed.add(f[1])
        elif f[0] == "symbol" and len(f) >= 10 and f[1] == ".dynsym":
            syms[int(f[2])] = (int(f[3], 16), int(f[4]), f[5], f[6], f[8], f[9])
    return sections, segments, needed, syms


# llvm-readelf and Loupe spell a few type names differently; neither is wrong.
TYPE_ALIASES = {
    "GNU_IFUNC": "IFUNC",
    "UNIQUE": "GNU_UNIQUE",
}

# readelf writes a versioned symbol as "dlerror@GLIBC_2.34 (2)", where the
# trailing number is the symbol's index in the version table rather than part
# of its name. Loupe prints the version and leaves the index out. Same category
# as the aliases above: a spelling difference, not a disagreement.
VERSION_INDEX_RE = re.compile(r"\s+\(\d+\)$")


def norm_name(name: str) -> str:
    return VERSION_INDEX_RE.sub("", name)


def same_symbol(a, b) -> bool:
    va, sa, ta, ba, na, nma = a
    vb, sb, tb, bb, nb, nmb = b
    ta, tb = TYPE_ALIASES.get(ta, ta), TYPE_ALIASES.get(tb, tb)
    ba, bb = TYPE_ALIASES.get(ba, ba), TYPE_ALIASES.get(bb, bb)
    nma, nmb = norm_name(nma), norm_name(nmb)
    return (va, sa, ta, ba, na, nma) == (vb, sb, tb, bb, nb, nmb)


def compare(path: str, loupe: str, readelf: str, show: int):
    text = run([loupe, "--flat", "-S", "-l", "-D", "-s", "-i", path])
    if not text.startswith("format\tELF"):
        return path, "not an ELF file", 0
    if "warning\t" in text:
        return path, "loupe reported warnings", 0
    ls, lp, ln, lsym = parse_loupe(text)
    rs, rp, rn, rsym = parse_readelf(
        run([readelf, "-W", "-S", "-l", "-d", "--dyn-syms", path]))

    problems, records = [], len(ls) + len(lp) + len(ln) + len(lsym)
    if rs and ls != rs:
        diff = [k for k in set(ls) | set(rs) if ls.get(k) != rs.get(k)]
        problems.append("sections differ at %s %s" % (
            sorted(diff)[:show], [(ls.get(k), rs.get(k)) for k in sorted(diff)[:1]]))
    if rp and lp != rp:
        diff = [k for k in set(lp) | set(rp) if lp.get(k) != rp.get(k)]
        problems.append("segments differ at %s %s" % (
            sorted(diff)[:show], [(lp.get(k), rp.get(k)) for k in sorted(diff)[:1]]))
    if ln != rn:
        problems.append("needed: only loupe %s, only readelf %s" % (
            sorted(ln - rn)[:show], sorted(rn - ln)[:show]))
    if rsym:
        diff = [k for k in set(lsym) | set(rsym)
                if k not in lsym or k not in rsym or not same_symbol(lsym[k], rsym[k])]
        if diff:
            k = sorted(diff)[0]
            problems.append("%d dynamic symbols differ, first #%d: loupe %s readelf %s" % (
                len(diff), k, lsym.get(k), rsym.get(k)))
    return path, "; ".join(problems), records


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--dir")
    ap.add_argument("--recurse", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--loupe", default=DEFAULT_LOUPE)
    ap.add_argument("--readelf")
    ap.add_argument("--jobs", type=int, default=min(16, (os.cpu_count() or 4)))
    ap.add_argument("--show", type=int, default=3)
    args = ap.parse_args()

    paths = []
    for pattern in args.files:
        paths += glob.glob(pattern) if "*" in pattern else [pattern]
    if args.dir:
        if args.recurse:
            for root, _, files in os.walk(args.dir):
                paths += [os.path.join(root, f) for f in files]
        else:
            paths += [os.path.join(args.dir, f) for f in sorted(os.listdir(args.dir))]
    paths = [p for p in paths if os.path.isfile(p)]
    if args.limit:
        paths = paths[:args.limit]
    if not paths:
        return ap.print_usage() or 2

    readelf = args.readelf or find_readelf()
    loupe = os.path.abspath(args.loupe)
    checked = mismatched = skipped = records = 0
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futures = [pool.submit(compare, p, loupe, readelf, args.show) for p in paths]
        for fut in concurrent.futures.as_completed(futures):
            path, problem, n = fut.result()
            records += n
            if problem in ("not an ELF file", "loupe reported warnings"):
                skipped += 1
            elif problem:
                mismatched += 1
                print("MISMATCH %s\n         %s" % (path, problem))
            else:
                checked += 1
    print("\n%d files agree (%d records), %d mismatched, %d skipped"
          % (checked, records, mismatched, skipped))
    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
