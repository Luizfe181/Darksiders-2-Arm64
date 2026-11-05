#!/usr/bin/env python3
"""Extract MSVC RTTI type-descriptor names ('.?A...') from a PE and summarize by namespace.

Usage:
    python analysis/scripts/pe_rtti_names.py game_original/Darksiders2.exe out.txt
"""
import re
import struct
import sys
from collections import Counter

NAME_RE = re.compile(rb"\.\?A[\x20-\x7e]{2,400}")


def main(path, out):
    data = open(path, "rb").read()
    names = []
    seen = set()
    for m in NAME_RE.finditer(data):
        raw = m.group(0).rstrip(b"\0")
        # type descriptor names end at the first NUL; strip trailing junk classes
        try:
            s = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        if s in seen:
            continue
        seen.add(s)
        names.append((m.start(), s))

    names.sort()
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# MSVC RTTI type descriptor names found in the image\n")
        for off, s in names:
            f.write(f"0x{off:08X} {s}\n")

    def ns(s):
        m = re.search(r"@([A-Za-z_][A-Za-z0-9_]*)@@", s)
        return m.group(1) if m else "(none)"

    counts = Counter(ns(s) for _, s in names)
    print(f"unique mangled type names: {len(names)}")
    print("top enclosing namespaces:")
    for k, v in counts.most_common(25):
        print(f"  {k:28} {v}")

    lowered = [(off, s) for off, s in names
               if re.search(r"compress|codec|zlib|deflat|inflate|lz|pak|upak|obpk|stream|archive|serial|file", s, re.I)]
    print(f"\nnames matching compress/codec/pak/stream/archive/file: {len(lowered)}")
    for off, s in lowered[:120]:
        print(f"  0x{off:08X} {s}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "game_original/Darksiders2.exe",
         sys.argv[2] if len(sys.argv) > 2 else "analysis/reports/pe_rtti_names.txt")
