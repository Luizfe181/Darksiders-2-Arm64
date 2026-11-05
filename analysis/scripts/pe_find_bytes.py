#!/usr/bin/env python3
"""Search raw bytes for ASCII patterns and print the surrounding printable text."""
import re
import sys

path = sys.argv[1]
patterns = sys.argv[2:]
data = open(path, "rb").read()
for pat in patterns:
    raw = pat.encode("latin1")
    print(f"=== {pat!r} ===")
    start = 0
    n = 0
    while True:
        i = data.find(raw, start)
        if i < 0:
            break
        lo = i
        while lo > 0 and 0x20 <= data[lo - 1] < 0x7F:
            lo -= 1
        hi = i
        while hi < len(data) and 0x20 <= data[hi] < 0x7F:
            hi += 1
        print(f"  file=0x{i:X} ctx={data[lo:hi].decode('latin1')[:200]!r}")
        start = i + 1
        n += 1
        if n >= 20:
            break
