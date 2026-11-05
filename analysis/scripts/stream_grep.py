#!/usr/bin/env python3
"""Stream-search large files for ASCII needles and print byte context."""
import sys

path = sys.argv[1]
needles = [n.encode("latin1") for n in sys.argv[2:]]
chunk = 64 << 20
overlap = 256
pos = 0
hits = 0
with open(path, "rb") as f:
    prev = b""
    while True:
        buf = f.read(chunk)
        if not buf:
            break
        data = prev + buf
        for n in needles:
            start = 0
            while True:
                i = data.find(n, start)
                if i < 0:
                    break
                lo = max(0, i - 120)
                hi = min(len(data), i + 200)
                ctx = data[lo:hi]
                ctx = b"".join(bytes([c]) if 0x20 <= c < 0x7F else b"." for c in ctx)
                print(f"0x{pos - len(prev) + i:X} [{n.decode()}] {ctx.decode('latin1')}")
                hits += 1
                if hits > 40:
                    raise SystemExit
                start = i + 1
        prev = data[-overlap:]
        pos += len(buf)
print("done", hits)
