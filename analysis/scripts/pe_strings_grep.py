#!/usr/bin/env python3
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else r"game_original/Darksiders2.exe"
needles = [n.lower() for n in sys.argv[2:]] or [
    "renderer", "d3d11", "d3d9", "dx11", "dx9", "direct3d", "platform",
]
data = open(path, "rb").read()
for m in re.finditer(rb"[ -~]{4,}", data):
    s = m.group().decode("latin1")
    low = s.lower()
    if any(n in low for n in needles):
        print(f"0x{m.start():X}  {s[:140]}")
