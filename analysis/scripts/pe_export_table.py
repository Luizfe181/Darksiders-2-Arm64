#!/usr/bin/env python3
"""Write the full PE export table (ordinal, VA, RVA, name) and per-namespace counts.

Usage: python analysis/scripts/pe_export_table.py game_original/Darksiders2.exe analysis/reports/pe_exports.txt
"""
import struct
import sys
from collections import Counter


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main(path, out):
    data = open(path, "rb").read()
    pe = u32(data, 0x3C)
    fh = pe + 4
    nsec = u16(data, fh + 2)
    opt_size = u16(data, fh + 16)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else u32(data, opt + 28)
    dir_off = opt + 112 if magic == 0x20B else opt + 96

    sections = []
    sec_off = opt + opt_size
    for i in range(nsec):
        o = sec_off + i * 40
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections.append((va, vsize, raw_off, raw_size))

    def rva_to_off(rva):
        for va, vsize, raw_off, raw_size in sections:
            if va <= rva < va + max(vsize, raw_size):
                return raw_off + (rva - va)
        return None

    def cstr(rva):
        off = rva_to_off(rva)
        end = data.index(b"\0", off)
        return data[off:end].decode("latin1", "replace")

    exp_rva = u32(data, dir_off)
    o = rva_to_off(exp_rva)
    (chars, ts, major, minor, name_rva, base, nfuncs, nnames,
     addr_funcs, addr_names, addr_ords) = struct.unpack_from("<IIHHIIIIIII", data, o)

    funcs = [u32(data, rva_to_off(addr_funcs) + i * 4) for i in range(nfuncs)]
    names = []
    for i in range(nnames):
        nrva = u32(data, rva_to_off(addr_names) + i * 4)
        ordv = u16(data, rva_to_off(addr_ords) + i * 2)
        names.append((ordv, cstr(nrva)))

    rows = []
    for ordv, name in names:
        rva = funcs[ordv] if ordv < len(funcs) else 0
        rows.append((base + ordv, image_base + rva, rva, name))
    rows.sort()

    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# PE exports of Darksiders2.exe (ordinal VA RVA decorated_name)\n")
        for ordinal, va, rva, name in rows:
            f.write(f"{ordinal:5d} 0x{va:012X} 0x{rva:08X} {name}\n")

    def ns(name):
        if "@Scaleform@@" in name:
            return "Scaleform"
        if "@GFx@" in name or name.startswith("?") and "@GFx@@" in name:
            return "GFx"
        if "CAk" in name or "@AK" in name or "Ak" in name:
            return "Wwise"
        return "other"

    counts = Counter(ns(n) for _, _, _, n in rows)
    print(f"wrote {len(rows)} exports to {out}")
    for k, v in counts.most_common():
        print(f"  {k:12} {v}")
    print("non-Scaleform/Wwise entries (first 40):")
    shown = 0
    for _, va, rva, name in rows:
        if ns(name) == "other":
            print(f"  0x{va:012X} {name}")
            shown += 1
            if shown >= 40:
                break


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "game_original/Darksiders2.exe",
         sys.argv[2] if len(sys.argv) > 2 else "analysis/reports/pe_exports.txt")
