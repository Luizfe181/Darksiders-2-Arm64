#!/usr/bin/env python3
"""Scan a PE for ASCII/UTF-16 strings matching keywords; print file offset and VA.

Usage:
    python analysis/scripts/pe_keyword_strings.py game_original/Darksiders2.exe inflate zlib lz4 ...
"""
import re
import struct
import sys

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def section_map(data):
    pe = u32(data, 0x3C)
    fh = pe + 4
    nsec = u16(data, fh + 2)
    opt_size = u16(data, fh + 16)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else u32(data, opt + 28)
    sections = []
    sec_off = opt + opt_size
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections.append({"name": name, "va": va, "vsize": vsize,
                         "raw_off": raw_off, "raw_size": raw_size})
    return image_base, sections


def off_to_va(sections, off):
    for s in sections:
        if s["raw_off"] <= off < s["raw_off"] + s["raw_size"]:
            return s["va"] + (off - s["raw_off"]), s["name"]
    return None, None


def main(path, keywords):
    data = open(path, "rb").read()
    image_base, sections = section_map(data)
    kws = [k.lower().encode() for k in keywords]
    hits = {k: [] for k in kws}
    for m in ASCII_RE.finditer(data):
        s = m.group(0)
        low = s.lower()
        for k in kws:
            if k in low:
                rva, sec = off_to_va(sections, m.start())
                hits[k].append((m.start(), rva, sec, s.decode("latin1")))
    for k in kws:
        rows = hits[k]
        print(f"\n=== {k.decode()} : {len(rows)} hits ===")
        for off, rva, sec, s in rows[:60]:
            va = f"0x{image_base + rva:012X}" if rva is not None else "?"
            print(f"  off=0x{off:08X} rva=0x{(rva or 0):08X} va={va} {sec} | {s[:160]}")
        if len(rows) > 60:
            print(f"  ... {len(rows) - 60} more")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2:])
