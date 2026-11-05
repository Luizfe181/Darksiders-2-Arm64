#!/usr/bin/env python3
"""Locate the RUNTIME_FUNCTION containing an RVA and find absolute references to an address.

Usage:
    python analysis/scripts/pe_xref_addr.py game_original/Darksiders2.exe 0xEBEBC0
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main(path, addr_s):
    data = open(path, "rb").read()
    pe = u32(data, 0x3C)
    fh = pe + 4
    nsec = u16(data, fh + 2)
    opt_size = u16(data, fh + 16)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else u32(data, opt + 28)
    dir_off = opt + 112 if magic == 0x20B else opt + 96

    sections = {}
    sec_off = opt + opt_size
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections[name] = (va, vsize, raw_off, raw_size)

    def rva_to_off(rva):
        for va, vsize, raw_off, raw_size in sections.values():
            if va <= rva < va + max(vsize, raw_size):
                return raw_off + (rva - va)
        return None

    rva = int(addr_s, 16)
    if rva >= image_base:
        rva -= image_base
    va = image_base + rva
    print(f"rva=0x{rva:X} va=0x{va:X} file_off=0x{(rva_to_off(rva) or 0):X}")

    ex_rva = u32(data, dir_off + 3 * 8)
    ex_size = u32(data, dir_off + 3 * 8 + 4)
    o = rva_to_off(ex_rva)
    funcs = [struct.unpack_from("<III", data, o + i * 12) for i in range(ex_size // 12)]
    enclosing = None
    for begin, end, unwind in funcs:
        if begin <= rva < end:
            enclosing = (begin, end, unwind)
            break
    if enclosing:
        begin, end, unwind = enclosing
        print(f"enclosing RUNTIME_FUNCTION begin=0x{begin:X} end=0x{end:X} "
              f"size={end - begin} unwind=0x{unwind:X} "
              f"begin_va=0x{image_base + begin:X}")
        idx = funcs.index(enclosing)
        for k in range(max(0, idx - 2), min(len(funcs), idx + 3)):
            b, e, u = funcs[k]
            print(f"  [{k}] 0x{b:X}..0x{e:X} ({e - b} bytes)")
    else:
        print("no .pdata entry contains this RVA")

    pat8 = struct.pack("<Q", va)
    pat4 = struct.pack("<I", rva)
    print("absolute 8-byte references (VA little-endian):")
    hits = 0
    start = 0
    while True:
        i = data.find(pat8, start)
        if i < 0:
            break
        sec = next((n for n, (sva, vs, ro, rs) in sections.items()
                    if ro <= i < ro + rs), "?")
        print(f"  file_off=0x{i:X} rva=0x{((i - sections[sec][2]) + sections[sec][0]) if sec in sections else 0:X} {sec}")
        hits += 1
        start = i + 1
        if hits >= 40:
            print("  ... (stopped at 40)")
            break
    if hits == 0:
        print("  none")
    print("4-byte RVA references:")
    hits = 0
    start = 0
    while True:
        i = data.find(pat4, start)
        if i < 0:
            break
        sec = next((n for n, (sva, vs, ro, rs) in sections.items()
                    if ro <= i < ro + rs), "?")
        if sec == ".rdata" or sec == ".data":
            off = i - sections[sec][2] + sections[sec][0]
            print(f"  file_off=0x{i:X} rva=0x{off:X} {sec}")
        hits += 1
        start = i + 1
        if hits >= 60:
            print("  ... (stopped at 60)")
            break
    if hits == 0:
        print("  none")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "0xEBEBC0")
