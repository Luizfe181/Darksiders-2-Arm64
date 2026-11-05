#!/usr/bin/env python3
"""Find direct relative branches (call/jmp/jcc) that target a specific RVA/VA.

Usage:
    python analysis/scripts/pe_relbranch.py game_original/Darksiders2.exe 0x140EBEBC0
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main(path, target_s):
    data = open(path, "rb").read()
    pe = u32(data, 0x3C)
    fh = pe + 4
    nsec = u16(data, fh + 2)
    opt_size = u16(data, fh + 16)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else u32(data, opt + 28)
    sec_off = opt + opt_size
    sections = {}
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections[name] = (va, vsize, raw_off, raw_size)

    target = int(target_s, 16)
    if target < image_base:
        target += image_base
    text_va, text_vsize, text_raw, text_rawsize = sections[".text"]

    def rva_of(off):
        return text_va + (off - text_raw)

    hits = []
    for i in range(text_raw, text_raw + text_rawsize - 5):
        op = data[i]
        if op == 0xE8:
            rel = struct.unpack_from("<i", data, i + 1)[0]
            dest = image_base + rva_of(i + 5) + rel
            kind = "call"
        elif op == 0xE9:
            rel = struct.unpack_from("<i", data, i + 1)[0]
            dest = image_base + rva_of(i + 5) + rel
            kind = "jmp"
        elif op == 0x0F and 0x80 <= data[i + 1] <= 0x8F:
            rel = struct.unpack_from("<i", data, i + 2)[0]
            dest = image_base + rva_of(i + 6) + rel
            kind = f"jcc 0x{data[i + 1]:02X}"
        else:
            continue
        if dest == target:
            hits.append((i, kind))

    for off, kind in hits:
        rva = rva_of(off)
        print(f"{kind:10} at file_off=0x{off:X} rva=0x{rva:X} va=0x{image_base + rva:X}")
    print(f"{len(hits)} direct branches to 0x{target:X}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "0x140EBEBC0")
