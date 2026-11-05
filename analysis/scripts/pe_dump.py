#!/usr/bin/env python3
"""Dump a region of a PE32+ image as qwords/dwords with pointer annotations.

Usage:
    python analysis/scripts/pe_dump.py game_original/Darksiders2.exe 0x1C3A940 0x1C3AB00 [--qword|--dword]
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def load_pe(path):
    data = open(path, "rb").read()
    pe = u32(data, 0x3C)
    fh = pe + 4
    nsec = u16(data, fh + 2)
    opt_size = u16(data, fh + 16)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = u64(data, opt + 24) if magic == 0x20B else u32(data, opt + 28)
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, va, vsize, raw_off, raw_size))
    return data, image_base, sections


def main(path, start_s, end_s, mode="qword"):
    data, image_base, sections = load_pe(path)
    start = int(start_s, 16)
    end = int(end_s, 16)
    step = 8 if mode == "qword" else 4

    def annotate(v):
        if v == 0:
            return ""
        rva = v - image_base
        for name, va, vsize, raw_off, raw_size in sections:
            if va <= rva < va + max(vsize, raw_size):
                off = raw_off + (rva - va)
                if name in (".rdata", ".data", ".rodata"):
                    chunk = data[off:off + 80]
                    printable = bytearray()
                    for c in chunk:
                        if c == 0:
                            break
                        if 0x20 <= c < 0x7F:
                            printable.append(c)
                        else:
                            break
                    if len(printable) >= 3:
                        return f'{name} "{printable.decode("latin1")}"'
                return f"{name}+0x{rva - va:X}" if name == ".text" else name
        return ""

    fmt = "<Q" if step == 8 else "<I"
    for off in range(start, end, step):
        v = struct.unpack_from(fmt, data, off)[0]
        print(f"0x{off:08X}  0x{v:0{step*2}X}  {annotate(v)}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    mode = "qword" if "--dword" not in sys.argv else "dword"
    main(args[0], args[1], args[2], mode)
