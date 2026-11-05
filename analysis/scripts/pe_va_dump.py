#!/usr/bin/env python3
"""Dump memory at a VA/RVA with annotations and follow the first qword (vtable)."""
import struct
import sys

sys.path.insert(0, r"analysis/scripts")
from pe_dump import load_pe


def main(path, addr_s, count=8):
    data, image_base, sections = load_pe(path)
    addr = int(addr_s, 16)
    if addr < image_base:
        addr += image_base
    rva = addr - image_base
    off = None
    sec_name = None
    for name, va, vsize, raw_off, raw_size in sections:
        if va <= rva < va + max(vsize, raw_size):
            off = raw_off + (rva - va)
            sec_name = name
            break
    if off is None:
        raise SystemExit("not mapped")

    def annotate(v):
        if v == 0:
            return ""
        r = v - image_base
        for name, va, vsize, raw_off, raw_size in sections:
            if va <= r < va + max(vsize, raw_size):
                o = raw_off + (r - va)
                if name in (".rdata", ".data", ".rodata"):
                    chunk = data[o:o + 80]
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
                return f"{name}+0x{r - va:X}" if name == ".text" else name
        return ""

    print(f"VA 0x{addr:012X}  section={sec_name} file_off=0x{off:X}")
    for i in range(count):
        o = off + i * 8
        v = struct.unpack_from("<Q", data, o)[0]
        print(f"  [{i}] 0x{v:016X}  {annotate(v)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 8)
