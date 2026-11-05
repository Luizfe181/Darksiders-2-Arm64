#!/usr/bin/env python3
"""Resolve the MSVC RTTI class name for a vtable that contains a given pointer.

Given an address (RVA or VA) of a function pointer stored inside a vtable, walk
back to the first slot, read vtable[-1] (pointer to the Complete Object Locator)
and resolve the COL's type descriptor name.

Usage:
    python analysis/scripts/pe_rtti_vtable.py game_original/Darksiders2.exe 0x1415DCC58
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
    sections = {}
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections[name] = {"va": va, "vsize": vsize, "raw": raw_off, "rawsize": raw_size}
    return data, image_base, sections


def rva_to_off(sections, rva):
    for s in sections.values():
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def off_to_rva(sections, off):
    for name, s in sections.items():
        if s["raw"] <= off < s["raw"] + s["rawsize"]:
            return s["va"] + (off - s["raw"]), name
    return None, None


def main(path, addr_s):
    data, image_base, sections = load_pe(path)
    addr = int(addr_s, 16)
    if addr < image_base:
        addr += image_base
    off = rva_to_off(sections, addr - image_base)
    if off is None:
        raise SystemExit("address not mapped")

    text = sections[".text"]

    def is_code_ptr(v):
        if v < image_base:
            return False
        rva = v - image_base
        return text["va"] <= rva < text["va"] + text["vsize"]

    slot = off
    # align down to 8
    while slot % 8:
        slot -= 1
    while slot - 8 >= 0 and is_code_ptr(u64(data, slot - 8)):
        slot -= 8

    print(f"vtable start ~0x{image_base + off_to_rva(sections, slot)[0]:012X} "
          f"(file_off=0x{slot:X})")

    prev = u64(data, slot - 8) if slot >= 8 else 0
    print(f"  vtable[-1] = 0x{prev:016X}")
    slots = []
    p = slot
    while is_code_ptr(u64(data, p)):
        slots.append(u64(data, p))
        p += 8
    print(f"  {len(slots)} vtable slots")
    for i, v in enumerate(slots):
        mark = " <== queried" if image_base + off_to_rva(sections, slot)[0] + i * 8 == addr else ""
        print(f"    [{i:3}] 0x{v:012X}{mark}")

    if not is_code_ptr(prev):
        return
    col_rva = prev - image_base
    col_off = rva_to_off(sections, col_rva)
    if col_off is None:
        print("  COL not mapped")
        return
    sig, offset, cd = struct.unpack_from("<III", data, col_off)
    td_rva = u32(data, col_off + 12)
    print(f"  COL rva=0x{col_rva:X} signature=0x{sig:X} offset=0x{offset:X} "
          f"cdOffset=0x{cd:X} typeDescriptorRva=0x{td_rva:X}")
    td_off = rva_to_off(sections, td_rva)
    if td_off is None:
        print("  type descriptor not mapped")
        return
    ptype, mangled = struct.unpack_from("<QQ", data, td_off)
    end = data.index(b"\0", td_off + 16)
    name = data[td_off + 16:end].decode("latin1", "replace")
    print(f"  type name: {name}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
