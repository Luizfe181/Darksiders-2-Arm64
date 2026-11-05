#!/usr/bin/env python3
"""Dump the PE export directory and summarize .pdata RUNTIME_FUNCTION coverage.

Usage: python analysis/scripts/pe_exports_pdata.py game_original/Darksiders2.exe
"""
import struct
import sys

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main(path):
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
        if off is None:
            return None
        end = data.index(b"\0", off)
        return data[off:end].decode("latin1", "replace")

    exp_rva = u32(data, dir_off + IMAGE_DIRECTORY_ENTRY_EXPORT * 8)
    exp_size = u32(data, dir_off + IMAGE_DIRECTORY_ENTRY_EXPORT * 8 + 4)
    print(f"export dir: rva=0x{exp_rva:X} size=0x{exp_size:X}")
    if exp_rva:
        o = rva_to_off(exp_rva)
        if o is None:
            print("  export dir RVA does not map to a section")
        else:
            (chars, ts, major, minor, name_rva, base, nfuncs, nnames,
             addr_funcs, addr_names, addr_ords) = struct.unpack_from("<IIHHIIIIIII", data, o)
            print(f"  characteristics=0x{chars:X} timestamp=0x{ts:X} version={major}.{minor}")
            print(f"  dll_name={cstr(name_rva)!r} ordinal_base={base}")
            print(f"  number_of_functions={nfuncs} number_of_names={nnames}")
            print(f"  address_of_functions=0x{addr_funcs:X} address_of_names=0x{addr_names:X} "
                  f"address_of_name_ordinals=0x{addr_ords:X}")
            for i in range(min(nfuncs, 40)):
                frva = u32(data, rva_to_off(addr_funcs) + i * 4)
                print(f"    func[{i}] rva=0x{frva:X} va=0x{image_base + frva:X}")
            for i in range(min(nnames, 40)):
                nrva = u32(data, rva_to_off(addr_names) + i * 4)
                ordv = u16(data, rva_to_off(addr_ords) + i * 2)
                print(f"    name[{i}] {cstr(nrva)!r} -> ordinal index {ordv}")

    ex_rva = u32(data, dir_off + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8)
    ex_size = u32(data, dir_off + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8 + 4)
    print(f"\nexception dir: rva=0x{ex_rva:X} size=0x{ex_size:X} "
          f"({ex_size // 12} RUNTIME_FUNCTION entries)")
    if ex_rva and ex_size:
        o = rva_to_off(ex_rva)
        starts = []
        for i in range(ex_size // 12):
            begin, end, unwind = struct.unpack_from("<III", data, o + i * 12)
            starts.append(begin)
        print(f"  first begin=0x{starts[0]:X} last begin=0x{starts[-1]:X}")
        print(f"  unique function starts={len(set(starts))}")
        nonmono = sum(1 for a, b in zip(starts, starts[1:]) if b < a)
        print(f"  non-monotonic transitions={nonmono}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "game_original/Darksiders2.exe")
