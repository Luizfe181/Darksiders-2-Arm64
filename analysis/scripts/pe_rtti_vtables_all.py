#!/usr/bin/env python3
"""Map every MSVC RTTI vtable in a PE32+ x64 image: class name -> vtable VA.

Strategy:
  1. Scan .rdata/.data for Complete Object Locator candidates:
        [0] signature == 1
        [4] offset       (small, multiple of 4)
        [8] cdOffset     (small)
        [12] pTypeDescriptor  (RVA inside .rdata)
     and validate the type descriptor:
        pSelf == image_base + RVA, name starts with ".?A".
  2. Find the 8-byte VA of each COL inside the image; the vtable starts at
     reference + 8.

Usage:
    python analysis/scripts/pe_rtti_vtables_all.py game_original/Darksiders2.exe out.txt
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


def main(path, out):
    data, image_base, sections = load_pe(path)
    text = sections[".text"]

    def is_text(va):
        rva = va - image_base
        return text["va"] <= rva < text["va"] + text["vsize"]

    # 1. COL candidates
    cols = []  # (col_va, name)
    for sec_name in (".rdata", ".data"):
        s = sections[sec_name]
        for off in range(s["raw"], s["raw"] + s["rawsize"] - 16, 4):
            if u32(data, off) != 1:
                continue
            offset = u32(data, off + 4)
            cd = u32(data, off + 8)
            td_rva = u32(data, off + 12)
            if offset > 0x10000 or cd > 0x10000:
                continue
            td_off = rva_to_off(sections, td_rva)
            if td_off is None:
                continue
            pself = u64(data, td_off)
            if pself != image_base + td_rva:
                continue
            if data[td_off + 16:td_off + 19] != b".?A":
                continue
            end = data.index(b"\0", td_off + 16)
            name = data[td_off + 16:end].decode("latin1", "replace")
            col_va = image_base + off_to_rva(sections, off)[0]
            cols.append((col_va, name, offset, cd))

    # 2. references to each COL (vtable[-1])
    refs = {}
    for col_va, name, offset, cd in cols:
        pat = struct.pack("<Q", col_va)
        pos = 0
        while True:
            i = data.find(pat, pos)
            if i < 0:
                break
            rva, sec = off_to_rva(sections, i)
            if rva is not None and sec in (".rdata", ".data", "_RDATA"):
                refs.setdefault(col_va, []).append(image_base + rva + 8)
            pos = i + 1

    rows = []
    for col_va, name, offset, cd in cols:
        for vt in refs.get(col_va, []):
            rows.append((name, vt, col_va, offset, cd))

    rows.sort()
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# col_va vtable_va offset cdOffset mangled_name\n")
        for name, vt, col_va, offset, cd in rows:
            f.write(f"0x{col_va:012X} 0x{vt:012X} 0x{offset:X} 0x{cd:X} {name}\n")

    print(f"COL candidates: {len(cols)}")
    print(f"vtables resolved: {len(rows)}")
    matches = [r for r in rows if any(k in r[0].lower() for k in
                                      ("graphics", "renderer", "swapchain", "dx11", "dx9"))]
    print(f"renderer-related vtables: {len(matches)}")
    for name, vt, col_va, offset, cd in matches:
        print(f"  0x{vt:012X}  {name}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "game_original/Darksiders2.exe",
         sys.argv[2] if len(sys.argv) > 2 else "analysis/reports/pe_rtti_vtables.txt")
