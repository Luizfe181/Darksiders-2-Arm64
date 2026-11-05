#!/usr/bin/env python3
"""Recover the static class-registration thunks (lea r9 / lea r8 / lea rcx / mov edx / jmp).

Pattern (MSVC, x64, no ASLR):
    4C 8D 0D <d32>   lea r9,  [rip+d]   ; factory / extra pointer
    4C 8D 05 <d32>   lea r8,  [rip+d]   ; name
    48 8D 0D <d32>   lea rcx, [rip+d]   ; &static node
    BA <imm32>       mov edx, imm32     ; id
    E9 <d32>         jmp Register

Usage:
    python analysis/scripts/pe_class_registry.py game_original/Darksiders2.exe out.txt
"""
import struct
import sys


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
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections.append({"name": name, "va": va, "vsize": vsize,
                         "raw": raw_off, "rawsize": raw_size})

    def off_to_va(off):
        for s in sections:
            if s["raw"] <= off < s["raw"] + s["rawsize"]:
                return image_base + s["va"] + (off - s["raw"])
        return None

    def va_to_off(va):
        rva = va - image_base
        for s in sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["raw"] + (rva - s["va"])
        return None

    def cstr(va, limit=160):
        off = va_to_off(va)
        if off is None:
            return None
        chunk = data[off:off + limit]
        end = chunk.find(b"\0")
        if end <= 0:
            return None
        s = chunk[:end]
        if not all(0x20 <= c <= 0x7E for c in s):
            return None
        return s.decode("ascii", "replace")

    text = next(s for s in sections if s["name"] == ".text")
    rows = []
    for i in range(text["raw"], text["raw"] + text["rawsize"] - 31):
        if not (data[i] == 0x4C and data[i + 1] == 0x8D and data[i + 2] == 0x0D):
            continue
        if not (data[i + 7] == 0x4C and data[i + 8] == 0x8D and data[i + 9] == 0x05):
            continue
        if not (data[i + 14] == 0x48 and data[i + 15] == 0x8D and data[i + 16] == 0x0D):
            continue
        if data[i + 21] != 0xBA or data[i + 26] != 0xE9:
            continue
        d9 = struct.unpack_from("<i", data, i + 3)[0]
        d8 = struct.unpack_from("<i", data, i + 10)[0]
        d1 = struct.unpack_from("<i", data, i + 17)[0]
        ident = u32(data, i + 22)
        dj = struct.unpack_from("<i", data, i + 27)[0]
        va = off_to_va(i)
        factory = va + 7 + d9
        name_va = va + 14 + d8
        node_va = va + 21 + d1
        dest = va + 31 + dj
        name = cstr(name_va)
        if name is None:
            continue
        rows.append({"thunk": va, "id": ident, "name": name,
                     "name_va": name_va, "factory_va": factory,
                     "node_va": node_va, "register_va": dest})

    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# class-registration thunks: id thunk name_va node_va register\n")
        for r in sorted(rows, key=lambda r: r["id"]):
            f.write(f"0x{r['id']:04X} 0x{r['thunk']:012X} 0x{r['name_va']:012X} "
                    f"0x{r['node_va']:012X} 0x{r['register_va']:012X} {r['name']}\n")

    print(f"thunks found: {len(rows)}")
    regs = {}
    for r in rows:
        regs[r["register_va"]] = regs.get(r["register_va"], 0) + 1
    print("register targets:", {hex(k): v for k, v in regs.items()})
    ids = [r["id"] for r in rows]
    print(f"id range: 0x{min(ids):X}..0x{max(ids):X}, unique ids: {len(set(ids))}")
    for r in sorted(rows, key=lambda r: r["id"])[:80]:
        print(f"  0x{r['id']:04X} {r['name']}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "game_original/Darksiders2.exe",
         sys.argv[2] if len(sys.argv) > 2 else "analysis/reports/pe_class_registry.txt")
