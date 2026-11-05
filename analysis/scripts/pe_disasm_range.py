#!/usr/bin/env python3
"""Disassemble one function (or explicit range) of a PE32+ x64 with resolved operands.

Every RIP-relative operand is annotated with the target section and, when the
target looks like printable data, with the ASCII string at that address.

Usage:
    python analysis/scripts/pe_disasm_range.py game_original/Darksiders2.exe 0x140D6C7DE
    python analysis/scripts/pe_disasm_range.py game_original/Darksiders2.exe 0x14074E2E1 0x14074E350
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86 import X86_REG_RIP


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def load_pe(path):
    data = open(path, "rb").read()
    pe = u32(data, 0x3C)
    fh = pe + 4
    nsec = u16(data, fh + 2)
    opt_size = u16(data, fh + 16)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else u32(data, opt + 28)
    dir_off = opt + 112 if magic == 0x20B else opt + 96
    sec_off = opt + opt_size
    sections = {}
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections[name] = {"va": va, "vsize": vsize, "raw": raw_off, "rawsize": raw_size}
    dirs = []
    for i in range(16):
        dirs.append((u32(data, dir_off + i * 8), u32(data, dir_off + i * 8 + 4)))
    return data, image_base, sections, dirs


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


def main(path, start_s, end_s=None):
    data, image_base, sections, dirs = load_pe(path)
    start = int(start_s, 16)
    if start < image_base:
        start += image_base

    if end_s:
        end = int(end_s, 16)
        if end < image_base:
            end += image_base
        source = "explicit range"
    else:
        # find enclosing RUNTIME_FUNCTION
        ex_rva, ex_size = dirs[3]
        o = rva_to_off(sections, ex_rva)
        end = None
        if o is not None:
            for i in range(ex_size // 12):
                begin, fend, unwind = struct.unpack_from("<III", data, o + i * 12)
                if image_base + begin <= start < image_base + fend:
                    start = image_base + begin
                    end = image_base + fend
                    source = f".pdata entry begin=0x{begin:X} end=0x{fend:X}"
                    break
        if end is None:
            # heuristic: bound by next callable boundary, cap 0x600 bytes
            end = start + 0x400
            source = "heuristic window (not in .pdata)"

    rva = start - image_base
    off = rva_to_off(sections, rva)
    if off is None:
        raise SystemExit("start not mapped")
    print(f"function 0x{start:012X} .. 0x{end:012X}  ({end - start} bytes)  [{source}]")

    def annotate(target):
        rva_t = target - image_base
        o = rva_to_off(sections, rva_t)
        if o is None:
            return f"0x{target:X}"
        _, sec = off_to_rva(sections, o)
        chunk = data[o:o + 96]
        printable = bytearray()
        for c in chunk:
            if c == 0:
                break
            if 0x20 <= c < 0x7F:
                printable.append(c)
            else:
                break
        label = ""
        if len(printable) >= 4 and len(printable) >= len(chunk.split(b"\0")[0]) - 1:
            label = '  "' + printable.decode("ascii") + '"'
        elif sec == ".text":
            label = "  (code)"
        return f"0x{target:X}{label}"

    blob = data[off:off + (end - start)]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    for insn in md.disasm(blob, start):
        notes = []
        try:
            ops = insn.operands
        except Exception:
            ops = []
        for op in ops:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                notes.append("-> " + annotate(target))
        raw = data[insn.address - image_base - sections[".text"]["va"] + sections[".text"]["raw"]:
                   insn.address - image_base - sections[".text"]["va"] + sections[".text"]["raw"] + insn.size]
        extra = ("   ; " + "  ".join(notes)) if notes else ""
        print(f"0x{insn.address:012X}  {raw.hex():<20} {insn.mnemonic} {insn.op_str}{extra}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
