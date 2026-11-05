#!/usr/bin/env python3
"""Capstone-based cross-reference scanner for PE32+ x64 images.

Linear-sweeps .text and reports every reference whose resolved target is one of
the requested addresses. Handles:

  * RIP-relative memory operands  (lea/mov/cmp ... [rip+disp])
  * absolute immediates           (mov rax, imm64 / push imm)
  * direct relative call/jmp      (rel32 targets)

Usage:
    python analysis/scripts/pe_xrefs_capstone.py game_original/Darksiders2.exe \
        0x1412B9C90=Direct3DCreate9 0x1412D6988=d3d11.dll

Addresses may be RVAs or VAs (>= image base => treated as VA).
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM
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
    sec_off = opt + opt_size
    sections = {}
    order = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        sections[name] = {"va": va, "vsize": vsize, "raw": raw_off, "rawsize": raw_size}
        order.append(name)
    return data, image_base, sections, order


def file_off_to_va(sections, off, image_base):
    for name, s in sections.items():
        if s["raw"] <= off < s["raw"] + s["rawsize"]:
            return image_base + s["va"] + (off - s["raw"]), name
    return None, None


def main(path, specs):
    data, image_base, sections, _ = load_pe(path)
    targets = {}
    for spec in specs:
        addr_s, _, label = spec.partition("=")
        addr = int(addr_s, 16)
        if addr < image_base:
            addr += image_base
        targets[addr] = label or addr_s

    text = sections[".text"]
    blob = data[text["raw"]:text["raw"] + text["rawsize"]]
    base_va = image_base + text["va"]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True

    hits = {t: [] for t in targets}

    for insn in md.disasm(blob, base_va):
        if insn.id == 0:  # skipdata placeholder (.byte)
            continue
        try:
            operands = insn.operands
        except Exception:
            continue
        for op in operands:
            resolved = None
            kind = None
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                resolved = insn.address + insn.size + op.mem.disp
                kind = "rip"
            elif op.type == CS_OP_IMM:
                resolved = op.imm & 0xFFFFFFFFFFFFFFFF
                kind = "imm"
            if resolved is None or resolved not in targets:
                continue
            hits[resolved].append((insn.address, insn.mnemonic, insn.op_str, kind))

    for target, label in targets.items():
        rows = hits[target]
        print(f"\n=== 0x{target:012X}  {label} : {len(rows)} refs ===")
        for addr, mnem, ops, kind in rows[:80]:
            print(f"  {kind:3} 0x{addr:012X}  {mnem} {ops}")
        if len(rows) > 80:
            print(f"  ... {len(rows) - 80} more")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2:])
