#!/usr/bin/env python3
"""Find RIP-relative code references (lea/mov/movzx...) to a target address.

Scans .text for REX-prefixed opcodes with mod=00, rm=101 (RIP-relative) and
resolves the disp32 against the instruction end. Also handles the non-REX forms.

Usage:
    python analysis/scripts/pe_ripref.py game_original/Darksiders2.exe 0x140EBEBC0
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


# (prefix bytes, opcode byte, total length)
FORMS = [
    (b"\x48\x8d", 7), (b"\x4c\x8d", 7), (b"\x48\x8b", 7), (b"\x4c\x8b", 7),
    (b"\x48\x89", 7), (b"\x4c\x89", 7), (b"\x8d", 6), (b"\x8b", 6),
    (b"\x48\xc7", 11),  # mov qword ptr [rip+d], imm32
    (b"\xf3\x0f\x10", 8), (b"\x0f\x10", 7),
]


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
    text_va, text_vsize, text_raw, text_rawsize = sections[".text"]
    start = text_raw
    end = text_raw + text_rawsize
    hits = []
    for prefix, length in FORMS:
        pos = start
        while True:
            i = data.find(prefix, pos)
            if i < 0 or i >= end:
                break
            # opcode/modrm position depends on prefix length
            modrm_off = i + len(prefix) - 1 if prefix[-1:] != b"" else i
            # For forms like b"\x48\x8d", opcode is at i+1; modrm at i+2
            modrm = data[i + len(prefix)]
            if (modrm & 0xC7) == 0x05:
                disp_off = i + len(prefix) + 1
                disp = struct.unpack_from("<i", data, disp_off)[0]
                insn_end = disp_off + 4
                va = image_base + text_va + (insn_end - text_raw)
                resolved = va + disp
                if target - 0x800 < resolved < target + 0x800:
                    hits.append((i, resolved, prefix))
            pos = i + 1
    seen = set()
    for off, resolved, prefix in sorted(hits):
        rva = text_va + (off - text_raw)
        key = (off, resolved)
        if key in seen:
            continue
        seen.add(key)
        print(f"file_off=0x{off:X} rva=0x{rva:X} va=0x{image_base + rva:X} "
              f"-> 0x{resolved:X} (delta {resolved - target})")
    print(f"{len(seen)} candidate references")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "0x140EBEBC0")
