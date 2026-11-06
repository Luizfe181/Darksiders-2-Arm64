#!/usr/bin/env python3
"""
Vigil static recompiler -- frontend (x86-64 PE -> C for ARM64 NDK).

Blueprint adapted from bloodborne-recomp:

  scan.c      ->  build_function_map(): exact function bounds from the PE's
                  .pdata (the x64 exception directory). That is the analogue of
                  the PS4 unwind tables the reference uses for the same job.
  bbrecomp.c  ->  Emitter: one C function per guest function, registers in
                  locals, branches as `goto`, calls direct or through the
                  runtime, anything untranslatable left to the interpreter.

Rules carried over verbatim from the reference:
  * a generated function is `void f_<rva>(CpuContext *c)` and returns normally;
  * guest registers live in `uint64_t r[16]` / `Vec256 v[16]` locals and are
    copied into `*c` only around calls, interpreter fallbacks and exits;
  * decoding follows control flow from the entry, bounded here by .pdata;
  * anything not translated becomes a one-instruction interpreter call, so the
    output is complete from the first run ("always playable").

V1 keeps two things simple on purpose: flags are materialised eagerly, and every
register is synced at boundaries. The reference's liveness-based selective sync
and lazy-flag tags are optimisations, not a change of shape.

Usage:
    python tools/recompiler/main.py --limit 500
    python tools/recompiler/main.py --exe game_original/Darksiders2.exe --out out/recomp
"""
from __future__ import annotations

import argparse
import bisect
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
except ImportError:  # pragma: no cover
    sys.exit("capstone is required:  pip install capstone")

IMAGE_SCN_MEM_EXECUTE = 0x20000000

REG_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REG_INDEX = {n: i for i, n in enumerate(REG_NAMES)}
REG_INDEX32 = {n: i for i, n in enumerate(
    ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"])}

# name -> (register index, access width in bytes, is high byte)
ALIASES: dict[str, tuple[int, int, bool]] = {}
for _i, _n in enumerate(REG_NAMES):
    ALIASES[_n] = (_i, 8, False)
for _n, _i in (("eax", 0), ("ecx", 1), ("edx", 2), ("ebx", 3),
               ("esp", 4), ("ebp", 5), ("esi", 6), ("edi", 7)):
    ALIASES[_n] = (_i, 4, False)
for _n, _i in (("ax", 0), ("cx", 1), ("dx", 2), ("bx", 3),
               ("sp", 4), ("bp", 5), ("si", 6), ("di", 7)):
    ALIASES[_n] = (_i, 2, False)
for _i in range(8, 16):
    ALIASES[f"r{_i}d"] = (_i, 4, False)
    ALIASES[f"r{_i}w"] = (_i, 2, False)
    ALIASES[f"r{_i}b"] = (_i, 1, False)
for _n, _i in (("al", 0), ("cl", 1), ("dl", 2), ("bl", 3)):
    ALIASES[_n] = (_i, 1, False)
for _n, _i in (("spl", 4), ("bpl", 5), ("sil", 6), ("dil", 7)):
    ALIASES[_n] = (_i, 1, False)
for _n, _i in (("ah", 0), ("ch", 1), ("dh", 2), ("bh", 3)):
    ALIASES[_n] = (_i, 1, True)

CC = {"o": 0x0, "no": 0x1, "b": 0x2, "c": 0x2, "nae": 0x2, "ae": 0x3, "nb": 0x3,
      "nc": 0x3, "e": 0x4, "z": 0x4, "ne": 0x5, "nz": 0x5, "be": 0x6, "na": 0x6,
      "a": 0x7, "nbe": 0x7, "s": 0x8, "ns": 0x9, "p": 0xa, "pe": 0xa,
      "np": 0xb, "po": 0xb, "l": 0xc, "nge": 0xc, "ge": 0xd, "nl": 0xd,
      "le": 0xe, "ng": 0xe, "g": 0xf, "nle": 0xf}

MASK = (1 << 64) - 1
KNOWN_LEAF_FUNCTIONS = (
    (0x86C20, 0x86C6D, b"\x33\xC0\x48\x89"),
    (0xA9492, 0xA949D, None),   # Getter/chained entry
    (0xA949D, 0xA94AC, None),   # Setter / ret final
    (0xAAC9E, 0xAACA9, None),   # Vizinhança anterior
    (0xAACA9, 0xAACB5, None),   # Ponto crítico pós-initterm isolado
    (0xEBEBC0, 0xEBEC00, b""),  # Inserção em lista intrusiva de reflexão
    (0xEBEBF0, 0xEBEC40, b""),  # Busca por id u16 na lista intrusiva
)

# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------
@dataclass
class Section:
    name: str
    vaddr: int
    vsize: int
    rawptr: int
    rawsize: int
    chars: int


class PE:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        d = self.data
        e = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e:e + 4] != b"PE\0\0":
            raise SystemExit(f"{path}: not a PE image")
        coff = e + 4
        nsec = struct.unpack_from("<H", d, coff + 2)[0]
        optsz = struct.unpack_from("<H", d, coff + 16)[0]
        opt = coff + 20
        if struct.unpack_from("<H", d, opt)[0] != 0x20B:
            raise SystemExit(f"{path}: expected PE32+ (x86-64)")
        self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
        self.entry_rva = struct.unpack_from("<I", d, opt + 16)[0]
        self.sections: list[Section] = []
        sh = opt + optsz
        for i in range(nsec):
            o = sh + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("latin-1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)
            chars = struct.unpack_from("<I", d, o + 36)[0]
            self.sections.append(Section(name, vaddr, vsize, rawptr, rawsize, chars))

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.rawsize):
                delta = rva - s.vaddr
                return s.rawptr + delta if delta < s.rawsize else None
        return None

    def read_rva(self, rva: int, n: int) -> bytes | None:
        o = self.rva_to_off(rva)
        return None if o is None else self.data[o:o + n]

    def pdata_functions(self) -> dict[int, int]:
        """.pdata = RUNTIME_FUNCTION[] {Begin, End, Unwind}, RVAs: exact bounds."""
        sec = next((s for s in self.sections if s.name == ".pdata"), None)
        if sec is None:
            return {}
        out: dict[int, int] = {}
        for i in range(sec.vsize // 12):
            begin, end, _ = struct.unpack_from("<III", self.data, sec.rawptr + i * 12)
            if begin and end > begin:
                out[begin] = end
        return out


def build_function_map(pe: PE) -> dict[int, int]:
    
    funcs = pe.pdata_functions()
    if pe.entry_rva not in funcs:
        funcs[pe.entry_rva] = pe.entry_rva + 0x1000
    for begin, end, signature in KNOWN_LEAF_FUNCTIONS:
        code = pe.read_rva(begin, len(signature)) if signature else None
        terminator = pe.read_rva(end - 1, 1)
        if (signature is None or signature == b"" or code == signature) and begin not in funcs:
            funcs[begin] = end

    if not hasattr(pe, "sections") or not hasattr(pe, "data"):
        return funcs

    # Discover leaf functions not listed in .pdata (e.g. static initializers,
    # C++ constructors, getters/setters called via direct calls or initterm).
    sorted_pdata = sorted(funcs.items())
    pdata_starts = [b for b, _ in sorted_pdata]

    def is_in_pdata(rva: int) -> bool:
        idx = bisect.bisect_right(pdata_starts, rva) - 1
        if idx >= 0:
            b, e = sorted_pdata[idx]
            if b <= rva < e:
                return True
        return False

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def find_leaf_bound(start_rva: int, max_len: int = 2048) -> int | None:
        code = pe.read_rva(start_rva, max_len)
        if not code:
            return None
        end = start_rva
        has_insns = False
        for insn in md.disasm(code, pe.image_base + start_rva):
            has_insns = True
            end = insn.address - pe.image_base + insn.size
            if insn.mnemonic in ("ret", "ud2"):
                return end
            if insn.mnemonic == "jmp":
                ops = insn.operands
                if ops and ops[0].type == CS_OP_IMM:
                    target = (ops[0].imm - pe.image_base) & MASK
                    if not (start_rva <= target < end):
                        return end
                else:
                    return end
        return None

    candidates: set[int] = set()

    # 1. Initterm tables in .rdata
    for start, end in [(0x12b9e48, 0x12d2870), (0x12d2878, 0x12d28a0)]:
        off = pe.rva_to_off(start)
        if off is not None:
            count = (end - start) // 8
            for i in range(count):
                val = struct.unpack_from("<Q", pe.data, off + i * 8)[0]
                if val:
                    rva = val - pe.image_base
                    if not is_in_pdata(rva):
                        candidates.add(rva)

    # 2. Direct calls (0xE8) and tail jumps (0xE9) from executable sections
    for s in pe.sections:
        if s.chars & IMAGE_SCN_MEM_EXECUTE:
            sec_data = pe.data[s.rawptr : s.rawptr + s.rawsize]
            for i in range(len(sec_data) - 4):
                op = sec_data[i]
                if op in (0xE8, 0xE9):  # Call ou Tail-Call/Jmp
                    disp = struct.unpack_from("<i", sec_data, i + 1)[0]
                    target = s.vaddr + i + 5 + disp
                    if s.vaddr <= target < s.vaddr + s.vsize:
                        if not is_in_pdata(target):
                            candidates.add(target)

    # Bound candidates and sort
    discovered: dict[int, int] = {}
    for rva in sorted(candidates):
        bound = find_leaf_bound(rva)
        if bound and bound > rva:
            discovered[rva] = bound

    # Filter out overlapping sub-ranges (keep the earlier/wider function)
    sorted_leaves = sorted(discovered.items())
    filtered_leaves: dict[int, int] = {}
    prev_end = 0
    for b, e in sorted_leaves:
        if b < prev_end:
            continue
        filtered_leaves[b] = e
        prev_end = e

    funcs.update(filtered_leaves)
    return funcs


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------
class Emitter:
    def __init__(self, pe: PE, funcs: dict[int, int]):
        self.pe = pe
        self.funcs = funcs
        self.stats = {"insn": 0, "native": 0, "func": 0}
        # Instruction starts of the function being emitted. A branch to an
        # address that is not one of them lands inside another instruction
        # (overlapping code), and emitting a goto to it would reference a label
        # that never exists.
        self._starts: set[int] = set()

    # ---- operand helpers --------------------------------------------------
    def mem_expr(self, insn, op) -> str | None:
        m = op.mem
        terms: list[str] = []
        segment_name = insn.reg_name(m.segment) if m.segment else None
        if segment_name == "fs":
            terms.append("c->fs_base")
        elif segment_name == "gs":
            terms.append("c->gs_base")
        base_name = insn.reg_name(m.base) if m.base else None
        if base_name:
            if base_name == "rip":           # absolute target, expressed image-relative
                target = (insn.address + insn.size + m.disp) - self.pe.image_base
                terms.append(f"(uint64_t)(B + 0x{target & MASK:x}ull)")
                return " + ".join(terms)
            if base_name in REG_INDEX:
                terms.append(f"r[{REG_INDEX[base_name]}]")
            elif base_name in REG_INDEX32:   # 32-bit address size: zero-extended
                terms.append(f"(uint64_t)(uint32_t)r[{REG_INDEX32[base_name]}]")
            else:
                return None
        if m.index:
            iname = insn.reg_name(m.index)
            if iname in ("riz", "eiz"):       # pseudo index: zero, no register
                pass
            elif iname in REG_INDEX:
                terms.append(f"r[{REG_INDEX[iname]}] * {m.scale}")
            elif iname in REG_INDEX32:
                terms.append(
                    f"(uint64_t)(uint32_t)r[{REG_INDEX32[iname]}] * {m.scale}")
            else:
                return None
        if m.disp:
            terms.append(f"0x{m.disp & MASK:x}ull" if m.disp > 0
                         else f"(uint64_t)(-0x{-m.disp:x})")
        if not terms:
            terms.append("0")
        return " + ".join(terms)

    def string_op(self, real: str, prefix: str | None) -> str | None:
        width = {"b": 1, "w": 2, "d": 4, "q": 8}.get(real[-1])
        if width is None:
            return None
        kind = real[:3]
        ctype = f"uint{width * 8}_t"
        bits = width * 8
        mask = f"0x{(1 << bits) - 1:x}ull"
        step = f"((c->flags & F_DF) ? -{width} : {width})"
        acc = {1: "(r[0] & 0xffull)", 2: "(r[0] & 0xffffull)",
               4: "(r[0] & 0xffffffffull)", 8: "r[0]"}[width]
        if kind == "mov":
            body = (f"const {ctype} value = GuestLoad<{ctype}>(r[6]); "
                    f"GuestStore<{ctype}>(r[7], value); "
                    "r[6] += step; r[7] += step; --count;")
        elif kind == "sto":
            body = (f"const {ctype} value = static_cast<{ctype}>({acc}); "
                    f"GuestStore<{ctype}>(r[7], value); "
                    "r[7] += step; --count;")
        elif kind == "lod":
            store = {1: "r[0] = (r[0] & ~0xffull) | (value & 0xffull);",
                     2: "r[0] = (r[0] & ~0xffffull) | (value & 0xffffull);",
                     4: "r[0] = static_cast<uint32_t>(value);",
                     8: "r[0] = value;"}[width]
            body = (f"const {ctype} value = GuestLoad<{ctype}>(r[6]); "
                    f"{store} r[6] += step; --count;")
        elif kind in ("sca", "cmp"):
            if kind == "sca":
                load = (f"const {ctype} a = static_cast<{ctype}>({acc}); "
                        f"const {ctype} b = GuestLoad<{ctype}>(r[7]); "
                        "r[7] += step;")
            else:
                load = (f"const {ctype} a = GuestLoad<{ctype}>(r[6]); "
                        f"const {ctype} b = GuestLoad<{ctype}>(r[7]); "
                        "r[6] += step; r[7] += step;")
            stop = ""
            if prefix in ("repe", "repz"):
                stop = "if (!(c->flags & F_ZF)) break;"
            elif prefix in ("repne", "repnz"):
                stop = "if (c->flags & F_ZF) break;"
            body = (f"{load} const uint64_t result = "
                    f"(static_cast<uint64_t>(a) - static_cast<uint64_t>(b)) & {mask}; "
                    f"c->flags = ArithFlags(c->flags, 1, a, b, result, {width}); "
                    f"--count; {stop}")
        else:
            return None
        loop = prefix is not None
        count = "r[1]" if loop else "1"
        save = "r[1] = count;" if loop else ""
        return (f"{{ intptr_t step = {step}; uint64_t count = {count}; "
                f"while (count != 0) {{ {body} }} {save} }}")

    def rd(self, insn, op, size) -> str | None:
        """Read an operand as an unsigned expression of `size` bytes."""
        if op.type == CS_OP_REG:
            info = ALIASES.get(insn.reg_name(op.reg))
            if not info:
                return None
            i, width, high = info
            if high:
                return f"((r[{i}] >> 8) & 0xffull)"
            if width == 8:
                return f"r[{i}]"
            return f"(r[{i}] & 0x{(1 << (width * 8)) - 1:x}ull)"
        if op.type == CS_OP_IMM:
            return f"0x{op.imm & MASK:x}ull"
        if op.type == CS_OP_MEM:
            a = self.mem_expr(insn, op)
            return None if a is None else f"GuestLoad<uint{size * 8}_t>({a})"
        return None

    def wr(self, insn, op, size, value: str) -> str | None:
        """Statement writing `value` into `op` (size bytes)."""
        if op.type == CS_OP_REG:
            info = ALIASES.get(insn.reg_name(op.reg))
            if not info:
                return None
            i, width, high = info
            if high:
                return f"r[{i}] = (r[{i}] & ~0xff00ull) | (({value} & 0xffull) << 8);"
            if width == 8:
                return f"r[{i}] = {value};"
            if width == 4:                       # 32-bit writes zero-extend
                return f"r[{i}] = (uint32_t)({value});"
            mask = (1 << (width * 8)) - 1
            return f"r[{i}] = (r[{i}] & ~0x{mask:x}ull) | (({value}) & 0x{mask:x}ull);"
        if op.type == CS_OP_MEM:
            a = self.mem_expr(insn, op)
            return None if a is None else f"GuestStore<uint{size * 8}_t>({a}, {value});"
        return None

    @staticmethod
    def arith(kind: int, a: str, b: str, res: str, size: int, keep_cf=False) -> str:
        call = (f"ArithFlags(c->flags, {kind}, {a}, {b}, {res}, {size})")
        if keep_cf:                                # inc/dec preserve CF on x86
            call = f"((c->flags & F_CF) | ({call} & ~(uint64_t)F_CF))"
        return f"c->flags = {call};"

    # ---- instruction translation -----------------------------------------
    def translate(self, insn, start: int, end: int) -> str | None:
        mn = insn.mnemonic
        locked = mn.startswith("lock ")
        if locked:
            mn = mn[5:]
        ops = insn.operands
        size = ops[0].size if ops else 0

        # ---- string instructions, with optional rep/repe/repne --------------
        _prefix = None
        _real = mn
        if mn.split(" ", 1)[0] in ("rep", "repe", "repz", "repne", "repnz"):
            _prefix, _real = mn.split(" ", 1)
        if (_real[:3] in ("mov", "sto", "lod", "sca", "cmp")
                and _real[-1:] in ("b", "w", "d", "q")):
            _xmm = any(op.type == CS_OP_REG
                       and insn.reg_name(op.reg).startswith("xmm")
                       for op in ops)
            if not _xmm:
                return self.string_op(_real, _prefix)
        if _prefix is not None and _real != mn:
            mn = _real               # e.g. "repz ret"

        if mn in ("nop", "endbr64", "fnop", "int3", "prefetchw", "prefetchnta",
                  "prefetcht0", "prefetcht1", "prefetcht2", "prefetch", "pause",
                  "hlt", "wait", "fwait", "invlpg", "invlpga", "wbinvd",
                  "vmfunc", "monitor", "mwaitx", "fsetpm", "lmsw", "lgdt",
                  "lidt"):
            return ""
        if mn == "rdpkru":
            # EAX := PKRU (0; no protection keys), EDX := 0; ECX is preserved.
            return "r[0] = 0; r[2] = 0;"
        if mn == "xlatb":
            return ("r[0] = (r[0] & ~0xffull) | "
                    "GuestLoad<uint8_t>(r[3] + (r[0] & 0xffull));")
        if mn in ("insb", "insw", "insd", "outsb", "outsw", "outsd"):
            width = {"b": 1, "w": 2, "d": 4}[mn[-1]]
            pointer = "r[7]" if mn.startswith("ins") else "r[6]"
            step = f"((c->flags & F_DF) ? -{width} : {width})"
            if _prefix is not None:
                return (f"{{ intptr_t step = {step}; uint64_t count = r[1]; "
                        f"while (count != 0) {{ {pointer} += step; --count; }} "
                        "r[1] = count; }")
            return (f"{{ intptr_t step = {step}; {pointer} += step; }}")

        if mn == "clc":
            return "c->flags &= ~(uint64_t)F_CF;"
        if mn == "stc":
            return "c->flags |= F_CF;"
        if mn == "cmc":
            return "c->flags ^= F_CF;"
        if mn == "cld":
            return "c->flags &= ~(uint64_t)F_DF;"
        if mn == "std":
            return "c->flags |= F_DF;"
        if mn == "cli":
            return "c->flags &= ~(uint64_t)F_IF;"
        if mn == "sti":
            return "c->flags |= F_IF;"

        # ---- flags and machine-state instructions ---------------------------
        if mn in ("pushf", "pushfd", "pushfq"):
            width = {"pushf": 2, "pushfd": 4, "pushfq": 8}[mn]
            ctype = f"uint{width * 8}_t"
            return (f"{{ const uint64_t value = (c->flags & 0x3f7fd5ull) | 0x2ull; "
                    f"r[4] -= {width}; GuestStore<{ctype}>(r[4], "
                    f"static_cast<{ctype}>(value)); }}")
        if mn in ("popf", "popfd", "popfq"):
            width = {"popf": 2, "popfd": 4, "popfq": 8}[mn]
            ctype = f"uint{width * 8}_t"
            return (f"{{ const uint64_t value = GuestLoad<{ctype}>(r[4]); "
                    f"r[4] += {width}; c->flags = (value & 0x3f7fd5ull) | 0x2ull; }}")
        if mn in ("stmxcsr", "ldmxcsr"):
            if not ops or ops[0].type != CS_OP_MEM:
                return None
            address = self.mem_expr(insn, ops[0])
            if address is None:
                return None
            if mn == "stmxcsr":
                return f"GuestStore<uint32_t>({address}, c->mxcsr);"
            return f"c->mxcsr = GuestLoad<uint32_t>({address});"
        if mn == "smsw":
            if not ops:
                return None
            width = ops[0].size if ops[0].size in (2, 4, 8) else 2
            # Low half of CR0 with PE|MP|ET|NE set: flat 64-bit protected mode.
            return self.wr(insn, ops[0], width, "0x33ull")
        if mn in ("sidt", "sgdt"):
            if not ops or ops[0].type != CS_OP_MEM:
                return None
            address = self.mem_expr(insn, ops[0])
            if address is None:
                return None
            return (f"{{ const uint64_t a = {address}; "
                    "GuestStore<uint16_t>(a, 0); "
                    "GuestStore<uint64_t>(a + 2, 0); }")
        if mn == "enter":
            if len(ops) != 2:
                return None
            allocation = ops[0].imm & 0xffff
            level = ops[1].imm & 0x1f
            return ("{ const uint64_t frame = r[5]; r[4] -= 8; "
                    "GuestStore<uint64_t>(r[4], frame); "
                    f"if ({level} > 0) {{ uint64_t walk = r[5]; "
                    f"for (int i = 1; i < {level}; ++i) {{ walk -= 8; "
                    "r[4] -= 8; GuestStore<uint64_t>(r[4], "
                    "GuestLoad<uint64_t>(walk)); } "
                    "r[4] -= 8; GuestStore<uint64_t>(r[4], frame); } "
                    f"r[5] = frame; r[4] -= 0x{allocation:x}ull; }}")

        # ---- rotate through carry -------------------------------------------
        if mn in ("rcl", "rcr"):
            if len(ops) != 2 or size not in (1, 2, 4, 8):
                return None
            value = self.rd(insn, ops[0], size)
            count = self.rd(insn, ops[1], size)
            write = self.wr(insn, ops[0], size, "result")
            if value is None or count is None or write is None:
                return None
            bits = size * 8
            total = bits + 1
            mask = f"0x{(1 << bits) - 1:x}ull"
            if mn == "rcl":
                rotate = "(wide << rot) | (wide >> (total - rot))"
                overflow = "(msb ^ out_carry)"
            else:
                rotate = "(wide >> rot) | (wide << (total - rot))"
                overflow = f"(msb ^ ((result >> {bits - 2}) & 1ull))"
            return (f"{{ const uint64_t value = {value} & {mask}; "
                    "const uint64_t carry = (c->flags & F_CF) ? 1ull : 0ull; "
                    f"const unsigned total = {total}; "
                    f"const unsigned rot = static_cast<unsigned>({count}) % total; "
                    f"const unsigned __int128 wide = (unsigned __int128)value | "
                    f"((unsigned __int128)carry << {bits}); "
                    "const unsigned __int128 maskw = "
                    "((unsigned __int128)1 << total) - 1; "
                    f"const unsigned __int128 rotated = rot == 0 ? wide : ({rotate}); "
                    f"const uint64_t result = static_cast<uint64_t>(rotated & maskw) "
                    f"& {mask}; "
                    f"const uint64_t out_carry = static_cast<uint64_t>"
                    f"((rotated >> {bits}) & 1); "
                    f"{write} if (rot != 0) {{ "
                    f"const uint64_t msb = (result >> {bits - 1}) & 1ull; "
                    f"c->flags = (c->flags & ~(uint64_t)(F_CF | F_OF)) | "
                    f"(out_carry ? F_CF : 0) | (({overflow}) ? F_OF : 0); }} }}")

        if mn == "cdqe":
            return "r[0] = (uint64_t)(int64_t)(int32_t)(r[0] & 0xffffffffull);"
        if mn == "cwde":
            return "r[0] = (uint64_t)(uint32_t)(int32_t)(int16_t)(r[0] & 0xffffull);"
        if mn == "leave":
            return ("{ r[4] = r[5]; r[5] = GuestLoad<uint64_t>(r[4]); "
                    "r[4] += 8; }")
        if mn == "sahf":
            return ("c->flags = (c->flags & ~(uint64_t)0xd5ull) | "
                    "((r[0] >> 8) & 0xd5ull);")
        if mn == "lahf":
            return ("r[0] = (r[0] & ~0xff00ull) | "
                    "(((c->flags & 0xd5ull) | 0x02ull) << 8);")
        if mn == "in":
            if len(ops) != 2:
                return None
            return self.wr(insn, ops[0], size, "0")
        if mn == "out":
            return ""
        if mn == "cdq":
            return "r[2] = ((int32_t)r[0] < 0) ? 0xffffffffull : 0;"
        if mn == "cqo":
            return "r[2] = ((int64_t)r[0] < 0) ? ~0ull : 0;"
        if mn == "rdtsc":
            return ("{ const uint64_t ticks = static_cast<uint64_t>("
                    "std::chrono::steady_clock::now().time_since_epoch().count()); "
                    "r[0] = static_cast<uint32_t>(ticks); "
                    "r[2] = static_cast<uint32_t>(ticks >> 32); }")
        if mn == "cpuid":
            return (
                "{ const uint32_t leaf = static_cast<uint32_t>(r[RAX]); "
                "uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0; "
                "if (leaf == 0) { eax = 1; ebx = 0x756e6547u; "
                "edx = 0x49656e69u; ecx = 0x6c65746eu; } "
                "else if (leaf == 1) { eax = 0x000006a1u; "
                "edx = (1u << 0) | (1u << 4) | (1u << 5) | (1u << 8) | "
                "(1u << 15) | (1u << 23) | (1u << 24) | (1u << 25) | (1u << 26); } "
                "else if (leaf == 0x80000000u) { eax = 0x80000001u; } "
                "else if (leaf == 0x80000001u) { edx = (1u << 11) | "
                "(1u << 20) | (1u << 29); } "
                "r[RAX] = eax; r[RBX] = ebx; r[RCX] = ecx; r[RDX] = edx; }")

        if mn.startswith("set") and mn[3:] in CC and len(ops) == 1:
            return self.wr(insn, ops[0], 1,
                           f"(uint8_t)Cond(0x{CC[mn[3:]]:x}, c->flags)")

        if mn == "ret":
            extra = ops[0].imm if ops and ops[0].type == CS_OP_IMM else 0
            return ("{ const uint64_t t = GuestLoad<uint64_t>(r[RSP]); "
                    f"r[RSP] += {8 + extra}; c->rip = t; RC_SAVE(); return; }}")

        if mn in ("retf", "lret"):
            extra = ops[0].imm if ops and ops[0].type == CS_OP_IMM else 0
            return ("{ const uint64_t t = GuestLoad<uint64_t>(r[RSP]); "
                    f"r[RSP] += {16 + extra}; c->rip = t; RC_SAVE(); return; }}")

        # ---- moves to/from segment registers (flat model) -------------------
        _SEGMENTS = {"es": 0x2b, "cs": 0x33, "ss": 0x2b, "ds": 0x2b,
                     "fs": 0x53, "gs": 0x2b}
        if (mn in ("mov", "movzx", "movsx")
                and len(ops) == 2 and ops[1].type == CS_OP_REG
                and insn.reg_name(ops[1].reg) in _SEGMENTS):
            selector = _SEGMENTS[insn.reg_name(ops[1].reg)]
            return self.wr(insn, ops[0], size, f"0x{selector:x}ull")
        if (mn == "mov" and len(ops) == 2 and ops[0].type == CS_OP_REG
                and insn.reg_name(ops[0].reg) in _SEGMENTS):
            return ""                 # loading a selector has no visible effect

        if mn == "jmp":
            if ops[0].type == CS_OP_IMM:
                t = ((ops[0].imm & MASK) - self.pe.image_base) & MASK
                if start <= t < end and t in self._starts:
                    return f"goto L_{t:x};"
                if start <= t < end:
                    return None       # inside the function but not on an instruction start
                return f"{{ RC_SAVE(); c->rip = B + 0x{t:x}ull; rc->tail(c); return; }}"
            v = self.rd(insn, ops[0], 8)
            if v is None:
                return None
            return (f"{{ const uint64_t dn = {v}; RC_SAVE(); c->rip = dn; "
                    "rc->tail(c); return; }")

        if mn.startswith("j") and mn[1:] in CC:
            if ops[0].type != CS_OP_IMM:
                return None
            t = ((ops[0].imm & MASK) - self.pe.image_base) & MASK
            if start <= t < end:
                if t not in self._starts:
                    return None
                return f"if (Cond(0x{CC[mn[1:]]:x}, c->flags)) goto L_{t:x};"
            return (f"if (Cond(0x{CC[mn[1:]]:x}, c->flags)) "
                    f"{{ RC_SAVE(); c->rip = B + 0x{t:x}ull; "
                    "rc->tail(c); return; }")

        if mn in ("loop", "loope", "loopz", "loopne", "loopnz",
                  "jrcxz", "jecxz", "jcxz"):
            if ops[0].type != CS_OP_IMM:
                return None
            t = ((ops[0].imm & MASK) - self.pe.image_base) & MASK
            if start <= t < end:
                if t not in self._starts:
                    return None
                dest = f"goto L_{t:x};"
            else:
                dest = (f"{{ RC_SAVE(); c->rip = B + 0x{t:x}ull; "
                        "rc->tail(c); return; }")
            if mn in ("jrcxz", "jecxz", "jcxz"):
                return f"if (r[1] == 0) {dest}"
            decrement = "r[1] -= 1;"
            if mn == "loop":
                cond = "r[1] != 0"
            elif mn in ("loope", "loopz"):
                cond = "(r[1] != 0 && (c->flags & F_ZF))"
            else:
                cond = "(r[1] != 0 && !(c->flags & F_ZF))"
            return f"{{ {decrement} if ({cond}) {dest} }}"

        if mn == "call":
            nxt = insn.address + insn.size - self.pe.image_base
            if ops[0].type == CS_OP_IMM:
                t = ((ops[0].imm & MASK) - self.pe.image_base) & MASK
                if t in self.funcs:
                    return (f"{{ extern RcFn d_{t:x}; RC_SAVE(); "
                            f"if (d_{t:x}) {{ c->r[RSP] -= 8; "
                            f"GuestStore<uint64_t>(c->r[RSP], B + 0x{nxt:x}ull); "
                            f"c->rip = B + 0x{t:x}ull; d_{t:x}(c); }} "
                            f"else rc->call(c, B + 0x{t:x}ull, B + 0x{nxt:x}ull); "
                            "RC_LOAD(); }")
                return (f"{{ RC_SAVE(); rc->call(c, B + 0x{t:x}ull, "
                        f"B + 0x{nxt:x}ull); RC_LOAD(); }}")
            v = self.rd(insn, ops[0], 8)
            if v is None:
                return None
            return (f"{{ const uint64_t t = {v}; RC_SAVE(); rc->call(c, t, "
                    f"B + 0x{nxt:x}ull); RC_LOAD(); }}")

        if mn == "push":
            v = self.rd(insn, ops[0], 8)
            if v is None:
                return None
            return (f"{{ const uint64_t v = {v}; r[RSP] -= 8; "
                    "GuestStore<uint64_t>(r[RSP], v); }")
        if mn == "pop":
            v = "({ uint64_t v = GuestLoad<uint64_t>(r[RSP]); r[RSP] += 8; v; })"
            return self.wr(insn, ops[0], size, v)

        if mn in ("mov", "movabs"):
            v = self.rd(insn, ops[1], size)
            return self.wr(insn, ops[0], size, v) if v else None

        if mn == "lea":
            a = self.mem_expr(insn, ops[1])
            return self.wr(insn, ops[0], size, a) if a else None

        if mn in ("movzx", "movsx", "movsxd"):
            ssz = ops[1].size
            v = self.rd(insn, ops[1], ssz)
            if v is None:
                return None
            expr = v if mn == "movzx" else f"(uint64_t)(int64_t)(int{ssz * 8}_t)({v})"
            return self.wr(insn, ops[0], size, expr)

        if locked and mn in ("add", "inc", "dec", "xadd"):
            if ops[0].type != CS_OP_MEM or size not in (1, 2, 4, 8):
                return None
            address = self.mem_expr(insn, ops[0])
            if address is None:
                return None
            ctype = f"uint{size * 8}_t"
            if mn in ("inc", "dec"):
                operand = "1"
                delta = "1" if mn == "inc" else "-1"
                kind = 0 if mn == "inc" else 1
                keep_cf = True
            else:
                if len(ops) != 2:
                    return None
                operand = self.rd(insn, ops[1], size)
                if operand is None:
                    return None
                delta = operand
                kind = 0
                keep_cf = False
            src_write = ""
            if mn == "xadd":
                src_write = self.wr(insn, ops[1], size, "old") or ""
                if not src_write:
                    return None
            result = f"(old {'+' if kind == 0 else '-'} operand)"
            flags = self.arith(kind, "old", "operand", result, size, keep_cf)
            operation = "__atomic_fetch_add"
            atomic_delta = delta if mn not in ("inc", "dec") else f"static_cast<{ctype}>({delta})"
            return (f"{{ auto *p = reinterpret_cast<{ctype} *>({address}); "
                    f"const {ctype} operand = static_cast<{ctype}>({operand}); "
                    f"const uint64_t old = {operation}(p, {atomic_delta}, "
                    f"__ATOMIC_SEQ_CST); {flags} {src_write} }}")

        if mn == "cmpxchg":
            dst = self.rd(insn, ops[0], size)
            src = self.rd(insn, ops[1], size)
            if dst is None or src is None or size not in (1, 2, 4, 8):
                return None

            mask = (1 << (size * 8)) - 1
            acc = f"(r[0] & 0x{mask:x}ull)"
            acc_write = (f"r[0] = observed;" if size == 8 else
                         "r[0] = (uint32_t)observed;" if size == 4 else
                         f"r[0] = (r[0] & ~0x{mask:x}ull) | "
                         f"(observed & 0x{mask:x}ull);")
            flags = self.arith(1, "accumulator", "observed",
                               "(accumulator - observed)", size)

            if ops[0].type == CS_OP_MEM:
                address = self.mem_expr(insn, ops[0])
                if address is None:
                    return None
                ctype = f"uint{size * 8}_t"
                return (f"{{ auto *p = reinterpret_cast<{ctype} *>({address}); "
                        f"const uint64_t accumulator = {acc}; "
                        f"{ctype} expected = __atomic_load_n(p, __ATOMIC_SEQ_CST); "
                        "while (true) { const uint64_t observed = expected; "
                        f"{flags} if (accumulator != observed) {{ {acc_write} break; }} "
                        f"if (__atomic_compare_exchange_n(p, &expected, "
                        f"static_cast<{ctype}>({src}), false, __ATOMIC_SEQ_CST, "
                        "__ATOMIC_SEQ_CST)) break; } }")

            dst_write = self.wr(insn, ops[0], size, src)
            if dst_write is None:
                return None
            return (f"{{ const uint64_t accumulator = {acc}; "
                    f"const uint64_t observed = {dst}; {flags} "
                    f"if (accumulator == observed) {{ {dst_write} }} "
                    f"else {{ {acc_write} }} }}")

        if mn == "imul":
            if len(ops) == 1:
                operand = self.rd(insn, ops[0], size)
                acc = {
                    1: "(r[0] & 0xffull)",
                    2: "(r[0] & 0xffffull)",
                    4: "(r[0] & 0xffffffffull)",
                    8: "r[0]",
                }.get(size)
                if operand is None or acc is None:
                    return None
                bits = size * 8
                wide = f"int{bits * 2}_t" if bits < 64 else "__int128"
                low_mask = f"0x{(1 << bits) - 1:x}ull"
                signed = f"int{bits}_t"
                low_write = ("r[0] = (r[0] & ~0xffull) | (low & 0xffull);"
                             if size == 1 else
                             "r[0] = (r[0] & ~0xffffull) | (low & 0xffffull);"
                             if size == 2 else
                             "r[0] = (uint32_t)low;" if size == 4 else
                             "r[0] = low;")
                high_write = (f"r[0] = (r[0] & ~0xff00ull) | ((high & 0xffull) << 8);"
                              if size == 1 else
                              "r[2] = (r[2] & ~0xffffull) | (high & 0xffffull);"
                              if size == 2 else
                              "r[2] = (uint32_t)high;" if size == 4 else
                              "r[2] = high;")
                sign_bit = f"0x{1 << (bits - 1):x}ull"
                return (f"{{ const {wide} product = ({wide})({signed})({acc}) * "
                        f"({wide})({signed})({operand}); "
                        f"const uint64_t low = (uint64_t)product & {low_mask}; "
                        f"const uint64_t high = ((uint64_t)(product >> {bits})) & {low_mask}; "
                        f"{low_write} {high_write} "
                        f"if (high != ((low & {sign_bit}) ? {low_mask} : 0)) "
                        "c->flags |= F_CF | F_OF; else c->flags &= ~(uint64_t)(F_CF | F_OF); }")
            if len(ops) not in (2, 3) or size not in (2, 4, 8):
                return None
            lhs = self.rd(insn, ops[1] if len(ops) == 3 else ops[0], size)
            rhs = self.rd(insn, ops[2] if len(ops) == 3 else ops[1], size)
            if lhs is None or rhs is None:
                return None
            bits = size * 8
            wide = "int64_t" if bits < 64 else "__int128"
            signed = f"int{bits}_t"
            dst_write = self.wr(insn, ops[0], size, "low")
            if dst_write is None:
                return None
            mask = f"0x{(1 << bits) - 1:x}ull"
            return (f"{{ const {wide} product = ({wide})({signed})({lhs}) * "
                    f"({wide})({signed})({rhs}); const uint64_t low = "
                    f"(uint64_t)product & {mask}; {dst_write} "
                    f"if (product < -((({wide})1) << {bits - 1}) || "
                    f"product > ((({wide})1 << {bits - 1}) - 1)) "
                    "c->flags |= F_CF | F_OF; else c->flags &= ~(uint64_t)(F_CF | F_OF); }")

        if mn == "mul":
            if len(ops) != 1 or size not in (1, 2, 4, 8):
                return None
            operand = self.rd(insn, ops[0], size)
            acc = {
                1: "(r[0] & 0xffull)",
                2: "(r[0] & 0xffffull)",
                4: "(r[0] & 0xffffffffull)",
                8: "r[0]",
            }.get(size)
            if operand is None or acc is None:
                return None
            bits = size * 8
            wide = f"uint{bits * 2}_t" if bits < 64 else "unsigned __int128"
            low_mask = f"0x{(1 << bits) - 1:x}ull"
            low_write = ("r[0] = (r[0] & ~0xffull) | (low & 0xffull);"
                         if size == 1 else
                         "r[0] = (r[0] & ~0xffffull) | (low & 0xffffull);"
                         if size == 2 else
                         "r[0] = (uint32_t)low;" if size == 4 else
                         "r[0] = low;")
            high_write = ("r[0] = (r[0] & ~0xff00ull) | ((high & 0xffull) << 8);"
                          if size == 1 else
                          "r[2] = (r[2] & ~0xffffull) | (high & 0xffffull);"
                          if size == 2 else
                          "r[2] = (uint32_t)high;" if size == 4 else
                          "r[2] = high;")
            return (f"{{ const {wide} product = ({wide})({acc}) * "
                    f"({wide})({operand}); "
                    f"const uint64_t low = (uint64_t)product & {low_mask}; "
                    f"const uint64_t high = ((uint64_t)(product >> {bits})) & {low_mask}; "
                    f"{low_write} {high_write} "
                    "if (high != 0) c->flags |= F_CF | F_OF; "
                    "else c->flags &= ~(uint64_t)(F_CF | F_OF); }")

        if mn in ("div", "idiv"):
            if len(ops) != 1 or size not in (1, 2, 4, 8):
                return None
            operand = self.rd(insn, ops[0], size)
            if operand is None:
                return None
            bits = size * 8
            signed = mn == "idiv"
            if size == 1:
                dividend = "(r[0] & 0xffffull)"
                quotient_write = "r[0] = (r[0] & ~0xffull) | (quotient & 0xffull);"
                remainder_write = ("r[0] = (r[0] & ~0xff00ull) | "
                                   "((remainder & 0xffull) << 8);")
            elif size == 2:
                dividend = "(((r[2] & 0xffffull) << 16) | (r[0] & 0xffffull))"
                quotient_write = ("r[0] = (r[0] & ~0xffffull) | "
                                  "(quotient & 0xffffull);")
                remainder_write = ("r[2] = (r[2] & ~0xffffull) | "
                                   "(remainder & 0xffffull);")
            elif size == 4:
                dividend = ("(((uint64_t)(r[2] & 0xffffffffull) << 32) | "
                            "(r[0] & 0xffffffffull))")
                quotient_write = "r[0] = (uint32_t)quotient;"
                remainder_write = "r[2] = (uint32_t)remainder;"
            else:
                dividend = ("(((unsigned __int128)r[2] << 64) | r[0])"
                            if not signed else
                            "(((__int128)(int64_t)r[2] << 64) | r[0])")
                quotient_write = "r[0] = (uint64_t)quotient;"
                remainder_write = "r[2] = (uint64_t)remainder;"
            if signed:
                wide = f"int{bits * 2}_t" if bits < 64 else "__int128"
                dtype = f"int{bits}_t"
                dividend = f"static_cast<{wide}>({dividend})"
            else:
                wide = f"uint{bits * 2}_t" if bits < 64 else "unsigned __int128"
                dtype = f"uint{bits}_t"
            here = insn.address - self.pe.image_base
            return (f"{{ const {wide} dividend = {dividend}; "
                    f"const {dtype} divisor = static_cast<{dtype}>({operand}); "
                    f"if (divisor == 0) {{ c->rip = B + 0x{here:x}ull; RC_SAVE(); "
                    "rc->interp(c); RC_LOAD(); } else { "
                    f"const {wide} quotient = dividend / divisor; "
                    f"const {wide} remainder = dividend % divisor; "
                    f"{quotient_write} {remainder_write} }} }}")

        if mn in ("bt", "bts", "btr", "btc"):
            if size not in (2, 4, 8):
                return None
            index = self.rd(insn, ops[1], size)
            if index is None:
                return None
            bit = f"({index} & {size * 8 - 1})"
            ctype = f"uint{size * 8}_t"
            if ops[0].type == CS_OP_MEM:
                address = self.mem_expr(insn, ops[0])
                if address is None:
                    return None
                if mn == "bt":
                    return (f"{{ const uint64_t tested = GuestLoad<{ctype}>({address}); "
                            f"c->flags = (c->flags & ~(uint64_t)F_CF) | "
                            f"(((tested >> {bit}) & 1ull) ? F_CF : 0); }}")
                op = {"bts": "|", "btr": "&", "btc": "^"}[mn]
                mask = f"(static_cast<{ctype}>(1) << {bit})"
                expr = (f"static_cast<{ctype}>(value & ~mask)" if mn == "btr"
                        else f"static_cast<{ctype}>(value {op} mask)")
                return (f"{{ const uint64_t tested = GuestLoad<{ctype}>({address}); "
                        f"c->flags = (c->flags & ~(uint64_t)F_CF) | "
                        f"(((tested >> {bit}) & 1ull) ? F_CF : 0); "
                        f"const {ctype} value = static_cast<{ctype}>(tested); "
                        f"const {ctype} mask = {mask}; "
                        f"GuestStore<{ctype}>({address}, {expr}); }}")
            if ops[0].type != CS_OP_REG:
                return None
            value = self.rd(insn, ops[0], size)
            if value is None:
                return None
            write = ""
            if mn != "bt":
                op = {"bts": "|", "btr": "&", "btc": "^"}[mn]
                mask = f"(1ull << {bit})"
                expr = f"({value} {op} {'~' if mn == 'btr' else ''}{mask})"
                write = self.wr(insn, ops[0], size, expr) or ""
                if not write:
                    return None
            return (f"{{ const uint64_t tested = {value}; "
                    f"c->flags = (c->flags & ~(uint64_t)F_CF) | "
                    f"(((tested >> {bit}) & 1ull) ? F_CF : 0); {write} }}")

        if mn == "bsr":
            if len(ops) != 2 or size not in (2, 4, 8):
                return None
            source = self.rd(insn, ops[1], size)
            write = self.wr(insn, ops[0], size, "index")
            if source is None or write is None:
                return None
            return (f"{{ uint64_t value = {source}; "
                    "if (value == 0) { c->flags |= F_ZF; } else { "
                    "uint64_t index = 0; while ((value >>= 1) != 0) ++index; "
                    f"{write} c->flags &= ~(uint64_t)F_ZF; }} }}")

        if mn == "xchg":
            if size not in (1, 2, 4, 8):
                return None
            ctype = f"uint{size * 8}_t"
            if ops[0].type == CS_OP_MEM or ops[1].type == CS_OP_MEM:
                mem_op, reg_op = (ops[0], ops[1]) if ops[0].type == CS_OP_MEM else (ops[1], ops[0])
                address = self.mem_expr(insn, mem_op)
                value = self.rd(insn, reg_op, size)
                writeback = self.wr(insn, reg_op, size, "old")
                if address is None or value is None or writeback is None:
                    return None
                return (f"{{ auto *p = reinterpret_cast<{ctype} *>({address}); "
                        f"const {ctype} value = static_cast<{ctype}>({value}); "
                        f"const {ctype} old = __atomic_exchange_n(p, value, "
                        f"__ATOMIC_SEQ_CST); {writeback} }}")

            first = self.rd(insn, ops[0], size)
            second = self.rd(insn, ops[1], size)
            write_first = self.wr(insn, ops[0], size, "second")
            write_second = self.wr(insn, ops[1], size, "first")
            if None in (first, second, write_first, write_second):
                return None
            return (f"{{ const uint64_t first = {first}; const uint64_t second = {second}; "
                    f"{write_first} {write_second} }}")

        if mn == "sbb":
            a = self.rd(insn, ops[0], size)
            b = self.rd(insn, ops[1], size)
            if a is None or b is None or size not in (1, 2, 4, 8):
                return None
            mask = f"0x{(1 << (size * 8)) - 1:x}ull"
            result = f"((a - b - carry) & {mask})"
            write = self.wr(insn, ops[0], size, "result")
            if write is None:
                return None
            return (f"{{ const uint64_t carry = (c->flags & F_CF) ? 1ull : 0ull; "
                    f"const uint64_t a = {a} & {mask}; "
                    f"const uint64_t b = {b} & {mask}; "
                    f"const uint64_t result = {result}; "
                    f"uint64_t flags = ArithFlags(c->flags, 1, a, b, result, {size}); "
                    f"if (a < b || (carry && a == b)) flags |= F_CF; "
                    f"else flags &= ~(uint64_t)F_CF; c->flags = flags; {write} }}")

        if mn == "adc":
            a = self.rd(insn, ops[0], size)
            b = self.rd(insn, ops[1], size)
            if a is None or b is None or size not in (1, 2, 4, 8):
                return None
            bits = size * 8
            mask = f"0x{(1 << bits) - 1:x}ull"
            write = self.wr(insn, ops[0], size, "result")
            if write is None:
                return None
            wide = f"uint{bits * 2}_t" if bits < 64 else "unsigned __int128"
            return (f"{{ const uint64_t carry = (c->flags & F_CF) ? 1ull : 0ull; "
                    f"const uint64_t a = {a} & {mask}; "
                    f"const uint64_t b = {b} & {mask}; "
                    f"const {wide} sum = ({wide})a + b + carry; "
                    f"const uint64_t result = (uint64_t)sum & {mask}; "
                    f"uint64_t flags = ArithFlags(c->flags, 0, a, b, result, {size}); "
                    f"if ((sum >> {bits}) != 0) flags |= F_CF; "
                    "else flags &= ~(uint64_t)F_CF; c->flags = flags; "
                    f"{write} }}")

        if mn in ("rol", "ror"):
            if len(ops) != 2 or size not in (1, 2, 4, 8):
                return None
            a = self.rd(insn, ops[0], size)
            count = self.rd(insn, ops[1], size)
            if a is None or count is None:
                return None
            bits = size * 8
            mask = f"0x{(1 << bits) - 1:x}ull"
            left = "<<" if mn == "rol" else ">>"
            right = ">>" if mn == "rol" else "<<"
            if mn == "rol":
                carry = "(result & 1ull)"
                overflow = (f"(((result >> {bits - 1}) ^ result) & 1ull)")
            else:
                carry = f"((result >> {bits - 1}) & 1ull)"
                overflow = (f"(((result >> {bits - 1}) ^ "
                            f"(result >> {bits - 2})) & 1ull)")
            write = self.wr(insn, ops[0], size, "result")
            if write is None:
                return None
            return (f"{{ const uint64_t value = {a} & {mask}; "
                    f"const unsigned count = static_cast<unsigned>({count}); "
                    f"const unsigned rot = count & {bits - 1}; "
                    f"const uint64_t result = rot == 0 ? value : "
                    f"(((value {left} rot) | (value {right} ({bits} - rot))) & {mask}); "
                    f"{write} c->flags = (c->flags & ~(uint64_t)(F_CF | F_OF)) | "
                    f"(rot == 0 ? (c->flags & F_CF) : ((({carry}) != 0) ? F_CF : 0)) | "
                    f"(rot == 1 && ({overflow}) != 0 ? F_OF : 0); }}")

        if mn in ("add", "sub", "and", "or", "xor", "cmp", "test"):
            a = self.rd(insn, ops[0], size)
            b = self.rd(insn, ops[1], size)
            if a is None or b is None:
                return None
            kind = {"add": 0, "sub": 1, "cmp": 1}.get(mn, 2)
            cop = {"add": "+", "sub": "-", "and": "&", "or": "|",
                   "xor": "^", "cmp": "-", "test": "&"}[mn]
            res = f"({a} {cop} {b})"
            flags = self.arith(kind, a, b, res, size)
            if mn in ("cmp", "test"):
                return f"{{ {flags} }}"
            st = self.wr(insn, ops[0], size, res)
            return f"{{ {flags} {st} }}" if st else None

        if mn in ("inc", "dec"):
            a = self.rd(insn, ops[0], size)
            if a is None:
                return None
            expr = f"({a} + 1)" if mn == "inc" else f"({a} - 1)"
            kind = 0 if mn == "inc" else 1
            st = self.wr(insn, ops[0], size, expr)
            return (f"{{ {self.arith(kind, a, '1', expr, size, keep_cf=True)} {st} }}"
                    if st else None)

        if mn == "neg":
            a = self.rd(insn, ops[0], size)
            if a is None:
                return None
            expr = f"(0 - {a})"
            st = self.wr(insn, ops[0], size, expr)
            return (f"{{ {self.arith(1, '0', a, expr, size)} {st} }}" if st else None)

        if mn == "not":
            a = self.rd(insn, ops[0], size)
            if a is None:
                return None
            st = self.wr(insn, ops[0], size, f"(~{a})")
            return f"{{ {st} }}" if st else None

        if mn in ("shl", "sal", "shr", "sar"):
            a = self.rd(insn, ops[0], size)
            if a is None:
                return None
            if len(ops) > 1:
                n = self.rd(insn, ops[1], 1)
            else:
                n = "1"
            if n is None:
                return None
            bits = size * 8
            if mn == "sar":
                expr = f"(uint64_t)((int{bits}_t)({a}) >> ({n} & {bits - 1}))"
            elif mn == "shr":
                expr = f"(({a} & 0x{(1 << bits) - 1:x}ull) >> ({n} & {bits - 1}))"
            else:
                expr = f"({a} << ({n} & {bits - 1}))"
            st = self.wr(insn, ops[0], size, expr)
            return f"{{ {st} }}" if st else None

        if mn.startswith("set") and mn[3:] in CC:
            return self.wr(insn, ops[0], 1,
                           f"(uint64_t)Cond(0x{CC[mn[3:]]:x}, c->flags)")

        if mn.startswith("cmov") and mn[4:] in CC:
            v = self.rd(insn, ops[1], size)
            if v is None:
                return None
            st = self.wr(insn, ops[0], size,
                         f"(Cond(0x{CC[mn[4:]]:x}, c->flags) ? {v} : "
                         f"{self.rd(insn, ops[0], size)})")
            return f"{{ {st} }}" if st else None

        result = self.x87(insn, mn, ops, size)
        if result is not None:
            return result
        return self.vec(insn, start, end)

    # ---- SSE (16-byte, legacy encoding) ----------------------------------
    @staticmethod
    def xmm_idx(insn, op) -> int | None:
        if op.type != CS_OP_REG:
            return None
        nm = insn.reg_name(op.reg)
        if not nm.startswith("xmm"):
            return None
        try:
            i = int(nm[3:])
        except ValueError:
            return None
        return i if 0 <= i < 16 else None

    def vec_addr(self, insn, op) -> str | None:
        return self.mem_expr(insn, op) if op.type == CS_OP_MEM else None

    PACKED_MOVES = {"movaps", "movups", "movdqa", "movdqu", "movapd", "movupd"}
    LOGIC = {"xorps": "^", "xorpd": "^", "pxor": "^", "andps": "&", "andpd": "&",
             "pand": "&", "orps": "|", "orpd": "|", "por": "|"}
    ARITH = {"addps": ("f", 4, "+"), "subps": ("f", 4, "-"), "mulps": ("f", 4, "*"),
             "divps": ("f", 4, "/"), "addpd": ("fd", 2, "+"), "subpd": ("fd", 2, "-"),
             "mulpd": ("fd", 2, "*"), "divpd": ("fd", 2, "/"),
             "addss": ("f", 1, "+"), "subss": ("f", 1, "-"), "mulss": ("f", 1, "*"),
             "divss": ("f", 1, "/"), "addsd": ("fd", 1, "+"), "subsd": ("fd", 1, "-"),
             "mulsd": ("fd", 1, "*"), "divsd": ("fd", 1, "/")}
    SCALAR_MOVES = {"movss": ("f", 4), "movsd": ("fd", 8)}

    # ---- x87 -------------------------------------------------------------
    @staticmethod
    def st_idx(insn, op) -> int | None:
        if op.type != CS_OP_REG:
            return None
        name = insn.reg_name(op.reg)
        if not (name.startswith("st(") and name.endswith(")")):
            return None
        try:
            return int(name[3:-1]) & 7
        except ValueError:
            return None

    def x87_mem(self, insn, op, integer: bool) -> str | None:
        address = self.mem_expr(insn, op)
        if address is None:
            return None
        if integer:
            signed = {2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(op.size)
            return (None if signed is None else
                    f"static_cast<double>(GuestLoad<{signed}>({address}))")
        if op.size == 4:
            return f"static_cast<double>(GuestLoad<float>({address}))"
        if op.size == 8:
            return f"GuestLoad<double>({address})"
        return None

    X87_ARITH = {"fadd": "+", "fsub": "-", "fsubr": "-",
                 "fmul": "*", "fdiv": "/", "fdivr": "/"}
    X87_INTEGER = {"fiadd": "+", "fisub": "-", "fisubr": "-",
                   "fimul": "*", "fidiv": "/", "fidivr": "/"}

    def x87(self, insn, mn: str, ops, size: int) -> str | None:
        if not mn.startswith("f"):
            return None

        if mn in ("fld1", "fldz", "fldl2e", "fldl2t", "fldlg2", "fldln2",
                  "fldpi"):
            constant = {"fld1": "1.0", "fldz": "0.0", "fldl2e": "1.4426950408889634",
                        "fldl2t": "3.321928094887362", "fldlg2": "0.3010299956639812",
                        "fldln2": "0.6931471805599453",
                        "fldpi": "3.141592653589793"}[mn]
            return f"X87Push(*c, {constant});"

        if mn == "fld":
            if not ops:
                return None
            if ops[0].type == CS_OP_REG:
                index = self.st_idx(insn, ops[0])
                if index is None:
                    return None
                return f"X87Push(*c, X87Get(*c, {index}));"
            source = self.x87_mem(insn, ops[0], integer=False)
            return None if source is None else f"X87Push(*c, {source});"

        if mn == "fild":
            if not ops:
                return None
            source = self.x87_mem(insn, ops[0], integer=True)
            return None if source is None else f"X87Push(*c, {source});"

        if mn in self.X87_ARITH or mn in self.X87_INTEGER:
            integer = mn in self.X87_INTEGER
            table = self.X87_INTEGER if integer else self.X87_ARITH
            op = table[mn]
            reverse = mn in ("fsubr", "fdivr", "fisubr", "fidivr")
            if len(ops) == 2 and ops[0].type == CS_OP_REG:
                dest = self.st_idx(insn, ops[0])
                if dest is None:
                    return None
                if ops[1].type == CS_OP_REG:
                    index = self.st_idx(insn, ops[1])
                    if index is None:
                        return None
                    source = f"X87Get(*c, {index})"
                else:
                    source = self.x87_mem(insn, ops[1], integer)
                if source is None:
                    return None
                left, right = f"X87Get(*c, {dest})", source
                expression = (f"{right} {op} {left}" if reverse
                              else f"{left} {op} {right}")
                return f"X87Set(*c, {dest}, {expression});"
            if not ops:
                return None
            if ops[0].type == CS_OP_REG:
                index = self.st_idx(insn, ops[0])
                if index is None:
                    return None
                source = f"X87Get(*c, {index})"
            else:
                source = self.x87_mem(insn, ops[0], integer)
            if source is None:
                return None
            left, right = "X87Get(*c, 0)", source
            expression = (f"{right} {op} {left}" if reverse
                          else f"{left} {op} {right}")
            return f"X87Set(*c, 0, {expression});"

        if mn in ("fst", "fstp"):
            if not ops:
                return None
            pop = mn == "fstp"
            if ops[0].type == CS_OP_REG:
                index = self.st_idx(insn, ops[0])
                if index is None:
                    return None
                body = f"X87Set(*c, {index}, X87Get(*c, 0));"
            else:
                address = self.mem_expr(insn, ops[0])
                if address is None:
                    return None
                if ops[0].size == 4:
                    body = f"GuestStore<float>({address}, static_cast<float>(X87Get(*c, 0)));"
                elif ops[0].size == 8:
                    body = f"GuestStore<double>({address}, X87Get(*c, 0));"
                else:
                    return None
            return f"{{ {body} {'X87Pop(*c);' if pop else ''} }}"

        if mn in ("fist", "fistp", "fisttp"):
            if not ops or ops[0].type != CS_OP_MEM:
                return None
            address = self.mem_expr(insn, ops[0])
            signed = {2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(ops[0].size)
            if address is None or signed is None:
                return None
            low = f"std::numeric_limits<{signed}>::min()"
            high = f"std::numeric_limits<{signed}>::max()"
            rounding = "std::trunc" if mn == "fisttp" else "std::nearbyint"
            pop = " X87Pop(*c);" if mn in ("fistp", "fisttp") else ""
            return (f"{{ const double value = X87Get(*c, 0); "
                    f"GuestStore<{signed}>({address}, static_cast<{signed}>("
                    f"value <= static_cast<double>({low}) ? {low} : "
                    f"value >= static_cast<double>({high}) ? {high} : "
                    f"{rounding}(value)));{pop} }}")

        if mn in ("fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp",
                  "ficom", "ficomp"):
            integer = mn in ("ficom", "ficomp")
            if ops:
                if ops[0].type == CS_OP_REG:
                    index = self.st_idx(insn, ops[0])
                    if index is None:
                        return None
                    source = f"X87Get(*c, {index})"
                else:
                    source = self.x87_mem(insn, ops[0], integer=integer)
            else:
                source = "X87Get(*c, 1)"
            if source is None:
                return None
            if mn.endswith("pp"):
                pop = " X87Pop(*c); X87Pop(*c);"
            elif mn.endswith("p"):
                pop = " X87Pop(*c);"
            else:
                pop = ""
            return f"{{ X87Compare(*c, X87Get(*c, 0), {source});{pop} }}"

        if mn in ("fcomi", "fcompi", "fcomip", "fucomi", "fucompi", "fucomip"):
            index = self.st_idx(insn, ops[0]) if ops else 1
            if index is None:
                return None
            pop = " X87Pop(*c);" if mn in ("fcompi", "fcomip",
                                           "fucompi", "fucomip") else ""
            return (f"{{ X87Compare(*c, X87Get(*c, 0), X87Get(*c, {index}));"
                    f"{pop} }}")

        if mn == "fxch":
            index = self.st_idx(insn, ops[0]) if ops else 1
            if index is None:
                return None
            return (f"{{ const double top = X87Get(*c, 0); "
                    f"X87Set(*c, 0, X87Get(*c, {index})); "
                    f"X87Set(*c, {index}, top); }}")

        if mn in ("fabs", "fchs", "fsqrt", "frndint"):
            operation = {"fabs": "std::fabs", "fchs": "(-)",
                         "fsqrt": "std::sqrt",
                         "frndint": "std::nearbyint"}[mn]
            if mn == "fchs":
                return "X87Set(*c, 0, -X87Get(*c, 0));"
            return f"X87Set(*c, 0, {operation}(X87Get(*c, 0)));"

        if mn == "fbld":
            if not ops or ops[0].type != CS_OP_MEM or ops[0].size != 10:
                return None
            address = self.mem_expr(insn, ops[0])
            if address is None:
                return None
            return (f"{{ const uint64_t a = {address}; uint64_t magnitude = 0; "
                    "for (int k = 8; k >= 0; --k) { "
                    "const uint8_t byte = GuestLoad<uint8_t>(a + k); "
                    "magnitude = magnitude * 100 + (byte >> 4) * 10 + (byte & 0x0f); } "
                    "const uint8_t sign = GuestLoad<uint8_t>(a + 9); "
                    "X87Push(*c, (sign & 0x80) ? -static_cast<double>(magnitude) "
                    ": static_cast<double>(magnitude)); }")

        if mn in ("fstsw", "fnstsw"):
            # No x87 status word is modelled; report an empty stack.
            if ops and ops[0].type == CS_OP_REG:
                return self.wr(insn, ops[0], 2, "c->fpu_sw")
            if ops and ops[0].type == CS_OP_MEM:
                address = self.mem_expr(insn, ops[0])
                return None if address is None else \
                    f"GuestStore<uint16_t>({address}, c->fpu_sw);"
            return None

        if mn in ("frstor", "fsave", "fnsave", "fxsave", "fxrstor"):
            return ""                 # no persistent x87 state to save/restore

        return None

    def vec(self, insn, start: int, end: int) -> str | None:
        mn = insn.mnemonic
        ops = insn.operands
        if mn in ("shufps", "shufpd", "pshufd"):
            if len(ops) != 3:
                return None
            di, si = self.xmm_idx(insn, ops[0]), self.xmm_idx(insn, ops[1])
            if di is None or ops[2].type != CS_OP_IMM:
                return None
            if si is not None:
                source = f"const Vec256 source = v[{si}];"
            else:
                address = self.vec_addr(insn, ops[1])
                if address is None:
                    return None
                source = f"Vec256 source; GuestLoadV(source, {address});"
            imm = ops[2].imm & 0xff
            if mn == "pshufd":
                lanes = " ".join(
                    f"v[{di}].d[{i}] = source.d[{(imm >> (2 * i)) & 3}];"
                    for i in range(4))
                return f"{{ {source} {lanes} }}"
            if mn == "shufps":
                picks = " ".join(
                    f"v[{di}].d[{i}] = " +
                    (f"old.d[{(imm >> (2 * i)) & 3}];" if i < 2 else
                     f"source.d[{(imm >> (2 * i)) & 3}];")
                    for i in range(4))
                return (f"{{ const Vec256 old = v[{di}]; {source} {picks} }}")
            return (f"{{ const Vec256 old = v[{di}]; {source} "
                    f"v[{di}].q[0] = old.q[{imm & 1}]; "
                    f"v[{di}].q[1] = source.q[{(imm >> 1) & 1}]; }}")

        if len(ops) != 2 and mn not in ("pinsrw", "pextrw"):
            return None
        d, s = ops[0], ops[1]
        size = d.size
        di, si = self.xmm_idx(insn, d), self.xmm_idx(insn, s)

        if mn == "movd":
            if di is not None:
                value = self.rd(insn, s, 4)
                if value is None:
                    return None
                return (f"{{ const uint32_t value = static_cast<uint32_t>({value}); "
                        f"std::memset(&v[{di}], 0, 16); v[{di}].d[0] = value; }}")
            if si is not None:
                value = f"v[{si}].d[0]"
                write = self.wr(insn, d, 4, value)
                if write:
                    return write
                address = self.vec_addr(insn, d)
                return f"GuestStore<uint32_t>({address}, {value});" if address else None
            return None

        if mn == "movq":
            if di is not None:
                value = f"v[{si}].q[0]" if si is not None else self.rd(insn, s, 8)
                if value is None:
                    return None
                return (f"{{ const uint64_t value = {value}; "
                        f"std::memset(&v[{di}], 0, 16); v[{di}].q[0] = value; }}")
            if si is not None:
                value = f"v[{si}].q[0]"
                write = self.wr(insn, d, 8, value)
                if write:
                    return write
                address = self.vec_addr(insn, d)
                return f"GuestStore<uint64_t>({address}, {value});" if address else None
            return None

        if mn in ("psrlq", "psllq", "psrld", "pslld", "psrad"):
            if di is None:
                return None
            if ops[1].type == CS_OP_IMM:
                count = f"0x{ops[1].imm & MASK:x}ull"
            elif si is not None:
                count = f"v[{si}].q[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                count = f"GuestLoad<uint64_t>({address})"
            lane_bits = 64 if mn.endswith("q") else 32
            lane_count = 2 if lane_bits == 64 else 4
            if mn == "psrad":
                shift = f"(uint64_t)((int32_t)v[{di}].d[k] >> count)"
                over = f"(v[{di}].d[k] & 0x80000000u) ? 0xffffffffu : 0"
            else:
                op = "<<" if mn.startswith("psll") else ">>"
                shift = f"(v[{di}].{'q' if lane_bits == 64 else 'd'}[k] {op} count)"
                over = "0"
            return (f"{{ const uint64_t count = {count}; "
                    f"for (int k = 0; k < {lane_count}; ++k) "
                    f"v[{di}].{'q' if lane_bits == 64 else 'd'}[k] = "
                    f"count >= {lane_bits} ? {over} : {shift}; }}")

        if mn in ("psrlw", "psllw", "psraw"):
            if di is None:
                return None
            if ops[1].type == CS_OP_IMM:
                count = f"0x{ops[1].imm & MASK:x}ull"
            elif si is not None:
                count = f"v[{si}].q[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                count = f"GuestLoad<uint64_t>({address})"
            lane = f"v[{di}].w[k]"
            if mn == "psraw":
                shift = f"(uint16_t)(v[{di}].sw[k] >> count)"
                over = f"({lane} & 0x8000u) ? 0xffffu : 0"
            else:
                op = "<<" if mn == "psllw" else ">>"
                shift = f"(uint16_t)({lane} {op} count)"
                over = "0"
            return (f"{{ const uint64_t count = {count}; "
                    "for (int k = 0; k < 8; ++k) "
                    f"{lane} = count >= 16 ? {over} : {shift}; }}")

        if mn in ("psrldq", "pslldq"):
            if di is None or ops[1].type != CS_OP_IMM:
                return None
            count = ops[1].imm & 0xff
            source_byte = "i + count" if mn == "psrldq" else "i - count"
            valid = "i + count < 16" if mn == "psrldq" else "i >= count"
            return (f"{{ const Vec256 old = v[{di}]; "
                    f"const unsigned count = {count}; "
                    f"for (int i = 0; i < 16; ++i) "
                    f"v[{di}].b[i] = count < 16 && {valid} "
                    f"? old.b[{source_byte}] : 0; }}")

        if mn in ("cmpltps", "cmpleps"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            compare = "<" if mn == "cmpltps" else "<="
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    f"for (int k = 0; k < 4; ++k) "
                    f"v[{di}].d[k] = lhs.f[k] {compare} rhs.f[k] "
                    f"? 0xffffffffu : 0; }}")

        if mn == "rsqrtps":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            return (f"{{ {source} for (int k = 0; k < 4; ++k) "
                    f"v[{di}].f[k] = 1.0f / std::sqrt(src.f[k]); }}")

        if mn in ("movlhps", "movhlps"):
            if di is None or si is None:
                return None
            return (f"v[{di}].q[1] = v[{si}].q[0];" if mn == "movlhps"
                    else f"v[{di}].q[0] = v[{si}].q[1];")

        if mn == "paddq":
            if di is None:
                return None
            if si is not None:
                return (f"{{ for (int k = 0; k < 2; ++k) "
                        f"v[{di}].q[k] += v[{si}].q[k]; }}")
            address = self.vec_addr(insn, s)
            if address is None:
                return None
            return (f"{{ Vec256 rhs; GuestLoadV(rhs, {address}); "
                    f"for (int k = 0; k < 2; ++k) v[{di}].q[k] += rhs.q[k]; }}")

        if mn in ("punpckldq", "punpckhdq"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            base = 0 if mn == "punpckldq" else 2
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    f"v[{di}].d[0] = lhs.d[{base}]; v[{di}].d[1] = rhs.d[{base}]; "
                    f"v[{di}].d[2] = lhs.d[{base + 1}]; "
                    f"v[{di}].d[3] = rhs.d[{base + 1}]; }}")

        if mn == "cvtsi2ss":
            if di is None:
                return None
            source = self.rd(insn, s, s.size)
            if source is None or s.size not in (4, 8):
                return None
            signed = f"int{s.size * 8}_t"
            return (f"v[{di}].f[0] = static_cast<float>("
                    f"static_cast<{signed}>({source}));")

        if mn == "cvttss2si":
            if si is not None:
                source = f"v[{si}].f[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"GuestLoad<float>({address})"
            if size not in (4, 8):
                return None
            signed = f"int{size * 8}_t"
            lower = "-2147483648.0" if size == 4 else "-9223372036854775808.0"
            upper = "2147483648.0" if size == 4 else "9223372036854775808.0"
            invalid = "0x80000000u" if size == 4 else "0x8000000000000000ull"
            value = (f"(std::isfinite(value) && static_cast<double>(value) >= {lower} "
                     f"&& static_cast<double>(value) < {upper} "
                     f"? static_cast<{signed}>(value) : static_cast<{signed}>({invalid}))")
            return (f"{{ const float value = {source}; "
                    f"{self.wr(insn, d, size, value)} }}")

        if mn in ("comiss", "ucomiss"):
            if di is None:
                return None
            if si is not None:
                rhs = f"v[{si}].f[0]"
            else:
                a = self.vec_addr(insn, s)
                if a is None:
                    return None
                rhs = f"GuestLoad<float>({a})"
            return (f"{{ const float lhs = v[{di}].f[0]; const float rhs = {rhs}; "
                    "c->flags &= ~(uint64_t)F_ARITH; "
                    "if (std::isunordered(lhs, rhs)) "
                    "c->flags |= F_CF | F_PF | F_ZF; "
                    "else if (lhs < rhs) c->flags |= F_CF; "
                    "else if (lhs == rhs) c->flags |= F_ZF; }")

        if mn in ("andnps", "andnpd", "pandn"):
            if di is None:
                return None
            if si is not None:
                return (f"{{ for (int k = 0; k < 2; ++k) "
                        f"v[{di}].q[k] = ~v[{di}].q[k] & v[{si}].q[k]; }}")
            address = self.vec_addr(insn, s)
            if address is None:
                return None
            return (f"{{ Vec256 source; GuestLoadV(source, {address}); "
                    f"for (int k = 0; k < 2; ++k) "
                    f"v[{di}].q[k] = ~v[{di}].q[k] & source.q[k]; }}")

        if mn in ("minps", "maxps"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            compare = "<" if mn == "minps" else ">"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    f"for (int k = 0; k < 4; ++k) "
                    f"v[{di}].f[k] = lhs.f[k] {compare} rhs.f[k] "
                    f"? lhs.f[k] : rhs.f[k]; }}")

        if mn in ("unpcklps", "unpckhps"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            base = 0 if mn == "unpcklps" else 2
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    f"v[{di}].d[0] = lhs.d[{base}]; v[{di}].d[1] = rhs.d[{base}]; "
                    f"v[{di}].d[2] = lhs.d[{base + 1}]; "
                    f"v[{di}].d[3] = rhs.d[{base + 1}]; }}")

        if mn == "cvtdq2ps":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            return (f"{{ {source} for (int k = 0; k < 4; ++k) "
                    f"v[{di}].f[k] = static_cast<float>(src.sd[k]); }}")

        if mn == "cvtps2pd":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = (f"Vec256 src; src.q[0] = GuestLoad<uint64_t>({address});")
            return (f"{{ {source} v[{di}].fd[0] = static_cast<double>(src.f[0]); "
                    f"v[{di}].fd[1] = static_cast<double>(src.f[1]); }}")

        if mn == "cvtpd2ps":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            return (f"{{ {source} v[{di}].f[0] = static_cast<float>(src.fd[0]); "
                    f"v[{di}].f[1] = static_cast<float>(src.fd[1]); "
                    f"v[{di}].d[2] = 0; v[{di}].d[3] = 0; }}")

        # ---- packed integer conversions -------------------------------------
        if mn == "cvttps2dq":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            return (f"{{ {source} for (int k = 0; k < 4; ++k) {{ "
                    "const float value = src.f[k]; "
                    f"v[{di}].d[k] = (std::isfinite(value) && "
                    "value >= -2147483648.0f && value < 2147483648.0f) "
                    "? static_cast<uint32_t>(static_cast<int32_t>(value)) "
                    ": 0x80000000u; } }")

        if mn == "cvtdq2pd":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; src.q[0] = GuestLoad<uint64_t>({address});"
            return (f"{{ {source} v[{di}].fd[0] = static_cast<double>(src.sd[0]); "
                    f"v[{di}].fd[1] = static_cast<double>(src.sd[1]); "
                    f"v[{di}].fd[2] = 0; v[{di}].fd[3] = 0; }}")

        if mn == "cvttpd2dq":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            return (f"{{ {source} for (int k = 0; k < 2; ++k) {{ "
                    "const double value = src.fd[k]; "
                    f"v[{di}].d[k] = (std::isfinite(value) && "
                    "value >= -2147483648.0 && value < 2147483648.0) "
                    "? static_cast<uint32_t>(static_cast<int32_t>(value)) "
                    f": 0x80000000u; }} v[{di}].q[1] = 0; }}")

        if mn == "cvtsd2ss":
            if di is None:
                return None
            if si is not None:
                return f"v[{di}].f[0] = static_cast<float>(v[{si}].fd[0]);"
            address = self.vec_addr(insn, s)
            if address is None:
                return None
            return f"v[{di}].f[0] = static_cast<float>(GuestLoad<double>({address}));"

        if mn == "cvtss2sd":
            if di is None:
                return None
            if si is not None:
                return f"v[{di}].fd[0] = static_cast<double>(v[{si}].f[0]);"
            address = self.vec_addr(insn, s)
            if address is None:
                return None
            return f"v[{di}].fd[0] = static_cast<double>(GuestLoad<float>({address}));"

        if mn == "cvtsi2sd":
            if di is None or s.size not in (4, 8):
                return None
            source = self.rd(insn, s, s.size)
            if source is None:
                return None
            signed = f"int{s.size * 8}_t"
            return (f"v[{di}].fd[0] = static_cast<double>("
                    f"static_cast<{signed}>({source}));")

        if mn == "cvttsd2si":
            if si is not None:
                source = f"v[{si}].fd[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"GuestLoad<double>({address})"
            if size not in (4, 8):
                return None
            signed = f"int{size * 8}_t"
            lower = "-2147483648.0" if size == 4 else "-9223372036854775808.0"
            upper = "2147483648.0" if size == 4 else "9223372036854775808.0"
            invalid = "0x80000000u" if size == 4 else "0x8000000000000000ull"
            value = (f"(std::isfinite(value) && static_cast<double>(value) >= {lower} "
                     f"&& static_cast<double>(value) < {upper} "
                     f"? static_cast<{signed}>(value) : static_cast<{signed}>({invalid}))")
            return (f"{{ const double value = {source}; "
                    f"{self.wr(insn, d, size, value)} }}")

        if mn == "cvtsd2si":
            if si is not None:
                source = f"v[{si}].fd[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"GuestLoad<double>({address})"
            if size not in (4, 8):
                return None
            signed = f"int{size * 8}_t"
            lower = "-2147483648.0" if size == 4 else "-9223372036854775808.0"
            upper = "2147483648.0" if size == 4 else "9223372036854775808.0"
            invalid = "0x80000000u" if size == 4 else "0x8000000000000000ull"
            value = (f"(std::isfinite(value) && value >= {lower} && value < {upper} "
                     f"? static_cast<{signed}>(std::nearbyint(value)) "
                     f": static_cast<{signed}>({invalid}))")
            return (f"{{ const double value = {source}; "
                    f"{self.wr(insn, d, size, value)} }}")

        # ---- high half moves and non-temporal stores ------------------------
        if mn in ("movlpd", "movhpd"):
            low = mn == "movlpd"
            lane = 0 if low else 1
            if di is not None:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                return f"v[{di}].q[{lane}] = GuestLoad<uint64_t>({address});"
            if si is not None:
                address = self.vec_addr(insn, d)
                if address is None:
                    return None
                return f"GuestStore<uint64_t>({address}, v[{si}].q[{lane}]);"
            return None

        if mn in ("movntps", "movntpd", "movntdq"):
            if si is None:
                return None
            address = self.vec_addr(insn, d)
            if address is None:
                return None
            return f"GuestStoreV({address}, v[{si}]);"

        if mn == "pmovmskb":
            if si is None or size not in (4, 8):
                return None
            write = self.wr(insn, d, size, "mask")
            if write is None:
                return None
            return (f"{{ uint64_t mask = 0; for (int k = 0; k < 16; ++k) "
                    f"mask |= ((uint64_t)((v[{si}].b[k] >> 7) & 1)) << k; "
                    f"{write} }}")

        # ---- saturated packed arithmetic ------------------------------------
        _saturating = {
            "paddusb": ("b", 16, "unsigned", "+"),
            "paddusw": ("w", 8, "unsigned", "+"),
            "paddsb": ("b", 16, "signed", "+"),
            "paddsw": ("w", 8, "signed", "+"),
            "psubusb": ("b", 16, "unsigned", "-"),
            "psubusw": ("w", 8, "unsigned", "-"),
            "psubsb": ("b", 16, "signed", "-"),
            "psubsw": ("w", 8, "signed", "-"),
        }
        if mn in _saturating:
            if di is None:
                return None
            field, lanes, kind, op = _saturating[mn]
            bits = 8 if field == "b" else 16
            if kind == "unsigned":
                ty = f"uint{bits}_t"
                low, high = "0", f"0x{(1 << bits) - 1:x}u"
            else:
                ty = f"int{bits}_t"
                low = f"-0x{1 << (bits - 1):x}"
                high = f"0x{(1 << (bits - 1)) - 1:x}"
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            if kind == "unsigned" and op == "+":
                body = (f"const uint32_t sum = static_cast<uint32_t>(v[{di}].{field}[k]) "
                        f"+ rhs.{field}[k]; "
                        f"v[{di}].{field}[k] = static_cast<{ty}>(sum > {high} "
                        f"? {high} : sum);")
            elif kind == "unsigned":
                body = (f"const uint32_t a = v[{di}].{field}[k], b = rhs.{field}[k]; "
                        f"v[{di}].{field}[k] = static_cast<{ty}>(a < b ? 0 : a - b);")
            else:
                body = (f"const int32_t value = static_cast<int32_t>(v[{di}].{field}[k]) "
                        f"{op} static_cast<int32_t>(rhs.{field}[k]); "
                        f"v[{di}].{field}[k] = static_cast<{ty}>(value < {low} ? {low} "
                        f": value > {high} ? {high} : value);")
            return (f"{{ {source} for (int k = 0; k < {lanes}; ++k) {{ {body} }} }}")

        # ---- packed integer arithmetic --------------------------------------
        _packed = {"b": (1, 16, "b", "sb"), "w": (2, 8, "w", "sw"),
                   "d": (4, 4, "d", "sd"), "q": (8, 2, "q", "sq")}
        for _name, _op in (("padd", "+"), ("psub", "-")):
            for _suffix, (_width, _lanes, _field, _sfield) in _packed.items():
                if mn != _name + _suffix:
                    continue
                if di is None:
                    return None
                _ctype = f"uint{_width * 8}_t"
                _lane = f"v[{di}].{_field}[k]"
                if si is not None:
                    return (f"{{ for (int k = 0; k < {_lanes}; ++k) "
                            f"{_lane} = static_cast<{_ctype}>({_lane} {_op} "
                            f"v[{si}].{_field}[k]); }}")
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                return (f"{{ Vec256 rhs; GuestLoadV(rhs, {address}); "
                        f"for (int k = 0; k < {_lanes}; ++k) "
                        f"{_lane} = static_cast<{_ctype}>({_lane} {_op} "
                        f"rhs.{_field}[k]); }}")

        for _name in ("pcmpeq", "pcmpgt"):
            for _suffix, (_width, _lanes, _field, _sfield) in _packed.items():
                if mn != _name + _suffix:
                    continue
                if di is None:
                    return None
                _ctype = f"uint{_width * 8}_t"
                _signed = f"int{_width * 8}_t"
                if si is not None:
                    source = f"const Vec256 rhs = v[{si}];"
                else:
                    address = self.vec_addr(insn, s)
                    if address is None:
                        return None
                    source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
                _lane = f"v[{di}].{_field}[k]"
                if _name == "pcmpeq":
                    test = f"{_lane} == rhs.{_field}[k]"
                else:
                    test = (f"static_cast<{_signed}>({_lane}) > "
                            f"static_cast<{_signed}>(rhs.{_field}[k])")
                return (f"{{ {source} "
                        f"for (int k = 0; k < {_lanes}; ++k) "
                        f"{_lane} = ({test}) "
                        f"? ~static_cast<{_ctype}>(0) : 0; }}")

        if mn == "pmulld":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    "for (int k = 0; k < 4; ++k) "
                    "v[" f"{di}].d[k] = static_cast<uint32_t>("
                    "static_cast<int32_t>(lhs.d[k]) * "
                    "static_cast<int32_t>(rhs.d[k])); }")

        if mn == "pmuludq":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    "for (int k = 0; k < 2; ++k) "
                    f"v[{di}].q[k] = static_cast<uint64_t>(lhs.d[2 * k]) * "
                    "static_cast<uint64_t>(rhs.d[2 * k]); }")

        if mn == "psadbw":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    "uint64_t sum0 = 0, sum1 = 0; "
                    "for (int k = 0; k < 8; ++k) { "
                    "const int a = lhs.b[k], b = rhs.b[k]; "
                    "sum0 += static_cast<uint64_t>(a > b ? a - b : b - a); } "
                    "for (int k = 8; k < 16; ++k) { "
                    "const int a = lhs.b[k], b = rhs.b[k]; "
                    "sum1 += static_cast<uint64_t>(a > b ? a - b : b - a); } "
                    f"v[{di}].q[0] = sum0; v[{di}].q[1] = sum1; }}")

        # ---- packed integer shuffles ----------------------------------------
        _unpack = {"punpcklbw": ("b", 8, 0), "punpckhbw": ("b", 8, 8),
                   "punpcklwd": ("w", 4, 0), "punpckhwd": ("w", 4, 4)}
        if mn in _unpack:
            if di is None:
                return None
            _field, _count, _offset = _unpack[mn]
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            return (f"{{ const Vec256 old = v[{di}]; {source} "
                    f"for (int k = 0; k < {_count}; ++k) {{ "
                    f"v[{di}].{_field}[2 * k] = old.{_field}[{_offset} + k]; "
                    f"v[{di}].{_field}[2 * k + 1] = rhs.{_field}[{_offset} + k]; }} }}")

        if mn in ("punpcklqdq", "punpckhqdq", "unpcklpd", "unpckhpd"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            lane = 0 if mn in ("punpcklqdq", "unpcklpd") else 1
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    f"v[{di}].q[0] = lhs.q[{lane}]; "
                    f"v[{di}].q[1] = rhs.q[{lane}]; }}")

        # ---- packed integer saturation --------------------------------------
        if mn == "packssdw":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    "for (int k = 0; k < 4; ++k) { "
                    "const int32_t value = lhs.sd[k]; "
                    f"v[{di}].sw[k] = static_cast<int16_t>(value < -32768 ? -32768 "
                    ": value > 32767 ? 32767 : value); } "
                    "for (int k = 0; k < 4; ++k) { "
                    "const int32_t value = rhs.sd[k]; "
                    f"v[{di}].sw[4 + k] = static_cast<int16_t>(value < -32768 ? -32768 "
                    ": value > 32767 ? 32767 : value); } }")

        if mn == "packuswb":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    "for (int k = 0; k < 8; ++k) { "
                    f"v[{di}].b[k] = static_cast<uint8_t>(lhs.sw[k] < 0 ? 0 "
                    ": lhs.sw[k] > 255 ? 255 : lhs.sw[k]); } "
                    "for (int k = 0; k < 8; ++k) { "
                    f"v[{di}].b[8 + k] = static_cast<uint8_t>(rhs.sw[k] < 0 ? 0 "
                    ": rhs.sw[k] > 255 ? 255 : rhs.sw[k]); } }")

        # ---- packed integer inserts / extracts ------------------------------
        if mn == "pinsrw":
            if di is None or len(ops) != 3 or ops[2].type != CS_OP_IMM:
                return None
            lane = ops[2].imm & 7
            if si is not None:
                source = f"v[{si}].d[0]"
            elif ops[1].type == CS_OP_REG:
                source = self.rd(insn, ops[1], 2)
                if source is None:
                    return None
            else:
                address = self.vec_addr(insn, ops[1])
                if address is None:
                    return None
                source = f"GuestLoad<uint16_t>({address})"
            return (f"v[{di}].w[{lane}] = static_cast<uint16_t>({source});")

        if mn == "pextrw":
            if si is None or len(ops) != 3 or ops[2].type != CS_OP_IMM:
                return None
            lane = ops[2].imm & 7
            return self.wr(
                insn, d, 4,
                f"static_cast<uint32_t>(v[{si}].w[{lane}])")

        # ---- floating point comparisons -------------------------------------
        if mn.startswith("cmp") and mn[-2:] in ("ps", "pd"):
            key = mn[3:-2]
            packed = mn[-2:]
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            if packed == "ps":
                lane, count, field = "d", 4, "f"
                all_ones = "0xffffffffu"
            else:
                lane, count, field = "q", 2, "fd"
                all_ones = "0xffffffffffffffffull"
            tests = {
                "eq": f"lhs.{field}[k] == rhs.{field}[k]",
                "neq": f"lhs.{field}[k] != rhs.{field}[k]",
                "lt": f"lhs.{field}[k] < rhs.{field}[k]",
                "le": f"lhs.{field}[k] <= rhs.{field}[k]",
                "gt": f"lhs.{field}[k] > rhs.{field}[k]",
                "ge": f"lhs.{field}[k] >= rhs.{field}[k]",
                "nlt": f"!(lhs.{field}[k] < rhs.{field}[k])",
                "nle": f"!(lhs.{field}[k] <= rhs.{field}[k])",
                "ord": (f"!std::isnan(lhs.{field}[k]) && "
                        f"!std::isnan(rhs.{field}[k])"),
                "unord": (f"std::isnan(lhs.{field}[k]) || "
                          f"std::isnan(rhs.{field}[k])"),
            }
            test = tests.get(key)
            if test is None:
                return None
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    f"for (int k = 0; k < {count}; ++k) "
                    f"v[{di}].{lane}[k] = ({test}) ? {all_ones} : 0; }}")

        if mn in ("comisd", "ucomisd"):
            if di is None:
                return None
            if si is not None:
                rhs = f"v[{si}].fd[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                rhs = f"GuestLoad<double>({address})"
            return (f"{{ const double lhs = v[{di}].fd[0]; const double rhs = {rhs}; "
                    "c->flags &= ~(uint64_t)F_ARITH; "
                    "if (std::isunordered(lhs, rhs)) "
                    "c->flags |= F_CF | F_PF | F_ZF; "
                    "else if (lhs < rhs) c->flags |= F_CF; "
                    "else if (lhs == rhs) c->flags |= F_ZF; }")

        # ---- floating point min/max and square roots ------------------------
        if mn in ("minss", "maxss"):
            if di is None:
                return None
            if si is not None:
                rhs = f"v[{si}].f[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                rhs = f"GuestLoad<float>({address})"
            compare = "<" if mn.startswith("min") else ">"
            return (f"{{ const float lhs = v[{di}].f[0]; const float rhs = {rhs}; "
                    f"v[{di}].f[0] = lhs {compare} rhs ? lhs : rhs; }}")

        if mn in ("minpd", "maxpd"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 rhs = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 rhs; GuestLoadV(rhs, {address});"
            compare = "<" if mn.startswith("min") else ">"
            return (f"{{ const Vec256 lhs = v[{di}]; {source} "
                    "for (int k = 0; k < 2; ++k) "
                    f"v[{di}].fd[k] = lhs.fd[k] {compare} rhs.fd[k] "
                    "? lhs.fd[k] : rhs.fd[k]; }")

        if mn in ("sqrtss", "sqrtsd"):
            if di is None:
                return None
            field = "f" if mn == "sqrtss" else "fd"
            ctype = "float" if mn == "sqrtss" else "double"
            if si is not None:
                source = f"v[{si}].{field}[0]"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"GuestLoad<{ctype}>({address})"
            return f"v[{di}].{field}[0] = std::sqrt({source});"

        if mn in ("sqrtps", "sqrtpd"):
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            field = "fd" if mn == "sqrtpd" else "f"
            count = 2 if mn == "sqrtpd" else 4
            return (f"{{ {source} for (int k = 0; k < {count}; ++k) "
                    f"v[{di}].{field}[k] = std::sqrt(src.{field}[k]); }}")

        if mn == "rcpps":
            if di is None:
                return None
            if si is not None:
                source = f"const Vec256 src = v[{si}];"
            else:
                address = self.vec_addr(insn, s)
                if address is None:
                    return None
                source = f"Vec256 src; GuestLoadV(src, {address});"
            return (f"{{ {source} for (int k = 0; k < 4; ++k) "
                    f"v[{di}].f[k] = 1.0f / src.f[k]; }}")

        if mn == "movmskpd":
            if si is None:
                return None
            return self.wr(insn, d, 4,
                           f"((v[{si}].q[0] >> 63) | ((v[{si}].q[1] >> 62) & 2))")

        if mn == "movmskps":
            if si is None:
                return None
            write = self.wr(insn, d, 4,
                            f"((v[{si}].d[0] >> 31) | ((v[{si}].d[1] >> 30) & 2) | "
                            f"((v[{si}].d[2] >> 29) & 4) | ((v[{si}].d[3] >> 28) & 8))")
            return write

        if mn in self.PACKED_MOVES:
            if di is not None and si is not None:
                return f"{{ std::memcpy(&v[{di}], &v[{si}], 16); }}"
            a = self.vec_addr(insn, s)
            if di is not None and a:
                return f"GuestLoadV(v[{di}], {a});"
            a = self.vec_addr(insn, d)
            if si is not None and a:
                return f"GuestStoreV({a}, v[{si}]);"
            return None

        if mn in self.LOGIC:
            op = self.LOGIC[mn]
            if di is None:
                return None
            if si is not None:
                return f"{{ for (int k = 0; k < 4; ++k) v[{di}].q[k] {op}= v[{si}].q[k]; }}"
            a = self.vec_addr(insn, s)
            if a:
                return (f"{{ Vec256 t; GuestLoadV(t, {a}); for (int k = 0; k < 4; ++k) "
                        f"v[{di}].q[k] {op}= t.q[k]; }}")
            return None

        if mn in self.SCALAR_MOVES:
            field, width = self.SCALAR_MOVES[mn]
            if di is not None and si is not None:      # reg <- reg: upper lanes kept
                return f"{{ std::memcpy(&v[{di}], &v[{si}], {width}); }}"
            a = self.vec_addr(insn, s)
            if di is not None and a:                   # reg <- mem: upper lanes cleared
                ctype = "float" if width == 4 else "double"
                return (f"{{ std::memset(&v[{di}], 0, 16); v[{di}].{field}[0] = "
                        f"GuestLoad<{ctype}>({a}); }}")
            a = self.vec_addr(insn, d)
            if si is not None and a:                   # mem <- reg
                return (f"GuestStore<{'float' if width == 4 else 'double'}>({a}, "
                        f"v[{si}].{field}[0]);")
            return None

        if mn in self.ARITH:
            field, lanes, op = self.ARITH[mn]
            if di is None:
                return None
            if si is not None:
                if lanes == 1:
                    return (f"{{ v[{di}].{field}[0] = v[{di}].{field}[0] {op} "
                            f"v[{si}].{field}[0]; }}")
                return (f"{{ for (int k = 0; k < {lanes}; ++k) v[{di}].{field}[k] = "
                        f"v[{di}].{field}[k] {op} v[{si}].{field}[k]; }}")
            a = self.vec_addr(insn, s)
            if not a:
                return None
            ctype = "float" if field == "f" else "double"
            if lanes == 1:
                return (f"{{ v[{di}].{field}[0] = v[{di}].{field}[0] {op} "
                        f"GuestLoad<{ctype}>({a}); }}")
            return (f"{{ Vec256 t; GuestLoadV(t, {a}); for (int k = 0; k < {lanes}; ++k) "
                    f"v[{di}].{field}[k] = v[{di}].{field}[k] {op} t.{field}[k]; }}")

        return None

    def emit_function(self, rva: int, end: int, md: Cs) -> str:
        code = self.pe.read_rva(rva, end - rva)
        if not code:
            return ""
        va = self.pe.image_base + rva
        insns = list(md.disasm(code, va))
        if not insns:
            return ""

        starts = {insn.address - self.pe.image_base for insn in insns}
        self._starts = starts

        targets: set[int] = set()
        for insn in insns:
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    t = (op.imm & MASK) - self.pe.image_base
                    if t in starts:
                        targets.add(t)

        out = [f'__attribute__((visibility("hidden"))) void f_{rva:x}(CpuContext *c) {{\n',
               "    const uint64_t B = rc->image_base;\n",
               "    uint64_t r[16];\n    Vec256 v[16];\n",
               "    RC_LOAD();\n"]
        native = 0
        for insn in insns:
            line = self.translate(insn, rva, end)
            here = insn.address - self.pe.image_base
            self.stats["insn"] += 1
            if here in targets:
                out.append(f"L_{here:x}: ;\n")
            if line is None:
                out.append(f"    {{ c->rip = B + 0x{here:x}ull; RC_SAVE(); rc->interp(c); "
                           f"RC_LOAD(); }} /* {insn.mnemonic} {insn.op_str} */\n")
            else:
                native += 1
                out.append(f"    {line}\n")
        out.append(f"    RC_SAVE(); c->rip = B + 0x{end:x}ull; return;\n}}\n\n")
        self.stats["native"] += native
        self.stats["func"] += 1
        return "".join(out)


PROLOGUE_TEMPLATE = """/* Generated by tools/recompiler/main.py from the user's own executable.
 * Not to be distributed: this is the game's code.
 */
#include <cstdint>
#include <cmath>
#include <chrono>
#include <limits>
#include "cpu_context.h"

namespace vigil::recomp {
static inline void rc_save(CpuContext *c, uint64_t r[16], Vec256 v[16]) {
    for (int i = 0; i < 16; ++i) c->r[i] = r[i];
    for (int i = 0; i < 16; ++i) c->v[i] = v[i];
}
static inline void rc_load(CpuContext *c, uint64_t r[16], Vec256 v[16]) {
    for (int i = 0; i < 16; ++i) r[i] = c->r[i];
    for (int i = 0; i < 16; ++i) v[i] = c->v[i];
}
}  // namespace vigil::recomp
using namespace vigil::recomp;
#define RC_SAVE() rc_save(c, r, v)
#define RC_LOAD() rc_load(c, r, v)

{rc_decl}
"""


def prologue(define_rc: bool) -> str:
    decl = ('__attribute__((visibility("hidden"))) const RcApi *rc;'
            if define_rc else 'extern const RcApi *rc;')
    return PROLOGUE_TEMPLATE.replace("{rc_decl}", decl)


def load_config() -> dict:
    p = Path(__file__).with_name("recompiler_config.json")
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def main() -> int:
    cfg = load_config()
    ap = argparse.ArgumentParser(description="Vigil static recompiler frontend")
    ap.add_argument("--exe", default=cfg.get("target_executable", "game_original/Darksiders2.exe"))
    ap.add_argument("--out", default=cfg.get("output_cpp_dir", "out/recomp"))
    ap.add_argument("--limit", type=int, default=0, help="functions to emit (0 = all)")
    ap.add_argument("--window", type=lambda s: int(s, 0), default=0x20000)
    args = ap.parse_args()

    pe = PE(Path(args.exe))
    funcs = build_function_map(pe)
    print(f"[*] image base 0x{pe.image_base:X}  entry RVA 0x{pe.entry_rva:X}")
    print(f"[*] .pdata functions: {len(funcs)}")

    em = Emitter(pe, funcs)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    order = sorted(funcs)
    if args.limit:
        order = order[: args.limit]

    windows: dict[int, list[str]] = {}
    emitted: list[int] = []          # only functions that actually produced C
    for rva in order:
        text = em.emit_function(rva, funcs[rva], md)
        if text:
            windows.setdefault(rva // args.window, []).append(text)
            emitted.append(rva)

    def write_if_changed(path: Path, content: str) -> bool:
        """Rewriting an identical file would make the whole build recompile."""
        try:
            if path.exists() and path.read_text(encoding="utf-8") == content:
                return False
        except OSError:
            pass
        path.write_text(content, encoding="utf-8")
        return True

    changed = 0
    for window, chunks in windows.items():
        if write_if_changed(outdir / f"OUT_{window:05x}.c",
                            prologue(False) + "".join(chunks)):
            changed += 1

    # library entry: the table the loader walks, and one slot per emitted function
    head = [prologue(True)]
    for rva in emitted:
        head.append(f'void f_{rva:x}(CpuContext *c);\n'
                    f'__attribute__((visibility("hidden"))) RcFn d_{rva:x};\n')
    head.append("\nstatic const RcFunction table[] = {\n")
    for rva in emitted:
        head.append(f"    {{0x{rva:x}, 0x{funcs[rva] - rva:x}, 0, f_{rva:x}, &d_{rva:x}}},\n")
    head.append("};\n\nextern \"C\" __attribute__((visibility(\"default\")))\n"
                "const RcFunction *bb_recomp_init(const RcApi *api, size_t *count) {\n"
                "    rc = api;\n    *count = sizeof(table) / sizeof(table[0]);\n"
                "    return table;\n}\n")
    write_if_changed(outdir / "OUT.c", "".join(head))

    print(f"[+] {em.stats['func']} functions ({len(emitted)} emitted) -> "
          f"{len(windows)} files ({changed} rewritten) + OUT.c in {outdir}")
    if em.stats["insn"]:
        pct = 100.0 * em.stats["native"] / em.stats["insn"]
        print(f"[+] {em.stats['native']}/{em.stats['insn']} instructions in C "
              f"({pct:.1f}%), the rest to the interpreter")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
