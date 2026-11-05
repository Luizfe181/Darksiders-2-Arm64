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
KNOWN_LEAF_FUNCTIONS = ((0x86C20, 0x86C6D, b"\x33\xC0\x48\x89"),)


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
        code = pe.read_rva(begin, len(signature))
        terminator = pe.read_rva(end - 1, 1)
        if code == signature and terminator == b"\xC3" and begin not in funcs:
            funcs[begin] = end
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
            if base_name not in REG_INDEX:
                return None
            terms.append(f"r[{REG_INDEX[base_name]}]")
        if m.index:
            iname = insn.reg_name(m.index)
            if iname not in REG_INDEX:
                return None
            terms.append(f"r[{REG_INDEX[iname]}] * {m.scale}")
        if m.disp:
            terms.append(f"0x{m.disp & MASK:x}ull" if m.disp > 0
                         else f"(uint64_t)(-0x{-m.disp:x})")
        if not terms:
            terms.append("0")
        return " + ".join(terms)

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

        if mn in ("nop", "endbr64", "fnop", "int3", "prefetchw"):
            return ""

        if mn == "cdqe":
            return "r[0] = (uint64_t)(int64_t)(int32_t)(r[0] & 0xffffffffull);"
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

        if mn in ("bt", "bts", "btr", "btc"):
            if ops[0].type != CS_OP_REG or size not in (2, 4, 8):
                return None
            value = self.rd(insn, ops[0], size)
            index = self.rd(insn, ops[1], size)
            if value is None or index is None:
                return None
            bit = f"({index} & {size * 8 - 1})"
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

        if len(ops) != 2:
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

        if mn in ("andnps", "pandn"):
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
