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
for _i in range(8, 16):
    ALIASES[f"r{_i}d"] = (_i, 4, False)
    ALIASES[f"r{_i}w"] = (_i, 2, False)
    ALIASES[f"r{_i}b"] = (_i, 1, False)
for _n, _i in (("al", 0), ("cl", 1), ("dl", 2), ("bl", 3)):
    ALIASES[_n] = (_i, 1, False)
for _n, _i in (("ah", 0), ("ch", 1), ("dh", 2), ("bh", 3)):
    ALIASES[_n] = (_i, 1, True)

CC = {"o": 0x0, "no": 0x1, "b": 0x2, "c": 0x2, "nae": 0x2, "ae": 0x3, "nb": 0x3,
      "nc": 0x3, "e": 0x4, "z": 0x4, "ne": 0x5, "nz": 0x5, "be": 0x6, "na": 0x6,
      "a": 0x7, "nbe": 0x7, "s": 0x8, "ns": 0x9, "p": 0xa, "pe": 0xa,
      "np": 0xb, "po": 0xb, "l": 0xc, "nge": 0xc, "ge": 0xd, "nl": 0xd,
      "le": 0xe, "ng": 0xe, "g": 0xf, "nle": 0xf}

MASK = (1 << 64) - 1


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
    return funcs


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------
class Emitter:
    def __init__(self, pe: PE, funcs: dict[int, int]):
        self.pe = pe
        self.funcs = funcs
        self.stats = {"insn": 0, "native": 0, "func": 0}

    # ---- operand helpers --------------------------------------------------
    def mem_expr(self, insn, op) -> str | None:
        m = op.mem
        terms: list[str] = []
        base_name = insn.reg_name(m.base) if m.base else None
        if base_name:
            if base_name == "rip":           # absolute target, expressed image-relative
                target = (insn.address + insn.size + m.disp) - self.pe.image_base
                return f"(uint64_t)(B + 0x{target & MASK:x}ull)"
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
        ops = insn.operands
        size = ops[0].size if ops else 0

        if mn in ("nop", "endbr64", "fnop"):
            return ""

        if mn == "ret":
            extra = ops[0].imm if ops and ops[0].type == CS_OP_IMM else 0
            return ("{ const uint64_t t = GuestLoad<uint64_t>(r[RSP]); "
                    f"r[RSP] += {8 + extra}; c->rip = t; RC_SAVE(); return; }}")

        if mn == "jmp":
            if ops[0].type == CS_OP_IMM:
                t = (ops[0].imm & MASK) - self.pe.image_base
                if start <= t < end:
                    return f"goto L_{t:x};"
                return f"{{ RC_SAVE(); c->rip = B + 0x{t:x}ull; rc->tail(c); return; }}"
            v = self.rd(insn, ops[0], 8)
            if v is None:
                return None
            return (f"{{ const uint64_t dn = {v}; RC_SAVE(); c->rip = dn; "
                    "rc->tail(c); return; }")

        if mn.startswith("j") and mn[1:] in CC:
            if ops[0].type != CS_OP_IMM:
                return None
            t = (ops[0].imm & MASK) - self.pe.image_base
            if not (start <= t < end):
                return None
            return f"if (Cond(0x{CC[mn[1:]]:x}, c->flags)) goto L_{t:x};"

        if mn == "call":
            nxt = insn.address + insn.size - self.pe.image_base
            if ops[0].type == CS_OP_IMM:
                t = (ops[0].imm & MASK) - self.pe.image_base
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
        if len(ops) != 2:
            return None
        d, s = ops[0], ops[1]
        di, si = self.xmm_idx(insn, d), self.xmm_idx(insn, s)

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

        targets: set[int] = set()
        for insn in insns:
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    t = (op.imm & MASK) - self.pe.image_base
                    if rva <= t < end:
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
    for rva in order:
        text = em.emit_function(rva, funcs[rva], md)
        if text:
            windows.setdefault(rva // args.window, []).append(text)

    for window, chunks in windows.items():
        (outdir / f"OUT_{window:05x}.c").write_text(
            prologue(False) + "".join(chunks), encoding="utf-8")

    # library entry: the table the loader walks, and one slot per function
    head = [prologue(True)]
    for rva in order:
        head.append(f'void f_{rva:x}(CpuContext *c);\n'
                    f'__attribute__((visibility("hidden"))) RcFn d_{rva:x};\n')
    head.append("\nstatic const RcFunction table[] = {\n")
    for rva in order:
        head.append(f"    {{0x{rva:x}, 0x{funcs[rva] - rva:x}, 0, f_{rva:x}, &d_{rva:x}}},\n")
    head.append("};\n\nextern \"C\" __attribute__((visibility(\"default\")))\n"
                "const RcFunction *bb_recomp_init(const RcApi *api, size_t *count) {\n"
                "    rc = api;\n    *count = sizeof(table) / sizeof(table[0]);\n"
                "    return table;\n}\n")
    (outdir / "OUT.c").write_text("".join(head), encoding="utf-8")

    print(f"[+] {em.stats['func']} functions -> {len(windows)} files + OUT.c in {outdir}")
    if em.stats["insn"]:
        pct = 100.0 * em.stats["native"] / em.stats["insn"]
        print(f"[+] {em.stats['native']}/{em.stats['insn']} instructions in C "
              f"({pct:.1f}%), the rest to the interpreter")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
