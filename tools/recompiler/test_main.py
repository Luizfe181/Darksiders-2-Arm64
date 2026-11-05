import sys
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, str(Path(__file__).parent))
import main


class DummyPE:
    image_base = 0


class LeafPE:
    image_base = 0
    entry_rva = 0x100

    def __init__(self, code):
        self.code = code

    def pdata_functions(self):
        return {}

    def read_rva(self, rva, size):
        if rva == 0x86C20:
            return self.code[:size]
        if rva == 0x86C6C:
            return self.code[0x4C:0x4C + size]
        return None


class EmitterInstructionTests(unittest.TestCase):
    def setUp(self):
        self.emitter = main.Emitter(DummyPE(), {})
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        self.disassembler.detail = True

    def translate(self, code):
        insn = next(self.disassembler.disasm(code, 0x1000))
        return self.emitter.translate(insn, 0, 0x2000)

    def test_int3_does_not_require_interpreter(self):
        self.assertEqual(self.translate(b"\xcc"), "")

    def test_known_leaf_without_pdata_is_added_only_for_matching_code(self):
        code = bytearray(0x4D)
        code[:4] = b"\x33\xC0\x48\x89"
        code[-1] = 0xC3
        self.assertIn(0x86C20, main.build_function_map(LeafPE(code)))
        code[0] = 0x90
        self.assertNotIn(0x86C20, main.build_function_map(LeafPE(code)))

    def test_ucomiss_memory_operand_translates_flags(self):
        translated = self.translate(b"\x0f\x2e\x00")  # ucomiss xmm0, [rax]
        self.assertIn("std::isunordered(lhs, rhs)", translated)
        self.assertIn("F_CF | F_PF | F_ZF", translated)

    def test_comiss_register_operand_translates(self):
        translated = self.translate(b"\x0f\x2f\xc1")  # comiss xmm0, xmm1
        self.assertIn("v[1].f[0]", translated)

    def test_locked_atomic_instructions_translate(self):
        xadd = self.translate(b"\xf0\x0f\xc1\x08")  # lock xadd [rax], ecx
        add = self.translate(b"\xf0\x01\x08")  # lock add [rax], ecx
        inc = self.translate(b"\xf0\xff\x00")  # lock inc [rax]
        self.assertIn("__atomic_fetch_add", xadd)
        self.assertIn("r[1] = (uint32_t)(old);", xadd)
        self.assertIn("ArithFlags", add)
        self.assertIn("F_CF", inc)

    def test_shufps_immediate_selects_lanes(self):
        translated = self.translate(b"\x0f\xc6\xc1\x1b")
        self.assertIn("old.d[3]", translated)
        self.assertIn("source.d[1]", translated)

    def test_movd_register_transfers(self):
        to_xmm = self.translate(b"\x66\x0f\x6e\xc0")
        to_gpr = self.translate(b"\x66\x0f\x7e\xc0")
        self.assertIn("std::memset(&v[0]", to_xmm)
        self.assertIn("r[0] = (uint32_t)(v[0].d[0]);", to_gpr)

    def test_fs_and_gs_segment_bases_are_preserved(self):
        fs = self.translate(b"\x64\x48\x8b\x04\x25\x30\x00\x00\x00")
        gs = self.translate(b"\x65\x48\x8b\x0c\x25\x30\x00\x00\x00")
        self.assertIn("c->fs_base + 0x30ull", fs)
        self.assertIn("c->gs_base + 0x30ull", gs)

    def test_cdqe_sign_extends_eax(self):
        translated = self.translate(b"\x48\x98")
        self.assertIn("int32_t", translated)

    def test_sbb_uses_incoming_borrow(self):
        translated = self.translate(b"\x1b\xc1")  # sbb eax, ecx
        self.assertIn("carry = (c->flags & F_CF)", translated)
        self.assertIn("a < b || (carry && a == b)", translated)

    def test_rdtsc_writes_low_and_high_halves(self):
        translated = self.translate(b"\x0f\x31")
        self.assertIn("steady_clock", translated)
        self.assertIn("ticks >> 32", translated)

    def test_cpuid_emulates_a_conservative_x64_cpu_profile(self):
        translated = self.translate(b"\x0f\xa2")
        self.assertIn("0x756e6547u", translated)
        self.assertIn("0x49656e69u", translated)
        self.assertIn("0x6c65746eu", translated)
        self.assertIn("(1u << 26)", translated)

    def test_setcc_supports_low_byte_registers(self):
        translated = self.translate(b"\x40\x0f\x95\xc6")  # setne sil
        self.assertIn("r[6] =", translated)
        self.assertIn("Cond(0x5, c->flags)", translated)

    def test_conditional_branch_to_another_function_dispatches(self):
        translated = self.translate(b"\x0f\x84\xfa\x1f\x00\x00")  # je 0x3000
        self.assertIn("Cond(0x4, c->flags)", translated)
        self.assertIn("c->rip = B + 0x3000ull", translated)
        self.assertIn("rc->tail(c); return;", translated)

    def test_conditional_branch_inside_function_keeps_local_goto(self):
        insn = next(self.disassembler.disasm(b"\x0f\x84\xfa\xff\xff\xff", 0x1000))
        self.emitter._starts = {0x1000}
        translated = self.emitter.translate(insn, 0, 0x2000)
        self.assertIn("goto L_1000;", translated)

    def test_integer_multiply_forms_translate_overflow(self):
        one_operand = self.translate(b"\x48\xf7\xe9")  # imul rcx
        two_operand = self.translate(b"\x48\x0f\xaf\xc1")  # imul rax, rcx
        self.assertIn("__int128", one_operand)
        self.assertIn("F_CF | F_OF", one_operand)
        self.assertIn("__int128", two_operand)
        self.assertIn("F_CF | F_OF", two_operand)

    def test_bit_test_and_modify_registers(self):
        translated = self.translate(b"\x0f\xab\xc8")  # bts eax, ecx
        self.assertIn("F_CF", translated)
        self.assertIn("r[0] = (uint32_t)", translated)

    def test_packed_sse_operations_translate(self):
        cases = (
            (b"\x0f\x55\xc1", "pandn"),
            (b"\x0f\x5f\xc1", "maxps"),
            (b"\x66\x0f\x70\xc1\x1b", "pshufd"),
            (b"\x0f\x5b\xc1", "cvtdq2ps"),
            (b"\x0f\x14\xc1", "unpcklps"),
            (b"\x66\x0f\xd3\xc1", "psrlq"),
            (b"\x66\x0f\x73\xd8\x04", "psrldq"),
            (b"\xf3\x0f\x2c\xc1", "cvttss2si"),
            (b"\xf3\x0f\x2a\xc1", "cvtsi2ss"),
            (b"\x0f\x16\xc1", "movlhps"),
            (b"\x66\x0f\xd4\xc1", "paddq"),
        )
        for code, expected in cases:
            with self.subTest(expected=expected):
                translated = self.translate(code)
                self.assertIsNotNone(translated)
                if expected == "psrldq":
                    self.assertIn("const unsigned count = 4", translated)


if __name__ == "__main__":
    unittest.main()
