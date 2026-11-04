import sys, collections
sys.path.insert(0, r'C:\Darksiders2-Android-Port\tools\recompiler')
from main import PE, build_function_map, Emitter
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = PE(Path(r'C:\Darksiders2-Android-Port\game_original\Darksiders2.exe'))
funcs = build_function_map(pe)
em = Emitter(pe, funcs)
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

miss = collections.Counter()
tot = collections.Counter()
n_insn = n_native = 0
for rva in sorted(funcs):
    end = funcs[rva]
    code = pe.read_rva(rva, end - rva)
    if not code: continue
    for insn in md.disasm(code, pe.image_base + rva):
        n_insn += 1
        tot[insn.mnemonic] += 1
        if em.translate(insn, rva, end) is None:
            n_native += 0
            miss[insn.mnemonic] += 1
print(f"instructions {n_insn}, translated {n_insn - sum(miss.values())} "
      f"({100*(n_insn-sum(miss.values()))/n_insn:.1f}%), fallback {sum(miss.values())}")
print("\ntop fallback mnemonics (count, % of that mnemonic):")
for mn, c in miss.most_common(25):
    print(f"  {mn:<12} {c:>8}  ({100*c/tot[mn]:5.1f}% of {tot[mn]})")
