import struct, os, math
from collections import Counter

UP=os.path.join("game_original","media","media.upak")
def H(b):
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

f=open(UP,"rb")
TOC_OFF=0x54900; toc=f.read(0x2D000)

print("=== per-byte-position entropy for candidate entry sizes ===")
for p in (4,8,16,20,24,28,32):
    ents=[]
    for k in range(p):
        col=toc[k::p]
        ents.append(H(col[:20000]))
    print(f" period {p:2d}: min={min(ents):.3f} max={max(ents):.3f} mean={sum(ents)/len(ents):.3f}")
    if p in (8,24) :
        print("   per-pos:", " ".join(f"{e:.2f}" for e in ents))

# distribution of high byte of every u32 (should be low if small ints)
vals=struct.unpack(f"<{len(toc)//4}I",toc)
hi=Counter((v>>24)&0xFF for v in vals)
print("\nhigh-byte histogram of u32s (top10):", hi.most_common(10))
print("fraction with high byte == 0:", hi[0]/len(vals))

# inspect nested OBPK signatures
for off in (0x77800, 0x888800, 0xabd000):
    f.seek(off); b=f.read(0x60)
    print(f"\n--- 0x{off:X} ---")
    print(b[:0x40].hex(' ').upper())
    print("  u32:", [hex(x) for x in struct.unpack('<8I', b[:32])])

# what is at 0x1000 (first 256 of data region)?
f.seek(0x1000); b=f.read(0x80)
print("\n--- 0x1000 ---"); print(b.hex(' ').upper())
