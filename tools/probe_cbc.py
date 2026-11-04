import struct, os, math
from collections import Counter
UP=os.path.join("game_original","media","media.upak")
f=open(UP,"rb"); toc=f.read(0x2D000)

def H(b):
    if not b: return 0.0
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def xorbuf(a,b): return bytes(x^y for x,y in zip(a,b))

def report(name, buf, stride=24):
    # column entropy assuming 'stride' records
    cols=[H(buf[k::stride][:4000]) for k in range(min(stride,len(buf)))]
    u32=struct.unpack(f"<{len(buf)//4}I", buf[:len(buf)//4*4])
    small=sum(1 for v in u32 if v < 0x100000)/len(u32)
    zeros=sum(1 for v in u32 if v==0)/len(u32)
    print(f"{name:<28} overall={H(buf):.3f} colmin={min(cols):.3f} colmax={max(cols):.3f} "
          f"frac_u32<1M={small:.4f} frac_zero={zeros:.4f}")

report("raw", toc)
for s in (24,):
    report(f"CBC-xor prev entry (s={s})", xorbuf(toc[s:], toc[:-s]), s)
report("xor prev byte", xorbuf(toc[1:], toc[:-1]), 24)
report("xor prev u32", xorbuf(toc[4:], toc[:-4]), 24)
report("xor prev u64", xorbuf(toc[8:], toc[:-8]), 24)

# XOR with first 24-byte block repeated (keystream = block0)
b0=toc[:24]
ks=(b0*((len(toc)//24)+1))[:len(toc)]
report("xor repeating first 24B", xorbuf(toc,ks),24)

# check for 4-byte-period repeating key: byte-position entropy mod 4 on CBC result
cbc=xorbuf(toc[24:],toc[:-24])
print("\nCBC result per-byte-mod-24 entropy:", " ".join(f"{H(cbc[k::24][:3000]):.2f}" for k in range(24)))
print("CBC result first 48 bytes:", cbc[:48].hex(' ').upper())

# look for long zero runs anywhere in raw & transforms
for nm,buf in [("raw",toc),("cbc",cbc)]:
    run=0;best=0
    for x in buf:
        run = run+1 if x==0 else 0
        best=max(best,run)
    print(f"longest zero-byte run in {nm}: {best}")
