"""Empirical probe of media.upak -- no assumptions about encryption."""
import struct, zlib, math, sys, os
from collections import Counter

P = os.path.join("game_original", "media", "media.upak")
FSIZE = os.path.getsize(P)
print(f"file size = {FSIZE} (0x{FSIZE:X})")

f = open(P, "rb")

def dump(off, n, label):
    f.seek(off)
    b = f.read(n)
    print(f"\n--- {label} @ 0x{off:X} ({n} bytes) ---")
    for i in range(0, len(b), 32):
        chunk = b[i:i+32]
        hx = " ".join(f"{x:02X}" for x in chunk)
        tx = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        print(f"{off+i:010X}  {hx:<96}  {tx}")
    return b

hdr = dump(0, 0x120, "header")

# entropy helper
def entropy(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def zscan(b, label):
    """find zlib/gzip/OBPK/bik/jpg etc signatures"""
    sigs = {b'\x78\x9c':'zlib-default', b'\x78\x01':'zlib-fast', b'\x78\xda':'zlib-max',
            b'\x1f\x8b':'gzip', b'OBPK':'OBPK', b'BIK':'bink', b'\xff\xd8\xff':'jpeg',
            b'DDS ':'dds', b'\x89PNG':'png'}
    hits=[]
    for sig,name in sigs.items():
        i=0
        while True:
            i=b.find(sig,i)
            if i<0: break
            hits.append((name,i)); i+=1
            if len(hits)>50: break
    print(f"  [{label}] sig hits: {hits[:20]}")

print("\n=== region entropies ===")
for off,n,lab in [(0x24,0x1000,'hdr+'),(0x54900,0x2D000,'claimed TOC'),(0x81900,0x10000,'post-TOC'),
                  (FSIZE-0x10000,0x10000,'tail')]:
    f.seek(off); b=f.read(min(n,FSIZE-off))
    print(f"  {lab:<14} @0x{off:08X} len={len(b):7d} entropy={entropy(b):.4f}")
    zscan(b,lab)

# how many OBPK signatures in first 64MB?
f.seek(0); head=f.read(64*1024*1024)
idx=[]; i=0
while True:
    i=head.find(b'OBPK',i)
    if i<0: break
    idx.append(i); i+=1
    if len(idx)>20: break
print(f"\nOBPK occurrences in first 64MB: {[hex(x) for x in idx[:20]]}")

# entropy profile of first 2MB in 4K windows: where does structure start/end?
print("\n=== 4K-window entropy map (first 1.2MB) ===")
f.seek(0); buf=f.read(0x130000)
for off in range(0, len(buf), 0x1000):
    e=entropy(buf[off:off+0x1000])
    bar='#'*int(e*8)
    print(f"  0x{off:06X} {e:5.2f} {bar}")
