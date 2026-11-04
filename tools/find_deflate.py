import zlib, struct, os
P=os.path.join("game_original","media","media.upak")
f=open(P,"rb"); FS=os.path.getsize(P)

def try_inflate(off, want=1<<20):
    f.seek(off); b=f.read(min(4<<20, FS-off))
    for wbits in (15, -15):
        try:
            d=zlib.decompressobj(wbits)
            out=d.decompress(b, want)
            if len(out) >= want//2:
                return out, wbits, len(b)
        except Exception:
            pass
    return None, None, 0

def scan(start, end, label, step=0x1000):
    print(f"\n=== scanning {label}: 0x{start:X}..0x{end:X} step 0x{step:X} ===")
    found=[]
    off=start
    while off < end:
        out, wbits, nb = try_inflate(off)
        if out:
            print(f"  *** zlib @ 0x{off:X} wbits={wbits} inflated {len(out)}B  head={out[:32].hex(' ')}")
            print(f"      ascii: {''.join(chr(c) if 32<=c<127 else '.' for c in out[:48])}")
            found.append(off)
            if len(found)>=3: break
        off += step
    if not found: print("  none")
    return found

scan(0, 0x40000, "top header region", 0x1000)
scan(0x40000, 0x78000, "before first nested OBPK", 0x1000)
scan(0x78000, 0x8a0000, "nested pack @0x77800", 0x1000)
