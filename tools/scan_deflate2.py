import zlib, os
P=os.path.join("game_original","media","media.upak")
f=open(P,"rb"); FS=os.path.getsize(P)
print("relaxed deflate scan (>=4096 out) at 0x1000 multiples, first 8MB")
best=[]
off=0
while off < 8<<20:
    f.seek(off); b=f.read(1<<20)
    for wbits in (15,-15,31):
        try:
            d=zlib.decompressobj(wbits)
            out=d.decompress(b, 1<<22)
            if len(out)>=4096:
                best.append((off,wbits,len(out),out[:24]))
                print(f"  HIT 0x{off:X} wbits={wbits} out={len(out)} head={out[:24].hex(' ')}")
        except Exception:
            pass
    off += 0x1000
    if len(best)>=4: break
if not best: print("  no deflate stream at any 0x1000 multiple in first 8MB")
