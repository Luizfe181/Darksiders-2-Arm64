import zlib, os, struct
P=os.path.join("game_original","media","media.upak")
f=open(P,"rb")
cands=[0x2E,0x30,0x40,0x1000,0x180,0x200,0x54900,0x56700,0x70000,0x250000,0x28C00,0x81900,0x1B80000,0x77800+0x2E]
for off in cands:
    f.seek(off); b=f.read(0x40000)
    ok=False
    for wbits in (15,-15,31):
        try:
            d=zlib.decompressobj(wbits)
            out=d.decompress(b, 1<<20)
            if len(out)>64:
                print(f"  off 0x{off:X} wbits={wbits}: INFLATED {len(out)} bytes, head={out[:24].hex(' ')}")
                ok=True
        except Exception as e:
            pass
    if not ok:
        print(f"  off 0x{off:X}: no zlib")
