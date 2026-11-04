import struct, os, math
from collections import Counter

def entropy(b):
    if not b: return 0.0
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

for name in ["media.upak","maps.upak","anim_streams.upak"]:
    P=os.path.join("game_original","media",name)
    if not os.path.exists(P): print("missing",P); continue
    sz=os.path.getsize(P)
    with open(P,"rb") as f:
        h=f.read(0x40)
    u=struct.unpack("<16I",h)
    print(f"\n===== {name}  size={sz} (0x{sz:X}) =====")
    print("  magic:",h[:4])
    print("  u32:",[hex(x) for x in u[:10]])
    print("  dec:",u[:10])
    for off in [0x0,0x1000,0x54900,sz//2,sz-0x1000]:
        if 0<=off<sz:
            with open(P,"rb") as f:
                f.seek(off); b=f.read(0x1000)
            print(f"   entropy@0x{off:X} = {entropy(b):.3f}")

P=os.path.join("game_original","media","manifest.bin")
print("\n===== manifest.bin =====")
with open(P,"rb") as f: m=f.read()
print("size",len(m),"entropy",round(entropy(m),3))
print(m[:256].hex(' ').upper())
print("printable sample:",''.join(chr(c) if 32<=c<=126 else '.' for c in m[:160]))
# look for strings
import re
strs=re.findall(rb'[\x20-\x7e]{6,}', m)
print("num strings>=6:",len(strs))
print("first 30:",[s.decode() for s in strs[:30]])
print("last 10:",[s.decode() for s in strs[-10:]])
# extensions histogram
exts=Counter()
for s in strs:
    t=s.decode(errors='ignore')
    for e in ['.dds','.tga','.bik','.wav','.ogg','.stream','.model','.anim','.map','.world','.node','.png','.lua','.h','.txt','.bin','.swf','.gfx','.obsp']:
        if t.lower().endswith(e): exts[e]+=1
print("exts:",exts.most_common())
