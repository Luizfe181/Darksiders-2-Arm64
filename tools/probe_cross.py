import struct, os, math
from collections import Counter

M=os.path.join("game_original","media","media.upak")
P=os.path.join("game_original","media","maps.upak")
def H(b):
    if not b: return 0.0
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

fm=open(M,"rb"); fp=open(P,"rb")
fm.seek(0x54900); a=fm.read(0x2D000)
fp.seek(0x42000); b=fp.read(0x2D000)
x=bytes(p^q for p,q in zip(a,b))
print(f"keystream-reuse XOR: entropy={H(x):.3f} zero_or={x.count(0)/len(x):.6f} frac_u32_small={sum(1 for v in struct.unpack('<%dI'%(len(x)//4),x[:len(x)//4*4]) if v<0x10000)/(len(x)//4):.4f}")
print("  first 48:", x[:48].hex(' ').upper())

# where is the 101-byte zero run in media TOC?
i=a.find(b'\x00'*101)
print(f"\nzero run(101) at TOC+0x{i:X} -> abs 0x{0x54900+i:X}")
print("  context:", a[max(0,i-32):i+140].hex(' ').upper())

# enumerate zero runs >=48 in first 0x90000
fm.seek(0); head=fm.read(0x90000)
runs=[]; j=0
while j < len(head):
    if head[j]==0:
        k=j
        while k<len(head) and head[k]==0: k+=1
        if k-j>=48: runs.append((j,k-j))
        j=k
    else: j+=1
print("\nzero runs >=48 in first 0x90000:", [(hex(o),l) for o,l in runs][:20])

# numeric test: for each 8-byte position within 24, are values plausible as file offsets?
FS=7146668032
print("\n=== value ranges by field position (entry=24B) ===")
for base in (0,4,8,12,16):
    vals=[struct.unpack_from("<Q",a,i)[0] for i in range(base,len(a)-7,24)]
    mx=max(vals); frac=sum(1 for v in vals if v<FS)/len(vals)
    print(f" u64@{base:2d}: max=0x{mx:016X} frac<filesize={frac:.3f}")
for base in (0,4,8,12,16,20):
    vals=[struct.unpack_from("<I",a,i)[0] for i in range(base,len(a)-3,24)]
    mx=max(vals); frac=sum(1 for v in vals if v<FS)/len(vals)
    print(f" u32@{base:2d}: max={mx:12d} frac<filesize={frac:.3f}  (max/1e6={mx/1e6:.1f})")
