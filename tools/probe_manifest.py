import struct, os, re
from collections import Counter

MAN = os.path.join("game_original","media","manifest.bin")
UP  = os.path.join("game_original","media","media.upak")

m = open(MAN,"rb").read()
print("manifest size", len(m))

# parse records: [hash u64][namelen u32][name]
hashes = {}
pos = 0x40
recs = []
while pos + 12 <= len(m):
    h, nlen = struct.unpack_from("<QI", m, pos)
    if nlen == 0 or nlen > 260:
        break
    name = m[pos+12:pos+12+nlen]
    if any(c < 0x20 or c > 0x7e for c in name):
        break
    recs.append((h, name.decode('ascii','replace')))
    hashes.setdefault(h, name.decode('ascii','replace'))
    pos += 12 + nlen
print(f"parsed {len(recs)} records, ended at 0x{pos:X}, next bytes: {m[pos:pos+32].hex(' ')}")
print("first 5:", [(hex(h),n) for h,n in recs[:5]])
print("last 3:", [(hex(h),n) for h,n in recs[-3:]])
hs = set(hashes)

# ---- TOC ----
f = open(UP,"rb")
TOC_OFF=0x54900; N=7680; ES=24
f.seek(TOC_OFF); toc = f.read(N*ES)
print(f"\nTOC bytes {len(toc)}")

for stride, base in [(24,0),(24,8),(24,16),(8,0)]:
    vals = [struct.unpack_from("<Q", toc, i)[0] for i in range(base, len(toc)-7, stride)]
    inter = hs.intersection(vals)
    print(f"  stride={stride} base={base}: {len(vals)} qwords, matched manifest hashes = {len(inter)}")
    if inter and len(inter) < 12:
        print("     ", [ (hex(x), hashes[x]) for x in list(inter)[:10] ])
