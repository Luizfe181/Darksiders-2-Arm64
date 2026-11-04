import struct, os, sys, json

P = os.path.join("game_original", "media", "media.upak")
f = open(P, "rb")
FS = os.path.getsize(P)
print("filesize", FS)

def u32(o):
    f.seek(o); return struct.unpack("<I", f.read(4))[0]
def u64(o):
    f.seek(o); return struct.unpack("<Q", f.read(8))[0]
def u8(o):
    f.seek(o); return f.read(1)[0]

f.seek(0); magic = f.read(5)
print("magic", magic.hex(' ').upper(), magic)
pos = 5
vals = []
for nm in ["a","b","c"]:
    v = u32(pos); vals.append(("u32@"+hex(pos), v)); pos += 4
v = u8(pos); vals.append(("u8@"+hex(pos), v)); pos += 1
for nm in ["d","e","num"]:
    v = u32(pos); vals.append(("u32@"+hex(pos), v)); pos += 4
for k, v in vals:
    print(f"  {k} = {v} (0x{v:X})")

num = vals[-1][1]
print("\nnum =", num)
if num > 10000:
    print("!! num implausible; header layout likely differs for this build")
    sys.exit(0)

def read_name(pos, tag):
    h = u64(pos); pos += 8
    ln = u32(pos); pos += 4
    if ln > 512:
        print(f"  [{tag}] IMPLAUSIBLE len={ln} at 0x{pos-4:X}; header parse wrong")
        return h, None, pos, False
    f.seek(pos); nm = f.read(ln); pos += ln
    if any(c < 0x20 or c > 0x7e for c in nm):
        print(f"  [{tag}] NON-PRINTABLE name at 0x{pos-ln:X}: {nm[:24].hex(' ')}")
        return h, nm, pos, False
    return h, nm, pos, True

ok = True
for i in range(num):
    h, nm, pos, good = read_name(pos, f"prefix{i}")
    print(f"  [{i}] hash=0x{h:016X} len={len(nm) if nm else -1} name={nm.decode() if good else '<bad>'}")
    if not good: ok = False; break
print("pos after prefix names = 0x%X" % pos)
if ok:
    print("bytes there:", f.seek(pos) or f.read(24).hex(' ').upper())
