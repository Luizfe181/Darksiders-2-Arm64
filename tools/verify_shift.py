import struct, os

P = os.path.join("game_original", "media", "media.upak")
f = open(P, "rb"); FS = os.path.getsize(P)

def rd(off, n):
    f.seek(off); return f.read(n)

print("=== PROOF: the three 'magic numbers' are misaligned by 1 byte ===")
h = rd(0, 64)
u32 = lambda o: struct.unpack_from("<I", h, o)[0]
pairs = [
    ("version", 0x04, 0x05),
    ("file count", 0x08, 0x09),
    ("toc offset", 0x0C, 0x0D),
]
for name, shifted, real in pairs:
    a = u32(shifted); b = u32(real)
    print(f"  {name:<11} read@0x{shifted:02X} = {a:>10} (0x{a:08X})   read@0x{real:02X} = {b:>10} (0x{b:08X})   {a} == {b}<<8 ? {a == b << 8}")

print("\n=== exact header bytes, pack0 vs pack1 ===")
for base, label in [(0, "pack0 @0x0"), (0x77800, "pack1 @0x77800")]:
    b = rd(base, 80)
    print(f"\n-- {label} --")
    for i in range(0, 72, 8):
        chunk = b[i:i+8]
        print(f"  +{i:02X}: " + " ".join(f"{x:02X}" for x in chunk) +
              f"   u32={struct.unpack('<I', chunk[:4])[0]:<12}")

TAG = bytes.fromhex("04D521E716E65D397383A34DB2B0F14F")
print("\n=== 16-byte constant tag search in pack headers ===")
for base, label in [(0, "pack0"), (0x77800, "pack1"), (0x888800, "pack2"), (0xABD000, "pack3")]:
    b = rd(base, 128)
    i = b.find(TAG)
    print(f"  {label:<7} tag found at +0x{i:02X}" if i >= 0 else f"  {label:<7} tag NOT found in first 128B")

print("\n=== payload forensics (first 32MB) ===")
buf = rd(0, 32 << 20)
mags = {"DDS ": b"DDS ", "BIK": b"BIK", "RIFF": b"RIFF", "OggS": b"OggS",
        "PNG": b"\x89PNG", "zstd": b"\x28\xb5\x2f\xfd", "lz4": b"\x04\x22\x4d\x18",
        "OBPK": b"OBPK", "zlib9c": b"\x78\x9c", "zlibda": b"\x78\xda"}
for k, m in mags.items():
    print(f"  {k:<7} occurrences in 32MB: {buf.count(m)}")
# printable runs
runs = 0; cur = 0; best = 0
for x in buf[0x10000:]:
    if 32 <= x <= 126:
        cur += 1
        if cur == 12: runs += 1
    else:
        best = max(best, cur); cur = 0
print(f"  printable runs >=12: {runs}   longest printable run: {max(best,cur)}")
