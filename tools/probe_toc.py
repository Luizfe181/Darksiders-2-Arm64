import struct, os
from collections import Counter

P = os.path.join("game_original", "media", "media.upak")
f = open(P, "rb")

PROMPT = bytes.fromhex(
 "FC78F8F5 2F9ED7F8 5451D334 DCFF2AD5 5981DFB5 D2C9F0EE AA989F3F 2A0E92F8 "
 "2FCCFEAC 78BF4CEE 758E145E FD3D4FCE FA00BEE1 114DF2D1 1FE358E7 0FFC9995 "
 "4CDF6FC4 6AC4689C 7326C305 F1FDFEFD 23A58AF9 D169F2CD 7D5318BD 39F59DEF")

f.seek(0x54900)
actual = f.read(120)
print("prompt sample == actual@0x54900 :", actual == PROMPT)
print("actual   :", actual.hex(' ').upper())
print("prompt   :", PROMPT.hex(' ').upper())
if actual != PROMPT:
    for i,(a,b) in enumerate(zip(actual,PROMPT)):
        if a!=b:
            print(f"first diff at byte {i}: actual {a:02X} vs prompt {b:02X}"); break

# ---- word repetition analysis over claimed TOC region ----
f.seek(0x54900); toc = f.read(0x2D000)
words = struct.unpack(f"<{len(toc)//4}I", toc)
c = Counter(words)
print(f"\nwords={len(words)} unique={len(c)}  most common: {c.most_common(8)}")

# ---- are 8-byte halves zero often? (would reveal XOR key directly) ----
q = struct.unpack(f"<{len(toc)//8}Q", toc)
cq = Counter(q)
print(f"qwords={len(q)} unique={len(cq)} most common: {[ (hex(k),v) for k,v in cq.most_common(5)]}")

# ---- the actual header fields ----
f.seek(0); h = f.read(0x40)
print("\nheader u32s:", [hex(x) for x in struct.unpack("<16I", h)])
print("header u32s dec:", struct.unpack("<16I", h))
print("as u16:", struct.unpack("<32H", h))
