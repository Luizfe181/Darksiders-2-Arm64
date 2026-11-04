import struct, os, sys

EXE=os.path.join("game_original","Darksiders2.exe")
d=open(EXE,"rb").read()
print("size",len(d))

e_lfanew=struct.unpack_from("<I",d,0x3C)[0]
assert d[e_lfanew:e_lfanew+4]==b'PE\0\0'
coff=e_lfanew+4
nsec,=struct.unpack_from("<H",d,coff+2)
opt_size,=struct.unpack_from("<H",d,coff+16)
opt=coff+20
magic,=struct.unpack_from("<H",d,opt)
print("opt magic",hex(magic),"sections",nsec)
imagebase=struct.unpack_from("<Q",d,opt+24)[0] if magic==0x20b else struct.unpack_from("<I",d,opt+28)[0]
print("ImageBase",hex(imagebase))
secs=[]
sh=opt+opt_size
for i in range(nsec):
    o=sh+i*40
    name=d[o:o+8].rstrip(b'\0').decode('latin1')
    vsize,vaddr,rawsize,rawptr=struct.unpack_from("<IIII",d,o+8)
    secs.append((name,vaddr,vsize,rawptr,rawsize))
    print(f"  {name:<9} VA=0x{vaddr:08X} VSize=0x{vsize:08X} RawPtr=0x{rawptr:08X} RawSize=0x{rawsize:08X}")

def off2va(off):
    for name,va,vs,rp,rs in secs:
        if rp<=off<rp+rs: return imagebase+va+(off-rp)
    return None
def va2off(v):
    r=v-imagebase
    for name,va,vs,rp,rs in secs:
        if va<=r<va+max(vs,rs): return rp+(r-va)
    return None

STR_OFF=0x1672C78
str_va=off2va(STR_OFF)
print("OBPK string VA =", hex(str_va) if str_va else None)

# scan executable sections for RIP-relative references
MODRM={0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d}
hits=[]
for name,va,vs,rp,rs in secs:
    if not (name.startswith('.text') or name.startswith('CODE') or name.startswith('.rdata')): continue
    blob=d[rp:rp+rs]
    base_rva=va
    for i in range(len(blob)-7):
        b0=blob[i]
        if b0 not in (0x48,0x4C,0x49): continue
        b1=blob[i+1]
        if b1 not in (0x8D,0x8B,0x89): continue
        if blob[i+2] not in MODRM: continue
        disp=struct.unpack_from("<i",blob,i+3)[0]
        tgt=base_rva+i+7+disp+imagebase
        if str_va is not None and tgt==str_va:
            hits.append((name, rp+i))
print("xref hits to OBPK literal:",[(n,hex(o)) for n,o in hits])
for n,o in hits[:4]:
    print(f"\n--- code around file 0x{o:X} ---")
    print(d[max(0,o-64):o+96].hex(' ').upper())
