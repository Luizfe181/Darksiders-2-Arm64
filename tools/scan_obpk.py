import mmap, struct, os, sys
P=os.path.join("game_original","media","media.upak")
f=open(P,"rb")
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
size=len(mm)
pos=[]; i=0
while True:
    i=mm.find(b'OBPK',i)
    if i<0: break
    pos.append(i); i+=1
print("total OBPK occurrences:",len(pos))
print("\nfirst 25 with header words:")
for o in pos[:25]:
    u=struct.unpack_from("<10I",mm,o)
    gap = (o-pos[pos.index(o)-1]) if pos.index(o)>0 else 0
    print(f"  0x{o:010X} gap=0x{gap:08X} ver=0x{u[1]:X} n={u[2]} f3=0x{u[3]:X} f4=0x{u[4]:X} f5=0x{u[5]:X} f6=0x{u[6]:X}")
print("\nlast 10:")
for o in pos[-10:]:
    u=struct.unpack_from("<10I",mm,o)
    print(f"  0x{o:010X} ver=0x{u[1]:X} n={u[2]} f3=0x{u[3]:X} f4=0x{u[4]:X}")
mm.close()
