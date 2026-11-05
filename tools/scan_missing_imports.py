import sys
import re
from pathlib import Path

sys.path.insert(0, 'tools/recompiler')
from main import PE

pe = PE(Path('game_original/Darksiders2.exe'))
stubs_text = Path('source/android/src/win32_stubs.cpp').read_text(encoding='utf-8')

# extract from kEntries: {"kernel32.dll", "VirtualAlloc", Stub_VirtualAlloc}
registered = set(re.findall(r'\{\s*"[^"]+"\s*,\s*"([^"]+)"', stubs_text))
print(f"Total registered stubs in win32_stubs.cpp: {len(registered)}")

data = pe.data
e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
opt = e_lfanew + 24
import_rva = int.from_bytes(data[opt + 112 + 8: opt + 112 + 12], 'little')

missing_by_mod = {}
total_imports = 0
resolved_count = 0

d = 0
while True:
    desc_off = pe.rva_to_off(import_rva + d * 20)
    desc = data[desc_off:desc_off + 20]
    orig_thunk = int.from_bytes(desc[0:4], 'little')
    name_rva = int.from_bytes(desc[12:16], 'little')
    first_thunk = int.from_bytes(desc[16:20], 'little')
    if orig_thunk == 0 and name_rva == 0:
        break
    
    mod_name = pe.read_rva(name_rva, 64).split(b'\x00')[0].decode('ascii', errors='ignore')
    thunk_rva = orig_thunk if orig_thunk != 0 else first_thunk
    
    i = 0
    while True:
        entry_data = pe.read_rva(thunk_rva + i * 8, 8)
        entry = int.from_bytes(entry_data, 'little')
        if entry == 0:
            break
        total_imports += 1
        if (entry & (1 << 63)) == 0:
            fn_name = pe.read_rva((entry & 0x7FFFFFFF) + 2, 64).split(b'\x00')[0].decode('ascii', errors='ignore')
            if fn_name in registered:
                resolved_count += 1
            else:
                missing_by_mod.setdefault(mod_name, []).append(fn_name)
        i += 1
    d += 1

print(f"Total imports in Darksiders2.exe: {total_imports}, Resolved: {resolved_count}, Missing: {total_imports - resolved_count}")
for mod, fns in missing_by_mod.items():
    print(f"\n--- {mod} ({len(fns)} missing) ---")
    print(", ".join(fns))
