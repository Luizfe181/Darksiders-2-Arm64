import struct

pe_path = r'C:\Darksiders2-Android-Port\game_original\Darksiders2.exe'
rva = 0xA9492

with open(pe_path, 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
sec_offset = e_lfanew + 24 + opt_size

raw_offset = None
for i in range(num_sec):
    name, vsize, vaddr, rawsize, rawptr = struct.unpack_from('<8sIIII', data, sec_offset + i * 40)
    if vaddr <= rva < vaddr + vsize:
        raw_offset = rawptr + (rva - vaddr)
        break

if raw_offset:
    print(f'Raw offset: {hex(raw_offset)}')
    code = data[raw_offset:raw_offset+64]
    print('Bytes:', code.hex())
    ret_idx = code.find(b'\xc3')
    if ret_idx != -1:
        print(f'End RVA: {hex(rva + ret_idx + 1)}')
    else:
        print('ret nao encontrado')
else:
    print('RVA nao encontrado')
