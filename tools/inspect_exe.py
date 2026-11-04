import os
import sys
import json
import pefile

exe_path = os.path.join("game_original", "Darksiders2.exe")
report_path = os.path.join("analysis", "reports", "pe_inspection.json")

if not os.path.exists(exe_path):
    print(f"[!] Erro: Arquivo nao encontrado em {exe_path}")
    sys.exit(1)

print(f"[*] Analisando: {exe_path}")
pe = pefile.PE(exe_path)

sections = []
for section in pe.sections:
    name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
    sections.append({
        "name": name,
        "virtual_address": hex(section.VirtualAddress),
        "virtual_size": hex(section.Misc_VirtualSize),
        "raw_size": hex(section.SizeOfRawData)
    })

imports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='ignore')
        funcs = [imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}" for imp in entry.imports]
        imports[dll_name] = funcs

data = {
    "sections": sections,
    "imports": imports
}

os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4)

print(f"[+] Relatorio completo salvo em: {report_path}")