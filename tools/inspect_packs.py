import os
import glob
import json

game_dir = "game_original"
report_path = os.path.join("analysis", "reports", "pack_files_inventory.json")

print(f"[*] Varrendo diretório de dados em: {game_dir}")

pack_files = []
for ext in ('*.opp', '*.pck', '*.pak'):
    pack_files.extend(glob.glob(os.path.join(game_dir, '**', ext), recursive=True))

inventory = []

for file_path in pack_files:
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    
    header_hex = ""
    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(16)
            header_hex = header_bytes.hex(' ').upper()
    except Exception as e:
        header_hex = f"Erro de leitura: {str(e)}"
        
    inventory.append({
        "name": file_name,
        "path": file_path,
        "size_bytes": file_size,
        "size_mb": round(file_size / (1024 * 1024), 2),
        "header_magic_hex": header_hex
    })

print(f"[+] Encontrados {len(inventory)} arquivos de pacote (.opp / .pck / .pak).")
for item in inventory[:10]:  # Exibe os 10 primeiros no terminal
    print(f"  - {item['name']:30} | {item['size_mb']:8.2f} MB | Header: {item['header_magic_hex']}")

os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(inventory, f, indent=4)

print(f"\n[+] Inventário de pacotes salvo em: {report_path}")