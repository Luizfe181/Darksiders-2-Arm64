import os
import glob
import json

game_dir = "game_original"
output_report = os.path.join("analysis", "reports", "asset_tree_inventory.json")

print(f"[*] Varrendo árvore completa de arquivos em: {game_dir}\n")

extensions_count = {}
large_files = []

for root, dirs, files in os.walk(game_dir):
    for file in files:
        full_path = os.path.join(root, file)
        ext = os.path.splitext(file)[1].lower()
        if not ext:
            ext = "[sem extensão]"
            
        extensions_count[ext] = extensions_count.get(ext, 0) + 1
        
        file_size = os.path.getsize(full_path)
        if file_size > 5 * 1024 * 1024:  # Maior que 5 MB
            large_files.append({
                "file": file,
                "relative_path": os.path.relpath(full_path, game_dir),
                "size_mb": round(file_size / (1024 * 1024), 2)
            })

print("=== RESUMO DE EXTENSÕES ENCONTRADAS ===")
for ext, count in sorted(extensions_count.items(), key=lambda x: x[1], reverse=True):
    print(f"  - {ext:20} : {count} arquivo(s)")

print("\n=== ARQUIVOS PRINCIPAIS DE RECURSOS (> 5 MB) ===")
for item in sorted(large_files, key=lambda x: x['size_mb'], reverse=True)[:15]:
    print(f"  - {item['relative_path']:50} | {item['size_mb']} MB")

summary = {
    "extensions_summary": extensions_count,
    "large_files": large_files
}

os.makedirs(os.path.dirname(output_report), exist_ok=True)
with open(output_report, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=4)

print(f"\n[+] Inventário de assets salvo em: {output_report}")