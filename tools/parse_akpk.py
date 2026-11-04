import os
import glob
import struct
import json

# Busca dinamica pelo core.pck em subpastas
pck_files = glob.glob(os.path.join("game_original", "**", "core.pck"), recursive=True)

if not pck_files:
    print("[!] Erro: Arquivo core.pck nao encontrado em game_original/ nem em subpastas.")
    exit(1)

pck_path = pck_files[0]
output_report = os.path.join("analysis", "reports", "akpk_structure.json")

print(f"[*] Encontrado arquivo em: {pck_path}")

with open(pck_path, "rb") as f:
    magic = f.read(4)
    if magic != b'AKPK':
        print(f"[!] Header invalido: {magic}")
        exit(1)
        
    header_size = struct.unpack("<I", f.read(4))[0]
    version = struct.unpack("<I", f.read(4))[0]
    language_map_size = struct.unpack("<I", f.read(4))[0]
    
    print(f"[*] Assinatura Validada: AKPK (Audiokinetic Wwise)")
    print(f"[*] Tamanho do Header: {header_size} bytes")
    print(f"[*] Versão do Wwise Format: {version}")

    info = {
        "file_path": pck_path,
        "magic": "AKPK",
        "header_size": header_size,
        "version": version,
        "language_map_size": language_map_size
    }
    
    os.makedirs(os.path.dirname(output_report), exist_ok=True)
    with open(output_report, "w", encoding="utf-8") as out:
        json.dump(info, out, indent=4)
        
    print(f"[+] Analise de estrutura salva em: {output_report}")