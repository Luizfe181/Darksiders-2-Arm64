import os
import struct
import json

upak_path = os.path.join("game_original", "media", "media.upak")
report_path = os.path.join("analysis", "reports", "upak_header.json")

if not os.path.exists(upak_path):
    print(f"[!] Erro: Arquivo nao encontrado em {upak_path}")
    exit(1)

print(f"[*] Analisando o arquivo de dados principal: {upak_path}")

with open(upak_path, "rb") as f:
    header_bytes = f.read(64)
    magic_hex = header_bytes[:16].hex(' ').upper()
    magic_ascii = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in header_bytes[:16]])
    
    # Leitura de inteiros do inicio do pacote (Little Endian)
    v1, v2, v3, v4 = struct.unpack("<IIII", header_bytes[:16])

print(f"[+] Magic Bytes (HEX)  : {magic_hex}")
print(f"[+] ASCII Equivalente   : {magic_ascii}")
print(f"[+] Valores Int (LE)    : v1={v1}, v2={v2}, v3={v3}, v4={v4}")

info = {
    "file": "media.upak",
    "magic_hex": magic_hex,
    "magic_ascii": magic_ascii,
    "parsed_ints": [v1, v2, v3, v4]
}

os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, "w", encoding="utf-8") as out:
    json.dump(info, out, indent=4)

print(f"\n[+] Relatorio de header UPAK salvo em: {report_path}")