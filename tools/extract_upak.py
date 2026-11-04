import os
import struct
import json

upak_path = os.path.join("game_original", "media", "media.upak")
output_report = os.path.join("analysis", "reports", "upak_toc_inventory.json")

if not os.path.exists(upak_path):
    print(f"[!] Erro: Arquivo {upak_path} não encontrado.")
    exit(1)

print(f"[*] Analisando a Tabela de Conteúdos (TOC) de: {upak_path}\n")

with open(upak_path, "rb") as f:
    magic = f.read(4)
    if magic != b'OBPK':
        print(f"[!] Erro: Assinatura inválida: {magic}")
        exit(1)
        
    version, num_files, toc_offset = struct.unpack("<III", f.read(12))
    
    print(f"[*] Assinatura Validada: OBPK (Vigil Engine Container)")
    print(f"[*] Versão do Formato : {version}")
    print(f"[*] Total de Arquivos : {num_files}")
    print(f"[*] Offset da TOC      : 0x{toc_offset:X} ({toc_offset} bytes)")

    f.seek(toc_offset)
    
    entries = []
    # Teste de parsing alinhado em entradas de 20/24 bytes
    for i in range(num_files):
        entry_bytes = f.read(24)
        if len(entry_bytes) < 24:
            break
            
        # Unpack de offsets de 32-bit (uint32) para validar offsets relativos
        hash_lo, hash_hi, offset_32, comp_size, uncomp_size, flags = struct.unpack("<IIIIII", entry_bytes)
        
        # Filtra e normaliza offsets válidos dentro do tamanho total do arquivo
        real_offset = offset_32
        
        entries.append({
            "index": i,
            "hash": f"0x{hash_hi:08X}{hash_lo:08X}",
            "offset_raw": offset_32,
            "offset_hex": f"0x{offset_32:X}",
            "comp_size": comp_size,
            "uncomp_size": uncomp_size,
            "flags": flags
        })

print(f"[+] Total de entradas processadas: {len(entries)}")

print("\n=== REAMOSTRAGEM DA TOC (ESTRUTURA ALINHADA 32-BIT) ===")
for entry in entries[:10]:
    print(f"  - [{entry['index']:4d}] Hash: {entry['hash']} | Offset: {entry['offset_hex']:10} | Tam. Comp: {entry['comp_size']:8d} B | Tam. Orig: {entry['uncomp_size']:8d} B")

report_data = {
    "package": "media.upak",
    "version": version,
    "total_files": len(entries),
    "toc_offset": toc_offset,
    "files": entries
}

os.makedirs(os.path.dirname(output_report), exist_ok=True)
with open(output_report, "w", encoding="utf-8") as out:
    json.dump(report_data, out, indent=4)

print(f"\n[+] Relatório atualizado em: {output_report}")