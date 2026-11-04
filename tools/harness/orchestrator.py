import os
import sys
import argparse
from cache import HarnessCache
from client import DeepSeekClient

def process_function(func_name: str, raw_code: str, force_refresh: bool = False):
    cache = HarnessCache()
    
    # 1. Checa o Cache Local
    if not force_refresh:
        cached_res = cache.get(raw_code)
        if cached_res:
            print(f"[CACHE] Análise recuperada do SQLite (Hash: {cached_res['hash'][:8]}...)")
            return cached_res['analyzed_code']

    # 2. Chamada à API caso não esteja em Cache
    print(f"[API] Enviando '{func_name}' para inferência via DeepSeek...")
    try:
        client = DeepSeekClient()
        analyzed_code = client.analyze(func_name, raw_code)
        
        # 3. Salva a resposta no banco local
        code_hash = cache.put(func_name, raw_code, analyzed_code, {"target_abi": "arm64-v8a"})
        print(f"[SUCCESS] Análise concluída e salva no cache (Hash: {code_hash[:8]}...)")
        return analyzed_code
    except Exception as e:
        print(f"[ERROR] Falha ao processar função: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepSeek Harness Orchestrator com Cache SQLite")
    parser.add_argument("--name", type=str, default="FUN_Sample", help="Nome da função")
    parser.add_argument("--file", type=str, help="Caminho do arquivo com o código bruto do Ghidra")
    parser.add_argument("--force", action="store_true", help="Ignora o cache e força a consulta na API")

    args = parser.parse_args()

    # Exemplo de teste rápido caso nenhum arquivo seja passado
    if not args.file:
        sample_code = """
        undefined8 FUN_140001000(longlong param_1, int param_2) {
            if (param_2 == 1) {
                *(int *)(param_1 + 0x10) = 0;
            }
            return 1;
        }
        """
        print("[*] Testando orquestrador com exemplo simulado...")
        res = process_function(args.name, sample_code, force_refresh=args.force)
        print("\n--- RESULTADO DA ANÁLISE ---")
        print(res)
    else:
        if os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8") as f:
                raw_code = f.read()
            res = process_function(args.name, raw_code, force_refresh=args.force)
            print("\n--- RESULTADO DA ANÁLISE ---")
            print(res)
        else:
            print(f"[!] Arquivo não encontrado: {args.file}")