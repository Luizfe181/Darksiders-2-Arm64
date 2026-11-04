import os
import requests

SYSTEM_PROMPT = """
Você é um especialista em engenharia reversa de jogos de PC e recompilação estática de x86_64 para ARM64 Android (NDK).
Sua missão é analisar funções decompiladas no Ghidra do jogo Darksiders II (Vigil Engine).

Regras de Tradução:
1. Alinhar a convenção de chamada Win64 (RCX, RDX, R8, R9 + Shadow Space) para AAPCS64 (X0-X7).
2. Substituir chamadas diretas de Win32/DirectX por stubs em C++ limpos compatíveis com POSIX/Vulkan.
3. Retipar variáveis brutas (undefined4, longlong) para tipos explícitos em C++ (uint32_t, int64_t, ponteiros válidos).
4. Fornecer a resposta final em C++ nativo limpo e modular.
"""

class DeepSeekClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.api_url = "https://api.deepseek.com/v1/chat/completions"

    def analyze(self, func_name: str, raw_code: str) -> str:
        if not self.api_key:
            raise ValueError("[!] DEEPSEEK_API_KEY não encontrada nas variáveis de ambiente.")

        prompt = f"Função: {func_name}\n\nPseudocódigo Ghidra (x86_64):\n```c\n{raw_code}\n```"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "deepseek-coder",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            raise RuntimeError(f"Erro na API ({response.status_code}): {response.text}")