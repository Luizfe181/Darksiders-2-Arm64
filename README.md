# Darksiders II - Native ARM64 Android Port (Static Recompilation)

Este projeto consiste na recompilação estática (port nativo) do jogo **Darksiders II** (x86/x64) para a arquitetura **ARM64 (Android)**, utilizando o ecossistema de recompilação `rea` e suporte gráfico via **Vulkan nativo**.

> ⚠️ **Nota:** Este projeto é um estudo de engenharia reversa e porta de preservação. Os assets originais do jogo não estão incluídos e devem ser fornecidos a partir de uma cópia legítima do jogo.

---

## 🛠️ Estado Atual do Projeto

* **Cobertura de Tradução de Instruções:** `~100
  ` traduzidas nativamente via recompilador estático.
* **Arquitetura Alvo:** ARM64-v8a (Android NDK / Clang).
* **Motor Gráfico:** Vulkan (via integração direta com a camada de superfície SDL / Android).
* **Arquitetura Base:** `rea` com pipeline automatizado em Python/C++.

---

## ⚡ Principais Funcionalidades & Correções Implementadas

* **Tradução Nativa x86/x64:** Suporte expandido a instruções escalares, vetoriais (SIMD: `movd`, `movq`, `movlhps`) e instruções de 16 bits (`movzx`).
* **Suporte a Registadores de Segmento:** Implementada a resolução de prefixos `GS` e `FS` no Windows, com a criação de um **TEB (Thread Environment Block)** mínimo por thread no ecossistema Android.
* **Endereçamento Relativo (RIP-Relative):** Generalização do *dispatcher* no runtime (`rc_runtime.cpp`) para reconhecer sequências lineares de inicialização de ponteiros globais e tabelas `.pdata`.
* **Resolução de Imports & Ordinais:** Tratamento estático e stubs nativos para chamadas das bibliotecas dinâmicas de sistema (`KERNEL32.dll`, etc.).

---

## 📁 Estrutura do Repositório

```text
├── game_original/      # Executáveis e binários base para a extração/recompilação
├── out/                # Código C/C++ regenerado a partir da análise estática
├── source/             # Código-fonte da runtime nativa e integração com Android/SDL
│   └── android/        # Scripts de build CMake/NDK e projeto Android Studio/Gradle
├── tools/              # Ferramentas do recompilador em Python (main.py, coverage.py)
└── dist/               # Ficheiros APK gerados para testes no dispositivo
🚀 Como Compilar e Testar
Pré-requisitos
Python 3.10+

Android NDK (r27c ou superior recomendado)

CMake & Ninja Build

Android SDK (ferramenta adb configurada no ambiente)

1. Regenerar o Código C
Para processar o binário do jogo e aplicar as atualizações mais recentes do tradutor de instruções:

Bash
python tools/recompiler/main.py --exe game_original/Darksiders2.exe --out out/recomp_full
2. Medir a Cobertura do Recompilador
Para verificar a percentagem atual de instruções traduzidas e o total de fallbacks:

Bash
python tools/recompiler/coverage.py
3. Compilar a Runtime e Gerar o APK
Para empacotar a biblioteca nativa .so e gerar o APK de testes na pasta dist/:

PowerShell
powershell -File source/android/build_apk.ps1
4. Instalar no Dispositivo via ADB
PowerShell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" install -r dist\darksiders2-boot-test.apk
📜 Licença & Créditos
Desenvolvedor: Luizfe181

Ferramenta de Recompilação: Baseado na arquitetura rea.

Darksiders II: © THQ Nordic / Vigil Games. Todos os direitos reservados.


---

Se quiseres ajustar algum detalhe das seções ou adicionar alguma funcionalidade específica antes de env
