# Darksiders II - Native ARM64 Android Port (Static Recompilation)

Este projeto consiste na recompilação estática (port nativo) do jogo **Darksiders II** (x86/x64) para a arquitetura **ARM64 (Android)**, utilizando o ecossistema de recompilação `rea` e suporte gráfico via **Vulkan nativo**.

> ⚠️ **Nota:** Este projeto é um estudo de engenharia reversa e porta de preservação. Os assets originais do jogo não estão incluídos e devem ser fornecidos a partir de uma cópia legítima do jogo.

---

## 🛠️ Estado Atual do Projeto

* **Cobertura de Tradução de Instruções:** `~99.4%` traduzidas nativamente via recompilador estático.
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
