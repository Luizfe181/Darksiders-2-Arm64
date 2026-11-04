# DXVK 1.10.3 para Android ARM64 — estado do port

Esta pasta recebe a `libdxvk_d3d11.so` que o `win32::LoadDxvk()` carrega em run time.
O patch em `patches/` é a parte de **WSI** do port: é real, aplica limpo ao 1.10.3
e está verificado. **O build completo ainda não é possível** — ver "Bloqueios".

## O que o patch faz

| Ficheiro | Alteração |
|---|---|
| `src/vulkan/vulkan_presenter.cpp` | `createSurface()` usa uma `VkSurfaceKHR` externa (criada pelo SDL2 no host) em vez de `vkCreateWin32SurfaceKHR`; exporta `dxvk_android_set_surface()`; `destroySurface()` não destrói uma surface emprestada |
| `src/vulkan/vulkan_presenter.h` | `m_ownsSurface` (quem liberta a surface) |
| `src/dxvk/platform/dxvk_win32_exts.cpp` | Em Android regista `VK_KHR_surface` em vez de `VK_KHR_win32_surface` |
| `meson.build` | Em Android usa `libvulkan` em vez de `vulkan-1`, e não depende de `d3d9`/`d3d11`/`dxgi`/`d3dcompiler` |

Aplicar sobre a árvore limpa:

```sh
curl -L -o dxvk.tar.gz https://github.com/doitsujin/dxvk/archive/refs/tags/v1.10.3.tar.gz
tar xzf dxvk.tar.gz
cd dxvk-1.10.3
git apply /path/to/0001-android-external-surface.patch     # verificado com --check
```

## Handoff da surface

O host chama, logo depois do `dlopen`:

```c
extern "C" void dxvk_android_set_surface(VkSurfaceKHR surface);   // exportado pelo DXVK
```

`win32::LoadDxvk()` já faz `dlsym` deste símbolo e passa-lhe
`win32::RenderingSurface()`. Não há símbolos globais partilhados: o ponteiro
viaja explicitamente.

## Sobre o extent

Pedido: "forçar `VkExtent2D` com a resolução real (`currentExtent`) para evitar
crash por tamanho zero". **Já é o que o DXVK faz** — `Presenter::pickImageExtent()`
(vulkan_presenter.cpp:415) devolve `caps.currentExtent` quando este não é
`UINT32_MAX`, e só cai para o tamanho pedido na janela quando é. Numa surface
Android `currentExtent` está sempre definido, pelo que o caminho problemático
(a janela Win32 a reportar 0×0) não é alcançável. Não foi preciso patch para isto.

## Bloqueios reais (medidos, não supostos)

`meson setup` com o cross file deste diretório, na ordem em que falham:

| # | Erro | Estado |
|---|---|---|
| 1 | `C++ shared or static library 'vulkan-1' not found` | **resolvido** pelo patch (usa `libvulkan`) |
| 2 | `Program 'glslangValidator' not found` | por resolver — DXVK compila os shaders no build |
| 3 | `windres` em falta | por resolver — recursos `.rc` das DLLs Windows |
| 4 | Sem `windows.h`, `d3d11.h`, `dxgi.h`, `unknwn.h` no NDK | **o bloqueio de fundo** |

O nº 4 é a razão pela qual o 1.10.3 não compila para Android: ele é um **DLL
Windows (PE)** construído com MinGW, e todo o código usa os tipos Win32/COM.
Compilar para `aarch64-linux-android26` exige substituir essa camada por shims
POSIX — não é um patch de dois ficheiros.

## O problema seguinte, mesmo com o build feito

O guest chama D3D11 por **vtable COM**: `D3D11CreateDevice` devolve um
`ID3D11Device*` e o jogo faz `call [rax + 0xNN]` em cada método. No recompilador
estático isso vira `rc->call(c, target, ret)` e precisa de um thunk que traduza
de registradores x86-64 (RCX = `this`) para a ABI ARM64 (X0). Ou seja: **cada
método COM usado pelo jogo tem de ser uma import bridged**, não apenas as três
funções de entrada. É trabalho que ainda não existe neste port.

## Pré-requisitos para retomar

- `glslangValidator` (Vulkan SDK) no `PATH`
- `windres` (binutils-mingw) — ou patch para o dispensar
- Substituição dos headers Windows por shims (o grosso do trabalho)
- Confirmar `HRESULT` como `int32_t` em todo o DXVK: no Windows `long` é 32-bit,
  no Android é 64-bit, e um `HRESULT` de 64 bits corrompe o retorno para o guest

## Verificação do lado do runtime

`win32::LoadDxvk()` procura `dxvk_android_set_surface` e, se existir, liga-o à
surface actual. Sem DXVK as três entradas continuam a devolver `E_FAIL` — testado
em `tests/win32_stubs_selftest.cpp`.
