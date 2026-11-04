cmake_minimum_required(VERSION 3.22.1)
project(darksiders2_host_runtime C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define a arquitetura alvo como ARM64 se compilado via NDK
if(ANDROID)
    add_compile_definitions(ANDROID_NDK)
    add_compile_options(-Wall -Wextra -O3)
endif()

# Inclusao de diretorios de cabecalhos
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ---------------------------------------------------------------------------
# SDL2
#
# Android nao tem SDL2 de sistema. Os dois setups suportados sao:
#   * uma copia vendorizada em third_party/SDL2 (recomendado para o NDK), ou
#   * um pacote SDL2 instalado, encontrado em modo CONFIG.
# Em ambos os casos o alvo final e SDL2::SDL2.
# ---------------------------------------------------------------------------
set(D2_SDL2_VENDOR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/SDL2")
if(EXISTS "${D2_SDL2_VENDOR}/CMakeLists.txt")
    message(STATUS "SDL2: usando copia vendorizada em ${D2_SDL2_VENDOR}")
    add_subdirectory("${D2_SDL2_VENDOR}" "${CMAKE_BINARY_DIR}/sdl2" EXCLUDE_FROM_ALL)
else()
    find_package(SDL2 CONFIG QUIET)
    if(NOT SDL2_FOUND)
        message(FATAL_ERROR
            "SDL2 nao encontrado.\n"
            "  Android: coloque os fontes do SDL2 em third_party/SDL2.\n"
            "  Desktop: aponte SDL2_DIR para o diretorio com SDL2Config.cmake.")
    endif()
    message(STATUS "SDL2: usando pacote em ${SDL2_DIR}")
endif()

if(NOT TARGET SDL2::SDL2)
    message(FATAL_ERROR "Alvo SDL2::SDL2 indisponivel")
endif()

find_library(LOG_LIB log)
find_library(ANDROID_LIB android)
find_library(VULKAN_LIB vulkan)
find_library(DL_LIB dl)

# Fontes do Host Runtime
set(RUNTIME_SOURCES
    src/main.cpp
    src/platform_bridge.cpp
    src/win32_stubs.cpp
)

# Definicao da Biblioteca Nativa (.so)
add_library(darksiders2_runtime SHARED ${RUNTIME_SOURCES})

# Mapeamento de dependencias e links
target_link_libraries(darksiders2_runtime PRIVATE SDL2::SDL2)

# SDL2main traz o glue de entrada do Android (SDL_main); linka se existir.
if(TARGET SDL2::SDL2main)
    target_link_libraries(darksiders2_runtime PRIVATE SDL2::SDL2main)
endif()

if(LOG_LIB)
    target_link_libraries(darksiders2_runtime PRIVATE ${LOG_LIB})
endif()

if(ANDROID_LIB)
    target_link_libraries(darksiders2_runtime PRIVATE ${ANDROID_LIB})
endif()

# Vulkan: o SDL cria a VkInstance e a VkSurfaceKHR do jogo.
if(VULKAN_LIB)
    target_link_libraries(darksiders2_runtime PRIVATE ${VULKAN_LIB})
else()
    message(WARNING "libvulkan nao encontrada: a surface Vulkan nao vai ligar.")
endif()

# dlopen: o DXVK e carregado em run time.
if(DL_LIB)
    target_link_libraries(darksiders2_runtime PRIVATE ${DL_LIB})
endif()

# DXVK 1.10.3 e opcional. Se houver um build em third_party/dxvk, passa-se o
# caminho ao loader (win32::LoadDxvk); caso contrario procura-se em run time.
set(D2_DXVK_SO "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dxvk/libdxvk_d3d11.so")
if(EXISTS "${D2_DXVK_SO}")
    target_compile_definitions(darksiders2_runtime
        PRIVATE D2_DXVK_D3D11_SO="${D2_DXVK_SO}")
    message(STATUS "DXVK: ${D2_DXVK_SO}")
else()
    message(STATUS "DXVK: nao vendorizado (procurado em run time: D2_DXVK / libdxvk_d3d11.so)")
endif()

target_link_libraries(darksiders2_runtime PRIVATE m)
