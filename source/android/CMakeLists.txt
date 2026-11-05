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
    if(DEFINED SDL2_DIR AND EXISTS "${SDL2_DIR}/lib/cmake/SDL2/SDL2Config.cmake")
        set(SDL2_DIR "${SDL2_DIR}/lib/cmake/SDL2" CACHE PATH "Path to SDL2Config.cmake" FORCE)
    elseif(EXISTS "C:/sdl2_android/lib/cmake/SDL2/SDL2Config.cmake" AND NOT DEFINED SDL2_DIR)
        set(SDL2_DIR "C:/sdl2_android/lib/cmake/SDL2" CACHE PATH "Path to SDL2Config.cmake" FORCE)
    endif()
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

# DXVK Native backend (optional external checkout, e.g.
# C:/LMS_Android/android/app/jni/dxvk). This is the D3D9-to-Vulkan backend;
# the regular DXVK 1.10.3 Windows DLL is not suitable for this Android build.
set(D2_DXVK_NATIVE_DIR "" CACHE PATH "Path to an Android-ready DXVK Native checkout")
if(D2_DXVK_NATIVE_DIR)
    if(NOT EXISTS "${D2_DXVK_NATIVE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR
            "D2_DXVK_NATIVE_DIR must point to an Android-ready DXVK Native checkout.")
    endif()
    if(NOT TARGET SDL2)
        add_library(SDL2 ALIAS SDL2::SDL2)
    endif()
    if(VULKAN_LIB AND NOT TARGET vulkan)
        add_library(vulkan UNKNOWN IMPORTED)
        set_target_properties(vulkan PROPERTIES IMPORTED_LOCATION "${VULKAN_LIB}")
    endif()
    add_subdirectory("${D2_DXVK_NATIVE_DIR}" "${CMAKE_BINARY_DIR}/dxvk-native" EXCLUDE_FROM_ALL)
    if(NOT TARGET dxvk_d3d9)
        message(FATAL_ERROR "The DXVK Native checkout did not define the dxvk_d3d9 target.")
    endif()
    message(STATUS "DXVK Native D3D9 backend: ${D2_DXVK_NATIVE_DIR}")
else()
    message(STATUS
        "DXVK Native D3D9 backend not configured. Set D2_DXVK_NATIVE_DIR to build it.")
endif()

# Fontes do Host Runtime
set(RUNTIME_SOURCES
    src/main.cpp
    src/platform_bridge.cpp
    src/win32_stubs.cpp
    src/game_image.cpp
    src/rc_runtime.cpp
)

# Definicao da Biblioteca Nativa (.so)
add_library(darksiders2_runtime SHARED ${RUNTIME_SOURCES})

# Mapeamento de dependencias e links
target_link_libraries(darksiders2_runtime PRIVATE SDL2::SDL2)
if(TARGET dxvk_d3d9)
    target_link_libraries(darksiders2_runtime PRIVATE dxvk_d3d9)
    target_compile_definitions(darksiders2_runtime PRIVATE D2_HAS_DXVK_D3D9=1)
    message(STATUS "DXVK Native D3D9 backend linked; guest calls use the Win64 bridge.")
endif()

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
set(D2_DXVK_SO "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/dxvk/libdxvk_d3d11.so")
if(EXISTS "${D2_DXVK_SO}")
    target_compile_definitions(darksiders2_runtime
        PRIVATE D2_DXVK_D3D11_SO="${D2_DXVK_SO}")
    message(STATUS "DXVK: ${D2_DXVK_SO}")
else()
    message(STATUS "DXVK: nao vendorizado (procurado em run time: D2_DXVK / libdxvk_d3d11.so)")
endif()

target_link_libraries(darksiders2_runtime PRIVATE m)

# ---------------------------------------------------------------------------
# Codigo do jogo recompilado (tools/recompiler sobre o executavel do jogador).
#
# Vive em out/ e nao no repositorio: e codigo do jogo. Compilado a -O0 porque
# um ficheiro de 2,4 MB leva 8 s a -O0 e 65 s a -O1; 150 deles a -O1 seriam
# horas. Otimizar vem depois de o jogo correr.
# ---------------------------------------------------------------------------
set(D2_RECOMP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../out/recomp_verified" CACHE PATH
    "Diretorio com OUT.c e OUT_*.c gerados pelo recompiler")

file(GLOB D2_RECOMP_SOURCES CONFIGURE_DEPENDS "${D2_RECOMP_DIR}/OUT_*.c")
if(D2_RECOMP_SOURCES AND EXISTS "${D2_RECOMP_DIR}/OUT.c")
    list(APPEND D2_RECOMP_SOURCES "${D2_RECOMP_DIR}/OUT.c")
    list(LENGTH D2_RECOMP_SOURCES D2_RECOMP_COUNT)
    set_source_files_properties(${D2_RECOMP_SOURCES} PROPERTIES
        LANGUAGE CXX
        COMPILE_OPTIONS "-O0;-w")
    add_library(darksiders2_game STATIC ${D2_RECOMP_SOURCES})
    target_include_directories(darksiders2_game PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(darksiders2_runtime PRIVATE darksiders2_game)
    message(STATUS "Jogo recompilado: ${D2_RECOMP_COUNT} ficheiros de ${D2_RECOMP_DIR}")
else()
    message(STATUS "Sem codigo recompilado em ${D2_RECOMP_DIR}: o APK sai sem o jogo.")
endif()
