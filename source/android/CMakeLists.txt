cmake_minimum_required(VERSION 3.22.1)
project(darksiders2_host_runtime C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define a arquitetura alvo como ARM64 se compilado via NDK
if(ANDROID)
    add_compile_definitions(ANDROID_NDK)
    add_compile_options(-Wall -Wextra -O3)
endif()

# Inclusão de diretórios de cabeçalhos
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Pacotes e Bibliotecas Base
find_package(SDL2 REQUIRED)
find_library(LOG_LIB log)
find_library(ANDROID_LIB android)

# Fontes do Host Runtime
set(RUNTIME_SOURCES
    src/main.cpp
    src/platform_bridge.cpp
    src/win32_stubs.cpp
)

# Definição da Biblioteca Nativa (.so)
add_library(darksiders2_runtime SHARED ${RUNTIME_SOURCES})

# Mapeamento de dependências e links
target_link_libraries(darksiders2_runtime
    PRIVATE
        SDL2::SDL2
        ${LOG_LIB}
        ${ANDROID_LIB}
)