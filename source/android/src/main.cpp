#include <SDL.h>
#include "host_runtime.h"
#include "platform_bridge.h"

namespace darksiders2::host {

bool HostRuntime::Initialize(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    LOGI("Inicializando Host Runtime para Darksiders II: Deathinitive Edition...");

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMECONTROLLER | SDL_INIT_AUDIO) < 0) {
        LOGE("Falha ao inicializar SDL2: %s", SDL_GetError());
        return false;
    }

    LOGI("Subssistema SDL2 inicializado com sucesso.");
    m_state = RuntimeState::kRunning;
    return true;
}

void HostRuntime::RunMainLoop() {
    LOGI("Entrando no loop principal da engine...");
    bool quit = false;
    SDL_Event event;

    while (!quit && m_state == RuntimeState::kRunning) {
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) {
                quit = true;
            }
        }
        
        // Render tick & CPU execution stub
        SDL_Delay(16); // Target ~60 FPS idle loop
    }
}

void HostRuntime::Shutdown() {
    LOGI("Encerrando Host Runtime...");
    SDL_Quit();
    m_state = RuntimeState::kShutdown;
}

} // namespace darksiders2::host

// Ponto de entrada compatível com SDL2 Main no Android
int main(int argc, char* argv[]) {
    darksiders2::host::HostRuntime runtime;

    if (!runtime.Initialize(argc, argv)) {
        return -1;
    }

    runtime.RunMainLoop();
    runtime.Shutdown();

    return 0;
}