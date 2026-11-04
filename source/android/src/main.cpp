#include <SDL.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>

#include "host_runtime.h"
#include "platform_bridge.h"
#include "win32_stubs.h"

namespace darksiders2::host {
namespace {

// The one file that proves a directory is the game's data root.
constexpr const char *kGameDataRelative = "media/media.upak";
constexpr const char *kWindowTitle = "Darksiders II: Deathinitive Edition";

bool FileExists(const std::string &path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string Trim(std::string text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }
    return text.substr(begin, end - begin);
}

std::string LowerAscii(std::string text) {
    for (char &c : text) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return text;
}

std::string StripTrailingSlashes(std::string text) {
    while (text.size() > 1 && (text.back() == '/' || text.back() == '\\')) text.pop_back();
    return text;
}

std::string JoinPath(const std::string &dir, const char *name) {
    if (dir.empty()) return name;
    const char last = dir.back();
    return (last == '/' || last == '\\') ? dir + name : dir + "/" + name;
}

// Reads `data_root = <path>` from an ini file. Accepts a few spellings and
// ignores sections and comments; an Android build has no registry to fall back
// on, so the file is the only user-facing override.
std::string ReadConfigDataRoot(const std::string &ini_path) {
    std::FILE *file = std::fopen(ini_path.c_str(), "rb");
    if (file == nullptr) return std::string();

    char line[1024];
    std::string value;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        const std::string text = Trim(line);
        if (text.empty() || text[0] == ';' || text[0] == '#' || text[0] == '[') continue;
        const std::size_t sep = text.find_first_of("=:");
        if (sep == std::string::npos) continue;

        const std::string key = LowerAscii(Trim(text.substr(0, sep)));
        if (key != "data_root" && key != "game_path" && key != "gamedir" && key != "path" &&
            key != "data") {
            continue;
        }
        value = Trim(text.substr(sep + 1));
        if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') &&
            value.back() == value.front()) {
            value = value.substr(1, value.size() - 2);
        }
        break;
    }
    std::fclose(file);
    return StripTrailingSlashes(value);
}

void AddCandidate(std::vector<std::string> *out, const std::string &dir) {
    if (dir.empty()) return;
    const std::string clean = StripTrailingSlashes(dir);
    for (const std::string &existing : *out) {
        if (existing == clean) return;
    }
    out->push_back(clean);
}

std::string AndroidInternalPath() {
#ifdef __ANDROID__
    const char *path = SDL_AndroidGetInternalStoragePath();
    return path != nullptr ? path : std::string();
#else
    return std::string();
#endif
}

std::string AndroidExternalPath() {
#ifdef __ANDROID__
    const char *path = SDL_AndroidGetExternalStoragePath();
    return path != nullptr ? path : std::string();
#else
    return std::string();
#endif
}

}  // namespace

bool HostRuntime::InitDataRoot() {
    const std::string app_dir = AndroidInternalPath();

    // config.ini: first beside the working directory, then in the app's storage.
    std::string configured = ReadConfigDataRoot("config.ini");
    if (configured.empty() && !app_dir.empty()) {
        configured = ReadConfigDataRoot(JoinPath(app_dir, "config.ini"));
    }
    if (!configured.empty()) {
        LOGI("config.ini: data_root = %s", configured.c_str());
    }

    std::vector<std::string> candidates;
    AddCandidate(&candidates, configured);          // explicit override wins
    AddCandidate(&candidates, app_dir);             // SDL's app-private storage
    AddCandidate(&candidates, AndroidExternalPath());
    AddCandidate(&candidates, "/sdcard/Android/data/com.vigil.darksiders2/files");
    AddCandidate(&candidates, "/storage/emulated/0/Android/data/com.vigil.darksiders2/files");
    AddCandidate(&candidates, "/sdcard/Darksiders2");
    AddCandidate(&candidates, "/data/data/com.vigil.darksiders2/files");
    AddCandidate(&candidates, ".");
    AddCandidate(&candidates, "..");

    for (const std::string &dir : candidates) {
        const std::string upak = JoinPath(dir, kGameDataRelative);
        if (!FileExists(upak)) continue;

        win32::SetDataRoot(dir.c_str());
        m_data_root = dir;
        LOGI("Data root encontrado: %s", dir.c_str());
        LOGI("  media.upak: %s", upak.c_str());
        return true;
    }

    LOGE("media/media.upak nao encontrado. Caminhos testados:");
    for (const std::string &dir : candidates) {
        LOGE("  %s", JoinPath(dir, kGameDataRelative).c_str());
    }
    LOGE("Crie um config.ini com 'data_root=<pasta do jogo>' para indicar o caminho.");
    return false;
}

bool HostRuntime::CreateWindow() {
    // Native resolution when the display reports one, 1280x720 otherwise.
    int width = 1280;
    int height = 720;
    SDL_DisplayMode mode;
    if (SDL_GetCurrentDisplayMode(0, &mode) == 0 && mode.w > 0 && mode.h > 0) {
        width = mode.w;
        height = mode.h;
    }

    const Uint32 base = SDL_WINDOW_VULKAN | SDL_WINDOW_SHOWN;
    m_window = SDL_CreateWindow(kWindowTitle, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                width, height, base | SDL_WINDOW_FULLSCREEN);
    if (m_window == nullptr) {
        LOGI("Fullscreen recusado (%s); tentando fullscreen desktop", SDL_GetError());
        m_window = SDL_CreateWindow(kWindowTitle, SDL_WINDOWPOS_CENTERED,
                                    SDL_WINDOWPOS_CENTERED, width, height,
                                    base | SDL_WINDOW_FULLSCREEN_DESKTOP);
    }
    if (m_window == nullptr) {
        LOGI("Fullscreen desktop recusado (%s); usando 1280x720 em janela", SDL_GetError());
        m_window = SDL_CreateWindow(kWindowTitle, SDL_WINDOWPOS_CENTERED,
                                    SDL_WINDOWPOS_CENTERED, 1280, 720, base);
    }
    if (m_window == nullptr) {
        LOGE("SDL_CreateWindow(SDL_WINDOW_VULKAN) falhou: %s", SDL_GetError());
        return false;
    }

    int actual_w = 0;
    int actual_h = 0;
    SDL_GetWindowSize(m_window, &actual_w, &actual_h);
    const bool fullscreen = (SDL_GetWindowFlags(m_window) & SDL_WINDOW_FULLSCREEN) != 0;
    LOGI("Janela Vulkan criada: %dx%d (%s)", actual_w, actual_h,
         fullscreen ? "fullscreen" : "windowed");
    return true;
}

bool HostRuntime::Initialize(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    LOGI("Inicializando Host Runtime para Darksiders II: Deathinitive Edition...");

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_GAMECONTROLLER) < 0) {
        LOGE("Falha ao inicializar SDL2: %s", SDL_GetError());
        return false;
    }
    LOGI("SDL2: video, audio e gamecontroller inicializados.");

#ifdef __ANDROID__
    SDL_SetHint(SDL_HINT_ORIENTATIONS, "LandscapeLeft LandscapeRight");
#endif

    // Camada Win32: liga os imports do executavel aos shims POSIX/Android.
    // O RcApi do recompilador e ligado depois, quando a biblioteca recompilada
    // for carregada (win32::SetRecompApi).
    win32::RegisterBuiltins();
    LOGI("Win32 stubs registrados (kernel32/kernelbase).");

    if (!InitDataRoot()) {
        LOGE("Sem data root: o jogo nao conseguira abrir os assets.");
    }

    if (!CreateWindow()) {
        SDL_Quit();
        return false;
    }

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
            } else if (event.type == SDL_KEYDOWN && event.key.keysym.sym == SDLK_AC_BACK) {
                quit = true;  // Android back button
            }
        }

        // Render tick & CPU execution stub
        SDL_Delay(16);  // Target ~60 FPS idle loop
    }
}

void HostRuntime::Shutdown() {
    LOGI("Encerrando Host Runtime...");
    if (m_window != nullptr) {
        SDL_DestroyWindow(m_window);
        m_window = nullptr;
    }
    win32::Shutdown();  // threads, critical sections, TLS, ficheiros e mapeamentos
    SDL_Quit();
    m_state = RuntimeState::kShutdown;
}

}  // namespace darksiders2::host

// Ponto de entrada compatível com SDL2 Main no Android
// (SDL_main.h renomeia main -> SDL_main; a Activity chama-o)
int main(int argc, char* argv[]) {
    darksiders2::host::HostRuntime runtime;

    if (!runtime.Initialize(argc, argv)) {
        return -1;
    }

    runtime.RunMainLoop();
    runtime.Shutdown();

    return 0;
}
