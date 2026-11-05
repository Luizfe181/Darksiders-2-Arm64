#include <SDL.h>
#include <SDL_vulkan.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <vulkan/vulkan.h>

#include "host_runtime.h"
#include "platform_bridge.h"
#include "render_context.h"
#include "game_image.h"
#include "rc_runtime.h"
#include "win32_stubs.h"

extern const vigil::recomp::RcApi* rc;

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

// Reads `key = value` from an ini file. Android has no registry, so the file is
// the only user-facing override.
std::string ReadConfigValue(const std::string &ini_path, const char *wanted_key) {
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
        if (key != wanted_key) continue;

        value = Trim(text.substr(sep + 1));
        if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') &&
            value.back() == value.front()) {
            value = value.substr(1, value.size() - 2);
        }
        break;
    }
    std::fclose(file);
    return value;
}

// Reads the data root, accepting a few spellings for the same thing.
// (Kept as a helper for callers that only have a path; ConfiguredDataRoot()
// is what the runtime uses because it also checks the app's storage.)

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

// A key from config.ini: the working directory first, then the app's storage.
std::string ConfiguredValue(const char *key) {
    std::string value = ReadConfigValue("config.ini", key);
    if (value.empty()) {
        const std::string app_dir = AndroidInternalPath();
        if (!app_dir.empty()) value = ReadConfigValue(JoinPath(app_dir, "config.ini"), key);
    }
    return value;
}

std::string ConfiguredDataRoot() {
    static const char *const kKeys[] = {"data_root", "game_path", "gamedir", "path", "data"};
    for (const char *key : kKeys) {
        const std::string value = ConfiguredValue(key);
        if (!value.empty()) return StripTrailingSlashes(value);
    }
    return std::string();
}

// VkSurfaceKHR is a pointer on some header configurations and a uint64_t on
// others, so convert through memory instead of assuming either.
std::uint64_t HandleToInteger(VkSurfaceKHR handle) {
    static_assert(sizeof(std::uint64_t) >= sizeof(handle), "handle does not fit");
    std::uint64_t value = 0;
    std::memcpy(&value, &handle, sizeof(handle));
    return value;
}

}  // namespace

bool HostRuntime::InitDataRoot() {
    const std::string app_dir = AndroidInternalPath();
    const std::string configured = ConfiguredDataRoot();
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

bool HostRuntime::CreateVulkanContext() {
    // A custom driver (Mesa Turnip / freedreno) must be installed BEFORE the
    // instance exists, because the loader chooses the ICD at vkCreateInstance.
    //
    // Turnip ships as an ICD, not as a loader: the system libvulkan.so picks it
    // up through VK_ICD_FILENAMES, and SDL is asked to load it directly too for
    // builds that export the whole API. Both are set so either packaging works.
    const std::string custom_driver = ConfiguredValue("custom_driver");
    if (!custom_driver.empty()) {
        if (!FileExists(custom_driver)) {
            LOGE("custom_driver: ficheiro nao encontrado: %s", custom_driver.c_str());
        } else {
            ::setenv("VK_ICD_FILENAMES", custom_driver.c_str(), 1);
            if (SDL_Vulkan_LoadLibrary(custom_driver.c_str()) == 0) {
                m_custom_driver_loaded = true;
                LOGI("Vulkan: driver customizado carregado: %s", custom_driver.c_str());
            } else {
                LOGI("Vulkan: SDL nao carregou %s (%s); a usar o loader do sistema com "
                     "VK_ICD_FILENAMES",
                     custom_driver.c_str(), SDL_GetError());
            }
        }
    }

    // Source of vkCreateInstance: whichever library SDL ended up with, so the
    // instance and the surface always come from the same driver.
    // SDL returns the raw pointer; the loader entry takes (instance, name).
    PFN_vkGetInstanceProcAddr get_proc_addr =
        reinterpret_cast<PFN_vkGetInstanceProcAddr>(SDL_Vulkan_GetVkGetInstanceProcAddr());
    if (get_proc_addr == nullptr) {
        LOGE("SDL_Vulkan_GetVkGetInstanceProcAddr falhou: %s", SDL_GetError());
        return false;
    }
    auto create_instance = reinterpret_cast<PFN_vkCreateInstance>(
        get_proc_addr(VK_NULL_HANDLE, "vkCreateInstance"));
    if (create_instance == nullptr) {
        LOGE("vkCreateInstance indisponivel no driver carregado.");
        return false;
    }

    // 1. Ask SDL which instance extensions its surface needs (surface + the
    //    platform one). This is what makes the window usable as a surface.
    unsigned extension_count = 0;
    if (SDL_Vulkan_GetInstanceExtensions(m_window, &extension_count, nullptr) != SDL_TRUE) {
        LOGE("SDL_Vulkan_GetInstanceExtensions(count) falhou: %s", SDL_GetError());
        return false;
    }
    std::vector<const char *> extensions(extension_count);
    if (SDL_Vulkan_GetInstanceExtensions(m_window, &extension_count, extensions.data()) !=
        SDL_TRUE) {
        LOGE("SDL_Vulkan_GetInstanceExtensions(list) falhou: %s", SDL_GetError());
        return false;
    }

    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = kWindowTitle;
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "Vigil Engine";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_1;

    VkInstanceCreateInfo create_info{};
    create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create_info.pApplicationInfo = &app_info;
    create_info.enabledExtensionCount = extension_count;
    create_info.ppEnabledExtensionNames = extensions.data();

    VkResult result = create_instance(&create_info, nullptr, &m_instance);
    if (result != VK_SUCCESS) {
        LOGE("vkCreateInstance falhou: %d", static_cast<int>(result));
        m_instance = VK_NULL_HANDLE;
        return false;
    }

    // 2. The native surface. DXVK needs this instead of an HWND.
    if (SDL_Vulkan_CreateSurface(m_window, m_instance, &m_surface) != SDL_TRUE) {
        LOGE("SDL_Vulkan_CreateSurface falhou: %s", SDL_GetError());
        vkDestroyInstance(m_instance, nullptr);
        m_instance = VK_NULL_HANDLE;
        return false;
    }

    // 3. Diagnostics: an instance that cannot see a device will fail at the
    //    first real draw, so report it now rather than later.
    std::uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(m_instance, &device_count, nullptr);
    LOGI("Vulkan: %u extensao(oes), %u dispositivo(s)", extension_count, device_count);
    if (device_count > 0) {
        VkPhysicalDevice devices[8] = {};
        std::uint32_t count = device_count < 8 ? device_count : 8;
        if (vkEnumeratePhysicalDevices(m_instance, &count, devices) == VK_SUCCESS && count > 0) {
            VkPhysicalDeviceProperties props{};
            vkGetPhysicalDeviceProperties(devices[0], &props);
            LOGI("Vulkan: GPU 0 = %s (API %u.%u.%u)", props.deviceName,
                 VK_VERSION_MAJOR(props.apiVersion), VK_VERSION_MINOR(props.apiVersion),
                 VK_VERSION_PATCH(props.apiVersion));
        }
    }

    int width = 0;
    int height = 0;
    SDL_GetWindowSize(m_window, &width, &height);
    render::Context context;
    context.instance = m_instance;
    context.surface = m_surface;
    context.width = static_cast<std::uint32_t>(width);
    context.height = static_cast<std::uint32_t>(height);
    render::SetContext(context);

    // Publish it to the Win32 layer too: the D3D11/DXGI shims hand it to DXVK.
    win32::SetRenderingSurface(HandleToInteger(m_surface));
    LOGI("Vulkan: surface conectada ao runtime (%dx%d)", width, height);
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
    win32::SetRenderingWindow(reinterpret_cast<std::uint64_t>(m_window));

    if (!CreateVulkanContext()) {
        LOGE("Vulkan indisponivel: nao ha como apresentar o renderizador.");
        SDL_DestroyWindow(m_window);
        m_window = nullptr;
        SDL_Quit();
        return false;
    }

    // DXVK e opcional. A tela de configuracao pode apontar um .so instalado
    // pelo utilizador (dxvk_library); sem isso o loader procura um empacotado
    // no APK. Sem nenhum, os entry points D3D11 falham de forma limpa.
    const std::string dxvk_path = ConfiguredValue("dxvk_library");
    if (!win32::LoadDxvk(dxvk_path.empty() ? nullptr : dxvk_path.c_str())) {
        if (dxvk_path.empty()) {
            LOGE("DXVK nao encontrado (nem dxvk_library, nem empacotado); D3D11 indisponivel.");
        } else {
            LOGE("DXVK nao carregou de %s; D3D11/DXGI indisponiveis.", dxvk_path.c_str());
        }
    }

    // Codigo do jogo: mapeia o executavel do jogador, liga a IAT aos stubs e
    // arranca o entry point recompilado. Para no primeiro import/instrucao que
    // ainda nao existe, com o offset no log.
    if (!m_data_root.empty()) {
        const std::string exe = m_data_root + "/Darksiders2.exe";
        static vigil::recomp::GameImage image;
        if (!image.Map(exe.c_str())) {
            LOGE("Jogo: nao consegui mapear %s", exe.c_str());
        } else {
            image.PatchImports();
            LOGI("Jogo: imagem em 0x%llx, entry 0x%llx, imports %llu (%llu em falta)",
                 static_cast<unsigned long long>(image.base()),
                 static_cast<unsigned long long>(image.entry()),
                 static_cast<unsigned long long>(image.imports().size()),
                 static_cast<unsigned long long>(image.unresolved()));

            vigil::recomp::InstallRcApi(image.base(), image.size());
            win32::SetRecompApi(rc);
            if (vigil::recomp::InitializeGameLibrary()) {
                vigil::recomp::RunStats stats;
                vigil::recomp::RunGuest(image.entry(), image.base(), &stats);
                LOGI("Jogo: parou — calls=%llu thunks=%llu interp=%llu unhandled=%llu",
                     static_cast<unsigned long long>(stats.calls),
                     static_cast<unsigned long long>(stats.thunk_calls),
                     static_cast<unsigned long long>(stats.interpreted),
                     static_cast<unsigned long long>(stats.unhandled));
            } else {
                LOGE("Jogo: build sem funcoes recompiladas (out/recomp_full vazio).");
            }
        }
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

    // Vulkan objects first: the surface is tied to the window.
    render::SetContext(render::Context{});
    win32::SetRenderingSurface(0);
    if (m_surface != VK_NULL_HANDLE && m_instance != VK_NULL_HANDLE) {
        vkDestroySurfaceKHR(m_instance, m_surface, nullptr);
    }
    m_surface = VK_NULL_HANDLE;
    if (m_instance != VK_NULL_HANDLE) {
        vkDestroyInstance(m_instance, nullptr);
    }
    m_instance = VK_NULL_HANDLE;
    if (m_custom_driver_loaded) {
        SDL_Vulkan_UnloadLibrary();
        m_custom_driver_loaded = false;
    }

    if (m_window != nullptr) {
        win32::SetRenderingWindow(0);
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
