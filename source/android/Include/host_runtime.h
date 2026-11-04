#pragma once

#include <cstdint>
#include <string>

#include <vulkan/vulkan.h>

// Forward-declared so this header does not drag SDL into everything that
// includes it (win32_stubs, tests).
struct SDL_Window;

namespace darksiders2::host {

enum class RuntimeState {
    kUninitialized,
    kRunning,
    kShutdown
};

class HostRuntime {
public:
    HostRuntime() = default;
    ~HostRuntime() = default;

    bool Initialize(int argc, char* argv[]);
    void RunMainLoop();
    void Shutdown();

    // Finds the directory that holds media/media.upak: a config.ini override
    // first, then the known Android locations. On success it also points the
    // Win32 VFS at it (win32::SetDataRoot).
    bool InitDataRoot();

    const std::string& DataRoot() const { return m_data_root; }

private:
    bool CreateWindow();
    bool CreateVulkanContext();

    RuntimeState m_state{RuntimeState::kUninitialized};
    SDL_Window* m_window{nullptr};
    VkInstance m_instance{VK_NULL_HANDLE};
    VkSurfaceKHR m_surface{VK_NULL_HANDLE};
    bool m_custom_driver_loaded{false};
    std::string m_data_root;
};

}  // namespace darksiders2::host
