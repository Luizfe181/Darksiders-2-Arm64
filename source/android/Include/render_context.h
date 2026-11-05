// render_context.h -- the Vulkan objects the platform layer creates, published
// for anything that needs to draw into the game's window.
//
// main.cpp owns the lifetime: it creates the VkInstance and the VkSurfaceKHR
// from the SDL window and calls SetContext().
#pragma once

#include <cstdint>

#include <vulkan/vulkan.h>

namespace darksiders2::render {

struct Context {
    VkInstance instance = VK_NULL_HANDLE;
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
};

namespace detail {
inline Context &Mutable() {
    static Context context;
    return context;
}
}  // namespace detail

inline void SetContext(const Context &context) { detail::Mutable() = context; }
inline const Context &GetContext() { return detail::Mutable(); }
inline bool IsReady() { return GetContext().instance != VK_NULL_HANDLE; }

}  // namespace darksiders2::render
