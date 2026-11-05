// dxvk_mock.cpp -- a stand-in for libdxvk_d3d11.so, built for arm64 so the
// symbol contract that win32::LoadDxvk() relies on can be checked without a
// full DXVK port. Every entry point below has the signature the shims forward
// to; the real library exports the same names.
#include <cstdint>

extern "C" {

__attribute__((visibility("default"))) std::int32_t D3D11CreateDevice(
    void * /*adapter*/, std::uint32_t /*driverType*/, void * /*software*/,
    std::uint32_t /*flags*/, const std::int32_t * /*featureLevels*/,
    std::uint32_t /*numLevels*/, std::uint32_t /*sdkVersion*/, void ** /*device*/,
    std::int32_t * /*featureLevel*/, void ** /*context*/) {
    return 0;
}

__attribute__((visibility("default"))) std::int32_t D3D11CreateDeviceAndSwapChain(
    void * /*adapter*/, std::uint32_t /*driverType*/, void * /*software*/,
    std::uint32_t /*flags*/, const std::int32_t * /*featureLevels*/,
    std::uint32_t /*numLevels*/, std::uint32_t /*sdkVersion*/, const void * /*desc*/,
    void ** /*swapChain*/, void ** /*device*/, std::int32_t * /*featureLevel*/,
    void ** /*context*/) {
    return 0;
}

__attribute__((visibility("default"))) std::int32_t CreateDXGIFactory(
    const void * /*riid*/, void ** /*factory*/) {
    return 0;
}

// Added by patches/0001-android-external-surface.patch.
__attribute__((visibility("default"))) void dxvk_android_set_surface(
    std::uint64_t /*surface*/) {}
}
