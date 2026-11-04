// win32_stubs_selftest.cpp -- behavioural test of the Win32 shims.
//
// Built as a *static* x86-64 Android binary so it can run on the Linux kernel
// directly (no device, no emulator), and it drives the stubs exactly the way the
// recompiled guest does: arguments in guest registers, result in guest RAX.
//
//   x86_64-linux-android26-clang++ -static -std=c++17 -O1 \
//       -Iinclude tests/win32_stubs_selftest.cpp src/win32_stubs.cpp -llog -o selftest
//   ./selftest
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "win32_stubs.h"

// The static test binary has no liblog.a, so provide the one symbol the shims
// use from it. On a device the real liblog is linked.
#if defined(__ANDROID__)
#include <cstdarg>
extern "C" int __android_log_vprint(int, const char *, const char *fmt, va_list ap) {
    return std::vfprintf(stderr, fmt, ap);
}
#endif

using namespace darksiders2;
using recomp::CpuContext;

static int g_fail = 0;

#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            std::printf("FAIL  %s\n", msg);                 \
            ++g_fail;                                       \
        } else {                                            \
            std::printf("ok    %s\n", msg);                 \
        }                                                   \
    } while (0)

static CpuContext g_ctx;
static std::uint64_t g_stack[64];  // guest stack for shadow space + stack args

static void Reset(std::uint64_t a0 = 0, std::uint64_t a1 = 0, std::uint64_t a2 = 0,
                  std::uint64_t a3 = 0) {
    std::memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.r[recomp::RSP] = reinterpret_cast<std::uint64_t>(g_stack) + 0x100;
    g_ctx.r[recomp::RCX] = a0;
    g_ctx.r[recomp::RDX] = a1;
    g_ctx.r[recomp::R8] = a2;
    g_ctx.r[recomp::R9] = a3;
}

static std::uint64_t Ret() { return g_ctx.r[recomp::RAX]; }

static bool Call(const char *module, const char *name) {
    const std::uint64_t thunk = win32::ResolveImport(module, name);
    if (thunk == 0) {
        std::printf("FAIL  unresolved %s!%s\n", module, name);
        ++g_fail;
        return false;
    }
    return win32::Dispatch(&g_ctx, thunk);
}

static void SetStackArg(int index, std::uint64_t value) {
    // Win64: arg 4 at [rsp+0x28], arg 5 at [rsp+0x30].
    auto *slot = reinterpret_cast<std::uint64_t *>(g_ctx.r[recomp::RSP] + 0x28 + index * 8);
    *slot = value;
}

int main() {
    constexpr const char *K32 = "kernel32.dll";

    win32::RegisterBuiltins();
    std::printf("== module / export resolution ==\n");

    const std::uint64_t va_thunk = win32::ResolveImport(K32, "VirtualAlloc");
    CHECK(va_thunk != 0 && win32::IsThunk(va_thunk), "VirtualAlloc resolves to a thunk");
    CHECK(win32::ResolveImport(K32, "NoSuchApi") == 0, "unknown import resolves to 0");
    CHECK(win32::ResolveImport("kernelbase.dll", "VirtualAlloc") == va_thunk,
          "kernel32/kernelbase aliasing gives the same thunk");

    Reset();
    CHECK(Call(K32, "GetModuleHandleA"), "GetModuleHandleA dispatched");
    const std::uint64_t main_mod = Ret();
    CHECK(main_mod != 0, "GetModuleHandleA(NULL) returns a handle");

    Reset(reinterpret_cast<std::uint64_t>("kernel32.dll"));
    CHECK(Call(K32, "GetModuleHandleA"), "GetModuleHandleA(\"kernel32.dll\")");
    const std::uint64_t k32_mod = Ret();
    CHECK(k32_mod != 0 && k32_mod != main_mod, "kernel32 has its own handle");

    Reset(k32_mod, reinterpret_cast<std::uint64_t>("VirtualAlloc"));
    CHECK(Call(K32, "GetProcAddress"), "GetProcAddress dispatched");
    CHECK(Ret() == va_thunk, "GetProcAddress returns the same thunk");

    // Windows behaviour: the main module has no such export, so this must fail.
    Reset(main_mod, reinterpret_cast<std::uint64_t>("VirtualAlloc"));
    Call(K32, "GetProcAddress");
    CHECK(Ret() == 0, "GetProcAddress on the main exe for a kernel32 API returns 0");

    std::printf("\n== VirtualAlloc / VirtualFree ==\n");

    Reset(0, 0x8000, win32::MEM_COMMIT | win32::MEM_RESERVE, win32::PAGE_READWRITE);
    CHECK(Call(K32, "VirtualAlloc"), "VirtualAlloc dispatched");
    void *p = reinterpret_cast<void *>(Ret());
    CHECK(p != nullptr, "VirtualAlloc returns an address");
    if (p != nullptr) {
        std::memset(p, 0xAB, 0x8000);
        CHECK(static_cast<unsigned char *>(p)[0x7FFF] == 0xAB,
              "committed memory is read/write");
    }

    Reset(0, 0x4000, win32::MEM_RESERVE, win32::PAGE_NOACCESS);
    CHECK(Call(K32, "VirtualAlloc"), "VirtualAlloc(reserve) dispatched");
    void *base = reinterpret_cast<void *>(Ret());
    CHECK(base != nullptr, "reservation returns an address");

    Reset(reinterpret_cast<std::uint64_t>(base), 0x4000, win32::MEM_COMMIT,
          win32::PAGE_READWRITE);
    CHECK(Call(K32, "VirtualAlloc"), "VirtualAlloc(commit over reservation) dispatched");
    CHECK(Ret() == reinterpret_cast<std::uint64_t>(base),
          "commit keeps the reserved base");
    if (base != nullptr) {
        std::memset(base, 0x5A, 0x4000);
        CHECK(static_cast<unsigned char *>(base)[0x3FFF] == 0x5A,
              "reserved-then-committed memory is writable");
    }

    if (p != nullptr) {
        Reset(reinterpret_cast<std::uint64_t>(p), 0, win32::MEM_RELEASE);
        CHECK(Call(K32, "VirtualFree") && Ret() == 1, "VirtualFree(MEM_RELEASE) succeeds");
    }
    if (base != nullptr) {
        Reset(reinterpret_cast<std::uint64_t>(base), 0, win32::MEM_RELEASE);
        CHECK(Call(K32, "VirtualFree") && Ret() == 1, "VirtualFree of the reservation");
    }

    std::printf("\n== critical sections ==\n");
    alignas(16) std::uint64_t cs[8];  // guest passes ~40 bytes; we keep state aside
    Reset(reinterpret_cast<std::uint64_t>(cs));
    Call(K32, "InitializeCriticalSection");

    Reset(reinterpret_cast<std::uint64_t>(cs));
    CHECK(Call(K32, "TryEnterCriticalSection") && Ret() == 1, "TryEnter takes a free lock");

    Reset(reinterpret_cast<std::uint64_t>(cs));
    CHECK(Call(K32, "TryEnterCriticalSection") && Ret() == 1,
          "TryEnter re-enters on the same thread (recursive)");

    Reset(reinterpret_cast<std::uint64_t>(cs));
    CHECK(Call(K32, "LeaveCriticalSection"), "first leave");
    Reset(reinterpret_cast<std::uint64_t>(cs));
    CHECK(Call(K32, "LeaveCriticalSection"), "second leave");

    std::printf("\n== threads ==\n");
    std::uint64_t thread_id = 0;
    Reset();
    SetStackArg(0, 0);                                           // dwCreationFlags
    SetStackArg(1, reinterpret_cast<std::uint64_t>(&thread_id));  // lpThreadId
    CHECK(Call(K32, "CreateThread"), "CreateThread dispatched");
    const std::uint64_t thread = Ret();
    CHECK(thread != 0, "CreateThread returns a handle");
    CHECK(thread_id != 0, "CreateThread writes the thread id");

    if (thread != 0) {
        Reset(thread, 2000);
        CHECK(Call(K32, "WaitForSingleObject") && Ret() == win32::WAIT_OBJECT_0,
              "WaitForSingleObject returns WAIT_OBJECT_0");
        Reset(thread);
        CHECK(Call(K32, "CloseHandle") && Ret() == 1, "CloseHandle joins the thread");
    }

    std::printf("\n== atomics / TLS / time ==\n");
    volatile std::uint32_t counter = 41;
    Reset(reinterpret_cast<std::uint64_t>(&counter));
    CHECK(Call(K32, "InterlockedIncrement") && Ret() == 42, "InterlockedIncrement returns 42");

    Reset(reinterpret_cast<std::uint64_t>(&counter));
    CHECK(Call(K32, "InterlockedDecrement") && Ret() == 41, "InterlockedDecrement returns 41");

    Reset();
    CHECK(Call(K32, "TlsAlloc"), "TlsAlloc");
    const std::uint64_t tls = Ret();
    CHECK(tls != 0xFFFFFFFFu, "TlsAlloc returns a slot");

    Reset(tls, 0x1234);
    Call(K32, "TlsSetValue");
    Reset(tls);
    Call(K32, "TlsGetValue");
    CHECK(Ret() == 0x1234, "TlsSetValue/TlsGetValue round-trip");

    Reset();
    Call(K32, "GetTickCount64");
    CHECK(Ret() > 0, "GetTickCount64 returns a positive tick count");

    win32::Shutdown();
    std::printf("\n%s (%d failure(s))\n", g_fail ? "FAILED" : "ALL PASSED", g_fail);
    return g_fail ? 1 : 0;
}
