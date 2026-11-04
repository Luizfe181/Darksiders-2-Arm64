// win32_stubs.h -- Win32 API shims for the Darksiders II static recompiler.
//
// The guest is a Windows x86-64 PE. Its imports (kernel32, user32, d3d11, ...)
// do not exist on Android, so each one is bound to a host function here and the
// call is intercepted by the recompiler runtime.
//
// Two facts shape the whole design:
//
//  1. A Win32 call arrives with its arguments in GUEST registers (Win64 ABI:
//     rcx, rdx, r8, r9, then the stack), not in the ARM64 host ABI. So a stub is
//     not a normal C function: it takes the CpuContext and reads/writes the
//     guest registers itself. `StubFn` below is that shape.
//
//  2. GetProcAddress must return something the GUEST can call. It cannot be a
//     host pointer to libc, because the guest will `call` it. So every stub owns
//     a synthetic guest address ("thunk") in a reserved range, and the runtime
//     maps a call to that address back to the host function. `Dispatch` is that
//     mapping.
//
// Threading note: the guest is x86-64 TSO and the host is ARM64. Every guest
// pointer is a host pointer, so the shims go through recomp::GuestLoad /
// GuestStore for anything the guest can observe, to keep acquire/release.
#pragma once

#include <cstddef>
#include <cstdint>

#include "cpu_context.h"

namespace recomp = vigil::recomp;

namespace darksiders2::win32 {

using recomp::CpuContext;
using recomp::RcApi;

// A Win32 shim: reads its arguments from the guest registers, writes the result
// to guest RAX.
using StubFn = void (*)(CpuContext *c);

// Synthetic guest address space for thunks. Outside any real image (the game is
// based at 0x140000000) and inside the 48-bit user range, so a thunk is never
// confused with game code.
inline constexpr std::uint64_t kThunkBase = 0x00007F00'00000000ull;
inline constexpr std::uint64_t kThunkEnd = 0x00007F00'01000000ull;  // 16 MiB of thunks

// Windows constants the guest passes to us (kept local: no windows.h on Android).
enum : std::uint32_t {
    MEM_COMMIT = 0x00001000,
    MEM_RESERVE = 0x00002000,
    MEM_DECOMMIT = 0x00004000,
    MEM_RELEASE = 0x00008000,
    MEM_FREE = 0x00010000,
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    INFINITE = 0xFFFFFFFFu,
    WAIT_OBJECT_0 = 0x00000000u,
    WAIT_TIMEOUT = 0x00000102u,
    WAIT_FAILED = 0xFFFFFFFFu,
};

// True when `addr` is in the thunk range.
bool IsThunk(std::uint64_t addr) noexcept;

// The runtime hands us its RcApi before running guest code; CreateThread needs it
// to start a recompiled entry point. May be null (then threads run nothing).
void SetRecompApi(const RcApi *api) noexcept;
const RcApi *GetRecompApi() noexcept;

// Binds every built-in shim to a thunk. Idempotent. Call once at startup.
void RegisterBuiltins();

// Resolves "kernel32.dll!VirtualAlloc" style imports. Returns a thunk, or 0 when
// the API is not shimmed yet (the caller should log it and keep the guest
// function on the interpreter).
std::uint64_t ResolveImport(const char *module, const char *name);

// True when `module` is a module this layer knows (real Windows DLL or a
// virtual one such as d3d11.dll that we answer for).
bool HasModule(const char *module);

// Module handle the guest sees for `module` (a stable synthetic base address).
std::uint64_t ModuleBase(const char *module);

// If `thunk` is one of ours, runs the shim against `c` and returns true.
bool Dispatch(CpuContext *c, std::uint64_t thunk);

// Releases guest threads, critical sections and TLS keys.
void Shutdown();

// Diagnostics: imports that were asked for and never found, one line each.
void LogMissingImport(const char *module, const char *name);

}  // namespace darksiders2::win32
