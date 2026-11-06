// win32_stubs.h -- Win32 API shims for the Darksiders II static recompiler.
//
// The guest is a Windows x86-64 PE. Its imports (kernel32, user32, ...)
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
#include <string>

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

    // CreateFile access and disposition
    GENERIC_READ = 0x80000000u,
    GENERIC_WRITE = 0x40000000u,
    CREATE_NEW = 1,
    CREATE_ALWAYS = 2,
    OPEN_EXISTING = 3,
    OPEN_ALWAYS = 4,
    TRUNCATE_EXISTING = 5,

    // SetFilePointer move methods
    FILE_BEGIN = 0,
    FILE_CURRENT = 1,
    FILE_END = 2,

    // GetFileAttributes / WIN32_FIND_DATA
    FILE_ATTRIBUTE_READONLY = 0x00000001,
    FILE_ATTRIBUTE_HIDDEN = 0x00000002,
    FILE_ATTRIBUTE_SYSTEM = 0x00000004,
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
    FILE_ATTRIBUTE_NORMAL = 0x00000080,

    // MapViewOfFile desired access
    FILE_MAP_COPY = 0x0001,
    FILE_MAP_WRITE = 0x0002,
    FILE_MAP_READ = 0x0004,
    FILE_MAP_ALL_ACCESS = 0x000F001F,
};

// INVALID_HANDLE_VALUE is (HANDLE)-1, i.e. all bits set.
inline constexpr std::uint64_t kInvalidHandle = ~0ull;
// GetFileAttributes returns this on failure.
inline constexpr std::uint32_t kInvalidFileAttributes = 0xFFFFFFFFu;

// Windows' fixed layout constants, needed because the guest allocates these
// structs itself and reads them field by field.
inline constexpr std::size_t kMaxPath = 260;
inline constexpr std::size_t kFindDataSize = 0x140;   // sizeof(WIN32_FIND_DATAA) on Win64
inline constexpr std::size_t kFindDataSizeW = 0x250;  // sizeof(WIN32_FIND_DATAW) on Win64
inline constexpr std::size_t kFileAttributeDataSize = 0x34;

// ---------------------------------------------------------------------------
// Virtual file system
//
// The guest passes Windows paths. They are normalised ('\' -> '/'), stripped of
// drive/UNC prefixes, and resolved against the game's data root -- the directory
// that holds media/, maps.upak, etc.
// ---------------------------------------------------------------------------
void SetDataRoot(const char *root);
std::string GetDataRoot();

// The host path a guest path resolves to. Exposed so the runtime can open the
// containers (media.upak) by the same rules the guest's CreateFile uses.
std::string ResolveGuestPath(const char *win_path);

// The SDL window is passed to the D3D9 Native backend as the guest HWND.
void SetRenderingWindow(std::uint64_t sdl_window);

// True when `addr` is in the thunk range.
bool IsThunk(std::uint64_t addr) noexcept;

// The runtime hands us its RcApi before running guest code; CreateThread needs it
// to start a recompiled entry point. May be null (then threads run nothing).
void SetRecompApi(const RcApi *api) noexcept;
const RcApi *GetRecompApi() noexcept;

// ---------------------------------------------------------------------------
// Guest instructions the translator could not emit.
//
// These are not Win32 API shims: they operate on the guest FPU/SSE state. The
// instruction form is what `rc->interp` calls (the generated function resumes
// at the next instruction); the function form is what the dispatcher calls
// when guest code enters the address directly (it must emulate the `ret`).
// ---------------------------------------------------------------------------
void Stub_FloatConverter(CpuContext *c);
void Stub_FloatConverterInstruction(CpuContext *c);

// Binds every built-in shim to a thunk. Idempotent. Call once at startup.
void RegisterBuiltins();

// Resolves "kernel32.dll!VirtualAlloc" style imports. Unknown exports receive a
// generic fallback thunk so the guest never calls an unmapped address.
std::uint64_t ResolveImport(const char *module, const char *name);
std::uint64_t ResolveImportOrdinal(const char *module, std::uint16_t ordinal);

// True when `module` is a module this layer knows (real Windows DLL or a
// virtual one such as kernel32.dll that we answer for).
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
