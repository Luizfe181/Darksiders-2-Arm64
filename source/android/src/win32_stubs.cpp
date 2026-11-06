// win32_stubs.cpp -- Win32 API shims: Windows -> POSIX/Android.
//
// Every shim reads the Win64 guest ABI itself (rcx, rdx, r8, r9, then the stack
// at [rsp+0x28], [rsp+0x30]) and writes the result to guest RAX. See
// win32_stubs.h for why the stubs are shaped this way.
#include "win32_stubs.h"

#if defined(D2_HAS_DXVK_D3D9)
#include <d3d9.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace darksiders2::win32 {

namespace {

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
void Log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
#if defined(__ANDROID__)
    __android_log_vprint(ANDROID_LOG_INFO, "D2Win32", fmt, ap);
#else
    std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
#endif
    va_end(ap);
}

// ---------------------------------------------------------------------------
// Guest ABI accessors (Win64: rcx, rdx, r8, r9, then stack slots)
// ---------------------------------------------------------------------------
inline std::uint64_t Arg0(CpuContext *c) { return c->r[recomp::RCX]; }
inline std::uint64_t Arg1(CpuContext *c) { return c->r[recomp::RDX]; }
inline std::uint64_t Arg2(CpuContext *c) { return c->r[recomp::R8]; }
inline std::uint64_t Arg3(CpuContext *c) { return c->r[recomp::R9]; }
// Shadow space: 0x08 return address, 0x10..0x27 home area, args from 0x28.
inline std::uint64_t Arg4(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x28);
}
inline std::uint64_t Arg5(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x30);
}
inline std::uint64_t Arg6(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x38);
}
inline void SetRet(CpuContext *c, std::uint64_t v) { c->r[recomp::RAX] = v; }
// HRESULT is 32 bits; the guest reads EAX, so sign-extend for clarity.
inline void SetRet32(CpuContext *c, std::int32_t v) {
    c->r[recomp::RAX] = static_cast<std::uint64_t>(static_cast<std::int64_t>(v));
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
constexpr std::size_t kMaxStubs = 4096;
constexpr std::uint64_t kThunkStride = 0x10;
constexpr std::uint64_t kModuleBaseStart = 0x00007F01'00000000ull;

std::mutex g_registry_mutex;
std::unordered_map<std::string, std::uint64_t> g_exports;  // "mod!fn" -> thunk
std::unordered_map<std::string, std::uint64_t> g_module_base;
std::unordered_map<std::uint64_t, std::string> g_module_name;
StubFn g_slot_table[kMaxStubs] = {};   // filled before any guest thread starts
// Names for tracing: an import is "module/name", a COM method "Interface/name".
std::string g_slot_owner[kMaxStubs];
std::string g_slot_name[kMaxStubs];
std::int32_t g_crt_fmode = 0;
std::int32_t g_crt_commode = 0;
std::atomic<std::uint64_t> g_unhandled_exception_filter{0};
// Which thunk is running. Dispatch sets it, so one generic handler can serve
// every slot; thread-local because guest threads run concurrently.
thread_local std::uint64_t g_active_thunk = 0;
std::uint64_t g_next_thunk = kThunkBase;
std::uint32_t g_next_module = 0;

const RcApi *g_api = nullptr;

std::string Lower(std::string s) {
    for (char &ch : s) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return s;
}
std::string Key(const char *module, const char *name) {
    return Lower(module ? module : "") + "!" + (name ? name : "");
}
std::string OrdinalKey(const char *module, std::uint16_t ordinal) {
    return Lower(module ? module : "") + "!#ordinal:" + std::to_string(ordinal);
}
bool ParseOrdinalName(const char *name, std::uint16_t &ordinal) {
    constexpr char kPrefix[] = "Ordinal_";
    if (name == nullptr || std::strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0 ||
        name[sizeof(kPrefix) - 1] == '\0') {
        return false;
    }
    std::uint32_t value = 0;
    for (const char *p = name + sizeof(kPrefix) - 1; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
        value = value * 10 + static_cast<std::uint32_t>(*p - '0');
        if (value > UINT16_MAX) return false;
    }
    ordinal = static_cast<std::uint16_t>(value);
    return true;
}
const char *OrdinalExportName(const char *module, std::uint16_t ordinal) {
    struct OrdinalExport {
        const char *module;
        std::uint16_t ordinal;
        const char *name;
    };
    static constexpr OrdinalExport kOrdinalExports[] = {
        {"xinput1_3.dll", 2, "XInputGetState"},
        {"xinput1_3.dll", 3, "XInputSetState"},
        {"xinput1_3.dll", 4, "XInputGetCapabilities"},
        {"ws2_32.dll", 1, "accept"},
        {"ws2_32.dll", 2, "bind"},
        {"ws2_32.dll", 3, "closesocket"},
        {"ws2_32.dll", 4, "connect"},
        {"ws2_32.dll", 6, "getsockname"},
        {"ws2_32.dll", 9, "htons"},
        {"ws2_32.dll", 10, "ioctlsocket"},
        {"ws2_32.dll", 13, "listen"},
        {"ws2_32.dll", 15, "ntohs"},
        {"ws2_32.dll", 16, "recv"},
        {"ws2_32.dll", 18, "select"},
        {"ws2_32.dll", 19, "send"},
        {"ws2_32.dll", 21, "setsockopt"},
        {"ws2_32.dll", 57, "gethostname"},
        {"ws2_32.dll", 111, "WSAGetLastError"},
        {"ws2_32.dll", 115, "WSAStartup"},
        {"ws2_32.dll", 151, "__WSAFDIsSet"},
        {"oleaut32.dll", 2, "SysAllocString"},
        {"oleaut32.dll", 6, "SysFreeString"},
    };
    const std::string mod = Lower(module ? module : "");
    for (const OrdinalExport &entry : kOrdinalExports) {
        if (mod == entry.module && ordinal == entry.ordinal) return entry.name;
    }
    return nullptr;
}

std::uint64_t AddStub(const char *module, const char *name, StubFn fn) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    const std::string key = Key(module, name);
    auto it = g_exports.find(key);
    if (it != g_exports.end()) return it->second;

    if ((g_next_thunk - kThunkBase) / kThunkStride >= kMaxStubs) {
        Log("[win32] thunk table full, dropping %s!%s", module, name);
        return 0;
    }
    const std::uint64_t thunk = g_next_thunk;
    g_next_thunk += kThunkStride;
    g_slot_table[(thunk - kThunkBase) / kThunkStride] = fn;
    g_slot_owner[(thunk - kThunkBase) / kThunkStride] = module;
    g_slot_name[(thunk - kThunkBase) / kThunkStride] = name;
    g_exports[key] = thunk;

    const std::string mod = Lower(module);
    if (!g_module_base.count(mod)) {
        const std::uint64_t base = kModuleBaseStart + (g_next_module++ * 0x100000ull);
        g_module_base[mod] = base;
        g_module_name[base] = mod;
    }
    return thunk;
}

// ---------------------------------------------------------------------------
// Memory: VirtualAlloc / VirtualFree / VirtualProtect
// ---------------------------------------------------------------------------
constexpr std::size_t kPage = 4096;
// Windows reserves in 64 KiB units; Android only needs page alignment, but the
// constant documents the guest's expectation for callers that pass a hint.
constexpr std::size_t kGranularity = 64 * 1024;
static_assert(kGranularity % kPage == 0, "granularity must be a page multiple");

inline std::size_t RoundUp(std::size_t v, std::size_t a) { return (v + a - 1) & ~(a - 1); }

struct Region {
    std::size_t size;
    std::uint32_t prot;
};

std::mutex g_region_mutex;
std::unordered_map<std::uintptr_t, Region> g_regions;

int ProtToMmap(std::uint32_t prot) {
    switch (prot & 0xFFu) {
        case PAGE_NOACCESS: return PROT_NONE;
        case PAGE_READONLY: return PROT_READ;
        case PAGE_READWRITE:
        case PAGE_WRITECOPY: return PROT_READ | PROT_WRITE;
        case PAGE_EXECUTE: return PROT_EXEC;
        case PAGE_EXECUTE_READ: return PROT_EXEC | PROT_READ;
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY: return PROT_EXEC | PROT_READ | PROT_WRITE;
        default: return PROT_READ | PROT_WRITE;
    }
}

void *Impl_VirtualAlloc(void *addr, std::size_t size, std::uint32_t type, std::uint32_t prot) {
    if (size == 0 || (type & MEM_RELEASE)) return nullptr;
    const std::size_t len = RoundUp(size, kPage);

    // MEM_COMMIT over an existing reservation: just change the protection.
    if ((type & MEM_COMMIT) && !(type & MEM_RESERVE)) {
        std::lock_guard<std::mutex> lock(g_region_mutex);
        auto it = g_regions.find(reinterpret_cast<std::uintptr_t>(addr) & ~(kPage - 1));
        if (it != g_regions.end()) {
            if (mprotect(reinterpret_cast<void *>(it->first), len, ProtToMmap(prot)) != 0) {
                return nullptr;
            }
            it->second.prot = prot;
            return reinterpret_cast<void *>(it->first);
        }
        // Not a reservation we know: fall through and map it fresh.
    }

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(MAP_FIXED_NOREPLACE)
    if (addr != nullptr && (type & MEM_RESERVE)) flags |= MAP_FIXED_NOREPLACE;
#endif
    const int mmap_prot = (type & MEM_COMMIT) ? ProtToMmap(prot) : PROT_NONE;
    void *p = mmap(addr, len, mmap_prot, flags, -1, 0);
    if (p == MAP_FAILED) {
        Log("[win32] VirtualAlloc(0x%zx, 0x%zx, 0x%x) failed: %s", size, len, type,
            std::strerror(errno));
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(g_region_mutex);
        g_regions[reinterpret_cast<std::uintptr_t>(p)] = Region{len, prot};
    }
    return p;
}

std::uint32_t Impl_VirtualFree(void *addr, std::size_t size, std::uint32_t type) {
    if (addr == nullptr) return 0;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(addr);

    if (type & MEM_RELEASE) {
        std::size_t len = 0;
        {
            std::lock_guard<std::mutex> lock(g_region_mutex);
            auto it = g_regions.find(base);
            if (it == g_regions.end()) return 0;
            len = it->second.size;
            g_regions.erase(it);
        }
        return munmap(reinterpret_cast<void *>(base), len) == 0 ? 1u : 0u;
    }

    if (type & MEM_DECOMMIT) {
        std::lock_guard<std::mutex> lock(g_region_mutex);
        auto it = g_regions.find(base);
        if (it == g_regions.end()) return 0;
        const std::size_t len = size ? RoundUp(size, kPage) : it->second.size;
        return mprotect(reinterpret_cast<void *>(base), len, PROT_NONE) == 0 ? 1u : 0u;
    }
    return 0;
}

std::uint32_t Impl_VirtualProtect(void *addr, std::size_t size, std::uint32_t prot,
                                  std::uint64_t old_prot_out) {
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(addr) & ~(kPage - 1);
    const std::size_t len = RoundUp(size, kPage);
    std::uint32_t old = 0;
    {
        std::lock_guard<std::mutex> lock(g_region_mutex);
        auto it = g_regions.find(base);
        if (it != g_regions.end()) old = it->second.prot;
        if (mprotect(reinterpret_cast<void *>(base), len, ProtToMmap(prot)) != 0) return 0;
        if (it != g_regions.end()) it->second.prot = prot;
    }
    if (old_prot_out != 0) recomp::GuestStore<std::uint32_t>(old_prot_out, old);
    return 1;
}

// ---------------------------------------------------------------------------
// Modules: GetModuleHandleA / LoadLibraryA / GetProcAddress
// ---------------------------------------------------------------------------
std::uint64_t ModuleBaseLocked(const std::string &mod, bool create) {
    auto it = g_module_base.find(mod);
    if (it != g_module_base.end()) return it->second;
    if (!create) return 0;
    const std::uint64_t base = kModuleBaseStart + (g_next_module++ * 0x100000ull);
    g_module_base[mod] = base;
    g_module_name[base] = mod;
    return base;
}

std::uint64_t Impl_GetModuleHandle(const char *name) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    if (name == nullptr || name[0] == '\0') {
        return g_api ? g_api->image_base : ModuleBaseLocked("darksiders2.exe", true);
    }
    return ModuleBaseLocked(Lower(name), true);
}

std::uint64_t Impl_GetProcAddress(std::uint64_t module, const char *name) {
    if (name == nullptr) return 0;
    const std::uintptr_t proc = reinterpret_cast<std::uintptr_t>(name);
    const bool by_ordinal = (proc >> 16) == 0;

    std::string mod;
    {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        auto it = g_module_name.find(module);
        mod = (it != g_module_name.end()) ? it->second : std::string();
    }
    if (mod.empty()) return 0;

    if (by_ordinal) {
        const auto ordinal = static_cast<std::uint16_t>(proc);
        const std::uint64_t thunk = ResolveImportOrdinal(mod.c_str(), ordinal);
        if (thunk == 0) {
            Log("[win32] unresolved ordinal %u in %s", ordinal, mod.c_str());
        }
        return thunk;
    }

    const std::uint64_t thunk = ResolveImport(mod.c_str(), name);
    if (thunk == 0) LogMissingImport(mod.c_str(), name);
    return thunk;
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------
constexpr std::uint64_t kThreadReturnSentinel = kThunkBase - 0x10;
constexpr std::size_t kDefaultStack = 1u << 20;  // 1 MiB

struct GuestThread {
    std::uint32_t magic;
    pthread_t tid;
    CpuContext ctx;
    void *stack;
    std::size_t stack_size;
    std::uint64_t start;
    std::uint64_t param;
    std::uint32_t exit_code;
    std::mutex m;
    std::condition_variable cv;
    bool done;
    bool joined;
};

constexpr std::uint32_t kThreadMagic = 0x54485244u;  // 'THRD'

// Handles are host pointers, but a handle value that did not come from us must
// never be dereferenced: the kind is looked up in this registry first.
enum class HandleKind : std::uint32_t {
    kThread = 1,
    kFile = 2,
    kFileMapping = 3,
    kFileView = 4,
    kFind = 5,
};

std::mutex g_handle_mutex;
std::unordered_map<std::uint64_t, HandleKind> g_handles;

void RegisterHandle(std::uint64_t handle, HandleKind kind) {
    std::lock_guard<std::mutex> lock(g_handle_mutex);
    g_handles[handle] = kind;
}

bool HandleKindOf(std::uint64_t handle, HandleKind *kind) {
    std::lock_guard<std::mutex> lock(g_handle_mutex);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) return false;
    *kind = it->second;
    return true;
}

bool TakeHandle(std::uint64_t handle, HandleKind *kind) {
    std::lock_guard<std::mutex> lock(g_handle_mutex);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) return false;
    *kind = it->second;
    g_handles.erase(it);
    return true;
}

// An open guest file. The handle the guest sees is a pointer to this, never a
// bare fd: fd numbers are small integers and would collide with NULL/thread
// handles, and a closed fd could be reused behind the guest's back.
struct GuestFile {
    std::uint32_t magic;
    int fd;
};
constexpr std::uint32_t kFileMagic = 0x46494C45u;  // 'FILE'

// A section object. Windows maps lazily: CreateFileMapping only describes the
// mapping, MapViewOfFile is what actually calls mmap.
struct GuestMapping {
    std::uint32_t magic;
    int fd;                 // -1 for a pagefile-backed (anonymous) mapping
    std::uint64_t size;     // bytes
    std::uint32_t protect;  // PAGE_*
};
constexpr std::uint32_t kMappingMagic = 0x4D415000u;  // 'MAP\0'

// A view is addressed by the guest as the pointer MapViewOfFile returned, so the
// handle value IS the address; the length and the real mmap base live here.
struct ViewInfo {
    std::uint64_t mmap_base;
    std::size_t length;
};
std::mutex g_view_mutex;
std::unordered_map<std::uint64_t, ViewInfo> g_views;

// An open directory scan (FindFirstFile / FindNextFile).
struct GuestFind {
    std::uint32_t magic;
    DIR *dir;
    std::string dir_path;
    std::string pattern;
    bool wide;  // fills WIN32_FIND_DATAW (0x250) instead of ...A (0x140)
};
constexpr std::uint32_t kFindMagic = 0x464E4400u;  // 'FND\0'

// Guest memory writes for the fixed-layout structs Windows defines.
inline void Put32(std::uint64_t at, std::uint32_t v) {
    recomp::GuestStore<std::uint32_t>(at, v);
}
inline void Put64(std::uint64_t at, std::uint64_t v) {
    recomp::GuestStore<std::uint64_t>(at, v);
}
void GuestWrite(std::uint64_t at, const void *src, std::size_t n) {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    std::memcpy(reinterpret_cast<void *>(at), src, n);
}

void *ThreadMain(void *arg) {
    GuestThread *t = static_cast<GuestThread *>(arg);
    const RcApi *api = GetRecompApi();
    if (api != nullptr && t->start != 0) {
        recomp::InitializeGuestTeb(
            t->ctx, reinterpret_cast<std::uint64_t>(t->stack) + t->stack_size);
        api->call(&t->ctx, t->start, kThreadReturnSentinel);
        t->exit_code = static_cast<std::uint32_t>(t->ctx.r[recomp::RAX]);
    }
    {
        std::lock_guard<std::mutex> lock(t->m);
        t->done = true;
    }
    t->cv.notify_all();
    return nullptr;
}

std::uint64_t Impl_CreateThread(std::uint64_t /*attr*/, std::uint64_t stack_size,
                                std::uint64_t start, std::uint64_t param,
                                std::uint32_t /*flags*/, std::uint64_t thread_id_out) {
    const std::size_t size = stack_size ? static_cast<std::size_t>(stack_size) : kDefaultStack;
    void *stack = mmap(nullptr, RoundUp(size, kPage), PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        Log("[win32] CreateThread: stack mmap failed");
        return 0;
    }

    auto *t = new GuestThread{};
    t->magic = kThreadMagic;
    t->stack = stack;
    t->stack_size = RoundUp(size, kPage);
    t->start = start;
    t->param = param;

    // Win64 entry: rcx = parameter, rsp 16-byte aligned with the shadow space.
    t->ctx.r[recomp::RCX] = param;
    t->ctx.r[recomp::RSP] = reinterpret_cast<std::uint64_t>(stack) + t->stack_size - 0x40;

    if (pthread_create(&t->tid, nullptr, ThreadMain, t) != 0) {
        Log("[win32] CreateThread: pthread_create failed");
        munmap(stack, t->stack_size);
        delete t;
        return 0;
    }

    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(t);
    RegisterHandle(handle, HandleKind::kThread);
    if (thread_id_out != 0) {
        recomp::GuestStore<std::uint32_t>(thread_id_out,
                                          static_cast<std::uint32_t>(t->tid));
    }
    return handle;
}

std::uint32_t Impl_WaitForSingleObject(std::uint64_t handle, std::uint32_t ms) {
    HandleKind kind;
    if (!HandleKindOf(handle, &kind)) return WAIT_FAILED;
    if (kind == HandleKind::kFile) return WAIT_OBJECT_0;  // synchronous file: always ready

    auto *t = reinterpret_cast<GuestThread *>(handle);
    if (t == nullptr || t->magic != kThreadMagic) return WAIT_FAILED;
    std::unique_lock<std::mutex> lock(t->m);
    if (ms == INFINITE) {
        t->cv.wait(lock, [t] { return t->done; });
        return WAIT_OBJECT_0;
    }
    if (!t->cv.wait_for(lock, std::chrono::milliseconds(ms), [t] { return t->done; })) {
        return WAIT_TIMEOUT;
    }
    return WAIT_OBJECT_0;
}

std::uint32_t Impl_CloseHandle(std::uint64_t handle) {
    HandleKind kind;
    if (!TakeHandle(handle, &kind)) return 1;  // not one of ours: pretend success

    switch (kind) {
        case HandleKind::kThread: {
            auto *t = reinterpret_cast<GuestThread *>(handle);
            pthread_join(t->tid, nullptr);
            munmap(t->stack, t->stack_size);
            t->magic = 0;
            delete t;
            return 1;
        }
        case HandleKind::kFile: {
            auto *f = reinterpret_cast<GuestFile *>(handle);
            if (f == nullptr) return 1;
            const int rc = ::close(f->fd);
            f->magic = 0;
            delete f;
            return rc == 0 ? 1u : 0u;
        }
        case HandleKind::kFileMapping: {
            // The fd belongs to the GuestFile handle, not to the mapping: the
            // section object only borrows it. Closing it here would break the
            // guest's file handle.
            auto *m = reinterpret_cast<GuestMapping *>(handle);
            if (m != nullptr) {
                m->magic = 0;
                delete m;
            }
            return 1;
        }
        case HandleKind::kFileView: {
            ViewInfo info{0, 0};
            {
                std::lock_guard<std::mutex> lock(g_view_mutex);
                auto it = g_views.find(handle);
                if (it != g_views.end()) {
                    info = it->second;
                    g_views.erase(it);
                }
            }
            if (info.length == 0) return 1;
            return munmap(reinterpret_cast<void *>(info.mmap_base), info.length) == 0 ? 1u : 0u;
        }
        case HandleKind::kFind: {
            auto *scan = reinterpret_cast<GuestFind *>(handle);
            if (scan != nullptr) {
                if (scan->dir != nullptr) ::closedir(scan->dir);
                scan->magic = 0;
                delete scan;
            }
            return 1;
        }
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Files and the virtual file system
//
// The guest thinks in Windows paths. They are normalised here, stripped of the
// things Windows adds and Android has no notion of (drive letters, \\?\ and
// \\.\ prefixes), and resolved against the game's data root. Windows paths are
// also case-insensitive, which POSIX is not, so an open that fails is retried
// with the path lowercased before giving up.
// ---------------------------------------------------------------------------
std::mutex g_path_mutex;
std::string g_data_root;

std::string LowerAscii(std::string s) {
    for (char &c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string NormalizeWinPath(const std::string &in) {
    std::string p = in;
    for (char &c : p) {
        if (c == '\\') c = '/';
    }
    if (p.rfind("//?/", 0) == 0) p.erase(0, 4);
    else if (p.rfind("//./", 0) == 0) p.erase(0, 4);
    // "C:foo" -> "foo": the drive has no meaning on Android.
    if (p.size() >= 2 && p[1] == ':' && std::isalpha(static_cast<unsigned char>(p[0]))) {
        p.erase(0, 2);
    }
    while (!p.empty() && p[0] == '/') p.erase(0, 1);
    return p;
}

std::string EffectiveRoot() {
    {
        std::lock_guard<std::mutex> lock(g_path_mutex);
        if (!g_data_root.empty()) return g_data_root;
    }
    if (const char *env = std::getenv("D2_DATA_ROOT")) {
        if (env[0] != '\0') return NormalizeWinPath(env);
    }
    static const char *const kCandidates[] = {
        "/sdcard/files",
        "/storage/emulated/0/files",
        "/data/data/com.vigil.darksiders2/files",
        "/sdcard/Android/data/com.vigil.darksiders2/files",
        ".",
    };
    for (const char *candidate : kCandidates) {
        if (::access(candidate, R_OK) == 0) return candidate;
    }
    return ".";
}

int OpenGuestPath(const char *win_path, int flags, mode_t mode) {
    const std::string path = ResolveGuestPath(win_path);
    int fd = ::open(path.c_str(), flags, mode);
    if (fd < 0) {
        const std::string lower = LowerAscii(path);
        if (lower != path) fd = ::open(lower.c_str(), flags, mode);
    }
    if (fd < 0) {
        Log("[win32] open failed: %s (guest said \"%s\")", path.c_str(),
            win_path ? win_path : "?");
    }
    return fd;
}

GuestFile *AsFile(std::uint64_t handle) {
    HandleKind kind;
    if (!HandleKindOf(handle, &kind) || kind != HandleKind::kFile) return nullptr;
    auto *f = reinterpret_cast<GuestFile *>(handle);
    return (f != nullptr && f->magic == kFileMagic) ? f : nullptr;
}

std::uint64_t Impl_CreateFile(const char *path, std::uint32_t access, std::uint64_t /*share*/,
                              std::uint64_t /*security*/, std::uint32_t disposition,
                              std::uint32_t /*attrs*/, std::uint64_t /*template*/) {
    if (path == nullptr) return kInvalidHandle;

    int flags = 0;
    const bool rd = (access & GENERIC_READ) != 0;
    const bool wr = (access & GENERIC_WRITE) != 0;
    if (rd && wr) flags |= O_RDWR;
    else if (wr) flags |= O_WRONLY;
    else flags |= O_RDONLY;

    switch (disposition) {
        case CREATE_NEW: flags |= O_CREAT | O_EXCL; break;
        case CREATE_ALWAYS: flags |= O_CREAT | O_TRUNC; break;
        case OPEN_EXISTING: break;
        case OPEN_ALWAYS: flags |= O_CREAT; break;
        case TRUNCATE_EXISTING: flags |= O_TRUNC; break;
        default: break;
    }
    flags |= O_CLOEXEC;

    const int fd = OpenGuestPath(path, flags, 0644);
    if (fd < 0) return kInvalidHandle;

    auto *f = new GuestFile{kFileMagic, fd};
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(f);
    RegisterHandle(handle, HandleKind::kFile);
    return handle;
}

std::uint32_t Impl_ReadFile(std::uint64_t handle, std::uint64_t buffer, std::uint32_t count,
                            std::uint64_t read_out, std::uint64_t /*overlapped*/) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0;
    const ssize_t got = ::read(f->fd, reinterpret_cast<void *>(buffer), count);
    if (read_out != 0) {
        recomp::GuestStore<std::uint32_t>(
            read_out, got > 0 ? static_cast<std::uint32_t>(got) : 0u);
    }
    return got >= 0 ? 1u : 0u;
}

std::uint32_t Impl_WriteFile(std::uint64_t handle, std::uint64_t buffer, std::uint32_t count,
                             std::uint64_t written_out, std::uint64_t /*overlapped*/) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0;
    const ssize_t put = ::write(f->fd, reinterpret_cast<const void *>(buffer), count);
    if (written_out != 0) {
        recomp::GuestStore<std::uint32_t>(
            written_out, put > 0 ? static_cast<std::uint32_t>(put) : 0u);
    }
    return put >= 0 ? 1u : 0u;
}

std::uint32_t Impl_SetFilePointer(std::uint64_t handle, std::uint32_t dist_low,
                                  std::uint64_t dist_high_out, std::uint32_t method) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0xFFFFFFFFu;

    std::int64_t distance = static_cast<std::int64_t>(static_cast<std::int32_t>(dist_low));
    if (dist_high_out != 0) {
        distance |= static_cast<std::int64_t>(recomp::GuestLoad<std::uint32_t>(dist_high_out))
                    << 32;
    }
    const int whence = method == FILE_CURRENT ? SEEK_CUR : method == FILE_END ? SEEK_END : SEEK_SET;
    const off64_t pos = ::lseek64(f->fd, static_cast<off64_t>(distance), whence);
    if (pos < 0) return 0xFFFFFFFFu;
    if (dist_high_out != 0) {
        recomp::GuestStore<std::uint32_t>(dist_high_out,
                                          static_cast<std::uint32_t>(
                                              static_cast<std::uint64_t>(pos) >> 32));
    }
    return static_cast<std::uint32_t>(static_cast<std::uint64_t>(pos) & 0xFFFFFFFFull);
}

std::uint32_t Impl_SetFilePointerEx(std::uint64_t handle, std::int64_t distance,
                                    std::uint64_t new_pos_out, std::uint32_t method) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0;
    const int whence = method == FILE_CURRENT ? SEEK_CUR : method == FILE_END ? SEEK_END : SEEK_SET;
    const off64_t pos = ::lseek64(f->fd, static_cast<off64_t>(distance), whence);
    if (pos < 0) return 0;
    if (new_pos_out != 0) {
        recomp::GuestStore<std::uint64_t>(new_pos_out, static_cast<std::uint64_t>(pos));
    }
    return 1;
}

std::uint32_t Impl_GetFileSizeEx(std::uint64_t handle, std::uint64_t size_out) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0;
    struct stat st {};
    if (::fstat(f->fd, &st) != 0) return 0;
    if (size_out != 0) {
        recomp::GuestStore<std::uint64_t>(size_out, static_cast<std::uint64_t>(st.st_size));
    }
    return 1;
}

std::uint32_t Impl_GetFileSize(std::uint64_t handle, std::uint64_t high_out) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0xFFFFFFFFu;
    struct stat st {};
    if (::fstat(f->fd, &st) != 0) return 0xFFFFFFFFu;
    const std::uint64_t size = static_cast<std::uint64_t>(st.st_size);
    if (high_out != 0) {
        recomp::GuestStore<std::uint32_t>(high_out, static_cast<std::uint32_t>(size >> 32));
    }
    return static_cast<std::uint32_t>(size & 0xFFFFFFFFull);
}

// UTF-16 (Windows wide string) -> UTF-8, for CreateFileW.
std::string Utf16ToUtf8(const std::uint16_t *w) {
    std::string out;
    if (w == nullptr) return out;
    for (std::size_t i = 0; w[i] != 0; ++i) {
        std::uint32_t cp = w[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && w[i + 1] >= 0xDC00 && w[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (w[++i] - 0xDC00);
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// File mapping: the guest maps the .upak containers instead of reading them.
//
// Windows splits this in two calls and POSIX in one, so the split is kept:
// CreateFileMapping only records the file and the size, MapViewOfFile is what
// actually maps. The view handle the guest holds is the address mmap returned
// (plus any page-alignment delta), because that is the pointer it will pass back
// to UnmapViewOfFile.
// ---------------------------------------------------------------------------
std::uint64_t Impl_CreateFileMapping(std::uint64_t file_handle, std::uint32_t protect,
                                     std::uint32_t size_high, std::uint32_t size_low,
                                     const char * /*name*/) {
    int fd = -1;
    std::uint64_t size = (static_cast<std::uint64_t>(size_high) << 32) | size_low;

    if (file_handle == kInvalidHandle) {
        // Pagefile-backed mapping: no file at all.
        if (size == 0) return kInvalidHandle;
    } else {
        GuestFile *file = AsFile(file_handle);
        if (file == nullptr) return kInvalidHandle;
        fd = file->fd;

        struct stat st {};
        if (::fstat(fd, &st) != 0) return kInvalidHandle;
        const std::uint64_t current = static_cast<std::uint64_t>(st.st_size);
        if (size == 0) size = current;

        // Windows extends the file when a section larger than it is committed;
        // POSIX would SIGBUS on the first touched page past EOF instead.
        const bool writable = protect == PAGE_READWRITE || protect == PAGE_EXECUTE_READWRITE ||
                              protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_WRITECOPY;
        if (writable && size > current) {
            if (::ftruncate64(fd, static_cast<off64_t>(size)) != 0) {
                Log("[win32] CreateFileMapping: ftruncate to 0x%llx failed: %s",
                    static_cast<unsigned long long>(size), std::strerror(errno));
                return kInvalidHandle;
            }
        }
    }
    if (size == 0) return kInvalidHandle;

    auto *m = new GuestMapping{kMappingMagic, fd, size, protect};
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(m);
    RegisterHandle(handle, HandleKind::kFileMapping);
    return handle;
}

std::uint64_t Impl_MapViewOfFile(std::uint64_t mapping_handle, std::uint32_t access,
                                 std::uint32_t off_high, std::uint32_t off_low,
                                 std::uint64_t length) {
    HandleKind kind;
    if (!HandleKindOf(mapping_handle, &kind) || kind != HandleKind::kFileMapping) return 0;
    auto *m = reinterpret_cast<GuestMapping *>(mapping_handle);
    if (m == nullptr || m->magic != kMappingMagic) return 0;

    const std::uint64_t offset = (static_cast<std::uint64_t>(off_high) << 32) | off_low;
    if (offset >= m->size) return 0;

    std::size_t len = length != 0 ? static_cast<std::size_t>(length)
                                  : static_cast<std::size_t>(m->size - offset);
    if (offset + len > m->size) len = static_cast<std::size_t>(m->size - offset);
    if (len == 0) return 0;

    // FILE_MAP_ALL_ACCESS is a *combination* that contains FILE_MAP_READ, so it
    // must not be tested as a bit: only WRITE and COPY imply a writable view.
    const bool writable = (access & (FILE_MAP_WRITE | FILE_MAP_COPY)) != 0;
    const int prot = writable ? (PROT_READ | PROT_WRITE) : PROT_READ;
    // FILE_MAP_COPY is copy-on-write: MAP_PRIVATE, everything else shared.
    const int flags = (access & FILE_MAP_COPY) ? MAP_PRIVATE : MAP_SHARED;

    // Windows hands out 64 KiB-aligned offsets, which are page-aligned, but stay
    // correct if one is not: map from the page and bias the returned pointer.
    const std::uint64_t aligned = offset & ~static_cast<std::uint64_t>(kPage - 1);
    const std::size_t delta = static_cast<std::size_t>(offset - aligned);
    const std::size_t map_len = len + delta;

    void *base = nullptr;
    if (m->fd < 0) {
        base = mmap(nullptr, map_len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        base = mmap(nullptr, map_len, prot, flags, m->fd, static_cast<off_t>(aligned));
    }
    if (base == MAP_FAILED) {
        Log("[win32] MapViewOfFile(0x%llx, len 0x%zx, off 0x%llx) failed: %s",
            static_cast<unsigned long long>(m->size), map_len,
            static_cast<unsigned long long>(offset), std::strerror(errno));
        return 0;
    }

    const std::uint64_t guest_base = reinterpret_cast<std::uint64_t>(base) + delta;
    {
        std::lock_guard<std::mutex> lock(g_view_mutex);
        g_views[guest_base] = ViewInfo{reinterpret_cast<std::uint64_t>(base), map_len};
    }
    RegisterHandle(guest_base, HandleKind::kFileView);
    return guest_base;
}

std::uint32_t Impl_UnmapViewOfFile(std::uint64_t base) {
    HandleKind kind;
    if (!TakeHandle(base, &kind) || kind != HandleKind::kFileView) return 0;
    ViewInfo info{0, 0};
    {
        std::lock_guard<std::mutex> lock(g_view_mutex);
        auto it = g_views.find(base);
        if (it == g_views.end()) return 0;
        info = it->second;
        g_views.erase(it);
    }
    if (info.length == 0) return 0;
    return munmap(reinterpret_cast<void *>(info.mmap_base), info.length) == 0 ? 1u : 0u;
}

// ---------------------------------------------------------------------------
// Attributes and directory enumeration
// ---------------------------------------------------------------------------
std::uint32_t AttributesFor(const struct stat &st) {
    if (S_ISDIR(st.st_mode)) return FILE_ATTRIBUTE_DIRECTORY;
    std::uint32_t attrs = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE;
    if ((st.st_mode & S_IWUSR) == 0) attrs |= FILE_ATTRIBUTE_READONLY;
    return attrs;
}

// FILETIME counts 100 ns intervals since 1601-01-01.
std::uint64_t UnixToFileTime(std::int64_t seconds) {
    return static_cast<std::uint64_t>(seconds + 11644473600LL) * 10000000ull;
}

bool StatGuestPath(const char *path, struct stat *st) {
    const std::string p = ResolveGuestPath(path);
    if (::stat(p.c_str(), st) == 0) return true;
    const std::string lower = LowerAscii(p);
    return lower != p && ::stat(lower.c_str(), st) == 0;
}

std::uint32_t Impl_GetFileAttributes(const char *path) {
    if (path == nullptr) return kInvalidFileAttributes;
    struct stat st {};
    if (!StatGuestPath(path, &st)) return kInvalidFileAttributes;
    return AttributesFor(st);
}

std::uint32_t Impl_GetFileAttributesEx(const char *path, std::uint32_t /*level*/,
                                       std::uint64_t out) {
    if (path == nullptr) return 0;
    struct stat st {};
    if (!StatGuestPath(path, &st)) return 0;
    if (out == 0) return 1;

    const std::uint32_t attrs = AttributesFor(st);
    const std::uint64_t file_time = UnixToFileTime(st.st_mtime);
    Put32(out + 0x00, attrs);
    Put64(out + 0x04, file_time);  // creation
    Put64(out + 0x0C, file_time);  // last access
    Put64(out + 0x14, file_time);  // last write
    Put32(out + 0x1C, 0);          // volume serial
    Put32(out + 0x20, static_cast<std::uint32_t>(static_cast<std::uint64_t>(st.st_size) >> 32));
    Put32(out + 0x24, static_cast<std::uint32_t>(static_cast<std::uint64_t>(st.st_size)));
    Put32(out + 0x28, static_cast<std::uint32_t>(st.st_nlink));
    Put32(out + 0x2C, 0);  // file index high
    Put32(out + 0x30, static_cast<std::uint32_t>(st.st_ino));
    return 1;
}

// Windows wildcards: '*' any run, '?' one character, case-insensitive.
bool WildcardMatch(const std::string &pattern, const std::string &text) {
    std::size_t pi = 0, ti = 0;
    std::size_t star = std::string::npos, mark = 0;
    while (ti < text.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || std::tolower(
                static_cast<unsigned char>(pattern[pi])) ==
                std::tolower(static_cast<unsigned char>(text[ti])))) {
            ++pi;
            ++ti;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star = pi++;
            mark = ti;
        } else if (star != std::string::npos) {
            pi = star + 1;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

void FillFindData(std::uint64_t out, const std::string &name, const struct stat &st,
                  bool wide) {
    const std::size_t size = wide ? kFindDataSizeW : kFindDataSize;
    std::vector<unsigned char> buf(size, 0);

    const std::uint32_t attrs = AttributesFor(st);
    const std::uint64_t file_time = UnixToFileTime(st.st_mtime);
    const std::uint32_t size_high =
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(st.st_size) >> 32);
    const std::uint32_t size_low =
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(st.st_size));
    std::memcpy(buf.data() + 0x00, &attrs, 4);
    std::memcpy(buf.data() + 0x04, &file_time, 8);
    std::memcpy(buf.data() + 0x0C, &file_time, 8);
    std::memcpy(buf.data() + 0x14, &file_time, 8);
    std::memcpy(buf.data() + 0x1C, &size_high, 4);
    std::memcpy(buf.data() + 0x20, &size_low, 4);

    if (wide) {
        // cFileName is WCHAR[260] here, so the field is twice as wide.
        std::uint16_t name_w[kMaxPath];
        const std::size_t n = std::min(name.size(), kMaxPath - 1);
        for (std::size_t i = 0; i < n; ++i) {
            name_w[i] = static_cast<std::uint16_t>(
                static_cast<unsigned char>(name[i]));  // ASCII asset paths
        }
        name_w[n] = 0;
        std::memcpy(buf.data() + 0x2C, name_w, sizeof(std::uint16_t) * (n + 1));
    } else {
        const std::size_t n = std::min(name.size(), kMaxPath - 1);
        std::memcpy(buf.data() + 0x2C, name.data(), n);
        buf[0x2C + n] = 0;
    }

    GuestWrite(out, buf.data(), size);
}

bool NextMatch(GuestFind *scan, std::uint64_t out) {
    if (scan == nullptr || scan->dir == nullptr) return false;
    struct dirent *entry = nullptr;
    while ((entry = ::readdir(scan->dir)) != nullptr) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;  // Windows does not report these
        if (!WildcardMatch(scan->pattern, name)) continue;
        struct stat st {};
        const std::string full = scan->dir_path + "/" + name;
        if (::stat(full.c_str(), &st) != 0) continue;
        FillFindData(out, name, st, scan->wide);
        return true;
    }
    return false;
}

std::uint64_t Impl_FindFirstFile(const char *pattern, std::uint64_t out, bool wide) {
    if (pattern == nullptr || out == 0) return kInvalidHandle;
    const std::string full = ResolveGuestPath(pattern);

    std::string dir_path;
    std::string pat;
    const std::size_t slash = full.find_last_of('/');
    if (slash == std::string::npos) {
        dir_path = ".";
        pat = full;
    } else {
        dir_path = full.substr(0, slash);
        if (dir_path.empty()) dir_path = "/";
        pat = full.substr(slash + 1);
    }
    if (pat.empty()) pat = "*";
    if (pat == "*.*") pat = "*";

    DIR *dir = ::opendir(dir_path.c_str());
    if (dir == nullptr) {
        Log("[win32] FindFirstFile: opendir(%s) failed: %s", dir_path.c_str(),
            std::strerror(errno));
        return kInvalidHandle;
    }

    auto *scan = new GuestFind{kFindMagic, dir, dir_path, pat, wide};
    if (!NextMatch(scan, out)) {
        ::closedir(dir);
        delete scan;
        return kInvalidHandle;  // no match is an error in Windows, not an empty list
    }
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(scan);
    RegisterHandle(handle, HandleKind::kFind);
    return handle;
}

std::uint32_t Impl_FindNextFile(std::uint64_t handle, std::uint64_t out) {
    HandleKind kind;
    if (!HandleKindOf(handle, &kind) || kind != HandleKind::kFind) return 0;
    auto *scan = reinterpret_cast<GuestFind *>(handle);
    if (scan == nullptr || scan->magic != kFindMagic) return 0;
    return NextMatch(scan, out) ? 1u : 0u;
}

std::uint32_t Impl_FindClose(std::uint64_t handle) {
    HandleKind kind;
    if (!TakeHandle(handle, &kind) || kind != HandleKind::kFind) return 0;
    auto *scan = reinterpret_cast<GuestFind *>(handle);
    if (scan != nullptr) {
        if (scan->dir != nullptr) ::closedir(scan->dir);
        scan->magic = 0;
        delete scan;
    }
    return 1;
}

std::uint32_t Impl_DeleteFile(const char *path) {
    if (path == nullptr) return 0;
    const std::string p = ResolveGuestPath(path);
    return ::unlink(p.c_str()) == 0 ? 1u : 0u;
}

std::uint32_t Impl_SetEndOfFile(std::uint64_t handle) {
    GuestFile *f = AsFile(handle);
    if (f == nullptr) return 0;
    const off64_t pos = ::lseek64(f->fd, 0, SEEK_CUR);
    if (pos < 0) return 0;
    return ::ftruncate64(f->fd, pos) == 0 ? 1u : 0u;
}

// ---------------------------------------------------------------------------
// D3D9 thunk allocation shares the import thunk table.
namespace com {

std::uint64_t AllocThunk(const char *owner, const char *name, StubFn fn) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    if ((g_next_thunk - kThunkBase) / kThunkStride >= kMaxStubs) return 0;
    const std::uint64_t thunk = g_next_thunk;
    g_next_thunk += kThunkStride;
    const std::size_t slot = (thunk - kThunkBase) / kThunkStride;
    g_slot_table[slot] = fn;
    g_slot_owner[slot] = owner;
    g_slot_name[slot] = name;
    return thunk;
}

}  // namespace com

std::atomic<std::uint64_t> g_sdl_window{0};

#if defined(D2_HAS_DXVK_D3D9)
void Stub_D3D9Create(CpuContext *c);
#endif

#if defined(D2_HAS_DXVK_D3D9)
enum D3D9Interface : std::uint32_t { kD3d9 = 1, kD3d9Device = 2, kD3d9Surface = 3 };

struct D3D9Proxy {
    std::uint64_t *vtable;
    IUnknown *host;
    D3D9Interface iface;
};

struct D3D9ThunkInfo {
    D3D9Interface iface = {};
    std::uint16_t method = 0;
    bool valid = false;
};

D3D9ThunkInfo g_d3d9_thunks[kMaxStubs];
std::uint64_t g_d3d9_vtable[17]{};
std::uint64_t g_d3d9_device_vtable[119]{};
std::uint64_t g_d3d9_surface_vtable[17]{};
std::once_flag g_d3d9_once;

std::uint64_t D3DArg0(CpuContext *c) { return c->r[recomp::RDX]; }
std::uint64_t D3DArg1(CpuContext *c) { return c->r[recomp::R8]; }
std::uint64_t D3DArg2(CpuContext *c) { return c->r[recomp::R9]; }
std::uint64_t D3DArg3(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x28);
}
std::uint64_t D3DArg4(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x30);
}
std::uint64_t D3DArg5(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x38);
}
void Stub_D3D9ComMethod(CpuContext *c);

constexpr const char *kD3d9Methods[] = {
    "QueryInterface", "AddRef", "Release", "RegisterSoftwareDevice", "GetAdapterCount",
    "GetAdapterIdentifier", "GetAdapterModeCount", "EnumAdapterModes", "GetAdapterDisplayMode",
    "CheckDeviceType", "CheckDeviceFormat", "CheckDeviceMultiSampleType",
    "CheckDepthStencilMatch", "CheckDeviceFormatConversion", "GetDeviceCaps",
    "GetAdapterMonitor", "CreateDevice"};

const char *D3D9DeviceMethodName(std::uint16_t method) {
    switch (method) {
        case 0: return "QueryInterface";
        case 1: return "AddRef";
        case 2: return "Release";
        case 7: return "GetDeviceCaps";
        case 8: return "GetDisplayMode";
        case 9: return "GetCreationParameters";
        case 16: return "Reset";
        case 17: return "Present";
        case 37: return "SetRenderTarget";
        case 38: return "GetRenderTarget";
        case 39: return "SetDepthStencilSurface";
        case 40: return "GetDepthStencilSurface";
        case 41: return "BeginScene";
        case 42: return "EndScene";
        case 43: return "Clear";
        case 57: return "SetRenderState";
        case 58: return "GetRenderState";
        case 68: return "GetSamplerState";
        case 69: return "SetSamplerState";
        case 118: return "SetNPatchMode";
        default: return "Method";
    }
}

std::uint64_t *D3D9Vtable(D3D9Interface iface) {
    switch (iface) {
        case kD3d9: return g_d3d9_vtable;
        case kD3d9Device: return g_d3d9_device_vtable;
        case kD3d9Surface: return g_d3d9_surface_vtable;
    }
    return nullptr;
}

D3D9Proxy *D3D9Host(std::uint64_t guest, D3D9Interface expected) {
    auto *proxy = reinterpret_cast<D3D9Proxy *>(guest);
    if (proxy == nullptr || proxy->vtable != D3D9Vtable(expected) || proxy->host == nullptr) {
        return nullptr;
    }
    return proxy;
}

std::uint64_t D3D9Wrap(IUnknown *host, D3D9Interface iface) {
    if (host == nullptr) return 0;
    auto *proxy = new (std::nothrow) D3D9Proxy{D3D9Vtable(iface), host, iface};
    if (proxy == nullptr) {
        host->Release();
        return 0;
    }
    return reinterpret_cast<std::uint64_t>(proxy);
}

void WriteDisplayMode(std::uint64_t guest, const D3DDISPLAYMODE &mode) {
    recomp::GuestStore<std::uint32_t>(guest + 0, mode.Width);
    recomp::GuestStore<std::uint32_t>(guest + 4, mode.Height);
    recomp::GuestStore<std::uint32_t>(guest + 8, mode.RefreshRate);
    recomp::GuestStore<std::uint32_t>(guest + 12, mode.Format);
}

HRESULT D3D9CreateDevice(CpuContext *c, D3D9Proxy *proxy) {
    D3DPRESENT_PARAMETERS pp{};
    const std::uint64_t guest_pp = D3DArg4(c);
    const std::uint64_t guest_device = D3DArg5(c);
    if (guest_pp == 0 || guest_device == 0) return D3DERR_INVALIDCALL;
    pp.BackBufferWidth = recomp::GuestLoad<UINT>(guest_pp + 0);
    pp.BackBufferHeight = recomp::GuestLoad<UINT>(guest_pp + 4);
    pp.BackBufferFormat = static_cast<D3DFORMAT>(recomp::GuestLoad<UINT>(guest_pp + 8));
    pp.BackBufferCount = recomp::GuestLoad<UINT>(guest_pp + 12);
    pp.MultiSampleType =
        static_cast<D3DMULTISAMPLE_TYPE>(recomp::GuestLoad<UINT>(guest_pp + 16));
    pp.MultiSampleQuality = recomp::GuestLoad<DWORD>(guest_pp + 20);
    pp.SwapEffect = static_cast<D3DSWAPEFFECT>(recomp::GuestLoad<UINT>(guest_pp + 24));
    pp.hDeviceWindow = reinterpret_cast<HWND>(g_sdl_window.load());
    pp.Windowed = recomp::GuestLoad<BOOL>(guest_pp + 40);
    pp.EnableAutoDepthStencil = recomp::GuestLoad<BOOL>(guest_pp + 44);
    pp.AutoDepthStencilFormat = static_cast<D3DFORMAT>(recomp::GuestLoad<UINT>(guest_pp + 48));
    pp.Flags = recomp::GuestLoad<DWORD>(guest_pp + 52);
    pp.FullScreen_RefreshRateInHz = recomp::GuestLoad<UINT>(guest_pp + 56);
    pp.PresentationInterval = recomp::GuestLoad<UINT>(guest_pp + 60);

    IDirect3DDevice9 *device = nullptr;
    const HWND focus_window = reinterpret_cast<HWND>(g_sdl_window.load());
    pp.hDeviceWindow = focus_window;
    const HRESULT hr = reinterpret_cast<IDirect3D9 *>(proxy->host)->CreateDevice(
        static_cast<UINT>(D3DArg0(c)), static_cast<D3DDEVTYPE>(D3DArg1(c)),
        focus_window, static_cast<DWORD>(D3DArg3(c)) | D3DCREATE_MULTITHREADED, &pp, &device);

    recomp::GuestStore<UINT>(guest_pp + 0, pp.BackBufferWidth);
    recomp::GuestStore<UINT>(guest_pp + 4, pp.BackBufferHeight);
    recomp::GuestStore<UINT>(guest_pp + 8, pp.BackBufferFormat);
    recomp::GuestStore<UINT>(guest_pp + 12, pp.BackBufferCount);
    if (SUCCEEDED(hr)) {
        const std::uint64_t wrapped = D3D9Wrap(device, kD3d9Device);
        recomp::GuestStore<std::uint64_t>(guest_device, wrapped);
        if (wrapped == 0) return E_OUTOFMEMORY;
    } else {
        recomp::GuestStore<std::uint64_t>(guest_device, 0);
    }
    Log("[D3D9] IDirect3D9::CreateDevice %ux%u -> 0x%08x", pp.BackBufferWidth,
        pp.BackBufferHeight, static_cast<unsigned>(hr));
    return hr;
}

void Stub_D3D9Create(CpuContext *c) {
    std::call_once(g_d3d9_once, [] {
        for (std::uint16_t i = 0; i < 17; ++i) {
            const std::uint64_t thunk = com::AllocThunk("IDirect3D9", kD3d9Methods[i],
                                                        Stub_D3D9ComMethod);
            const std::size_t slot = (thunk - kThunkBase) / kThunkStride;
            g_d3d9_vtable[i] = thunk;
            g_d3d9_thunks[slot] = {kD3d9, i, true};
        }
        for (std::uint16_t i = 0; i < 119; ++i) {
            const char *name = D3D9DeviceMethodName(i);
            const std::uint64_t thunk = com::AllocThunk("IDirect3DDevice9", name,
                                                        Stub_D3D9ComMethod);
            const std::size_t slot = (thunk - kThunkBase) / kThunkStride;
            g_d3d9_device_vtable[i] = thunk;
            g_d3d9_thunks[slot] = {kD3d9Device, i, true};
        }
        for (std::uint16_t i = 0; i < 17; ++i) {
            const std::uint64_t thunk = com::AllocThunk("IDirect3DSurface9", "Method",
                                                        Stub_D3D9ComMethod);
            const std::size_t slot = (thunk - kThunkBase) / kThunkStride;
            g_d3d9_surface_vtable[i] = thunk;
            g_d3d9_thunks[slot] = {kD3d9Surface, i, true};
        }
    });

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    SetRet(c, D3D9Wrap(d3d, kD3d9));
    Log("[D3D9] Direct3DCreate9 -> %s", d3d != nullptr ? "IDirect3D9" : "NULL");
}

void Stub_D3D9ComMethod(CpuContext *c) {
    const std::size_t slot = (g_active_thunk - kThunkBase) / kThunkStride;
    if (slot >= kMaxStubs || !g_d3d9_thunks[slot].valid) {
        SetRet32(c, D3DERR_INVALIDCALL);
        return;
    }
    const D3D9ThunkInfo info = g_d3d9_thunks[slot];
    auto *proxy = D3D9Host(Arg0(c), info.iface);
    if (proxy == nullptr) {
        SetRet32(c, D3DERR_INVALIDCALL);
        return;
    }
    const std::uint16_t method = info.method;
    if (method == 0) {
        const std::uint64_t iid_address = D3DArg0(c);
        const std::uint64_t output_address = D3DArg1(c);
        if (iid_address == 0 || output_address == 0) {
            SetRet32(c, E_POINTER);
            return;
        }
        const GUID iid = recomp::GuestLoad<GUID>(iid_address);
        IUnknown *queried = nullptr;
        const HRESULT hr = proxy->host->QueryInterface(iid, reinterpret_cast<void **>(&queried));
        if (FAILED(hr)) {
            recomp::GuestStore<std::uint64_t>(output_address, 0);
            SetRet32(c, hr);
            return;
        }
        D3D9Interface iface = info.iface;
        if (iid == IID_IDirect3D9) iface = kD3d9;
        else if (iid == IID_IDirect3DDevice9) iface = kD3d9Device;
        else if (iid == IID_IDirect3DSurface9) iface = kD3d9Surface;
        else if (iid != IID_IUnknown) {
            queried->Release();
            recomp::GuestStore<std::uint64_t>(output_address, 0);
            SetRet32(c, E_NOINTERFACE);
            return;
        }
        const std::uint64_t wrapped = D3D9Wrap(queried, iface);
        recomp::GuestStore<std::uint64_t>(output_address, wrapped);
        SetRet32(c, wrapped != 0 ? hr : E_OUTOFMEMORY);
        return;
    }
    if (method == 1) {
        SetRet(c, proxy->host->AddRef());
        return;
    }
    if (method == 2) {
        const ULONG refs = proxy->host->Release();
        if (refs == 0) delete proxy;
        SetRet(c, refs);
        return;
    }

    HRESULT hr = D3DERR_INVALIDCALL;
    if (info.iface == kD3d9) {
        auto *d3d = reinterpret_cast<IDirect3D9 *>(proxy->host);
        switch (method) {
            case 4: SetRet(c, d3d->GetAdapterCount()); return;
            case 5:
                hr = d3d->GetAdapterIdentifier(static_cast<UINT>(D3DArg0(c)),
                    static_cast<DWORD>(D3DArg1(c)),
                    reinterpret_cast<D3DADAPTER_IDENTIFIER9 *>(D3DArg2(c)));
                break;
            case 6: SetRet(c, d3d->GetAdapterModeCount(static_cast<UINT>(D3DArg0(c)),
                static_cast<D3DFORMAT>(D3DArg1(c)))); return;
            case 7:
                hr = d3d->EnumAdapterModes(static_cast<UINT>(D3DArg0(c)),
                    static_cast<D3DFORMAT>(D3DArg1(c)), static_cast<UINT>(D3DArg2(c)),
                    reinterpret_cast<D3DDISPLAYMODE *>(D3DArg3(c)));
                break;
            case 8: {
                D3DDISPLAYMODE mode{};
                hr = d3d->GetAdapterDisplayMode(static_cast<UINT>(D3DArg0(c)), &mode);
                if (SUCCEEDED(hr)) WriteDisplayMode(D3DArg1(c), mode);
                break;
            }
            case 9:
                hr = d3d->CheckDeviceType(static_cast<UINT>(D3DArg0(c)),
                    static_cast<D3DDEVTYPE>(D3DArg1(c)), static_cast<D3DFORMAT>(D3DArg2(c)),
                    static_cast<D3DFORMAT>(D3DArg3(c)), static_cast<BOOL>(D3DArg4(c)));
                break;
            case 10:
                hr = d3d->CheckDeviceFormat(static_cast<UINT>(D3DArg0(c)),
                    static_cast<D3DDEVTYPE>(D3DArg1(c)), static_cast<D3DFORMAT>(D3DArg2(c)),
                    static_cast<DWORD>(D3DArg3(c)), static_cast<D3DRESOURCETYPE>(D3DArg4(c)),
                    static_cast<D3DFORMAT>(D3DArg5(c)));
                break;
            case 14:
                hr = d3d->GetDeviceCaps(static_cast<UINT>(D3DArg0(c)),
                    static_cast<D3DDEVTYPE>(D3DArg1(c)),
                    reinterpret_cast<D3DCAPS9 *>(D3DArg2(c)));
                break;
            case 16: hr = D3D9CreateDevice(c, proxy); break;
        }
    } else if (info.iface == kD3d9Device) {
        auto *device = reinterpret_cast<IDirect3DDevice9 *>(proxy->host);
        switch (method) {
            case 7:
                hr = device->GetDeviceCaps(reinterpret_cast<D3DCAPS9 *>(D3DArg0(c)));
                break;
            case 8: {
                D3DDISPLAYMODE mode{};
                hr = device->GetDisplayMode(static_cast<UINT>(D3DArg0(c)), &mode);
                if (SUCCEEDED(hr)) WriteDisplayMode(D3DArg1(c), mode);
                break;
            }
            case 9: {
                D3DDEVICE_CREATION_PARAMETERS p{};
                hr = device->GetCreationParameters(&p);
                if (SUCCEEDED(hr)) {
                    recomp::GuestStore<UINT>(D3DArg0(c) + 0, p.AdapterOrdinal);
                    recomp::GuestStore<D3DDEVTYPE>(D3DArg0(c) + 4, p.DeviceType);
                    recomp::GuestStore<std::uint64_t>(D3DArg0(c) + 8, g_sdl_window.load());
                    recomp::GuestStore<DWORD>(D3DArg0(c) + 16, p.BehaviorFlags);
                }
                break;
            }
            case 16: {
                const std::uint64_t guest_pp = D3DArg0(c);
                D3DPRESENT_PARAMETERS pp{};
                pp.BackBufferWidth = recomp::GuestLoad<UINT>(guest_pp + 0);
                pp.BackBufferHeight = recomp::GuestLoad<UINT>(guest_pp + 4);
                pp.BackBufferFormat = static_cast<D3DFORMAT>(recomp::GuestLoad<UINT>(guest_pp + 8));
                pp.BackBufferCount = recomp::GuestLoad<UINT>(guest_pp + 12);
                pp.MultiSampleType = static_cast<D3DMULTISAMPLE_TYPE>(recomp::GuestLoad<UINT>(guest_pp + 16));
                pp.MultiSampleQuality = recomp::GuestLoad<DWORD>(guest_pp + 20);
                pp.SwapEffect = static_cast<D3DSWAPEFFECT>(recomp::GuestLoad<UINT>(guest_pp + 24));
                pp.hDeviceWindow = reinterpret_cast<HWND>(g_sdl_window.load());
                pp.Windowed = recomp::GuestLoad<BOOL>(guest_pp + 40);
                pp.EnableAutoDepthStencil = recomp::GuestLoad<BOOL>(guest_pp + 44);
                pp.AutoDepthStencilFormat = static_cast<D3DFORMAT>(recomp::GuestLoad<UINT>(guest_pp + 48));
                pp.Flags = recomp::GuestLoad<DWORD>(guest_pp + 52);
                pp.FullScreen_RefreshRateInHz = recomp::GuestLoad<UINT>(guest_pp + 56);
                pp.PresentationInterval = recomp::GuestLoad<UINT>(guest_pp + 60);
                hr = device->Reset(&pp);
                recomp::GuestStore<UINT>(guest_pp + 0, pp.BackBufferWidth);
                recomp::GuestStore<UINT>(guest_pp + 4, pp.BackBufferHeight);
                recomp::GuestStore<UINT>(guest_pp + 8, pp.BackBufferFormat);
                recomp::GuestStore<UINT>(guest_pp + 12, pp.BackBufferCount);
                break;
            }
            case 17:
                hr = device->Present(reinterpret_cast<const RECT *>(D3DArg0(c)),
                    reinterpret_cast<const RECT *>(D3DArg1(c)),
                    reinterpret_cast<HWND>(D3DArg2(c)),
                    reinterpret_cast<const RGNDATA *>(D3DArg3(c)));
                break;
            case 37:
                if (auto *surface = D3D9Host(D3DArg1(c), kD3d9Surface)) {
                    hr = device->SetRenderTarget(static_cast<DWORD>(D3DArg0(c)),
                        reinterpret_cast<IDirect3DSurface9 *>(surface->host));
                } else if (D3DArg1(c) == 0) {
                    hr = device->SetRenderTarget(static_cast<DWORD>(D3DArg0(c)), nullptr);
                }
                break;
            case 38: {
                if (D3DArg1(c) == 0) {
                    hr = E_POINTER;
                    break;
                }
                IDirect3DSurface9 *surface = nullptr;
                hr = device->GetRenderTarget(static_cast<DWORD>(D3DArg0(c)), &surface);
                const std::uint64_t wrapped =
                    SUCCEEDED(hr) ? D3D9Wrap(surface, kD3d9Surface) : 0;
                recomp::GuestStore<std::uint64_t>(D3DArg1(c), wrapped);
                if (SUCCEEDED(hr) && wrapped == 0) hr = E_OUTOFMEMORY;
                break;
            }
            case 39: {
                const std::uint64_t guest_surface = D3DArg0(c);
                if (guest_surface == 0) {
                    hr = device->SetDepthStencilSurface(nullptr);
                } else if (auto *surface = D3D9Host(guest_surface, kD3d9Surface)) {
                    hr = device->SetDepthStencilSurface(
                        reinterpret_cast<IDirect3DSurface9 *>(surface->host));
                }
                break;
            }
            case 40: {
                if (D3DArg0(c) == 0) {
                    hr = E_POINTER;
                    break;
                }
                IDirect3DSurface9 *surface = nullptr;
                hr = device->GetDepthStencilSurface(&surface);
                const std::uint64_t wrapped =
                    SUCCEEDED(hr) ? D3D9Wrap(surface, kD3d9Surface) : 0;
                recomp::GuestStore<std::uint64_t>(D3DArg0(c), wrapped);
                if (SUCCEEDED(hr) && wrapped == 0) hr = E_OUTOFMEMORY;
                break;
            }
            case 41: hr = device->BeginScene(); break;
            case 42: hr = device->EndScene(); break;
            case 43:
                hr = device->Clear(static_cast<DWORD>(D3DArg0(c)),
                    reinterpret_cast<const D3DRECT *>(D3DArg1(c)),
                    static_cast<DWORD>(D3DArg2(c)), static_cast<D3DCOLOR>(D3DArg3(c)),
                    static_cast<float>(D3DArg4(c)), static_cast<DWORD>(D3DArg5(c)));
                break;
            case 57:
                hr = device->SetRenderState(static_cast<D3DRENDERSTATETYPE>(D3DArg0(c)),
                    static_cast<DWORD>(D3DArg1(c)));
                break;
            case 58: {
                DWORD value = 0;
                hr = device->GetRenderState(static_cast<D3DRENDERSTATETYPE>(D3DArg0(c)), &value);
                if (SUCCEEDED(hr)) recomp::GuestStore<DWORD>(D3DArg1(c), value);
                break;
            }
            case 68: {
                DWORD value = 0;
                hr = device->GetSamplerState(static_cast<DWORD>(D3DArg0(c)),
                    static_cast<D3DSAMPLERSTATETYPE>(D3DArg1(c)), &value);
                if (SUCCEEDED(hr)) recomp::GuestStore<DWORD>(D3DArg2(c), value);
                break;
            }
            case 69:
                hr = device->SetSamplerState(static_cast<DWORD>(D3DArg0(c)),
                    static_cast<D3DSAMPLERSTATETYPE>(D3DArg1(c)),
                    static_cast<DWORD>(D3DArg2(c)));
                break;
            case 118: device->SetNPatchMode(c->v[1].f[0]); SetRet(c, 0); return;
        }
    }

    SetRet32(c, static_cast<std::int32_t>(hr));
}
#endif

// ---------------------------------------------------------------------------
// Critical sections (recursive, like Windows). Keyed by the guest's address so
// we never depend on sizeof(CRITICAL_SECTION) (40 bytes on Win64).
// ---------------------------------------------------------------------------
std::mutex g_crit_mutex;
std::unordered_map<std::uintptr_t, pthread_mutex_t *> g_crit;

pthread_mutex_t *CritFor(std::uintptr_t key, bool create) {
    std::lock_guard<std::mutex> lock(g_crit_mutex);
    auto it = g_crit.find(key);
    if (it != g_crit.end()) return it->second;
    if (!create) return nullptr;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    auto *m = new pthread_mutex_t;
    if (pthread_mutex_init(m, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        delete m;
        return nullptr;
    }
    pthread_mutexattr_destroy(&attr);
    g_crit[key] = m;
    return m;
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------
std::mutex g_tls_mutex;
std::vector<pthread_key_t> g_tls_keys;
std::vector<bool> g_tls_used;

std::uint32_t Impl_TlsAlloc() {
    std::lock_guard<std::mutex> lock(g_tls_mutex);
    for (std::size_t i = 0; i < g_tls_keys.size(); ++i) {
        if (!g_tls_used[i]) {
            g_tls_used[i] = true;
            return static_cast<std::uint32_t>(i);
        }
    }
    pthread_key_t k;
    if (pthread_key_create(&k, nullptr) != 0) return 0xFFFFFFFFu;
    g_tls_keys.push_back(k);
    g_tls_used.push_back(true);
    return static_cast<std::uint32_t>(g_tls_keys.size() - 1);
}

void *Impl_TlsGetValue(std::uint32_t index) {
    std::lock_guard<std::mutex> lock(g_tls_mutex);
    if (index >= g_tls_keys.size()) return nullptr;
    return pthread_getspecific(g_tls_keys[index]);
}

std::uint32_t Impl_TlsSetValue(std::uint32_t index, void *value) {
    std::lock_guard<std::mutex> lock(g_tls_mutex);
    if (index >= g_tls_keys.size()) return 0;
    return pthread_setspecific(g_tls_keys[index], value) == 0 ? 1u : 0u;
}

std::uint32_t Impl_TlsFree(std::uint32_t index) {
    std::lock_guard<std::mutex> lock(g_tls_mutex);
    if (index >= g_tls_keys.size() || !g_tls_used[index]) return 0;
    pthread_key_delete(g_tls_keys[index]);
    g_tls_used[index] = false;
    return 1;
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------
std::uint64_t NowNanos() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

// ---------------------------------------------------------------------------
// Stub wrappers (guest registers -> implementation -> guest RAX)
// ---------------------------------------------------------------------------
void Stub_VirtualAlloc(CpuContext *c) {
    SetRet(c, reinterpret_cast<std::uint64_t>(Impl_VirtualAlloc(
                  reinterpret_cast<void *>(Arg0(c)), static_cast<std::size_t>(Arg1(c)),
                  static_cast<std::uint32_t>(Arg2(c)), static_cast<std::uint32_t>(Arg3(c)))));
}
void Stub_VirtualFree(CpuContext *c) {
    SetRet(c, Impl_VirtualFree(reinterpret_cast<void *>(Arg0(c)),
                               static_cast<std::size_t>(Arg1(c)),
                               static_cast<std::uint32_t>(Arg2(c))));
}
void Stub_VirtualProtect(CpuContext *c) {
    SetRet(c, Impl_VirtualProtect(reinterpret_cast<void *>(Arg0(c)),
                                  static_cast<std::size_t>(Arg1(c)),
                                  static_cast<std::uint32_t>(Arg2(c)), Arg3(c)));
}
void Stub_GetModuleHandleA(CpuContext *c) {
    SetRet(c, Impl_GetModuleHandle(reinterpret_cast<const char *>(Arg0(c))));
}
void Stub_LoadLibraryA(CpuContext *c) {
    SetRet(c, Impl_GetModuleHandle(reinterpret_cast<const char *>(Arg0(c))));
}
void Stub_GetProcAddress(CpuContext *c) {
    SetRet(c, Impl_GetProcAddress(Arg0(c), reinterpret_cast<const char *>(Arg1(c))));
}
void Stub_CreateThread(CpuContext *c) {
    SetRet(c, Impl_CreateThread(Arg0(c), Arg1(c), Arg2(c), Arg3(c),
                                static_cast<std::uint32_t>(Arg4(c)), Arg5(c)));
}
void Stub_WaitForSingleObject(CpuContext *c) {
    SetRet(c, Impl_WaitForSingleObject(Arg0(c), static_cast<std::uint32_t>(Arg1(c))));
}
void Stub_CloseHandle(CpuContext *c) { SetRet(c, Impl_CloseHandle(Arg0(c))); }
void Stub_InitializeCriticalSection(CpuContext *c) {
    CritFor(Arg0(c), true);
    SetRet(c, 0);
}
void Stub_EnterCriticalSection(CpuContext *c) {
    if (pthread_mutex_t *m = CritFor(Arg0(c), true)) pthread_mutex_lock(m);
    SetRet(c, 0);
}
void Stub_LeaveCriticalSection(CpuContext *c) {
    if (pthread_mutex_t *m = CritFor(Arg0(c), false)) pthread_mutex_unlock(m);
    SetRet(c, 0);
}
void Stub_DeleteCriticalSection(CpuContext *c) {
    pthread_mutex_t *m = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_crit_mutex);
        auto it = g_crit.find(Arg0(c));
        if (it != g_crit.end()) {
            m = it->second;
            g_crit.erase(it);
        }
    }
    if (m) {
        pthread_mutex_destroy(m);
        delete m;
    }
    SetRet(c, 0);
}
void Stub_TryEnterCriticalSection(CpuContext *c) {
    pthread_mutex_t *m = CritFor(Arg0(c), true);
    SetRet(c, (m && pthread_mutex_trylock(m) == 0) ? 1u : 0u);
}
void Stub_InterlockedIncrement(CpuContext *c) {
    SetRet(c, __atomic_add_fetch(reinterpret_cast<std::uint32_t *>(Arg0(c)), 1,
                                 __ATOMIC_SEQ_CST));
}
void Stub_InterlockedDecrement(CpuContext *c) {
    SetRet(c, __atomic_sub_fetch(reinterpret_cast<std::uint32_t *>(Arg0(c)), 1,
                                 __ATOMIC_SEQ_CST));
}
void Stub_InterlockedExchange(CpuContext *c) {
    SetRet(c, __atomic_exchange_n(reinterpret_cast<std::uint32_t *>(Arg0(c)),
                                  static_cast<std::uint32_t>(Arg1(c)), __ATOMIC_SEQ_CST));
}
void Stub_InterlockedCompareExchange(CpuContext *c) {
    auto *p = reinterpret_cast<std::uint32_t *>(Arg0(c));
    std::uint32_t expected = static_cast<std::uint32_t>(Arg2(c));
    __atomic_compare_exchange_n(p, &expected, static_cast<std::uint32_t>(Arg1(c)), false,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    SetRet(c, expected);  // Windows returns the initial value
}
void Stub_Sleep(CpuContext *c) {
    const std::uint32_t ms = static_cast<std::uint32_t>(Arg0(c));
    timespec ts{static_cast<time_t>(ms / 1000u), static_cast<long>((ms % 1000u) * 1000000L)};
    nanosleep(&ts, nullptr);
    SetRet(c, 0);
}
void Stub_GetTickCount64(CpuContext *c) { SetRet(c, NowNanos() / 1000000ull); }
void Stub_QueryPerformanceCounter(CpuContext *c) {
    const std::uint64_t v = NowNanos();
    if (Arg0(c) != 0) recomp::GuestStore<std::uint64_t>(Arg0(c), v);
    SetRet(c, 1);
}
void Stub_GetCurrentThreadId(CpuContext *c) {
    static std::atomic<std::uint32_t> next{1};
    thread_local const std::uint32_t id = next++;
    SetRet(c, id);
}
void Stub_TlsAlloc(CpuContext *c) { SetRet(c, Impl_TlsAlloc()); }
void Stub_TlsGetValue(CpuContext *c) {
    SetRet(c, reinterpret_cast<std::uint64_t>(
                  Impl_TlsGetValue(static_cast<std::uint32_t>(Arg0(c)))));
}
void Stub_TlsSetValue(CpuContext *c) {
    SetRet(c, Impl_TlsSetValue(static_cast<std::uint32_t>(Arg0(c)),
                               reinterpret_cast<void *>(Arg1(c))));
}
void Stub_TlsFree(CpuContext *c) {
    SetRet(c, Impl_TlsFree(static_cast<std::uint32_t>(Arg0(c))));
}
void Stub_OutputDebugStringA(CpuContext *c) {
    const auto *s = reinterpret_cast<const char *>(Arg0(c));
    if (s) Log("[guest] %s", s);
    SetRet(c, 0);
}

// ---- file I/O ----
void Stub_CreateFileA(CpuContext *c) {
    SetRet(c, Impl_CreateFile(reinterpret_cast<const char *>(Arg0(c)),
                              static_cast<std::uint32_t>(Arg1(c)),
                              static_cast<std::uint32_t>(Arg2(c)), Arg3(c),
                              static_cast<std::uint32_t>(Arg4(c)),
                              static_cast<std::uint32_t>(Arg5(c)), Arg6(c)));
}
void Stub_CreateFileW(CpuContext *c) {
    const std::string path =
        Utf16ToUtf8(reinterpret_cast<const std::uint16_t *>(Arg0(c)));
    SetRet(c, Impl_CreateFile(path.c_str(), static_cast<std::uint32_t>(Arg1(c)),
                              static_cast<std::uint32_t>(Arg2(c)), Arg3(c),
                              static_cast<std::uint32_t>(Arg4(c)),
                              static_cast<std::uint32_t>(Arg5(c)), Arg6(c)));
}
void Stub_ReadFile(CpuContext *c) {
    SetRet(c, Impl_ReadFile(Arg0(c), Arg1(c), static_cast<std::uint32_t>(Arg2(c)), Arg3(c),
                            Arg4(c)));
}
void Stub_WriteFile(CpuContext *c) {
    SetRet(c, Impl_WriteFile(Arg0(c), Arg1(c), static_cast<std::uint32_t>(Arg2(c)), Arg3(c),
                             Arg4(c)));
}
void Stub_SetFilePointer(CpuContext *c) {
    SetRet(c, Impl_SetFilePointer(Arg0(c), static_cast<std::uint32_t>(Arg1(c)), Arg2(c),
                                  static_cast<std::uint32_t>(Arg3(c))));
}
void Stub_SetFilePointerEx(CpuContext *c) {
    SetRet(c, Impl_SetFilePointerEx(Arg0(c), static_cast<std::int64_t>(Arg1(c)), Arg2(c),
                                    static_cast<std::uint32_t>(Arg3(c))));
}
void Stub_GetFileSize(CpuContext *c) { SetRet(c, Impl_GetFileSize(Arg0(c), Arg1(c))); }
void Stub_GetFileSizeEx(CpuContext *c) { SetRet(c, Impl_GetFileSizeEx(Arg0(c), Arg1(c))); }

// ---- file mapping, attributes, directory enumeration ----
void Stub_CreateFileMappingA(CpuContext *c) {
    SetRet(c, Impl_CreateFileMapping(Arg0(c), static_cast<std::uint32_t>(Arg2(c)),
                                     static_cast<std::uint32_t>(Arg3(c)),
                                     static_cast<std::uint32_t>(Arg4(c)),
                                     reinterpret_cast<const char *>(Arg5(c))));
}
void Stub_CreateFileMappingW(CpuContext *c) {
    // lpName is ignored: this layer does not share named mappings across processes.
    SetRet(c, Impl_CreateFileMapping(Arg0(c), static_cast<std::uint32_t>(Arg2(c)),
                                     static_cast<std::uint32_t>(Arg3(c)),
                                     static_cast<std::uint32_t>(Arg4(c)), nullptr));
}
void Stub_MapViewOfFile(CpuContext *c) {
    SetRet(c, Impl_MapViewOfFile(Arg0(c), static_cast<std::uint32_t>(Arg1(c)),
                                 static_cast<std::uint32_t>(Arg2(c)),
                                 static_cast<std::uint32_t>(Arg3(c)), Arg4(c)));
}
void Stub_UnmapViewOfFile(CpuContext *c) { SetRet(c, Impl_UnmapViewOfFile(Arg0(c))); }
void Stub_GetFileAttributesA(CpuContext *c) {
    SetRet(c, Impl_GetFileAttributes(reinterpret_cast<const char *>(Arg0(c))));
}
void Stub_GetFileAttributesW(CpuContext *c) {
    const std::string path = Utf16ToUtf8(reinterpret_cast<const std::uint16_t *>(Arg0(c)));
    SetRet(c, Impl_GetFileAttributes(path.c_str()));
}
void Stub_GetFileAttributesExA(CpuContext *c) {
    SetRet(c, Impl_GetFileAttributesEx(reinterpret_cast<const char *>(Arg0(c)),
                                       static_cast<std::uint32_t>(Arg1(c)), Arg2(c)));
}
void Stub_GetFileAttributesExW(CpuContext *c) {
    const std::string path = Utf16ToUtf8(reinterpret_cast<const std::uint16_t *>(Arg0(c)));
    SetRet(c, Impl_GetFileAttributesEx(path.c_str(), static_cast<std::uint32_t>(Arg1(c)),
                                       Arg2(c)));
}
void Stub_FindFirstFileA(CpuContext *c) {
    SetRet(c, Impl_FindFirstFile(reinterpret_cast<const char *>(Arg0(c)), Arg1(c), false));
}
void Stub_FindFirstFileW(CpuContext *c) {
    const std::string path = Utf16ToUtf8(reinterpret_cast<const std::uint16_t *>(Arg0(c)));
    SetRet(c, Impl_FindFirstFile(path.c_str(), Arg1(c), true));
}
void Stub_FindNextFileA(CpuContext *c) { SetRet(c, Impl_FindNextFile(Arg0(c), Arg1(c))); }
void Stub_FindNextFileW(CpuContext *c) { SetRet(c, Impl_FindNextFile(Arg0(c), Arg1(c))); }
void Stub_FindClose(CpuContext *c) { SetRet(c, Impl_FindClose(Arg0(c))); }
void Stub_DeleteFileA(CpuContext *c) {
    SetRet(c, Impl_DeleteFile(reinterpret_cast<const char *>(Arg0(c))));
}
void Stub_DeleteFileW(CpuContext *c) {
    const std::string path = Utf16ToUtf8(reinterpret_cast<const std::uint16_t *>(Arg0(c)));
    SetRet(c, Impl_DeleteFile(path.c_str()));
}
void Stub_SetEndOfFile(CpuContext *c) { SetRet(c, Impl_SetEndOfFile(Arg0(c))); }

void Stub_OrdinalSuccess(CpuContext *c) {
    const std::uint64_t index = (g_active_thunk - kThunkBase) / kThunkStride;
    const char *name = index < kMaxStubs ? g_slot_name[index].c_str() : "";
    if (std::strcmp(name, "XInputGetState") == 0 && Arg1(c) != 0) {
        std::memset(reinterpret_cast<void *>(Arg1(c)), 0, 12);
    } else if (std::strcmp(name, "XInputGetCapabilities") == 0 && Arg2(c) != 0) {
        std::memset(reinterpret_cast<void *>(Arg2(c)), 0, 20);
    } else if (std::strcmp(name, "WSAStartup") == 0 && Arg1(c) != 0) {
        std::memset(reinterpret_cast<void *>(Arg1(c)), 0, 408);
        recomp::GuestStore<std::uint16_t>(Arg1(c), 0x0202);
        recomp::GuestStore<std::uint16_t>(Arg1(c) + sizeof(std::uint16_t), 0x0202);
    } else if (std::strcmp(name, "gethostname") == 0 && Arg0(c) != 0 && Arg1(c) != 0) {
        constexpr char kHostname[] = "android";
        const std::size_t capacity = static_cast<std::size_t>(Arg1(c));
        const std::size_t count = std::min(capacity, sizeof(kHostname));
        std::memcpy(reinterpret_cast<void *>(Arg0(c)), kHostname, count);
        if (count < capacity) {
            std::memset(reinterpret_cast<void *>(Arg0(c) + count), 0, capacity - count);
        } else {
            reinterpret_cast<char *>(Arg0(c))[capacity - 1] = '\0';
        }
    }
    SetRet32(c, 0);
}

void Stub_Htons(CpuContext *c) {
    const std::uint16_t value = static_cast<std::uint16_t>(Arg0(c));
    SetRet(c, static_cast<std::uint16_t>((value << 8) | (value >> 8)));
}

void Stub_Ntohs(CpuContext *c) { Stub_Htons(c); }

thread_local std::uint32_t g_wsa_last_error = 0;
void Stub_WSAGetLastError(CpuContext *c) { SetRet(c, g_wsa_last_error); }

void Stub_SysAllocString(CpuContext *c) {
    const auto *source = reinterpret_cast<const char16_t *>(Arg0(c));
    if (source == nullptr) {
        SetRet(c, 0);
        return;
    }
    std::size_t length = 0;
    while (length < (1u << 20) && source[length] != u'\0') ++length;
    if (length == (1u << 20) ||
        length > (SIZE_MAX - sizeof(std::uint32_t)) / sizeof(char16_t) - 1) {
        SetRet(c, 0);
        return;
    }
    const std::size_t byte_length = length * sizeof(char16_t);
    auto *allocation = static_cast<std::uint8_t *>(
        std::malloc(sizeof(std::uint32_t) + byte_length + sizeof(char16_t)));
    if (allocation == nullptr) {
        SetRet(c, 0);
        return;
    }
    const auto byte_length_32 = static_cast<std::uint32_t>(byte_length);
    std::memcpy(allocation, &byte_length_32, sizeof(byte_length_32));
    auto *string = reinterpret_cast<char16_t *>(allocation + sizeof(byte_length_32));
    std::memcpy(string, source, byte_length);
    string[length] = u'\0';
    SetRet(c, reinterpret_cast<std::uint64_t>(string));
}

void Stub_SysFreeString(CpuContext *c) {
    const std::uint64_t string = Arg0(c);
    if (string != 0) {
        std::free(reinterpret_cast<void *>(string - sizeof(std::uint32_t)));
    }
    SetRet(c, 0);
}

// ---------------------------------------------------------------------------
// CRT Bootstrap & Process/Thread Info
// ---------------------------------------------------------------------------
void Stub_GetSystemTimeAsFileTime(CpuContext *c) {
    auto *out = reinterpret_cast<std::uint64_t *>(Arg0(c));
    if (out) {
        timespec ts{};
        clock_gettime(CLOCK_REALTIME, &ts);
        std::uint64_t ft = (static_cast<std::uint64_t>(ts.tv_sec) * 10000000ull) +
                           (ts.tv_nsec / 100) + 116444736000000000ull;
        recomp::GuestStore<std::uint64_t>(Arg0(c), ft);
    }
    SetRet(c, 0);
}

void Stub_GetCurrentProcessId(CpuContext *c) {
    SetRet(c, static_cast<std::uint32_t>(getpid()));
}

void Stub_GetCurrentProcess(CpuContext *c) {
    SetRet(c, ~0ull);
}

void Stub_GetCurrentThread(CpuContext *c) {
    SetRet(c, static_cast<std::uint64_t>(static_cast<std::int64_t>(-2)));
}

void Stub_IsDebuggerPresent(CpuContext *c) {
    SetRet(c, 0);
}

void Stub_IsProcessorFeaturePresent(CpuContext *c) {
    std::uint32_t f = static_cast<std::uint32_t>(Arg0(c));
    if (f == 3 || f == 6 || f == 8 || f == 10 || f == 13 || f == 14) {
        SetRet(c, 1);
    } else {
        SetRet(c, 0);
    }
}

void Stub_EncodePointer(CpuContext *c) { SetRet(c, Arg0(c)); }
void Stub_DecodePointer(CpuContext *c) { SetRet(c, Arg0(c)); }

void Stub_InitializeCriticalSectionAndSpinCount(CpuContext *c) {
    CritFor(Arg0(c), true);
    SetRet(c, 1);
}

void Stub_memset(CpuContext *c) {
    const std::uint64_t destination = Arg0(c);
    const std::size_t size = static_cast<std::size_t>(Arg2(c));
    if (destination != 0 && size != 0) {
        std::memset(reinterpret_cast<void *>(destination),
                    static_cast<int>(Arg1(c)), size);
    }
    SetRet(c, destination);
}

void Stub_QueryPerformanceFrequency(CpuContext *c) {
    if (Arg0(c) != 0) {
        recomp::GuestStore<std::uint64_t>(Arg0(c), 1000000000ull);
    }
    SetRet(c, 1);
}

thread_local std::uint32_t g_last_error = 0;
void Stub_GetLastError(CpuContext *c) { SetRet(c, g_last_error); }
void Stub_SetLastError(CpuContext *c) {
    g_last_error = static_cast<std::uint32_t>(Arg0(c));
    SetRet(c, 0);
}
void Stub_SetErrorMode(CpuContext *c) { SetRet(c, 0); }

void Stub_GetSystemInfo(CpuContext *c) {
    auto *si = reinterpret_cast<std::uint8_t *>(Arg0(c));
    if (si) {
        std::memset(si, 0, 48);
        *reinterpret_cast<std::uint16_t *>(si + 0) = 9;
        *reinterpret_cast<std::uint32_t *>(si + 4) = 0x1000;
        *reinterpret_cast<std::uint64_t *>(si + 8) = 0x10000;
        *reinterpret_cast<std::uint64_t *>(si + 16) = 0x7FFFFFFEFFFFull;
        long cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (cores <= 0) cores = 8;
        *reinterpret_cast<std::uint64_t *>(si + 24) = (1ull << cores) - 1ull;
        *reinterpret_cast<std::uint32_t *>(si + 32) = static_cast<std::uint32_t>(cores);
        *reinterpret_cast<std::uint32_t *>(si + 36) = 0x10000;
    }
    SetRet(c, 0);
}

void Stub_GetModuleFileNameA(CpuContext *c) {
    char *buf = reinterpret_cast<char *>(Arg1(c));
    std::uint32_t sz = static_cast<std::uint32_t>(Arg2(c));
    if (buf && sz > 0) {
        std::string root = GetDataRoot();
        std::string p = root.empty() ? "Darksiders2.exe" : (root + "/Darksiders2.exe");
        std::strncpy(buf, p.c_str(), sz);
        buf[sz - 1] = '\0';
        SetRet(c, std::strlen(buf));
    } else {
        SetRet(c, 0);
    }
}

void Stub_GetModuleFileNameW(CpuContext *c) {
    auto *buf = reinterpret_cast<std::uint16_t *>(Arg1(c));
    std::uint32_t sz = static_cast<std::uint32_t>(Arg2(c));
    if (buf && sz > 0) {
        std::string root = GetDataRoot();
        std::string p = root.empty() ? "Darksiders2.exe" : (root + "/Darksiders2.exe");
        std::size_t len = std::min<std::size_t>(p.size(), sz - 1);
        for (std::size_t i = 0; i < len; ++i) buf[i] = static_cast<std::uint16_t>(p[i]);
        buf[len] = 0;
        SetRet(c, len);
    } else {
        SetRet(c, 0);
    }
}

void Stub_GetModuleHandleExA(CpuContext *c) {
    auto *out = reinterpret_cast<std::uint64_t *>(Arg2(c));
    if (out) *out = Impl_GetModuleHandle(reinterpret_cast<const char *>(Arg1(c)));
    SetRet(c, 1);
}

void Stub_GetModuleHandleExW(CpuContext *c) {
    auto *out = reinterpret_cast<std::uint64_t *>(Arg2(c));
    if (out) *out = Impl_GetModuleHandle(nullptr);
    SetRet(c, 1);
}

void Stub_ExitProcess(CpuContext *c) {
    Log("[win32] ExitProcess called: code %u", static_cast<unsigned>(Arg0(c)));
    exit(static_cast<int>(Arg0(c)));
}

void Stub_RaiseException(CpuContext *c) {
    Log("[win32] RaiseException: code 0x%x flags 0x%x",
        static_cast<unsigned>(Arg0(c)), static_cast<unsigned>(Arg1(c)));
    SetRet(c, 0);
}

void Stub_VirtualQuery(CpuContext *c) {
    auto *mbi = reinterpret_cast<std::uint8_t *>(Arg1(c));
    if (mbi && Arg2(c) >= 48) {
        std::memset(mbi, 0, 48);
        std::uint64_t addr = Arg0(c) & ~0xFFFull;
        *reinterpret_cast<std::uint64_t *>(mbi + 0) = addr;
        *reinterpret_cast<std::uint64_t *>(mbi + 8) = addr;
        *reinterpret_cast<std::uint32_t *>(mbi + 16) = PAGE_EXECUTE_READWRITE;
        *reinterpret_cast<std::uint64_t *>(mbi + 24) = 0x100000ull;
        *reinterpret_cast<std::uint32_t *>(mbi + 32) = MEM_COMMIT;
        *reinterpret_cast<std::uint32_t *>(mbi + 36) = PAGE_READWRITE;
        *reinterpret_cast<std::uint32_t *>(mbi + 40) = 0x20000u; // MEM_PRIVATE
        SetRet(c, 48);
    } else {
        SetRet(c, 0);
    }
}

// ---------------------------------------------------------------------------
// Synchronization: Events, Mutexes, Semaphores
// ---------------------------------------------------------------------------
struct WinSyncObject {
    enum Kind { kEvent, kMutex, kSemaphore } kind;
    bool manual_reset = false;
    std::atomic<bool> signaled{false};
    std::atomic<std::int32_t> count{0};
    std::mutex mtx;
    std::condition_variable cv;
};

std::mutex g_sync_mutex;
std::unordered_map<std::uint64_t, std::shared_ptr<WinSyncObject>> g_sync_objs;
std::uint64_t g_next_sync_handle = 0x500000ull;

std::uint64_t CreateSync(WinSyncObject::Kind kind, bool manual, bool init_signaled, int init_count) {
    auto obj = std::make_shared<WinSyncObject>();
    obj->kind = kind;
    obj->manual_reset = manual;
    obj->signaled = init_signaled;
    obj->count = init_count;
    std::lock_guard<std::mutex> lock(g_sync_mutex);
    std::uint64_t h = g_next_sync_handle++;
    g_sync_objs[h] = obj;
    RegisterHandle(h, HandleKind::kThread);
    return h;
}

void Stub_CreateEventA(CpuContext *c) {
    bool manual = Arg1(c) != 0;
    bool init = Arg2(c) != 0;
    SetRet(c, CreateSync(WinSyncObject::kEvent, manual, init, 0));
}

void Stub_CreateEventW(CpuContext *c) {
    bool manual = Arg1(c) != 0;
    bool init = Arg2(c) != 0;
    SetRet(c, CreateSync(WinSyncObject::kEvent, manual, init, 0));
}

void Stub_SetEvent(CpuContext *c) {
    std::shared_ptr<WinSyncObject> obj;
    {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        auto it = g_sync_objs.find(Arg0(c));
        if (it != g_sync_objs.end()) obj = it->second;
    }
    if (obj) {
        std::lock_guard<std::mutex> lock(obj->mtx);
        obj->signaled = true;
        obj->cv.notify_all();
    }
    SetRet(c, 1);
}

void Stub_ResetEvent(CpuContext *c) {
    std::shared_ptr<WinSyncObject> obj;
    {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        auto it = g_sync_objs.find(Arg0(c));
        if (it != g_sync_objs.end()) obj = it->second;
    }
    if (obj) {
        std::lock_guard<std::mutex> lock(obj->mtx);
        obj->signaled = false;
    }
    SetRet(c, 1);
}

void Stub_CreateMutexA(CpuContext *c) {
    bool owner = Arg1(c) != 0;
    SetRet(c, CreateSync(WinSyncObject::kMutex, false, !owner, 0));
}

void Stub_ReleaseMutex(CpuContext *c) {
    std::shared_ptr<WinSyncObject> obj;
    {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        auto it = g_sync_objs.find(Arg0(c));
        if (it != g_sync_objs.end()) obj = it->second;
    }
    if (obj) {
        std::lock_guard<std::mutex> lock(obj->mtx);
        obj->signaled = true;
        obj->cv.notify_one();
    }
    SetRet(c, 1);
}

void Stub_CreateSemaphoreA(CpuContext *c) {
    int init_count = static_cast<int>(Arg1(c));
    SetRet(c, CreateSync(WinSyncObject::kSemaphore, false, init_count > 0, init_count));
}

void Stub_CreateSemaphoreW(CpuContext *c) {
    int init_count = static_cast<int>(Arg1(c));
    SetRet(c, CreateSync(WinSyncObject::kSemaphore, false, init_count > 0, init_count));
}

void Stub_ReleaseSemaphore(CpuContext *c) {
    std::shared_ptr<WinSyncObject> obj;
    {
        std::lock_guard<std::mutex> lock(g_sync_mutex);
        auto it = g_sync_objs.find(Arg0(c));
        if (it != g_sync_objs.end()) obj = it->second;
    }
    if (obj) {
        int release = static_cast<int>(Arg1(c));
        if (release <= 0) release = 1;
        std::lock_guard<std::mutex> lock(obj->mtx);
        obj->count += release;
        obj->signaled = true;
        obj->cv.notify_all();
    }
    SetRet(c, 1);
}

void Stub_WaitForMultipleObjectsEx(CpuContext *c) {
    SetRet(c, WAIT_OBJECT_0);
}

// ---------------------------------------------------------------------------
// Thread Management & Strings
// ---------------------------------------------------------------------------
void Stub_ResumeThread(CpuContext *c) { SetRet(c, 1); }
void Stub_SuspendThread(CpuContext *c) { SetRet(c, 0); }
void Stub_SetThreadPriority(CpuContext *c) { SetRet(c, 1); }
void Stub_GetThreadPriority(CpuContext *c) { SetRet(c, 0); }
void Stub_SetThreadAffinityMask(CpuContext *c) { SetRet(c, 1); }
void Stub_GetExitCodeThread(CpuContext *c) {
    if (Arg1(c)) *reinterpret_cast<std::uint32_t *>(Arg1(c)) = 0;
    SetRet(c, 1);
}
void Stub_OutputDebugStringW(CpuContext *c) {
    const auto *w = reinterpret_cast<const std::uint16_t *>(Arg0(c));
    if (w) {
        std::string s = Utf16ToUtf8(w);
        Log("[guest] %s", s.c_str());
    }
    SetRet(c, 0);
}

void Stub_MultiByteToWideChar(CpuContext *c) {
    const char *src = reinterpret_cast<const char *>(Arg2(c));
    int srclen = static_cast<int>(Arg3(c));
    auto *dst = reinterpret_cast<std::uint16_t *>(Arg4(c));
    int dstlen = static_cast<int>(Arg5(c));
    if (srclen < 0 && src) srclen = static_cast<int>(std::strlen(src)) + 1;
    if (dstlen == 0) {
        SetRet(c, srclen > 0 ? srclen : 0);
        return;
    }
    if (src && dst) {
        int n = std::min(srclen, dstlen);
        for (int i = 0; i < n; ++i) dst[i] = static_cast<std::uint8_t>(src[i]);
        SetRet(c, n);
    } else {
        SetRet(c, 0);
    }
}

void Stub_WideCharToMultiByte(CpuContext *c) {
    const auto *src = reinterpret_cast<const std::uint16_t *>(Arg2(c));
    int srclen = static_cast<int>(Arg3(c));
    char *dst = reinterpret_cast<char *>(Arg4(c));
    int dstlen = static_cast<int>(Arg5(c));
    if (srclen < 0 && src) {
        srclen = 0;
        while (src[srclen] != 0) srclen++;
        srclen++;
    }
    if (dstlen == 0) {
        SetRet(c, srclen > 0 ? srclen : 0);
        return;
    }
    if (src && dst) {
        int n = std::min(srclen, dstlen);
        for (int i = 0; i < n; ++i) dst[i] = static_cast<char>(src[i] & 0x7F);
        SetRet(c, n);
    } else {
        SetRet(c, 0);
    }
}

// ---------------------------------------------------------------------------
// Global / Local Memory
// ---------------------------------------------------------------------------
void Stub_GlobalAlloc(CpuContext *c) {
    std::size_t sz = static_cast<std::size_t>(Arg1(c));
    SetRet(c, reinterpret_cast<std::uint64_t>(std::malloc(sz ? sz : 1)));
}
void Stub_GlobalLock(CpuContext *c) { SetRet(c, Arg0(c)); }
void Stub_GlobalUnlock(CpuContext *c) { SetRet(c, 0); }
void Stub_GlobalFree(CpuContext *c) {
    if (Arg0(c)) std::free(reinterpret_cast<void *>(Arg0(c)));
    SetRet(c, 0);
}
void Stub_LocalFree(CpuContext *c) {
    if (Arg0(c)) std::free(reinterpret_cast<void *>(Arg0(c)));
    SetRet(c, 0);
}
void Stub_FlushFileBuffers(CpuContext *c) { SetRet(c, 1); }
void Stub_SetHandleInformation(CpuContext *c) { SetRet(c, 1); }
void Stub_FreeLibrary(CpuContext *c) { SetRet(c, 1); }

void Stub_CreateDirectoryA(CpuContext *c) {
    const char *p = reinterpret_cast<const char *>(Arg0(c));
    if (p) {
        std::string r = ResolveGuestPath(p);
        mkdir(r.c_str(), 0755);
    }
    SetRet(c, 1);
}
void Stub_CreateDirectoryW(CpuContext *c) {
    const auto *w = reinterpret_cast<const std::uint16_t *>(Arg0(c));
    if (w) {
        std::string r = ResolveGuestPath(Utf16ToUtf8(w).c_str());
        mkdir(r.c_str(), 0755);
    }
    SetRet(c, 1);
}
void Stub_RemoveDirectoryA(CpuContext *c) {
    const char *p = reinterpret_cast<const char *>(Arg0(c));
    if (p) {
        std::string r = ResolveGuestPath(p);
        rmdir(r.c_str());
    }
    SetRet(c, 1);
}

// ---------------------------------------------------------------------------
// MSVCR120.dll C Runtime Stubs
// ---------------------------------------------------------------------------
void Stub_initterm(CpuContext *c) {
    std::uint64_t first = Arg0(c);
    std::uint64_t last = Arg1(c);
    if (first == 0 || last == 0 || first >= last) {
        SetRet(c, 0);
        return;
    }
    const std::uint64_t count = (last - first) / 8;
    Log("[crt] _initterm: %llu entries (0x%llx .. 0x%llx)",
        static_cast<unsigned long long>(count),
        static_cast<unsigned long long>(first),
        static_cast<unsigned long long>(last));
    for (std::uint64_t p = first; p < last; p += 8) {
        std::uint64_t fn = recomp::GuestLoad<std::uint64_t>(p);
        if (fn != 0 && g_api != nullptr) {
            c->rip = fn;
            g_api->call(c, fn, c->rip);
        }
    }
    SetRet(c, 0);
}

void Stub_initterm_e(CpuContext *c) {
    std::uint64_t first = Arg0(c);
    std::uint64_t last = Arg1(c);
    if (first == 0 || last == 0 || first >= last) {
        SetRet(c, 0);
        return;
    }
    Log("[crt] _initterm_e: 0x%llx .. 0x%llx",
        static_cast<unsigned long long>(first), static_cast<unsigned long long>(last));
    for (std::uint64_t p = first; p < last; p += 8) {
        std::uint64_t fn = recomp::GuestLoad<std::uint64_t>(p);
        if (fn != 0 && g_api != nullptr) {
            c->rip = fn;
            g_api->call(c, fn, c->rip);
            if (static_cast<std::int32_t>(c->r[recomp::RAX]) != 0) {
                SetRet(c, c->r[recomp::RAX]);
                return;
            }
        }
    }
    SetRet(c, 0);
}

void Stub_crt_lock(CpuContext *c) { SetRet(c, 0); }
void Stub_crt_unlock(CpuContext *c) { SetRet(c, 0); }
void Stub_onexit(CpuContext *c) { SetRet(c, Arg0(c)); }
void Stub_dllonexit(CpuContext *c) { SetRet(c, Arg0(c)); }
void Stub_XcptFilter(CpuContext *c) { SetRet(c, 1); }
void Stub_getmainargs(CpuContext *c) {
    static const char *kArgv[] = {"Darksiders2.exe", nullptr};
    static const char *kEnv[] = {nullptr};
    if (Arg0(c)) *reinterpret_cast<std::uint32_t *>(Arg0(c)) = 1;
    if (Arg1(c)) *reinterpret_cast<const char ***>(Arg1(c)) = kArgv;
    if (Arg2(c)) *reinterpret_cast<const char ***>(Arg2(c)) = kEnv;
    SetRet(c, 0);
}
void Stub_set_app_type(CpuContext *c) { SetRet(c, 0); }
void Stub_crtGetShowWindowMode(CpuContext *c) { SetRet(c, 10); }
void Stub_crtSetUnhandledExceptionFilter(CpuContext *c) {
    SetRet(c, g_unhandled_exception_filter.exchange(Arg0(c)));
}
void Stub_configthreadlocale(CpuContext *c) { SetRet(c, 0); }
static std::uint64_t g_dummy_locale = 0x10CAFE001ull;
void Stub_create_locale(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_dummy_locale)); }
void Stub_free_locale(CpuContext *c) { SetRet(c, 0); }
void Stub_setusermatherr(CpuContext *c) { SetRet(c, 0); }
void Stub_amsg_exit(CpuContext *c) { SetRet(c, 0); }
void Stub_cexit(CpuContext *c) { SetRet(c, 0); }
void Stub_exit(CpuContext *c) { exit(static_cast<int>(Arg0(c))); }
void Stub_abort(CpuContext * /*c*/) { exit(1); }

thread_local int g_crt_errno = 0;
void Stub_errno(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_crt_errno)); }
void Stub_purecall(CpuContext * /*c*/) { Log("[crt] pure virtual function call!"); }

void Stub_malloc(CpuContext *c) {
    SetRet(c, reinterpret_cast<std::uint64_t>(std::malloc(static_cast<std::size_t>(Arg0(c)))));
}
void Stub_calloc(CpuContext *c) {
    SetRet(c, reinterpret_cast<std::uint64_t>(std::calloc(static_cast<std::size_t>(Arg0(c)),
                                                          static_cast<std::size_t>(Arg1(c)))));
}
void Stub_realloc(CpuContext *c) {
    SetRet(c, reinterpret_cast<std::uint64_t>(std::realloc(reinterpret_cast<void *>(Arg0(c)),
                                                          static_cast<std::size_t>(Arg1(c)))));
}
void Stub_free(CpuContext *c) {
    if (Arg0(c)) std::free(reinterpret_cast<void *>(Arg0(c)));
    SetRet(c, 0);
}
void Stub_aligned_malloc(CpuContext *c) {
    std::size_t sz = static_cast<std::size_t>(Arg0(c));
    std::size_t al = static_cast<std::size_t>(Arg1(c));
    void *ptr = nullptr;
    if (al < sizeof(void *)) al = sizeof(void *);
    posix_memalign(&ptr, al, sz ? sz : 1);
    SetRet(c, reinterpret_cast<std::uint64_t>(ptr));
}
void Stub_aligned_free(CpuContext *c) {
    if (Arg0(c)) std::free(reinterpret_cast<void *>(Arg0(c)));
    SetRet(c, 0);
}

// ---------------------------------------------------------------------------
// SteamAPI Stubs
// ---------------------------------------------------------------------------
void Stub_SteamAPI_Init(CpuContext *c) {
    Log("[steam] SteamAPI_Init stubbed -> 1");
    SetRet(c, 1);
}
void Stub_SteamAPI_Shutdown(CpuContext *c) { SetRet(c, 0); }
void Stub_SteamAPI_RestartAppIfNecessary(CpuContext *c) { SetRet(c, 0); }
void Stub_SteamAPI_RunCallbacks(CpuContext *c) { SetRet(c, 0); }
void Stub_SteamAPI_RegisterCallback(CpuContext *c) { SetRet(c, 0); }
void Stub_SteamAPI_UnregisterCallback(CpuContext *c) { SetRet(c, 0); }
void Stub_SteamAPI_RegisterCallResult(CpuContext *c) { SetRet(c, 0); }
void Stub_SteamAPI_UnregisterCallResult(CpuContext *c) { SetRet(c, 0); }

static std::uint64_t g_steam_dummy_vtable[64] = {};
static std::uint64_t *g_steam_dummy_inst = g_steam_dummy_vtable;

void Stub_SteamUser(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_steam_dummy_inst)); }
void Stub_SteamUtils(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_steam_dummy_inst)); }
void Stub_SteamApps(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_steam_dummy_inst)); }
void Stub_SteamUserStats(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_steam_dummy_inst)); }
void Stub_SteamFriends(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_steam_dummy_inst)); }
void Stub_SteamRemoteStorage(CpuContext *c) { SetRet(c, reinterpret_cast<std::uint64_t>(&g_steam_dummy_inst)); }

// ---------------------------------------------------------------------------
// USER32.dll Stubs
// ---------------------------------------------------------------------------
void Stub_GetSystemMetrics(CpuContext *c) {
    std::uint32_t idx = static_cast<std::uint32_t>(Arg0(c));
    if (idx == 0) SetRet(c, 1280);
    else if (idx == 1) SetRet(c, 720);
    else SetRet(c, 0);
}
void Stub_GetClientRect(CpuContext *c) {
    auto *r = reinterpret_cast<std::int32_t *>(Arg1(c));
    if (r) { r[0] = 0; r[1] = 0; r[2] = 1280; r[3] = 720; }
    SetRet(c, 1);
}
void Stub_CreateWindowExA(CpuContext *c) { SetRet(c, 0x10001ull); }
void Stub_RegisterClassExA(CpuContext *c) { SetRet(c, 0x10002ull); }
void Stub_DefWindowProcA(CpuContext *c) { SetRet(c, 0); }
void Stub_ShowWindow(CpuContext *c) { SetRet(c, 1); }
void Stub_UpdateWindow(CpuContext *c) { SetRet(c, 1); }
void Stub_SetWindowPos(CpuContext *c) { SetRet(c, 1); }
void Stub_SetCursor(CpuContext *c) { SetRet(c, 0x10003ull); }
void Stub_ShowCursor(CpuContext *c) { SetRet(c, 1); }
void Stub_ClipCursor(CpuContext *c) { SetRet(c, 1); }
void Stub_LoadCursorA(CpuContext *c) { SetRet(c, 0x10004ull); }
void Stub_LoadIconA(CpuContext *c) { SetRet(c, 0x10005ull); }
void Stub_PeekMessageA(CpuContext *c) { SetRet(c, 0); }
void Stub_GetMessageA(CpuContext *c) { SetRet(c, 0); }
void Stub_TranslateMessage(CpuContext *c) { SetRet(c, 0); }
void Stub_DispatchMessageA(CpuContext *c) { SetRet(c, 0); }
void Stub_GetActiveWindow(CpuContext *c) { SetRet(c, 0x10001ull); }
void Stub_GetForegroundWindow(CpuContext *c) { SetRet(c, 0x10001ull); }
void Stub_SetFocus(CpuContext *c) { SetRet(c, 0x10001ull); }
void Stub_SetForegroundWindow(CpuContext *c) { SetRet(c, 1); }

// ---------------------------------------------------------------------------
// Fallback Generic Stub
// ---------------------------------------------------------------------------
void Stub_GenericFallback(CpuContext *c) {
    const std::uint64_t thunk = g_active_thunk;
    const std::uint64_t index = (thunk - kThunkBase) / kThunkStride;
    const char *owner = (index < kMaxStubs && !g_slot_owner[index].empty())
                            ? g_slot_owner[index].c_str()
                            : "?";
    const char *name = (index < kMaxStubs && !g_slot_name[index].empty())
                           ? g_slot_name[index].c_str()
                           : "?";
    Log("[win32] UNIMPLEMENTED IMPORT: %s!%s (rcx=0x%llx, rdx=0x%llx, r8=0x%llx, r9=0x%llx)",
        owner, name, Arg0(c), Arg1(c), Arg2(c), Arg3(c));
    SetRet(c, 0);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool IsThunk(std::uint64_t addr) noexcept { return addr >= kThunkBase && addr < kThunkEnd; }

void SetRecompApi(const RcApi *api) noexcept { g_api = api; }
const RcApi *GetRecompApi() noexcept { return g_api; }

// ---------------------------------------------------------------------------
// Virtual file system (public: the runtime resolves paths by the same rules)
// ---------------------------------------------------------------------------
std::string ResolveGuestPath(const char *win_path) {
    if (win_path == nullptr) return std::string();
    const std::string rel = NormalizeWinPath(win_path);
    const std::string root = EffectiveRoot();
    if (rel.empty()) return root;
    if (root.empty()) return rel;
    if (root.back() == '/') return root + rel;
    return root + "/" + rel;
}

void SetDataRoot(const char *root) {
    std::lock_guard<std::mutex> lock(g_path_mutex);
    if (root == nullptr) {
        g_data_root.clear();
        return;
    }
    std::string p = root;
    for (char &c : p) {
        if (c == '\\') c = '/';
    }
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    g_data_root = p;
}

std::string GetDataRoot() { return EffectiveRoot(); }

// ---------------------------------------------------------------------------
void SetRenderingWindow(std::uint64_t sdl_window) {
    g_sdl_window.store(sdl_window);
}

bool HasModule(const char *module) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    return g_module_base.count(Lower(module ? module : "")) > 0;
}

std::uint64_t ModuleBase(const char *module) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    return ModuleBaseLocked(Lower(module ? module : ""), true);
}

// ---------------------------------------------------------------------------
// Guest instructions the translator could not emit
// ---------------------------------------------------------------------------
// Darksiders2.exe offset 0x2ACD is `cvtsd2ss xmm0, xmm0`, in the middle of the
// function that starts at 0x2AB4:
//
//      ...                 mulsd  xmm0, [0x1416B45E0]
//      0x2ACD              cvtsd2ss xmm0, xmm0        <- rc->interp(c)
//      0x2AD1              movss  [0x141F0CC10], xmm0
//      ...                 add rsp, 0x28 / ret
//
// The generated function calls rc->interp() and then resumes at 0x2AD1, so the
// instruction form only converts (and leaves the other xmm lanes untouched, as
// legacy CVTSD2SS does). 0x2ACD is not a real function entry -- it is the
// middle of 0x2AB4 -- but the recompiler also emits an f_2acd entry, so the
// function form keeps the guest ABI if the dispatcher ever enters it directly:
// it converts, pops the return address and advances RSP.
void Stub_FloatConverterInstruction(CpuContext *c) {
    const double value = c->v[0].fd[0];
    c->v[0].f[0] = static_cast<float>(value);
}

void Stub_FloatConverter(CpuContext *c) {
    const double value = c->v[0].fd[0];
    c->v[0].f[0] = static_cast<float>(value);
    c->rip = recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP]);
    c->r[recomp::RSP] += sizeof(std::uint64_t);
}

void RegisterBuiltins() {
    static std::once_flag once;
    std::call_once(once, [] {
        struct Entry {
            const char *module;
            const char *name;
            StubFn fn;
        };
        static const Entry kEntries[] = {
            {"xinput1_3.dll", "XInputGetState", Stub_OrdinalSuccess},
            {"xinput1_3.dll", "XInputSetState", Stub_OrdinalSuccess},
            {"xinput1_3.dll", "XInputGetCapabilities", Stub_OrdinalSuccess},
            {"ws2_32.dll", "accept", Stub_OrdinalSuccess},
            {"ws2_32.dll", "bind", Stub_OrdinalSuccess},
            {"ws2_32.dll", "closesocket", Stub_OrdinalSuccess},
            {"ws2_32.dll", "connect", Stub_OrdinalSuccess},
            {"ws2_32.dll", "getsockname", Stub_OrdinalSuccess},
            {"ws2_32.dll", "htons", Stub_Htons},
            {"ws2_32.dll", "ioctlsocket", Stub_OrdinalSuccess},
            {"ws2_32.dll", "listen", Stub_OrdinalSuccess},
            {"ws2_32.dll", "ntohs", Stub_Ntohs},
            {"ws2_32.dll", "recv", Stub_OrdinalSuccess},
            {"ws2_32.dll", "select", Stub_OrdinalSuccess},
            {"ws2_32.dll", "send", Stub_OrdinalSuccess},
            {"ws2_32.dll", "setsockopt", Stub_OrdinalSuccess},
            {"ws2_32.dll", "gethostname", Stub_OrdinalSuccess},
            {"ws2_32.dll", "WSAGetLastError", Stub_WSAGetLastError},
            {"ws2_32.dll", "WSAStartup", Stub_OrdinalSuccess},
            {"ws2_32.dll", "__WSAFDIsSet", Stub_OrdinalSuccess},
            {"oleaut32.dll", "SysAllocString", Stub_SysAllocString},
            {"oleaut32.dll", "SysFreeString", Stub_SysFreeString},
            {"kernel32.dll", "VirtualAlloc", Stub_VirtualAlloc},
            {"kernel32.dll", "VirtualFree", Stub_VirtualFree},
            {"kernel32.dll", "VirtualProtect", Stub_VirtualProtect},
            {"kernel32.dll", "GetModuleHandleA", Stub_GetModuleHandleA},
            {"kernel32.dll", "GetModuleHandleW", Stub_GetModuleHandleA},
            {"kernel32.dll", "LoadLibraryA", Stub_LoadLibraryA},
            {"kernel32.dll", "GetProcAddress", Stub_GetProcAddress},
            {"kernel32.dll", "CreateThread", Stub_CreateThread},
            {"kernel32.dll", "WaitForSingleObject", Stub_WaitForSingleObject},
            {"kernel32.dll", "CloseHandle", Stub_CloseHandle},
            {"kernel32.dll", "InitializeCriticalSection", Stub_InitializeCriticalSection},
            {"kernel32.dll", "EnterCriticalSection", Stub_EnterCriticalSection},
            {"kernel32.dll", "LeaveCriticalSection", Stub_LeaveCriticalSection},
            {"kernel32.dll", "DeleteCriticalSection", Stub_DeleteCriticalSection},
            {"kernel32.dll", "TryEnterCriticalSection", Stub_TryEnterCriticalSection},
            {"kernel32.dll", "InterlockedIncrement", Stub_InterlockedIncrement},
            {"kernel32.dll", "InterlockedDecrement", Stub_InterlockedDecrement},
            {"kernel32.dll", "InterlockedExchange", Stub_InterlockedExchange},
            {"kernel32.dll", "InterlockedCompareExchange", Stub_InterlockedCompareExchange},
            {"kernel32.dll", "Sleep", Stub_Sleep},
            {"kernel32.dll", "GetTickCount64", Stub_GetTickCount64},
            {"kernel32.dll", "GetTickCount", Stub_GetTickCount64},
            {"kernel32.dll", "QueryPerformanceCounter", Stub_QueryPerformanceCounter},
            {"kernel32.dll", "GetCurrentThreadId", Stub_GetCurrentThreadId},
            {"kernel32.dll", "TlsAlloc", Stub_TlsAlloc},
            {"kernel32.dll", "TlsGetValue", Stub_TlsGetValue},
            {"kernel32.dll", "TlsSetValue", Stub_TlsSetValue},
            {"kernel32.dll", "TlsFree", Stub_TlsFree},
            {"kernel32.dll", "OutputDebugStringA", Stub_OutputDebugStringA},
            {"kernel32.dll", "CreateFileA", Stub_CreateFileA},
            {"kernel32.dll", "CreateFileW", Stub_CreateFileW},
            {"kernel32.dll", "ReadFile", Stub_ReadFile},
            {"kernel32.dll", "WriteFile", Stub_WriteFile},
            {"kernel32.dll", "SetFilePointer", Stub_SetFilePointer},
            {"kernel32.dll", "SetFilePointerEx", Stub_SetFilePointerEx},
            {"kernel32.dll", "GetFileSize", Stub_GetFileSize},
            {"kernel32.dll", "GetFileSizeEx", Stub_GetFileSizeEx},
            {"kernel32.dll", "CreateFileMappingA", Stub_CreateFileMappingA},
            {"kernel32.dll", "CreateFileMappingW", Stub_CreateFileMappingW},
            {"kernel32.dll", "MapViewOfFile", Stub_MapViewOfFile},
            {"kernel32.dll", "UnmapViewOfFile", Stub_UnmapViewOfFile},
            {"kernel32.dll", "GetFileAttributesA", Stub_GetFileAttributesA},
            {"kernel32.dll", "GetFileAttributesW", Stub_GetFileAttributesW},
            {"kernel32.dll", "GetFileAttributesExA", Stub_GetFileAttributesExA},
            {"kernel32.dll", "GetFileAttributesExW", Stub_GetFileAttributesExW},
            {"kernel32.dll", "FindFirstFileA", Stub_FindFirstFileA},
            {"kernel32.dll", "FindFirstFileW", Stub_FindFirstFileW},
            {"kernel32.dll", "FindNextFileA", Stub_FindNextFileA},
            {"kernel32.dll", "FindNextFileW", Stub_FindNextFileW},
            {"kernel32.dll", "FindClose", Stub_FindClose},
            {"kernel32.dll", "DeleteFileA", Stub_DeleteFileA},
            {"kernel32.dll", "DeleteFileW", Stub_DeleteFileW},
            {"kernel32.dll", "SetEndOfFile", Stub_SetEndOfFile},
#if defined(D2_HAS_DXVK_D3D9)
            {"d3d9.dll", "Direct3DCreate9", Stub_D3D9Create},
#endif

            // Kernel32 CRT Bootstrap & Diagnostics
            {"kernel32.dll", "GetSystemTimeAsFileTime", Stub_GetSystemTimeAsFileTime},
            {"kernel32.dll", "GetCurrentProcessId", Stub_GetCurrentProcessId},
            {"kernel32.dll", "GetCurrentProcess", Stub_GetCurrentProcess},
            {"kernel32.dll", "GetCurrentThread", Stub_GetCurrentThread},
            {"kernel32.dll", "IsDebuggerPresent", Stub_IsDebuggerPresent},
            {"kernel32.dll", "IsProcessorFeaturePresent", Stub_IsProcessorFeaturePresent},
            {"kernel32.dll", "EncodePointer", Stub_EncodePointer},
            {"kernel32.dll", "DecodePointer", Stub_DecodePointer},
            {"kernel32.dll", "InitializeCriticalSectionAndSpinCount", Stub_InitializeCriticalSectionAndSpinCount},
            {"kernel32.dll", "QueryPerformanceFrequency", Stub_QueryPerformanceFrequency},
            {"kernel32.dll", "GetLastError", Stub_GetLastError},
            {"kernel32.dll", "SetLastError", Stub_SetLastError},
            {"kernel32.dll", "SetErrorMode", Stub_SetErrorMode},
            {"kernel32.dll", "GetSystemInfo", Stub_GetSystemInfo},
            {"kernel32.dll", "GetModuleFileNameA", Stub_GetModuleFileNameA},
            {"kernel32.dll", "GetModuleFileNameW", Stub_GetModuleFileNameW},
            {"kernel32.dll", "GetModuleHandleExA", Stub_GetModuleHandleExA},
            {"kernel32.dll", "GetModuleHandleExW", Stub_GetModuleHandleExW},
            {"kernel32.dll", "ExitProcess", Stub_ExitProcess},
            {"kernel32.dll", "RaiseException", Stub_RaiseException},
            {"kernel32.dll", "VirtualQuery", Stub_VirtualQuery},
            {"kernel32.dll", "CreateEventA", Stub_CreateEventA},
            {"kernel32.dll", "CreateEventW", Stub_CreateEventW},
            {"kernel32.dll", "SetEvent", Stub_SetEvent},
            {"kernel32.dll", "ResetEvent", Stub_ResetEvent},
            {"kernel32.dll", "CreateMutexA", Stub_CreateMutexA},
            {"kernel32.dll", "ReleaseMutex", Stub_ReleaseMutex},
            {"kernel32.dll", "CreateSemaphoreA", Stub_CreateSemaphoreA},
            {"kernel32.dll", "CreateSemaphoreW", Stub_CreateSemaphoreW},
            {"kernel32.dll", "ReleaseSemaphore", Stub_ReleaseSemaphore},
            {"kernel32.dll", "WaitForMultipleObjectsEx", Stub_WaitForMultipleObjectsEx},
            {"kernel32.dll", "ResumeThread", Stub_ResumeThread},
            {"kernel32.dll", "SuspendThread", Stub_SuspendThread},
            {"kernel32.dll", "SetThreadPriority", Stub_SetThreadPriority},
            {"kernel32.dll", "GetThreadPriority", Stub_GetThreadPriority},
            {"kernel32.dll", "SetThreadAffinityMask", Stub_SetThreadAffinityMask},
            {"kernel32.dll", "GetExitCodeThread", Stub_GetExitCodeThread},
            {"kernel32.dll", "OutputDebugStringW", Stub_OutputDebugStringW},
            {"kernel32.dll", "MultiByteToWideChar", Stub_MultiByteToWideChar},
            {"kernel32.dll", "WideCharToMultiByte", Stub_WideCharToMultiByte},
            {"kernel32.dll", "GlobalAlloc", Stub_GlobalAlloc},
            {"kernel32.dll", "GlobalLock", Stub_GlobalLock},
            {"kernel32.dll", "GlobalUnlock", Stub_GlobalUnlock},
            {"kernel32.dll", "GlobalFree", Stub_GlobalFree},
            {"kernel32.dll", "LocalFree", Stub_LocalFree},
            {"kernel32.dll", "FlushFileBuffers", Stub_FlushFileBuffers},
            {"kernel32.dll", "SetHandleInformation", Stub_SetHandleInformation},
            {"kernel32.dll", "FreeLibrary", Stub_FreeLibrary},
            {"kernel32.dll", "CreateDirectoryA", Stub_CreateDirectoryA},
            {"kernel32.dll", "CreateDirectoryW", Stub_CreateDirectoryW},
            {"kernel32.dll", "RemoveDirectoryA", Stub_RemoveDirectoryA},

            // MSVCR120.dll C Runtime
            {"msvcr120.dll", "_initterm", Stub_initterm},
            {"msvcr120.dll", "_initterm_e", Stub_initterm_e},
            {"msvcr120.dll", "__crtGetShowWindowMode", Stub_crtGetShowWindowMode},
            {"msvcr120.dll", "__crtSetUnhandledExceptionFilter",
             Stub_crtSetUnhandledExceptionFilter},
            {"msvcr120.dll", "_lock", Stub_crt_lock},
            {"msvcr120.dll", "_unlock", Stub_crt_unlock},
            {"msvcr120.dll", "_onexit", Stub_onexit},
            {"msvcr120.dll", "__dllonexit", Stub_dllonexit},
            {"msvcr120.dll", "_XcptFilter", Stub_XcptFilter},
            {"msvcr120.dll", "__getmainargs", Stub_getmainargs},
            {"msvcr120.dll", "__set_app_type", Stub_set_app_type},
            {"msvcr120.dll", "_configthreadlocale", Stub_configthreadlocale},
            {"msvcr120.dll", "_create_locale", Stub_create_locale},
            {"msvcr120.dll", "_free_locale", Stub_free_locale},
            {"msvcr120.dll", "__setusermatherr", Stub_setusermatherr},
            {"msvcr120.dll", "_amsg_exit", Stub_amsg_exit},
            {"msvcr120.dll", "_cexit", Stub_cexit},
            {"msvcr120.dll", "_exit", Stub_exit},
            {"msvcr120.dll", "exit", Stub_exit},
            {"msvcr120.dll", "abort", Stub_abort},
            {"msvcr120.dll", "_errno", Stub_errno},
            {"msvcr120.dll", "_purecall", Stub_purecall},
            {"msvcr120.dll", "malloc", Stub_malloc},
            {"msvcr120.dll", "calloc", Stub_calloc},
            {"msvcr120.dll", "realloc", Stub_realloc},
            {"msvcr120.dll", "free", Stub_free},
            {"msvcr120.dll", "_aligned_malloc", Stub_aligned_malloc},
            {"msvcr120.dll", "_aligned_free", Stub_aligned_free},
            {"msvcr120.dll", "memset", Stub_memset},
            

            // steam_api64.dll
            {"steam_api64.dll", "SteamAPI_Init", Stub_SteamAPI_Init},
            {"steam_api64.dll", "SteamAPI_Shutdown", Stub_SteamAPI_Shutdown},
            {"steam_api64.dll", "SteamAPI_RestartAppIfNecessary", Stub_SteamAPI_RestartAppIfNecessary},
            {"steam_api64.dll", "SteamAPI_RunCallbacks", Stub_SteamAPI_RunCallbacks},
            {"steam_api64.dll", "SteamAPI_RegisterCallback", Stub_SteamAPI_RegisterCallback},
            {"steam_api64.dll", "SteamAPI_UnregisterCallback", Stub_SteamAPI_UnregisterCallback},
            {"steam_api64.dll", "SteamAPI_RegisterCallResult", Stub_SteamAPI_RegisterCallResult},
            {"steam_api64.dll", "SteamAPI_UnregisterCallResult", Stub_SteamAPI_UnregisterCallResult},
            {"steam_api64.dll", "SteamUser", Stub_SteamUser},
            {"steam_api64.dll", "SteamUtils", Stub_SteamUtils},
            {"steam_api64.dll", "SteamApps", Stub_SteamApps},
            {"steam_api64.dll", "SteamUserStats", Stub_SteamUserStats},
            {"steam_api64.dll", "SteamFriends", Stub_SteamFriends},
            {"steam_api64.dll", "SteamRemoteStorage", Stub_SteamRemoteStorage},

            // user32.dll
            {"user32.dll", "GetSystemMetrics", Stub_GetSystemMetrics},
            {"user32.dll", "GetClientRect", Stub_GetClientRect},
            {"user32.dll", "CreateWindowExA", Stub_CreateWindowExA},
            {"user32.dll", "RegisterClassExA", Stub_RegisterClassExA},
            {"user32.dll", "DefWindowProcA", Stub_DefWindowProcA},
            {"user32.dll", "ShowWindow", Stub_ShowWindow},
            {"user32.dll", "UpdateWindow", Stub_UpdateWindow},
            {"user32.dll", "SetWindowPos", Stub_SetWindowPos},
            {"user32.dll", "SetCursor", Stub_SetCursor},
            {"user32.dll", "ShowCursor", Stub_ShowCursor},
            {"user32.dll", "ClipCursor", Stub_ClipCursor},
            {"user32.dll", "LoadCursorA", Stub_LoadCursorA},
            {"user32.dll", "LoadIconA", Stub_LoadIconA},
            {"user32.dll", "PeekMessageA", Stub_PeekMessageA},
            {"user32.dll", "GetMessageA", Stub_GetMessageA},
            {"user32.dll", "TranslateMessage", Stub_TranslateMessage},
            {"user32.dll", "DispatchMessageA", Stub_DispatchMessageA},
            {"user32.dll", "GetActiveWindow", Stub_GetActiveWindow},
            {"user32.dll", "GetForegroundWindow", Stub_GetForegroundWindow},
            {"user32.dll", "SetFocus", Stub_SetFocus},
            {"user32.dll", "SetForegroundWindow", Stub_SetForegroundWindow},
        };
        for (const Entry &e : kEntries) {
            AddStub(e.module, e.name, e.fn);
            // kernelbase is not registered separately: ResolveImport forwards it
            // to kernel32 so both names yield the *same* thunk (Windows 10 does
            // the same forwarding, and one thunk keeps identity checks working).
        }
        Log("[win32] %zu built-in stubs registered", sizeof(kEntries) / sizeof(kEntries[0]));
    });
}

std::uint64_t ResolveImport(const char *module, const char *name) {
    RegisterBuiltins();
    std::uint16_t ordinal = 0;
    if (ParseOrdinalName(name, ordinal)) return ResolveImportOrdinal(module, ordinal);

    const std::string mod = Lower(module ? module : "");
    if (mod == "msvcr120.dll" && name != nullptr) {
        if (std::strcmp(name, "_fmode") == 0) {
            return reinterpret_cast<std::uint64_t>(&g_crt_fmode);
        }
        if (std::strcmp(name, "_commode") == 0) {
            return reinterpret_cast<std::uint64_t>(&g_crt_commode);
        }
    }

    const std::string key = Key(module, name);
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    auto it = g_exports.find(key);
    if (it != g_exports.end()) return it->second;

    const char *alt = nullptr;
    if (mod == "kernel32.dll") alt = "kernelbase.dll";
    else if (mod == "kernelbase.dll") alt = "kernel32.dll";
    if (alt != nullptr) {
        auto it2 = g_exports.find(Key(alt, name));
        if (it2 != g_exports.end()) return it2->second;
    }

    // Auto-create a fallback thunk so the guest never jumps into unmapped memory.
    if ((g_next_thunk - kThunkBase) / kThunkStride < kMaxStubs) {
        const std::uint64_t thunk = g_next_thunk;
        g_next_thunk += kThunkStride;
        const std::size_t idx = (thunk - kThunkBase) / kThunkStride;
        g_slot_table[idx] = Stub_GenericFallback;
        g_slot_owner[idx] = module ? module : "?";
        g_slot_name[idx] = name ? name : "?";
        g_exports[key] = thunk;
        Log("[win32] auto-bound fallback stub for %s!%s (thunk 0x%llx)",
            module ? module : "?", name ? name : "?",
            static_cast<unsigned long long>(thunk));
        return thunk;
    }
    return 0;
}

std::uint64_t ResolveImportOrdinal(const char *module, std::uint16_t ordinal) {
    RegisterBuiltins();
    if (const char *name = OrdinalExportName(module, ordinal)) {
        return ResolveImport(module, name);
    }

    const std::string key = OrdinalKey(module, ordinal);
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    auto it = g_exports.find(key);
    if (it != g_exports.end()) return it->second;

    const std::string mod = Lower(module ? module : "");
    const char *alt = nullptr;
    if (mod == "kernel32.dll") alt = "kernelbase.dll";
    else if (mod == "kernelbase.dll") alt = "kernel32.dll";
    if (alt != nullptr) {
        auto it2 = g_exports.find(OrdinalKey(alt, ordinal));
        if (it2 != g_exports.end()) return it2->second;
    }

    if ((g_next_thunk - kThunkBase) / kThunkStride >= kMaxStubs) {
        Log("[win32] thunk table full, dropping %s ordinal %u", module ? module : "?", ordinal);
        return 0;
    }

    const std::uint64_t thunk = g_next_thunk;
    g_next_thunk += kThunkStride;
    const std::size_t idx = (thunk - kThunkBase) / kThunkStride;
    g_slot_table[idx] = Stub_GenericFallback;
    g_slot_owner[idx] = module ? module : "?";
    g_slot_name[idx] = "Ordinal_" + std::to_string(ordinal);
    g_exports[key] = thunk;
    Log("[win32] auto-bound fallback stub for %s ordinal %u (thunk 0x%llx)",
        module ? module : "?", ordinal, static_cast<unsigned long long>(thunk));
    return thunk;
}

bool Dispatch(CpuContext *c, std::uint64_t thunk) {
    if (!IsThunk(thunk)) return false;
    const std::uint64_t index = (thunk - kThunkBase) / kThunkStride;
    if (index >= kMaxStubs) return false;
    const StubFn fn = g_slot_table[index];
    if (fn == nullptr) return false;
    const std::uint64_t previous = g_active_thunk;
    g_active_thunk = thunk;
    fn(c);
    g_active_thunk = previous;
    return true;
}

void LogMissingImport(const char *module, const char *name) {
    Log("[win32] unimplemented import: %s!%s", module ? module : "?",
        name ? name : "?");
}

void Shutdown() {
    {
        std::lock_guard<std::mutex> lock(g_crit_mutex);
        for (auto &kv : g_crit) {
            pthread_mutex_destroy(kv.second);
            delete kv.second;
        }
        g_crit.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_handle_mutex);
        for (auto &kv : g_handles) {
            switch (kv.second) {
                case HandleKind::kThread: {
                    auto *t = reinterpret_cast<GuestThread *>(kv.first);
                    pthread_join(t->tid, nullptr);
                    munmap(t->stack, t->stack_size);
                    t->magic = 0;
                    delete t;
                    break;
                }
                case HandleKind::kFile: {
                    auto *f = reinterpret_cast<GuestFile *>(kv.first);
                    if (f != nullptr) {
                        ::close(f->fd);
                        f->magic = 0;
                        delete f;
                    }
                    break;
                }
                case HandleKind::kFileMapping: {
                    auto *m = reinterpret_cast<GuestMapping *>(kv.first);
                    if (m != nullptr) {
                        m->magic = 0;
                        delete m;
                    }
                    break;
                }
                case HandleKind::kFind: {
                    auto *scan = reinterpret_cast<GuestFind *>(kv.first);
                    if (scan != nullptr) {
                        if (scan->dir != nullptr) ::closedir(scan->dir);
                        scan->magic = 0;
                        delete scan;
                    }
                    break;
                }
                case HandleKind::kFileView:
                    break;  // handled from g_views below
            }
        }
        g_handles.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_view_mutex);
        for (auto &kv : g_views) {
            munmap(reinterpret_cast<void *>(kv.second.mmap_base), kv.second.length);
        }
        g_views.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_tls_mutex);
        for (std::size_t i = 0; i < g_tls_keys.size(); ++i) {
            if (g_tls_used[i]) pthread_key_delete(g_tls_keys[i]);
        }
        g_tls_keys.clear();
        g_tls_used.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_region_mutex);
        for (auto &kv : g_regions) {
            munmap(reinterpret_cast<void *>(kv.first), kv.second.size);
        }
        g_regions.clear();
    }
}

}  // namespace darksiders2::win32
// Stubs em C puro com a assinatura correta esperada pela tabela de OUT.c
