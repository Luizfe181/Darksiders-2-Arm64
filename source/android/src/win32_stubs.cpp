// win32_stubs.cpp -- Win32 API shims: Windows -> POSIX/Android.
//
// Every shim reads the Win64 guest ABI itself (rcx, rdx, r8, r9, then the stack
// at [rsp+0x28], [rsp+0x30]) and writes the result to guest RAX. See
// win32_stubs.h for why the stubs are shaped this way.
#include "win32_stubs.h"

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
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <dirent.h>
#include <dlfcn.h>
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
inline std::uint64_t Arg7(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x40);
}
inline std::uint64_t Arg8(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x48);
}
inline std::uint64_t Arg9(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x50);
}
inline std::uint64_t Arg10(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x58);
}
inline std::uint64_t Arg11(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x60);
}
inline void SetRet(CpuContext *c, std::uint64_t v) { c->r[recomp::RAX] = v; }
// HRESULT is 32 bits; the guest reads EAX, so sign-extend for clarity.
inline void SetRet32(CpuContext *c, std::int32_t v) {
    c->r[recomp::RAX] = static_cast<std::uint64_t>(static_cast<std::int64_t>(v));
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
constexpr std::size_t kMaxStubs = 1024;
constexpr std::uint64_t kThunkStride = 0x10;
constexpr std::uint64_t kModuleBaseStart = 0x00007F01'00000000ull;

std::mutex g_registry_mutex;
std::unordered_map<std::string, std::uint64_t> g_exports;  // "mod!fn" -> thunk
std::unordered_map<std::string, std::uint64_t> g_module_base;
std::unordered_map<std::uint64_t, std::string> g_module_name;
StubFn g_slot_table[kMaxStubs] = {};   // filled before any guest thread starts
// Names for tracing: an import is "module/name", a COM method "Interface/name".
const char *g_slot_owner[kMaxStubs] = {};
const char *g_slot_name[kMaxStubs] = {};
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
    // MAKEINTRESOURCE(ordinal): high 16 bits clear. Ordinals are not mapped yet.
    if ((reinterpret_cast<std::uintptr_t>(name) >> 16) == 0) {
        Log("[win32] GetProcAddress: ordinal %llu unsupported module=0x%llx",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(name)),
            static_cast<unsigned long long>(module));
        return 0;
    }

    std::string mod;
    {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        auto it = g_module_name.find(module);
        mod = (it != g_module_name.end()) ? it->second : std::string();
    }
    if (mod.empty()) return 0;

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
// D3D11 / DXGI mock objects -- COM tracing
//
// The guest reaches D3D11 through COM vtables: its `call [rax + 8*n]` becomes
// rc->call(c, target, ret), so every vtable slot has to be a thunk in the same
// synthetic space as an import. That is what makes the calls traceable without
// a host function pointer ever reaching the guest.
//
// Win64 COM arguments: `this` in RCX, then RDX, R8, R9, then the stack. Every
// helper below is shifted by one relative to the free-function stubs.
//
// The mocks return S_OK so the engine keeps walking its boot sequence: the point
// is to learn which methods it calls, not to render.
// ---------------------------------------------------------------------------
namespace com {

constexpr std::size_t kDevice = 0;
constexpr std::size_t kContext = 1;
constexpr std::size_t kSwapChain = 2;
constexpr std::size_t kFactory = 3;
constexpr std::size_t kTexture = 4;
constexpr std::size_t kInterfaceCount = 5;

struct NamedSlot {
    std::size_t index;
    const char *name;
};

// Only the indices that are certain are named; the rest report as Method_<n>.
// A wrong name would be worse than none when the goal is to learn the API.
constexpr NamedSlot kDeviceNames[] = {
    {0, "QueryInterface"}, {1, "AddRef"}, {2, "Release"},
    {3, "CreateBuffer"}, {5, "CreateTexture2D"}, {7, "CreateShaderResourceView"},
    {9, "CreateRenderTargetView"}, {10, "CreateDepthStencilView"},
    {11, "CreateInputLayout"}, {12, "CreateVertexShader"}, {15, "CreatePixelShader"},
    {20, "CreateBlendState"}, {21, "CreateDepthStencilState"},
    {22, "CreateRasterizerState"}, {23, "CreateSamplerState"},
    {29, "CheckFormatSupport"}, {33, "CheckFeatureSupport"},
    {37, "GetFeatureLevel"}, {40, "GetImmediateContext"},
};

constexpr NamedSlot kContextNames[] = {
    {0, "QueryInterface"}, {1, "AddRef"}, {2, "Release"}, {3, "GetDevice"},
    {13, "DrawIndexed"}, {14, "Draw"}, {15, "Map"}, {16, "Unmap"},
};

constexpr NamedSlot kSwapChainNames[] = {
    {0, "QueryInterface"}, {1, "AddRef"}, {2, "Release"},
    {3, "SetPrivateData"}, {4, "SetPrivateDataInterface"}, {5, "GetPrivateData"},
    {6, "GetParent"}, {7, "GetDevice"}, {8, "Present"}, {9, "GetBuffer"},
    {10, "SetFullscreenState"}, {11, "GetFullscreenState"}, {12, "GetDesc"},
    {13, "ResizeBuffers"}, {14, "ResizeTarget"},
};

constexpr NamedSlot kFactoryNames[] = {
    {0, "QueryInterface"}, {1, "AddRef"}, {2, "Release"},
    {7, "EnumAdapters"}, {10, "CreateSwapChain"}, {11, "CreateSoftwareAdapter"},
};

constexpr NamedSlot kTextureNames[] = {
    {0, "QueryInterface"}, {1, "AddRef"}, {2, "Release"},
};

struct InterfaceDef {
    const char *name;
    std::size_t slots;
    const NamedSlot *names;
    std::size_t name_count;
    std::vector<std::uint64_t> vtable;
};

InterfaceDef g_interfaces[kInterfaceCount] = {
    {"ID3D11Device", 44, kDeviceNames,
     sizeof(kDeviceNames) / sizeof(kDeviceNames[0]), {}},
    {"ID3D11DeviceContext", 112, kContextNames,
     sizeof(kContextNames) / sizeof(kContextNames[0]), {}},
    {"IDXGISwapChain", 20, kSwapChainNames,
     sizeof(kSwapChainNames) / sizeof(kSwapChainNames[0]), {}},
    {"IDXGIFactory", 14, kFactoryNames,
     sizeof(kFactoryNames) / sizeof(kFactoryNames[0]), {}},
    {"ID3D11Texture2D", 14, kTextureNames,
     sizeof(kTextureNames) / sizeof(kTextureNames[0]), {}},
};

// A mock object the guest can dereference: first field is the vtable pointer.
struct MockObject {
    std::uint64_t *vtable;
    std::uint32_t refcount;
    std::uint32_t kind;
};

std::once_flag g_com_once;
bool g_com_enabled = true;

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

std::uint64_t NewObject(std::size_t kind) {
    auto *object = new MockObject{g_interfaces[kind].vtable.data(), 1,
                                  static_cast<std::uint32_t>(kind)};
    return reinterpret_cast<std::uint64_t>(object);
}

bool Enabled() { return g_com_enabled; }

// COM argument access: `this` occupies RCX.
inline std::uint64_t This(CpuContext *c) { return c->r[recomp::RCX]; }
inline std::uint64_t ComArg0(CpuContext *c) { return c->r[recomp::RDX]; }
inline std::uint64_t ComArg1(CpuContext *c) { return c->r[recomp::R8]; }
inline std::uint64_t ComArg2(CpuContext *c) { return c->r[recomp::R9]; }
inline std::uint64_t ComArg3(CpuContext *c) {
    return recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x28);
}

void Stub_ComMethod(CpuContext *c);

void Init();

}  // namespace com

// ---------------------------------------------------------------------------
// D3D11 / DXGI -- forwarded to DXVK 1.10.3
//
// DXVK is not vendored here: it is a large C++ project with its own build. Its
// d3d11 entry points are looked up in libdxvk_d3d11.so at run time, so a build
// of it can be dropped in without relinking this library. With nothing loaded
// the calls fail with E_FAIL -- what the engine already handles -- instead of
// crashing.
//
// Argument widths: the guest is Win64, so a 32-bit argument arrives in the low
// half of a 64-bit register. Declaring the forwards with std::uint32_t/uint64_t
// keeps the register layout identical; HRESULT is modelled as int32_t because
// Windows' long is 32-bit while Android's is not.
// ---------------------------------------------------------------------------
std::mutex g_dxvk_mutex;
void *g_dxvk_lib = nullptr;
std::atomic<std::uint64_t> g_vk_surface{0};
std::atomic<bool> g_dxvk_missing_logged{false};

using PfnD3D11CreateDevice = std::int32_t (*)(void *, std::uint32_t, void *, std::uint32_t,
                                              const std::int32_t *, std::uint32_t, std::uint32_t,
                                              void **, std::int32_t *, void **);
using PfnD3D11CreateDeviceAndSwapChain = std::int32_t (*)(
    void *, std::uint32_t, void *, std::uint32_t, const std::int32_t *, std::uint32_t,
    std::uint32_t, const void *, void **, void **, std::int32_t *, void **);
using PfnCreateDXGIFactory = std::int32_t (*)(const void *, void **);
// Added by patches/0001-android-external-surface.patch in third_party/dxvk.
using PfnDxvkSetSurface = void (*)(std::uint64_t);

struct DxvkApi {
    PfnD3D11CreateDevice create_device = nullptr;
    PfnD3D11CreateDeviceAndSwapChain create_device_swapchain = nullptr;
    PfnCreateDXGIFactory create_factory = nullptr;
    PfnDxvkSetSurface set_surface = nullptr;
};
DxvkApi g_dxvk;

void LogDxvkMissing() {
    bool expected = false;
    if (g_dxvk_missing_logged.compare_exchange_strong(expected, true)) {
        Log("[win32] D3D11/DXGI chamado sem DXVK: a devolver E_FAIL. "
            "Coloque libdxvk_d3d11.so ou defina D2_DXVK.");
    }
}

template <typename T>
inline T *GuestPtr(std::uint64_t value) {
    return reinterpret_cast<T *>(static_cast<std::uintptr_t>(value));
}

std::int32_t Impl_D3D11CreateDevice(std::uint64_t adapter, std::uint32_t driver_type,
                                    std::uint64_t software, std::uint32_t flags,
                                    std::uint64_t feature_levels, std::uint32_t num_levels,
                                    std::uint32_t sdk_version, std::uint64_t device_out,
                                    std::uint64_t feature_level_out, std::uint64_t context_out) {
    com::Init();
    if (g_dxvk.create_device != nullptr) {
        return g_dxvk.create_device(
            GuestPtr<void>(adapter), driver_type, GuestPtr<void>(software), flags,
            GuestPtr<const std::int32_t>(feature_levels), num_levels, sdk_version,
            GuestPtr<void *>(device_out), GuestPtr<std::int32_t>(feature_level_out),
            GuestPtr<void *>(context_out));
    }
    if (com::Enabled()) {
        // Tracing mode: hand the engine objects that log every method it calls.
        const std::uint64_t device = com::NewObject(com::kDevice);
        const std::uint64_t context = com::NewObject(com::kContext);
        if (device_out != 0) recomp::GuestStore<std::uint64_t>(device_out, device);
        if (feature_level_out != 0) {
            recomp::GuestStore<std::uint32_t>(feature_level_out, 0xB000u);  // 11_0
        }
        if (context_out != 0) recomp::GuestStore<std::uint64_t>(context_out, context);
        Log("[COM] D3D11CreateDevice -> mock device=0x%llx context=0x%llx (S_OK)",
            static_cast<unsigned long long>(device),
            static_cast<unsigned long long>(context));
        return 0;
    }
    LogDxvkMissing();
    return kD3dErrFail;
}

std::int32_t Impl_D3D11CreateDeviceAndSwapChain(
    std::uint64_t adapter, std::uint32_t driver_type, std::uint64_t software, std::uint32_t flags,
    std::uint64_t feature_levels, std::uint32_t num_levels, std::uint32_t sdk_version,
    std::uint64_t swapchain_desc, std::uint64_t swapchain_out, std::uint64_t device_out,
    std::uint64_t feature_level_out, std::uint64_t context_out) {
    com::Init();
    if (g_dxvk.create_device_swapchain != nullptr) {
        return g_dxvk.create_device_swapchain(
            GuestPtr<void>(adapter), driver_type, GuestPtr<void>(software), flags,
            GuestPtr<const std::int32_t>(feature_levels), num_levels, sdk_version,
            GuestPtr<const void>(swapchain_desc), GuestPtr<void *>(swapchain_out),
            GuestPtr<void *>(device_out), GuestPtr<std::int32_t>(feature_level_out),
            GuestPtr<void *>(context_out));
    }
    if (com::Enabled()) {
        const std::uint64_t device = com::NewObject(com::kDevice);
        const std::uint64_t context = com::NewObject(com::kContext);
        const std::uint64_t swapchain = com::NewObject(com::kSwapChain);
        if (swapchain_out != 0) recomp::GuestStore<std::uint64_t>(swapchain_out, swapchain);
        if (device_out != 0) recomp::GuestStore<std::uint64_t>(device_out, device);
        if (feature_level_out != 0) {
            recomp::GuestStore<std::uint32_t>(feature_level_out, 0xB000u);
        }
        if (context_out != 0) recomp::GuestStore<std::uint64_t>(context_out, context);
        Log("[COM] D3D11CreateDeviceAndSwapChain -> mock device=0x%llx context=0x%llx "
            "swapchain=0x%llx (S_OK)",
            static_cast<unsigned long long>(device), static_cast<unsigned long long>(context),
            static_cast<unsigned long long>(swapchain));
        return 0;
    }
    LogDxvkMissing();
    return kD3dErrFail;
}

std::int32_t Impl_CreateDXGIFactory(std::uint64_t riid, std::uint64_t factory_out) {
    com::Init();
    if (g_dxvk.create_factory != nullptr) {
        return g_dxvk.create_factory(GuestPtr<const void>(riid), GuestPtr<void *>(factory_out));
    }
    if (com::Enabled()) {
        if (factory_out != 0) {
            recomp::GuestStore<std::uint64_t>(factory_out, com::NewObject(com::kFactory));
        }
        Log("[COM] CreateDXGIFactory -> mock IDXGIFactory");
        return 0;  // S_OK
    }
    LogDxvkMissing();
    return kD3dErrFail;
}

// ---------------------------------------------------------------------------
// COM mock dispatch
// ---------------------------------------------------------------------------
namespace com {

void Stub_ComMethod(CpuContext *c) {
    const std::uint64_t thunk = g_active_thunk;
    const std::size_t slot = (thunk - kThunkBase) / kThunkStride;
    const char *owner = g_slot_owner[slot] != nullptr ? g_slot_owner[slot] : "COM";
    const char *name = g_slot_name[slot] != nullptr ? g_slot_name[slot] : "Method";
    const std::uint64_t self = This(c);

    Log("[COM TRACE] %s::%s this=0x%llx a0=0x%llx a1=0x%llx a2=0x%llx a3=0x%llx", owner,
        name, static_cast<unsigned long long>(self),
        static_cast<unsigned long long>(ComArg0(c)),
        static_cast<unsigned long long>(ComArg1(c)),
        static_cast<unsigned long long>(ComArg2(c)),
        static_cast<unsigned long long>(ComArg3(c)));

    auto *object = reinterpret_cast<MockObject *>(self);
    const bool valid = object != nullptr && object->vtable != nullptr &&
                       object->kind < kInterfaceCount &&
                       object->vtable == g_interfaces[object->kind].vtable.data();

    if (std::strcmp(name, "AddRef") == 0) {
        if (valid) ++object->refcount;
        SetRet(c, valid ? object->refcount : 1);
        return;
    }
    if (std::strcmp(name, "Release") == 0) {
        if (valid && object->refcount > 0) --object->refcount;
        SetRet(c, valid ? object->refcount : 0);
        return;
    }
    if (std::strcmp(name, "QueryInterface") == 0) {
        if (ComArg0(c) != 0) recomp::GuestStore<std::uint64_t>(ComArg0(c), self);
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "GetFeatureLevel") == 0) {
        SetRet(c, 0xB000);  // D3D_FEATURE_LEVEL_11_0
        return;
    }
    if (std::strcmp(name, "GetDevice") == 0) {
        if (ComArg0(c) != 0) {
            recomp::GuestStore<std::uint64_t>(ComArg0(c), NewObject(kDevice));
        }
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "GetImmediateContext") == 0) {
        if (ComArg0(c) != 0) {
            recomp::GuestStore<std::uint64_t>(ComArg0(c), NewObject(kContext));
        }
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "GetParent") == 0) {
        if (ComArg0(c) != 0) {
            recomp::GuestStore<std::uint64_t>(ComArg0(c), NewObject(kFactory));
        }
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "CreateSwapChain") == 0) {
        // (pDevice, pDesc, ppSwapChain): out is the R9 argument.
        if (ComArg2(c) != 0) {
            recomp::GuestStore<std::uint64_t>(ComArg2(c), NewObject(kSwapChain));
        }
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "CreateSwapChainForHwnd") == 0 ||
        std::strcmp(name, "CreateSwapChainForComposition") == 0) {
        // Six arguments before the out-pointer, so it is the 3rd stack slot.
        const std::uint64_t out = recomp::GuestLoad<std::uint64_t>(c->r[recomp::RSP] + 0x38);
        if (out != 0) recomp::GuestStore<std::uint64_t>(out, NewObject(kSwapChain));
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "GetBuffer") == 0) {
        // (UINT Buffer, REFIID riid, void **ppSurface): out is the R8 argument.
        if (ComArg1(c) != 0) {
            recomp::GuestStore<std::uint64_t>(ComArg1(c), NewObject(kTexture));
        }
        SetRet32(c, 0);
        return;
    }
    if (std::strcmp(name, "GetDesc") == 0) {
        if (ComArg0(c) != 0) {
            const unsigned char zero[0x40] = {};
            GuestWrite(ComArg0(c), zero, sizeof(zero));
        }
        SetRet32(c, 0);
        return;
    }

    SetRet32(c, 0);  // S_OK: keep the engine walking its boot sequence
}

void Init() {
    std::call_once(g_com_once, [] {
        if (const char *env = std::getenv("D2_NO_COM_MOCK")) {
            g_com_enabled = !(env[0] == '1' && env[1] == '\0');
        }
        std::size_t total = 0;
        for (std::size_t i = 0; i < kInterfaceCount; ++i) {
            InterfaceDef &def = g_interfaces[i];
            def.vtable.resize(def.slots);
            for (std::size_t slot = 0; slot < def.slots; ++slot) {
                const char *method = nullptr;
                for (std::size_t n = 0; n < def.name_count; ++n) {
                    if (def.names[n].index == slot) {
                        method = def.names[n].name;
                        break;
                    }
                }
                if (method == nullptr) {
                    static char generated[kInterfaceCount][128][24];
                    std::snprintf(generated[i][slot], sizeof(generated[i][0]), "Method_%zu",
                                  slot);
                    method = generated[i][slot];
                }
                def.vtable[slot] = AllocThunk(def.name, method, Stub_ComMethod);
                ++total;
            }
        }
        Log("[COM] %zu slots de vtable de teste construidos (trace %s)", total,
            g_com_enabled ? "ON" : "OFF");
    });
}

}  // namespace com

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

// ---- D3D11 / DXGI ----
void Stub_D3D11CreateDevice(CpuContext *c) {
    SetRet32(c, Impl_D3D11CreateDevice(
                    Arg0(c), static_cast<std::uint32_t>(Arg1(c)), Arg2(c),
                    static_cast<std::uint32_t>(Arg3(c)), Arg4(c),
                    static_cast<std::uint32_t>(Arg5(c)), static_cast<std::uint32_t>(Arg6(c)),
                    Arg7(c), Arg8(c), Arg9(c)));
}
void Stub_D3D11CreateDeviceAndSwapChain(CpuContext *c) {
    SetRet32(c, Impl_D3D11CreateDeviceAndSwapChain(
                    Arg0(c), static_cast<std::uint32_t>(Arg1(c)), Arg2(c),
                    static_cast<std::uint32_t>(Arg3(c)), Arg4(c),
                    static_cast<std::uint32_t>(Arg5(c)), static_cast<std::uint32_t>(Arg6(c)),
                    Arg7(c), Arg8(c), Arg9(c), Arg10(c), Arg11(c)));
}
void Stub_CreateDXGIFactory(CpuContext *c) {
    SetRet32(c, Impl_CreateDXGIFactory(Arg0(c), Arg1(c)));
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
// D3D11 / DXGI loading and the rendering surface handoff
// ---------------------------------------------------------------------------
namespace {

template <typename Fn>
Fn DxvkSymbol(void *library, const char *name) {
    void *symbol = ::dlsym(library, name);
    Fn fn = nullptr;
    if (symbol != nullptr) std::memcpy(&fn, &symbol, sizeof(fn));
    return fn;
}

}  // namespace

bool LoadDxvk(const char *library_path) {
    std::lock_guard<std::mutex> lock(g_dxvk_mutex);
    if (g_dxvk_lib != nullptr) return true;

    std::vector<const char *> candidates;
    if (library_path != nullptr && library_path[0] != '\0') candidates.push_back(library_path);
    if (const char *env = std::getenv("D2_DXVK")) {
        if (env[0] != '\0') candidates.push_back(env);
    }
#ifdef D2_DXVK_D3D11_SO
    candidates.push_back(D2_DXVK_D3D11_SO);
#endif
    candidates.push_back("libdxvk_d3d11.so");
    candidates.push_back("/data/data/com.vigil.darksiders2/files/libdxvk_d3d11.so");

    for (const char *path : candidates) {
        void *library = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (library == nullptr) continue;

        auto create = DxvkSymbol<PfnD3D11CreateDevice>(library, "D3D11CreateDevice");
        auto create_swapchain =
            DxvkSymbol<PfnD3D11CreateDeviceAndSwapChain>(library,
                                                         "D3D11CreateDeviceAndSwapChain");
        auto factory = DxvkSymbol<PfnCreateDXGIFactory>(library, "CreateDXGIFactory");
        if (create == nullptr && create_swapchain == nullptr && factory == nullptr) {
            Log("[win32] %s nao expoe D3D11CreateDevice/CreateDXGIFactory; ignorado.", path);
            ::dlclose(library);
            continue;
        }

        g_dxvk.create_device = create;
        g_dxvk.create_device_swapchain = create_swapchain;
        g_dxvk.create_factory = factory;
        g_dxvk.set_surface =
            DxvkSymbol<PfnDxvkSetSurface>(library, "dxvk_android_set_surface");
        g_dxvk_lib = library;

        // Hand the host's surface over. Without the patched DXVK this symbol is
        // absent and the patched build would fall back to a Win32 surface, which
        // does not exist here.
        if (g_dxvk.set_surface != nullptr) {
            g_dxvk.set_surface(g_vk_surface.load());
            Log("[win32] DXVK: surface 0x%llx entregue a dxvk_android_set_surface",
                static_cast<unsigned long long>(g_vk_surface.load()));
        } else {
            Log("[win32] DXVK carregado, mas sem dxvk_android_set_surface: "
                "a surface do host nao sera usada.");
        }

        Log("[win32] DXVK carregado de %s (surface 0x%llx)", path,
            static_cast<unsigned long long>(g_vk_surface.load()));
        return true;
    }
    return false;
}

bool IsDxvkLoaded() {
    std::lock_guard<std::mutex> lock(g_dxvk_mutex);
    return g_dxvk_lib != nullptr;
}

void SetRenderingSurface(std::uint64_t vk_surface) {
    g_vk_surface.store(vk_surface);

    // If DXVK is already loaded, tell it now; if it loads later, LoadDxvk()
    // pushes the value at that point.
    PfnDxvkSetSurface setter = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_dxvk_mutex);
        setter = g_dxvk.set_surface;
    }
    if (setter != nullptr) setter(vk_surface);
}

std::uint64_t RenderingSurface() { return g_vk_surface.load(); }

bool HasModule(const char *module) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    return g_module_base.count(Lower(module ? module : "")) > 0;
}

std::uint64_t ModuleBase(const char *module) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    return ModuleBaseLocked(Lower(module ? module : ""), true);
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
            {"d3d11.dll", "D3D11CreateDevice", Stub_D3D11CreateDevice},
            {"d3d11.dll", "D3D11CreateDeviceAndSwapChain", Stub_D3D11CreateDeviceAndSwapChain},
            {"dxgi.dll", "CreateDXGIFactory", Stub_CreateDXGIFactory},
            {"dxgi.dll", "CreateDXGIFactory1", Stub_CreateDXGIFactory},
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
    const std::string key = Key(module, name);
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    auto it = g_exports.find(key);
    if (it != g_exports.end()) return it->second;

    const std::string mod = Lower(module ? module : "");
    const char *alt = nullptr;
    if (mod == "kernel32.dll") alt = "kernelbase.dll";
    else if (mod == "kernelbase.dll") alt = "kernel32.dll";
    if (alt != nullptr) {
        auto it2 = g_exports.find(Key(alt, name));
        if (it2 != g_exports.end()) return it2->second;
    }
    return 0;
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
