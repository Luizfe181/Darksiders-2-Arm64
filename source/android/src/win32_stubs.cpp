// win32_stubs.cpp -- Win32 API shims: Windows -> POSIX/Android.
//
// Every shim reads the Win64 guest ABI itself (rcx, rdx, r8, r9, then the stack
// at [rsp+0x28], [rsp+0x30]) and writes the result to guest RAX. See
// win32_stubs.h for why the stubs are shaped this way.
#include "win32_stubs.h"

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
enum class HandleKind : std::uint32_t { kThread = 1, kFile = 2 };

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

    if (kind == HandleKind::kThread) {
        auto *t = reinterpret_cast<GuestThread *>(handle);
        pthread_join(t->tid, nullptr);
        munmap(t->stack, t->stack_size);
        t->magic = 0;
        delete t;
        return 1;
    }

    auto *f = reinterpret_cast<GuestFile *>(handle);
    if (f != nullptr) {
        if (::close(f->fd) != 0) {
            f->magic = 0;
            delete f;
            return 0;
        }
        f->magic = 0;
        delete f;
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
    fn(c);
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
            if (kv.second == HandleKind::kThread) {
                auto *t = reinterpret_cast<GuestThread *>(kv.first);
                pthread_join(t->tid, nullptr);
                munmap(t->stack, t->stack_size);
                t->magic = 0;
                delete t;
            } else {
                auto *f = reinterpret_cast<GuestFile *>(kv.first);
                if (f != nullptr) {
                    ::close(f->fd);
                    f->magic = 0;
                    delete f;
                }
            }
        }
        g_handles.clear();
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
