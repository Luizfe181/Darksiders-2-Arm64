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
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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

// CreateFileA(path, access, share, security, disposition, attrs, template)
static std::uint64_t OpenFile(const char *name, std::uint32_t access,
                              std::uint32_t disposition) {
    Reset(reinterpret_cast<std::uint64_t>(name), access, 0, 0);
    SetStackArg(0, disposition);
    SetStackArg(1, 0);
    SetStackArg(2, 0);
    Call("kernel32.dll", "CreateFileA");
    return Ret();
}

// CreateFileMappingA(hFile, attrs, protect, sizeHigh, sizeLow, name)
static std::uint64_t MapFile(std::uint64_t file, std::uint32_t protect, std::uint32_t size_low) {
    Reset(file, 0, protect, 0);
    SetStackArg(0, size_low);
    SetStackArg(1, 0);
    Call("kernel32.dll", "CreateFileMappingA");
    return Ret();
}

// MapViewOfFile(hMap, access, offHigh, offLow, bytes)
static std::uint64_t MapView(std::uint64_t map, std::uint32_t access, std::uint32_t off_low,
                             std::uint64_t bytes) {
    Reset(map, access, 0, off_low);
    SetStackArg(0, bytes);
    Call("kernel32.dll", "MapViewOfFile");
    return Ret();
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

    std::printf("\n== file I/O and VFS ==\n");

    // Work on a real filesystem: WSL's /mnt/c is v9fs, which refuses mmap, and
    // that is an environment limit, not something the stubs can work around.
    char tmp_dir[] = "/tmp/d2selftestXXXXXX";
    const char *work_dir = ::mkdtemp(tmp_dir);
    if (work_dir != nullptr) {
        ::chdir(work_dir);
        std::printf("      (working in %s)\n", work_dir);
    }

    constexpr const char *kSub = "d2_test_sub";
    constexpr const char *kRel = "d2_test_sub/d2_selftest.bin";
    ::mkdir(kSub, 0755);
    {
        const int fd = ::open(kRel, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        CHECK(fd >= 0, "host: dummy file created (4096 bytes of 0..255)");
        std::uint8_t pattern[256];
        for (int i = 0; i < 256; ++i) pattern[i] = static_cast<std::uint8_t>(i);
        for (int i = 0; i < 16; ++i) {
            if (::write(fd, pattern, sizeof(pattern)) != static_cast<ssize_t>(sizeof(pattern))) {
                break;
            }
        }
        ::close(fd);
    }

    win32::SetDataRoot(".");
    CHECK(win32::ResolveGuestPath("media\\media.upak") == "./media/media.upak",
          "Windows path separators and the data root are applied");
    CHECK(win32::ResolveGuestPath("C:\\Games\\DS2\\media\\x.bin") == "./Games/DS2/media/x.bin",
          "drive letter stripped (C:\\... -> Games/DS2/media/x.bin)");

    // CreateFileA(path, access, share, security, disposition, attrs, template):
    // the last three are stack arguments.
    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\d2_selftest.bin"), win32::GENERIC_READ, 0, 0);
    SetStackArg(0, win32::OPEN_EXISTING);
    SetStackArg(1, 0);
    SetStackArg(2, 0);
    CHECK(Call(K32, "CreateFileA"), "CreateFileA dispatched");
    const std::uint64_t fh = Ret();
    CHECK(fh != win32::kInvalidHandle && fh != 0, "CreateFileA opens a backslash path");

    std::uint64_t size = 0;
    Reset(fh, reinterpret_cast<std::uint64_t>(&size));
    CHECK(Call(K32, "GetFileSizeEx") && Ret() == 1, "GetFileSizeEx");
    CHECK(size == 4096, "GetFileSizeEx reports 4096 bytes");

    std::uint8_t buf[16] = {};
    std::uint32_t got = 0xFFFF;
    Reset(fh, reinterpret_cast<std::uint64_t>(buf), 16, reinterpret_cast<std::uint64_t>(&got));
    CHECK(Call(K32, "ReadFile") && Ret() == 1, "ReadFile");
    CHECK(got == 16 && buf[0] == 0 && buf[15] == 15, "ReadFile returns the first 16 bytes");

    std::uint64_t new_pos = 0;
    Reset(fh, 1000, reinterpret_cast<std::uint64_t>(&new_pos), win32::FILE_BEGIN);
    CHECK(Call(K32, "SetFilePointerEx") && Ret() == 1, "SetFilePointerEx");
    CHECK(new_pos == 1000, "SetFilePointerEx lands at offset 1000");

    got = 0;
    Reset(fh, reinterpret_cast<std::uint64_t>(buf), 4, reinterpret_cast<std::uint64_t>(&got));
    Call(K32, "ReadFile");
    CHECK(got == 4 && buf[0] == 232, "ReadFile after seek reads byte 232 (1000 = 3*256+232)");

    Reset(fh, 0, 0, win32::FILE_BEGIN);
    CHECK(Call(K32, "SetFilePointer") && Ret() == 0, "SetFilePointer(FILE_BEGIN, 0) returns 0");

    Reset(fh, 0);
    CHECK(Call(K32, "GetFileSize") && Ret() == 4096, "GetFileSize returns the low 32 bits");

    Reset(fh);
    CHECK(Call(K32, "CloseHandle") && Ret() == 1, "CloseHandle closes a file handle");

    // A missing file must fail the way Windows does.
    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\nope.bin"), win32::GENERIC_READ, 0, 0);
    SetStackArg(0, win32::OPEN_EXISTING);
    SetStackArg(1, 0);
    SetStackArg(2, 0);
    Call(K32, "CreateFileA");
    CHECK(Ret() == win32::kInvalidHandle,
          "opening a missing file returns INVALID_HANDLE_VALUE");

    // Write path, and CreateFileW (UTF-16).
    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\d2_write.bin"), win32::GENERIC_WRITE, 0, 0);
    SetStackArg(0, win32::CREATE_ALWAYS);
    SetStackArg(1, 0);
    SetStackArg(2, 0);
    Call(K32, "CreateFileA");
    const std::uint64_t wh = Ret();
    CHECK(wh != win32::kInvalidHandle, "CreateFileA(CREATE_ALWAYS) creates a file");
    {
        const std::uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        std::uint32_t written = 0;
        Reset(wh, reinterpret_cast<std::uint64_t>(data), 8,
              reinterpret_cast<std::uint64_t>(&written));
        CHECK(Call(K32, "WriteFile") && Ret() == 1 && written == 8, "WriteFile writes 8 bytes");
        Reset(wh);
        Call(K32, "CloseHandle");

        struct stat st {};
        CHECK(::stat("d2_test_sub/d2_write.bin", &st) == 0 && st.st_size == 8,
              "the bytes really landed on disk");
    }

    {
        const std::uint16_t wpath[] = {'d', '2', '_', 't', 'e', 's', 't', '_', 's', 'u', 'b',
                                       '/', 'd', '2', '_', 's', 'e', 'l', 'f', 't', 'e', 's',
                                       't', '.', 'b', 'i', 'n', 0};
        Reset(reinterpret_cast<std::uint64_t>(wpath), win32::GENERIC_READ, 0, 0);
        SetStackArg(0, win32::OPEN_EXISTING);
        SetStackArg(1, 0);
        SetStackArg(2, 0);
        CHECK(Call(K32, "CreateFileW") && Ret() != win32::kInvalidHandle,
              "CreateFileW opens the same file from a UTF-16 path");
        const std::uint64_t h = Ret();
        Reset(h);
        Call(K32, "CloseHandle");
    }

    std::printf("\n== file attributes ==\n");

    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\d2_selftest.bin"));
    CHECK(Call(K32, "GetFileAttributesA"), "GetFileAttributesA dispatched");
    const std::uint32_t file_attrs = static_cast<std::uint32_t>(Ret());
    CHECK(file_attrs != win32::kInvalidFileAttributes, "a file has attributes");
    CHECK((file_attrs & win32::FILE_ATTRIBUTE_DIRECTORY) == 0,
          "a file does not report FILE_ATTRIBUTE_DIRECTORY");

    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub"));
    Call(K32, "GetFileAttributesA");
    CHECK((static_cast<std::uint32_t>(Ret()) & win32::FILE_ATTRIBUTE_DIRECTORY) != 0,
          "a directory reports FILE_ATTRIBUTE_DIRECTORY");

    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\nope.bin"));
    Call(K32, "GetFileAttributesA");
    CHECK(static_cast<std::uint32_t>(Ret()) == win32::kInvalidFileAttributes,
          "a missing path returns INVALID_FILE_ATTRIBUTES");

    alignas(8) unsigned char finfo[0x34] = {};
    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\d2_selftest.bin"), 0,
          reinterpret_cast<std::uint64_t>(finfo));
    CHECK(Call(K32, "GetFileAttributesExA") && Ret() == 1, "GetFileAttributesExA");
    {
        std::uint32_t size_hi = 0, size_lo = 0;
        std::memcpy(&size_hi, finfo + 0x20, 4);
        std::memcpy(&size_lo, finfo + 0x24, 4);
        CHECK(((static_cast<std::uint64_t>(size_hi) << 32) | size_lo) == 4096,
              "GetFileAttributesExA reports the 4096-byte size");
    }

    std::printf("\n== directory enumeration ==\n");
    alignas(8) unsigned char find_data[0x140] = {};
    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\*"),
          reinterpret_cast<std::uint64_t>(find_data));
    CHECK(Call(K32, "FindFirstFileA"), "FindFirstFileA dispatched");
    const std::uint64_t find_handle = Ret();
    CHECK(find_handle != win32::kInvalidHandle, "FindFirstFileA finds the entries");

    int entries = 0;
    bool saw_selftest = false;
    if (find_handle != win32::kInvalidHandle) {
        for (;;) {
            const char *found = reinterpret_cast<const char *>(find_data + 0x2C);
            ++entries;
            if (std::strcmp(found, "d2_selftest.bin") == 0) saw_selftest = true;
            Reset(find_handle, reinterpret_cast<std::uint64_t>(find_data));
            Call(K32, "FindNextFileA");
            if (Ret() == 0) break;
        }
        Reset(find_handle);
        CHECK(Call(K32, "FindClose") && Ret() == 1, "FindClose");
    }
    CHECK(entries == 2, "the scan reports both files present");
    CHECK(saw_selftest, "the scan saw d2_selftest.bin");

    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\*.nothing"),
          reinterpret_cast<std::uint64_t>(find_data));
    Call(K32, "FindFirstFileA");
    CHECK(Ret() == win32::kInvalidHandle, "no match returns INVALID_HANDLE_VALUE");

    std::printf("\n== file mapping ==\n");
    const std::uint64_t map_file =
        OpenFile("d2_test_sub\\d2_selftest.bin", win32::GENERIC_READ, win32::OPEN_EXISTING);
    CHECK(map_file != win32::kInvalidHandle, "file opened for mapping");

    const std::uint64_t mapping = MapFile(map_file, win32::PAGE_READONLY, 0);
    CHECK(mapping != 0 && mapping != win32::kInvalidHandle, "CreateFileMappingA returns a handle");

    const std::uint64_t view = MapView(mapping, win32::FILE_MAP_READ, 0, 0);
    CHECK(view != 0, "MapViewOfFile returns a pointer");
    if (view != 0) {
        const auto *bytes = reinterpret_cast<const unsigned char *>(view);
        CHECK(bytes[0] == 0 && bytes[15] == 15 && bytes[4095] == 255,
              "the view exposes all 4096 bytes of the file");
    }

    const std::uint64_t offset_view = MapView(mapping, win32::FILE_MAP_READ, 1000, 8);
    CHECK(offset_view != 0 &&
              reinterpret_cast<const unsigned char *>(offset_view)[0] == 232,
          "a view at offset 1000 starts on byte 232");
    if (offset_view != 0) {
        Reset(offset_view);
        CHECK(Call(K32, "UnmapViewOfFile") && Ret() == 1, "UnmapViewOfFile (offset view)");
    }

    if (view != 0) {
        Reset(view);
        CHECK(Call(K32, "UnmapViewOfFile") && Ret() == 1, "UnmapViewOfFile");
    }
    Reset(mapping);
    CHECK(Call(K32, "CloseHandle") && Ret() == 1, "CloseHandle on a mapping");
    Reset(map_file);
    Call(K32, "CloseHandle");

    // A MAP_SHARED writable view must reach the file.
    const std::uint64_t write_file =
        OpenFile("d2_test_sub\\d2_map.bin", win32::GENERIC_READ | win32::GENERIC_WRITE,
                 win32::CREATE_ALWAYS);
    CHECK(write_file != win32::kInvalidHandle, "file created for a writable mapping");
    const std::uint64_t write_map = MapFile(write_file, win32::PAGE_READWRITE, 64);
    CHECK(write_map != 0 && write_map != win32::kInvalidHandle,
          "CreateFileMappingA extends the file to 64 bytes");
    const std::uint64_t write_view = MapView(write_map, win32::FILE_MAP_WRITE, 0, 64);
    CHECK(write_view != 0, "writable view created");
    if (write_view != 0) {
        reinterpret_cast<unsigned char *>(write_view)[4] = 0x5A;
        Reset(write_view);
        Call(K32, "UnmapViewOfFile");
    }
    Reset(write_map);
    Call(K32, "CloseHandle");
    Reset(write_file);
    Call(K32, "CloseHandle");
    {
        struct stat st {};
        CHECK(::stat("d2_test_sub/d2_map.bin", &st) == 0 && st.st_size == 64,
              "the mapped file is 64 bytes on disk");
        const int fd = ::open("d2_test_sub/d2_map.bin", O_RDONLY);
        unsigned char byte = 0;
        const bool read_ok = fd >= 0 && ::pread(fd, &byte, 1, 4) == 1;
        if (fd >= 0) ::close(fd);
        CHECK(read_ok && byte == 0x5A, "a MAP_SHARED write reached the file");
    }

    std::printf("\n== truncate and delete ==\n");
    const std::uint64_t trunc_file =
        OpenFile("d2_test_sub\\d2_trunc.bin", win32::GENERIC_READ | win32::GENERIC_WRITE,
                 win32::CREATE_ALWAYS);
    CHECK(trunc_file != win32::kInvalidHandle, "file created for truncation");
    {
        std::uint8_t big[200];
        std::memset(big, 7, sizeof(big));
        std::uint32_t written = 0;
        Reset(trunc_file, reinterpret_cast<std::uint64_t>(big), sizeof(big),
              reinterpret_cast<std::uint64_t>(&written));
        CHECK(Call(K32, "WriteFile") && written == 200, "200 bytes written");
    }
    Reset(trunc_file, 100, 0, win32::FILE_BEGIN);
    Call(K32, "SetFilePointer");
    Reset(trunc_file);
    CHECK(Call(K32, "SetEndOfFile") && Ret() == 1, "SetEndOfFile truncates at the pointer");
    Reset(trunc_file);
    Call(K32, "CloseHandle");
    {
        struct stat st {};
        CHECK(::stat("d2_test_sub/d2_trunc.bin", &st) == 0 && st.st_size == 100,
              "the file is 100 bytes after SetEndOfFile");
    }

    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\d2_trunc.bin"));
    CHECK(Call(K32, "DeleteFileA") && Ret() == 1, "DeleteFileA removes the file");
    {
        struct stat st {};
        CHECK(::stat("d2_test_sub/d2_trunc.bin", &st) != 0, "the file is really gone");
    }
    Reset(reinterpret_cast<std::uint64_t>("d2_test_sub\\d2_trunc.bin"));
    Call(K32, "DeleteFileA");
    CHECK(Ret() == 0, "DeleteFileA on a missing file returns 0");

    std::printf("\n== D3D11 / DXGI entry points ==\n");
    {
        const std::uint64_t device_thunk = win32::ResolveImport("d3d11.dll", "D3D11CreateDevice");
        CHECK(device_thunk != 0 && win32::IsThunk(device_thunk),
              "D3D11CreateDevice resolves to a thunk");
        CHECK(win32::ResolveImport("d3d11.dll", "D3D11CreateDeviceAndSwapChain") != 0,
              "D3D11CreateDeviceAndSwapChain resolves to a thunk");
        CHECK(win32::ResolveImport("dxgi.dll", "CreateDXGIFactory") != 0,
              "CreateDXGIFactory resolves to a thunk");
        CHECK(win32::ResolveImport("dxgi.dll", "CreateDXGIFactory1") != 0,
              "CreateDXGIFactory1 shares the CreateDXGIFactory stub");
        CHECK(!win32::IsDxvkLoaded(), "no DXVK is loaded in this test");

        // With no DXVK the call must fail cleanly, not crash: 10 arguments,
        // the last six on the guest stack.
        Reset(0, 1, 0, 0);
        SetStackArg(0, 0);
        SetStackArg(1, 0);
        SetStackArg(2, 7);
        SetStackArg(3, 0);
        SetStackArg(4, 0);
        SetStackArg(5, 0);
        CHECK(Call("d3d11.dll", "D3D11CreateDevice"), "D3D11CreateDevice dispatched");
        CHECK(static_cast<std::int32_t>(Ret()) == win32::kD3dErrFail,
              "D3D11CreateDevice returns E_FAIL without DXVK");

        Reset(0, 0);
        CHECK(Call("dxgi.dll", "CreateDXGIFactory"), "CreateDXGIFactory dispatched");
        CHECK(static_cast<std::int32_t>(Ret()) == win32::kD3dErrFail,
              "CreateDXGIFactory returns E_FAIL without DXVK");

        win32::SetRenderingSurface(0x1234ABCDull);
        CHECK(win32::RenderingSurface() == 0x1234ABCDull,
              "the Vulkan surface reaches the Win32 layer");
        win32::SetRenderingSurface(0);
        CHECK(win32::RenderingSurface() == 0, "the surface handoff clears on shutdown");
    }

    ::unlink(kRel);
    ::unlink("d2_test_sub/d2_write.bin");
    ::unlink("d2_test_sub/d2_map.bin");
    ::rmdir(kSub);
    if (work_dir != nullptr) {
        ::chdir("/tmp");
        ::rmdir(work_dir);
    }

    win32::Shutdown();
    std::printf("\n%s (%d failure(s))\n", g_fail ? "FAILED" : "ALL PASSED", g_fail);
    return g_fail ? 1 : 0;
}
