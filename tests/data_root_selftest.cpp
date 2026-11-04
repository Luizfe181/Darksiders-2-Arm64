// data_root_selftest.cpp -- behavioural test of HostRuntime::InitDataRoot().
//
// Links main.cpp with -ffunction-sections + --gc-sections so only the data-root
// path survives; the windowing code and its SDL calls are dropped, which is why
// this test needs no SDL at runtime. One SDL symbol is still referenced by the
// Android branch of InitDataRoot and is stubbed below.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <sys/stat.h>
#include <unistd.h>

#include "host_runtime.h"

// The only SDL entry points InitDataRoot reaches (Android build). The test
// builds as a host binary, so returning null makes those candidates empty.
extern "C" const char *SDL_AndroidGetInternalStoragePath(void) { return nullptr; }
extern "C" const char *SDL_AndroidGetExternalStoragePath(void) { return nullptr; }

// platform_bridge.h's LOGI/LOGE go to liblog on a device; here they are dropped.
extern "C" int __android_log_print(int, const char *, const char *, ...) { return 0; }

static int g_fail = 0;

#define CHECK(cond, msg)                        \
    do {                                        \
        if (!(cond)) {                          \
            std::printf("FAIL  %s\n", msg);     \
            ++g_fail;                           \
        } else {                                \
            std::printf("ok    %s\n", msg);     \
        }                                       \
    } while (0)

static bool WriteFileText(const char *path, const char *text) {
    std::FILE *f = std::fopen(path, "wb");
    if (f == nullptr) return false;
    const std::size_t n = std::strlen(text);
    const bool ok = std::fwrite(text, 1, n, f) == n;
    std::fclose(f);
    return ok;
}

static void MakeGameDir(const char *dir) {
    ::mkdir(dir, 0755);
    char media[512];
    std::snprintf(media, sizeof(media), "%s/media", dir);
    ::mkdir(media, 0755);
    char upak[512];
    std::snprintf(upak, sizeof(upak), "%s/media/media.upak", dir);
    WriteFileText(upak, "OBPK");
}

int main() {
    char base[] = "/tmp/d2datarootXXXXXX";
    const char *root = ::mkdtemp(base);
    if (root == nullptr) {
        std::printf("FAIL  could not create a temp dir\n");
        return 1;
    }
    ::chdir(root);

    // Three sibling directories: one game dir with assets, one empty, one that
    // a config.ini will point at.
    MakeGameDir("game_in_cwd");
    ::mkdir("empty_dir", 0755);
    MakeGameDir("game_in_config");

    char game_config[512];
    std::snprintf(game_config, sizeof(game_config), "%s/game_in_config", root);

    std::printf("== config.ini override ==\n");
    {
        ::chdir("empty_dir");
        char ini[512];
        std::snprintf(ini, sizeof(ini), "[paths]\n; comment\ndata_root = %s\n", game_config);
        CHECK(WriteFileText("config.ini", ini), "config.ini written");

        darksiders2::host::HostRuntime runtime;
        CHECK(runtime.InitDataRoot(), "InitDataRoot succeeds from config.ini");
        CHECK(runtime.DataRoot() == game_config, "the config.ini path is used");
        ::unlink("config.ini");
        ::chdir(root);
    }

    std::printf("\n== working-directory fallback ==\n");
    {
        ::chdir("game_in_cwd");
        darksiders2::host::HostRuntime runtime;
        CHECK(runtime.InitDataRoot(), "InitDataRoot finds media/media.upak in the cwd");
        CHECK(runtime.DataRoot() == ".", "the cwd becomes the data root");
        ::chdir(root);
    }

    std::printf("\n== no assets anywhere ==\n");
    {
        ::chdir("empty_dir");
        darksiders2::host::HostRuntime runtime;
        CHECK(!runtime.InitDataRoot(), "InitDataRoot fails when media/media.upak is absent");
        CHECK(runtime.DataRoot().empty(), "no data root is reported");
        ::chdir(root);
    }

    std::printf("\n== config.ini pointing at nothing is ignored ==\n");
    {
        ::chdir("game_in_cwd");
        CHECK(WriteFileText("config.ini", "data_root=/nonexistent/darksiders2\n"),
              "config.ini with a bad path written");
        darksiders2::host::HostRuntime runtime;
        CHECK(runtime.InitDataRoot(), "InitDataRoot still succeeds via the fallback list");
        CHECK(runtime.DataRoot() == ".", "a bad config.ini does not win over a real directory");
        ::unlink("config.ini");
        ::chdir(root);
    }

    ::chdir("/tmp");
    ::rmdir(root);
    std::printf("\n%s (%d failure(s))\n", g_fail ? "FAILED" : "ALL PASSED", g_fail);
    return g_fail ? 1 : 0;
}
