// rc_smoke.cpp -- maps the real Darksiders2.exe and exercises the RcApi.
//
// Runs on the host (x86-64 Linux under WSL) because the recompiled C is
// architecture-neutral; what is being tested here is the loader, the IAT
// patching and the dispatcher, not any particular instruction.
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "cpu_context.h"
#include "game_image.h"
#include "rc_runtime.h"
#include "win32_stubs.h"

// The static test binary has no liblog; the shims and the runtime only log.
extern "C" int __android_log_print(int, const char*, const char*, ...) { return 0; }
extern "C" int __android_log_vprint(int, const char*, const char*, va_list) { return 0; }

using namespace vigil::recomp;
namespace win32 = darksiders2::win32;

// OUT.c normally defines this; the smoke test provides it.
const RcApi* rc = nullptr;

static int g_fail = 0;
static std::uint64_t g_image_base = 0;
static std::uint64_t g_alloc_thunk = 0;
static std::uint64_t g_import_veneer = 0;
static std::uint64_t g_veneer_result = UINT64_MAX;
static std::uint64_t g_leaf_result = UINT64_MAX;
static std::uint64_t g_record_result = UINT64_MAX;
static std::uint64_t g_helper_result = UINT64_MAX;
static std::uint64_t g_helper_offset = 0;
alignas(8) static std::uint8_t g_record[0x50];
alignas(8) static std::uint64_t g_record_expected[0x50 / sizeof(std::uint64_t)];
static std::uint64_t g_first_pointer = 0x123456789ABCDEF0ull;
static std::uint64_t g_second_pointer = 0x0FEDCBA987654321ull;
static std::uint64_t g_list[3][2] = {
    {0x1111, 0}, {0x2222, 0}, {0x3333, 0}};

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            std::printf("FAIL  %s\n", msg);       \
            ++g_fail;                             \
        } else {                                  \
            std::printf("ok    %s\n", msg);       \
        }                                         \
    } while (0)

// Stands in for a recompiled function: calls an import through rc->call the way
// the generated C does.
static void SyntheticCaller(CpuContext* c) {
    c->r[RCX] = 0;
    c->r[RDX] = 0x2000;
    c->r[R8] = 0x3000;   // MEM_COMMIT | MEM_RESERVE
    c->r[R9] = 0x04;     // PAGE_READWRITE
    rc->call(c, g_alloc_thunk, c->rip + 0x100);
}

// Calls an address that has no recompiled function and no thunk.
static void SyntheticUnhandled(CpuContext* c) {
    rc->call(c, g_image_base + 0x00999999ull, c->rip + 0x100);
}

static void SyntheticImportVeneer(CpuContext* c) {
    c->r[RCX] = 0;
    c->r[RDX] = 0;
    rc->call(c, g_import_veneer, c->rip + 0x100);
}

static void SyntheticCriticalSectionVeneer(CpuContext* c) {
    c->r[RCX] = 0x1234;
    c->r[RDX] = 0;
    rc->call(c, g_import_veneer, c->rip + 0x100);
    g_veneer_result = c->r[RAX];
}

static void SyntheticZeroReturnLeaf(CpuContext* c) {
    rc->call(c, g_image_base + 0xA9550ull, c->rip + 0x100);
    g_leaf_result = c->r[RAX];
}

static void SyntheticOneArgumentThunk(CpuContext* c) {
    rc->call(c, g_image_base + 0x86B90ull, c->rip + 0x100);
}

static void SyntheticRecordHelper(CpuContext* c) {
    std::memset(g_record, 0xA5, sizeof(g_record));
    std::memset(g_record_expected, 0xA5, sizeof(g_record_expected));

    c->r[RCX] = reinterpret_cast<std::uint64_t>(g_record);
    c->r[RDX] = 0x1111222233334444ull;
    c->r[R8] = 0x5555666677778888ull;
    c->r[R9] = 0x9999AAAABBBBCCCCull;

    const std::uint64_t stack_args = c->r[RSP] + 0x28;
    GuestStore<std::uint32_t>(stack_args, 0xDDEEFF00u);
    GuestStore<std::uint64_t>(stack_args + 0x08, 0x1020304050607080ull);
    GuestStore<std::uint32_t>(stack_args + 0x10, 0xA1B2C3D4u);
    GuestStore<std::uint64_t>(stack_args + 0x18, 0x2132435465768798ull);
    GuestStore<std::uint32_t>(stack_args + 0x20, 0xB1C2D3E4u);
    GuestStore<std::uint64_t>(stack_args + 0x28, 0x31425364758697A8ull);
    GuestStore<std::uint64_t>(stack_args + 0x30, 0x415263748596A7B8ull);
    GuestStore<std::uint32_t>(stack_args + 0x38, 0xC1D2E3F4u);
    GuestStore<std::uint32_t>(stack_args + 0x40, 0xD1E2F304u);

    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected),
                &c->r[RDX], sizeof(c->r[RDX]));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x08,
                &c->r[R8], sizeof(c->r[R8]));
    const std::uint32_t arg4 = static_cast<std::uint32_t>(c->r[R9]);
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x10,
                &arg4, sizeof(arg4));
    const std::uint32_t arg5 = 0xDDEEFF00u;
    const std::uint64_t arg6 = 0x1020304050607080ull;
    const std::uint32_t arg7 = 0xA1B2C3D4u;
    const std::uint64_t arg8 = 0x2132435465768798ull;
    const std::uint32_t arg9 = 0xB1C2D3E4u;
    const std::uint64_t arg10 = 0x31425364758697A8ull;
    const std::uint64_t arg11 = 0x415263748596A7B8ull;
    const std::uint32_t arg12 = 0xC1D2E3F4u;
    const std::uint32_t arg13 = 0xD1E2F304u;
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x14,
                &arg5, sizeof(arg5));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x18,
                &arg6, sizeof(arg6));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x20,
                &arg7, sizeof(arg7));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x28,
                &arg8, sizeof(arg8));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x30,
                &arg9, sizeof(arg9));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x38,
                &arg10, sizeof(arg10));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x40,
                &arg11, sizeof(arg11));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x48,
                &arg12, sizeof(arg12));
    std::memcpy(reinterpret_cast<std::uint8_t*>(g_record_expected) + 0x4C,
                &arg13, sizeof(arg13));

    rc->call(c, g_image_base + 0xE62B00ull, c->rip + 0x100);
    g_record_result = c->r[RAX];
}

static void SyntheticPdataLessHelper(CpuContext* c) {
    c->r[RCX] = reinterpret_cast<std::uint64_t>(&g_first_pointer);
    if (g_helper_offset == 0xE62BD0 || g_helper_offset == 0xE62BE0) {
        g_list[0][1] = reinterpret_cast<std::uint64_t>(&g_list[1][0]);
        c->r[RCX] = reinterpret_cast<std::uint64_t>(&g_list[0][0]);
    } else if (g_helper_offset == 0xE62BF0) {
        g_list[0][1] = reinterpret_cast<std::uint64_t>(&g_list[1][0]);
        g_list[1][1] = reinterpret_cast<std::uint64_t>(&g_list[2][0]);
        g_list[2][1] = 0;
        c->r[RCX] = reinterpret_cast<std::uint64_t>(&g_list[0][0]);
    } else if (g_helper_offset == 0xE67C60 ||
               g_helper_offset == 0xE681E0) {
        std::memset(g_record, 0xA5, sizeof(g_record));
        c->r[RCX] = reinterpret_cast<std::uint64_t>(g_record);
    }
    rc->call(c, g_image_base + g_helper_offset, c->rip + 0x100);
    g_helper_result = c->r[RAX];
}

int main(int argc, char** argv) {
    const char* exe = argc > 1 ? argv[1] : "game_original/Darksiders2.exe";

    {
        CpuContext context{};
        constexpr std::uint64_t stack_base = 0x12345000ull;
        InitializeGuestTeb(context, stack_base);
        std::uint64_t teb_self = 0;
        std::uint64_t teb_stack_base = 0;
        std::memcpy(&teb_self, context.guest_teb + 0x30, sizeof(teb_self));
        std::memcpy(&teb_stack_base, context.guest_teb + 0x08, sizeof(teb_stack_base));
        CHECK(context.gs_base == reinterpret_cast<std::uint64_t>(context.guest_teb),
              "GS base aponta para o TEB sintetico");
        CHECK(teb_self == context.gs_base, "GS:[0x30] devolve o self do TEB");
        CHECK(teb_stack_base == stack_base, "TEB contem o stack base Win64");
    }

    GameImage image;
    if (!image.Map(exe)) {
        std::printf("FAIL  nao foi possivel mapear %s\n", exe);
        return 1;
    }
    g_image_base = image.base();
    std::printf("ok    imagem mapeada em 0x%llx (%llu MB)\n",
                static_cast<unsigned long long>(image.base()),
                static_cast<unsigned long long>(image.size() >> 20));

    CHECK(image.entry() == image.base() + 0xD7EC90ull, "entry point em 0xD7EC90");

    CHECK(image.PatchImports(), "tabela de imports processada");
    std::printf("      imports: %zu, sem resolucao: %zu\n", image.imports().size(),
                image.unresolved());

    {
        // Which DLLs the port still owes: the count per module is the shortest
        // description of what is missing.
        struct Group {
            std::string module;
            std::size_t total;
            std::size_t missing;
        };
        std::vector<Group> groups;
        for (const ImportRef& ref : image.imports()) {
            Group* found = nullptr;
            for (Group& g : groups) {
                if (g.module == ref.module) {
                    found = &g;
                    break;
                }
            }
            if (found == nullptr) {
                groups.push_back(Group{ref.module, 0, 0});
                found = &groups.back();
            }
            ++found->total;
            if (ref.thunk == 0) ++found->missing;
        }
        for (std::size_t i = 0; i < groups.size(); ++i) {
            for (std::size_t j = i + 1; j < groups.size(); ++j) {
                if (groups[j].missing > groups[i].missing) {
                    Group tmp = groups[i];
                    groups[i] = groups[j];
                    groups[j] = tmp;
                }
            }
        }
        std::printf("      por DLL (em falta / total):\n");
        for (std::size_t i = 0; i < groups.size() && i < 8; ++i) {
            std::printf("        %-24s %3zu / %3zu\n", groups[i].module.c_str(),
                        groups[i].missing, groups[i].total);
        }
    }

    std::uint64_t alloc_slot = 0;
    for (const ImportRef& ref : image.imports()) {
        if (ref.name == "VirtualAlloc" && ref.thunk != 0) {
            g_alloc_thunk = ref.thunk;
            alloc_slot = ref.iat_slot;
            break;
        }
    }
    CHECK(g_alloc_thunk != 0, "VirtualAlloc resolvido para um thunk");
    CHECK(alloc_slot != 0 && *reinterpret_cast<std::uint64_t*>(alloc_slot) == g_alloc_thunk,
          "a IAT do guest aponta para o thunk");

    InstallRcApi(image.base(), image.size());
    CHECK(rc != nullptr && rc->image_base == image.base(), "RcApi instalada");

    RegisterFunction(0x1000, SyntheticCaller);
    RunStats stats;
    CHECK(RunGuest(image.base() + 0x1000, image.base(), &stats), "RunGuest completou");
    CHECK(stats.calls == 1, "uma chamada registada");
    CHECK(stats.thunk_calls == 1, "a chamada atravessou o dispatcher de thunks");

    g_import_veneer = image.base() + 0xD7F3ACull;
    RegisterFunction(0x3000, SyntheticImportVeneer);
    RunStats veneer_stats;
    CHECK(RunGuest(image.base() + 0x3000, image.base(), &veneer_stats),
          "RunGuest resolveu um trampoline de import PE");
    CHECK(veneer_stats.thunk_calls == 1,
          "o trampoline de import foi encaminhado para o thunk Win32");

    g_import_veneer = image.base() + 0xA15FCull;
    bool critical_section_import_resolved = false;
    for (const ImportRef& ref : image.imports()) {
        if (ref.name == "InitializeCriticalSectionAndSpinCount" &&
            ref.iat_slot == image.base() + 0x12B9048ull &&
            ref.thunk != 0 &&
            *reinterpret_cast<const std::uint64_t*>(ref.iat_slot) == ref.thunk) {
            critical_section_import_resolved = true;
            break;
        }
    }
    CHECK(critical_section_import_resolved,
          "o slot IAT do trampoline REX.W aponta para o import esperado");
    RegisterFunction(0x5000, SyntheticCriticalSectionVeneer);
    RunStats rex_veneer_stats;
    CHECK(RunGuest(image.base() + 0x5000, image.base(), &rex_veneer_stats),
          "RunGuest resolveu um trampoline PE com prefixo REX.W");
    CHECK(rex_veneer_stats.thunk_calls == 1,
          "trampoline REX.W encaminhou o import para o thunk Win32");
    CHECK(g_veneer_result == 1,
          "InitializeCriticalSectionAndSpinCount retornou sucesso pelo trampoline");

    RegisterFunction(0x4000, SyntheticZeroReturnLeaf);
    RunStats leaf_stats;
    CHECK(RunGuest(image.base() + 0x4000, image.base(), &leaf_stats),
          "RunGuest executou um leaf zero-return fora de .pdata");
    CHECK(g_leaf_result == 0, "leaf xor eax,eax; ret devolveu zero");

    RegisterFunction(0x7000, SyntheticRecordHelper);
    RunStats record_stats;
    CHECK(RunGuest(image.base() + 0x7000, image.base(), &record_stats),
          "dispatcher executou o constructor sem .pdata");
    CHECK(g_record_result == reinterpret_cast<std::uint64_t>(g_record),
          "constructor devolveu o endereco do registro");
    const bool record_matches =
        std::memcmp(g_record, g_record_expected, sizeof(g_record)) == 0;
    if (!record_matches) {
        const auto* expected = reinterpret_cast<const std::uint8_t*>(g_record_expected);
        for (std::size_t i = 0; i < sizeof(g_record); ++i) {
            if (g_record[i] != expected[i]) {
                std::printf("      registro diverge em +0x%02zx: %02x != %02x\n", i,
                            g_record[i], expected[i]);
                break;
            }
        }
    }
    CHECK(record_matches, "constructor copiou corretamente os argumentos Win64");

    RegisterFunction(0x8000, SyntheticPdataLessHelper);
    g_helper_offset = 0xE62B60;
    RunStats pointer_stats;
    CHECK(RunGuest(image.base() + 0x8000, image.base(), &pointer_stats),
          "dispatcher executou o getter sem .pdata");
    CHECK(g_helper_result == g_first_pointer,
          "getter em E62B60 devolveu o ponteiro esperado");

    g_helper_offset = 0xE62BD0;
    RunStats first_field_stats;
    CHECK(RunGuest(image.base() + 0x8000, image.base(), &first_field_stats),
          "dispatcher executou o getter de campo em E62BD0");
    CHECK(g_helper_result == reinterpret_cast<std::uint64_t>(&g_list[1][0]),
          "getter em E62BD0 leu o campo +8");

    g_helper_offset = 0xE62BE0;
    RunStats second_field_stats;
    CHECK(RunGuest(image.base() + 0x8000, image.base(), &second_field_stats),
          "dispatcher executou o getter de campo em E62BE0");
    CHECK(g_helper_result == reinterpret_cast<std::uint64_t>(&g_list[1][0]),
          "getter em E62BE0 leu o campo +8");

    g_helper_offset = 0xE62BF0;
    RunStats list_count_stats;
    CHECK(RunGuest(image.base() + 0x8000, image.base(), &list_count_stats),
          "dispatcher executou a contagem de lista sem .pdata");
    CHECK(g_helper_result == 3, "contagem em E62BF0 devolveu tres nos");

    g_helper_offset = 0xE67C60;
    RunStats global_pointer_stats;
    CHECK(RunGuest(image.base() + 0x8000, image.base(), &global_pointer_stats),
          "dispatcher executou o initializer de E67C60");
    const std::uint64_t initialized_pointer = GuestLoad<std::uint64_t>(
        reinterpret_cast<std::uint64_t>(g_record));
    CHECK(g_helper_result == reinterpret_cast<std::uint64_t>(g_record),
          "initializer em E67C60 devolveu o registro");
    CHECK(initialized_pointer == image.base() + 0x1302AD0ull,
          "initializer em E67C60 gravou o global correto");

    g_helper_offset = 0xE681E0;
    RunStats pointer_identity_stats;
    CHECK(RunGuest(image.base() + 0x8000, image.base(), &pointer_identity_stats),
          "dispatcher executou o getter identity sem .pdata");
    CHECK(g_helper_result == reinterpret_cast<std::uint64_t>(g_record),
          "getter em E681E0 devolveu RCX");

    RegisterFunction(0x6000, SyntheticOneArgumentThunk);
    RunStats init_thunk_stats;
    CHECK(RunGuest(image.base() + 0x6000, image.base(), &init_thunk_stats),
          "dispatcher executou o thunk leaf que define RCX e salta para funcao");

    RegisterFunction(0x2000, SyntheticUnhandled);
    RunStats bad{};
    CHECK(!RunGuest(image.base() + 0x2000, image.base(), &bad),
          "endereco sem funcao para a execucao (e diz onde)");
    CHECK(bad.unhandled == 1, "o caso nao implementado foi contabilizado");

    win32::Shutdown();
    std::printf("\n%s (%d falha(s))\n", g_fail ? "FALHOU" : "TUDO OK", g_fail);
    return g_fail ? 1 : 0;
}
