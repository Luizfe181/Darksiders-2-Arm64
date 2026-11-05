// rc_runtime.cpp -- implementation of the RcApi used by the recompiled code.
#include "rc_runtime.h"

#include <algorithm>
#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "win32_stubs.h"

namespace win32 = darksiders2::win32;

// Defined by the generated OUT.c (global scope, like the generated code
// declares it); a test may define it instead.
extern const vigil::recomp::RcApi* rc;

// Exported by the generated OUT.c when the recompiled game is in the build.
// Weak so the runtime still links on its own (boot-test APK without game code).
extern "C" const vigil::recomp::RcFunction* bb_recomp_init(const vigil::recomp::RcApi*,
                                                           std::size_t*)
    __attribute__((weak));

#if defined(__ANDROID__)
#include <android/log.h>
#define RC_LOG(...) __android_log_print(ANDROID_LOG_INFO, "D2Recomp", __VA_ARGS__)
#else
#define RC_LOG(...)                                    \
    do {                                               \
        std::fprintf(stderr, __VA_ARGS__);             \
        std::fputc('\n', stderr);                      \
    } while (0)
#endif

namespace vigil::recomp {

namespace {

const RcFunction* g_table = nullptr;
std::size_t g_count = 0;
std::unordered_map<std::uint64_t, RcFn> g_registered;

std::uint64_t g_image_base = 0;
std::uint64_t g_image_size = 0;
RunStats g_stats;
std::jmp_buf g_stop;
bool g_stop_ready = false;

const char* g_reason = "";
std::uint64_t g_reason_offset = 0;

bool DispatchPdataLessHelper(CpuContext* c, std::uint64_t offset);

[[noreturn]] void Stop(const char* reason, std::uint64_t offset_in_image) {
    g_reason = reason;
    g_reason_offset = offset_in_image;
    ++g_stats.unhandled;
    std::longjmp(g_stop, 1);
}

void Dispatch(CpuContext* c, std::uint64_t target) {
    ++g_stats.dispatches;

    // A Win32 import: the IAT was patched to point at one of our thunks.
    if (win32::IsThunk(target)) {
        ++g_stats.thunk_calls;
        win32::Dispatch(c, target);
        return;
    }

    // PE import veneers are `jmp [rip+disp32]` with an optional REX prefix.
    // They are not in .pdata, so resolve the patched IAT target directly.
    if (target >= g_image_base && g_image_size >= sizeof(std::uint64_t) &&
        target - g_image_base <= g_image_size - 6) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        const std::size_t opcode = code[0] >= 0x40 && code[0] <= 0x4F ? 1 : 0;
        const std::size_t instruction_size = opcode + 6;
        if (instruction_size <= g_image_size - (target - g_image_base) &&
            code[opcode] == 0xFF && code[opcode + 1] == 0x25) {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, code + opcode + 2, sizeof(displacement));
            const std::int64_t slot_address =
                static_cast<std::int64_t>(target) + instruction_size + displacement;
            if (slot_address >= static_cast<std::int64_t>(g_image_base)) {
                const std::uint64_t slot_offset =
                    static_cast<std::uint64_t>(slot_address) - g_image_base;
                if (slot_offset <= g_image_size - sizeof(std::uint64_t)) {
                    std::uint64_t import_target = 0;
                    std::memcpy(&import_target,
                                reinterpret_cast<const void*>(slot_address),
                                sizeof(import_target));
                    if (win32::IsThunk(import_target)) {
                        ++g_stats.thunk_calls;
                        win32::Dispatch(c, import_target);
                        return;
                    }
                }
            }
        }
    }

    // A few CRT initializer thunks are leaf code outside .pdata: load one
    // image-relative argument into RCX, then tail-jump to a real function.
    if (target >= g_image_base && target - g_image_base <= g_image_size &&
        g_image_size - (target - g_image_base) >= 12) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        if (code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x0D &&
            code[7] == 0xE9) {
            std::int32_t argument_displacement = 0;
            std::int32_t target_displacement = 0;
            std::memcpy(&argument_displacement, code + 3, sizeof(argument_displacement));
            std::memcpy(&target_displacement, code + 8, sizeof(target_displacement));
            const std::int64_t argument =
                static_cast<std::int64_t>(target) + 7 + argument_displacement;
            const std::int64_t destination =
                static_cast<std::int64_t>(target) + 12 + target_displacement;
            if (argument >= static_cast<std::int64_t>(g_image_base) &&
                destination >= static_cast<std::int64_t>(g_image_base)) {
                const std::uint64_t argument_offset =
                    static_cast<std::uint64_t>(argument) - g_image_base;
                const std::uint64_t destination_offset =
                    static_cast<std::uint64_t>(destination) - g_image_base;
                if (argument_offset < g_image_size &&
                    destination_offset < g_image_size) {
                    c->r[RCX] = static_cast<std::uint64_t>(argument);
                    c->rip = static_cast<std::uint64_t>(destination);
                    Dispatch(c, c->rip);
                    return;
                }
            }
        }
    }

    // Some leaf functions are omitted from PE .pdata. Handle the exact
    // `xor eax,eax; ret` form used by the CRT image without guessing a target.
    if (target >= g_image_base && g_image_size >= 3 &&
        target - g_image_base <= g_image_size - 3) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        if (code[0] == 0x33 && code[1] == 0xC0 && code[2] == 0xC3) {
            c->r[RAX] = 0;
            c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
            c->r[RSP] += sizeof(std::uint64_t);
            return;
        }
    }

    const std::uint64_t offset = target - g_image_base;

    for (std::size_t i = 0; i < g_count; ++i) {
        if (g_table[i].offset != offset) continue;
        if (g_table[i].fn != nullptr) {
            g_table[i].fn(c);
            return;
        }
        break;
    }

    auto it = g_registered.find(offset);
    if (it != g_registered.end()) {
        it->second(c);
        return;
    }

    // Another pdata-less leaf used by the static initializer returns the
    // address of a global with `lea rax, [rip+disp32]; ret`.
    if (target >= g_image_base && g_image_size >= 8 &&
        target - g_image_base <= g_image_size - 8) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        if (code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x05 &&
            code[7] == 0xC3) {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, code + 3, sizeof(displacement));
            const std::int64_t address =
                static_cast<std::int64_t>(target + 7) + displacement;
            if (address >= static_cast<std::int64_t>(g_image_base) &&
                static_cast<std::uint64_t>(address) - g_image_base < g_image_size) {
                c->r[RAX] = static_cast<std::uint64_t>(address);
                c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
                c->r[RSP] += sizeof(std::uint64_t);
                return;
            }
        }
    }

    // A pdata-less global-pointer initializer copies one pointer, installs a
    // RIP-relative address, and returns.
    constexpr std::size_t kPointerInitSize = 29;
    if (target >= g_image_base && g_image_size >= kPointerInitSize &&
        target - g_image_base <= g_image_size - kPointerInitSize) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        constexpr std::uint8_t kPattern[] = {
            0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0x89, 0x05, 0, 0, 0, 0,
            0x48, 0x8D, 0x05, 0, 0, 0, 0, 0x48, 0x89, 0x05, 0, 0, 0, 0, 0xC3};
        bool matches = true;
        for (std::size_t i = 0; i < sizeof(kPattern); ++i) {
            if ((i >= 3 && i <= 6) || (i >= 10 && i <= 13) ||
                (i >= 17 && i <= 20) || (i >= 24 && i <= 27)) {
                continue;
            }
            if (code[i] != kPattern[i]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            std::int32_t displacement[4]{};
            constexpr std::size_t kDisplacementOffsets[] = {3, 10, 17, 24};
            for (std::size_t i = 0; i < 4; ++i) {
                std::memcpy(&displacement[i], code + kDisplacementOffsets[i],
                            sizeof(displacement[i]));
            }
            const std::int64_t source =
                static_cast<std::int64_t>(target + 7) + displacement[0];
            const std::int64_t first_destination =
                static_cast<std::int64_t>(target + 14) + displacement[1];
            const std::int64_t value =
                static_cast<std::int64_t>(target + 21) + displacement[2];
            const std::int64_t second_destination =
                static_cast<std::int64_t>(target + 28) + displacement[3];
            const auto in_image = [](std::int64_t address, std::size_t width) {
                return address >= static_cast<std::int64_t>(g_image_base) &&
                       static_cast<std::uint64_t>(address) - g_image_base <=
                           g_image_size - width;
            };
            if (in_image(source, sizeof(std::uint64_t)) &&
                in_image(first_destination, sizeof(std::uint64_t)) &&
                in_image(value, 1) &&
                in_image(second_destination, sizeof(std::uint64_t))) {
                const std::uint64_t copied = GuestLoad<std::uint64_t>(source);
                GuestStore<std::uint64_t>(first_destination, copied);
                GuestStore<std::uint64_t>(second_destination, value);
                c->r[RAX] = static_cast<std::uint64_t>(value);
                c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
                c->r[RSP] += sizeof(std::uint64_t);
                return;
            }
        }
    }

    if (target >= g_image_base && target - g_image_base < g_image_size) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        struct GlobalOperation {
            std::uint64_t address;
            bool load;
        };
        constexpr std::size_t kMaxOperations = 32;
        constexpr std::size_t kMaxSequenceSize = 0x100;
        GlobalOperation operations[kMaxOperations]{};
        const std::size_t available = static_cast<std::size_t>(
            std::min<std::uint64_t>(g_image_size - (target - g_image_base),
                                    kMaxSequenceSize));
        std::size_t operation_count = 0;
        std::size_t cursor = 0;
        bool matches = false;

        while (cursor < available) {
            if (code[cursor] == 0xC3) {
                matches = operation_count != 0;
                break;
            }
            if (available - cursor < 7 ||
                operation_count == kMaxOperations ||
                code[cursor] != 0x48 ||
                (code[cursor + 1] != 0x8B && code[cursor + 1] != 0x89) ||
                code[cursor + 2] != 0x05) {
                break;
            }

            std::int32_t source_displacement = 0;
            std::memcpy(&source_displacement, code + cursor + 3,
                        sizeof(source_displacement));
            const std::int64_t address =
                static_cast<std::int64_t>(target + cursor + 7) +
                source_displacement;
            if (address < static_cast<std::int64_t>(g_image_base) ||
                static_cast<std::uint64_t>(address) - g_image_base >
                    g_image_size - sizeof(std::uint64_t)) {
                break;
            }
            operations[operation_count++] = {
                static_cast<std::uint64_t>(address), code[cursor + 1] == 0x8B};
            cursor += 7;
        }

        if (matches) {
            for (std::size_t i = 0; i < operation_count; ++i) {
                if (operations[i].load) {
                    c->r[RAX] = GuestLoad<std::uint64_t>(operations[i].address);
                } else {
                    GuestStore<std::uint64_t>(operations[i].address, c->r[RAX]);
                }
            }
            c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
            c->r[RSP] += sizeof(std::uint64_t);
            return;
        }
    }

    constexpr std::size_t kPointerInitializerSize = 14;
    if (target >= g_image_base && g_image_size >= kPointerInitializerSize &&
        target - g_image_base <= g_image_size - kPointerInitializerSize) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        constexpr std::uint8_t kPattern[] = {
            0x48, 0x8D, 0x05, 0, 0, 0, 0, 0x48, 0x89, 0x01,
            0x48, 0x8B, 0xC1, 0xC3};
        bool matches = true;
        for (std::size_t i = 0; i < sizeof(kPattern); ++i) {
            if (i >= 3 && i <= 6) continue;
            if (code[i] != kPattern[i]) {
                matches = false;
                break;
            }
        }

        constexpr std::size_t kCompareSetSize = 15;
        if (target >= g_image_base && g_image_size >= kCompareSetSize &&
            target - g_image_base <= g_image_size - kCompareSetSize) {
            const auto* code = reinterpret_cast<const std::uint8_t*>(target);
            if (code[0] == 0x83 && code[1] == 0x3D &&
                (code[7] == 0x0F && (code[8] == 0x94 || code[8] == 0x95)) &&
                code[9] == 0x05 && code[14] == 0xC3) {
                std::int32_t source_displacement = 0;
                std::int32_t destination_displacement = 0;
                std::memcpy(&source_displacement, code + 2,
                            sizeof(source_displacement));
                std::memcpy(&destination_displacement, code + 10,
                            sizeof(destination_displacement));
                const std::int64_t source =
                    static_cast<std::int64_t>(target + 7) + source_displacement;
                const std::int64_t destination =
                    static_cast<std::int64_t>(target + 14) + destination_displacement;
                const std::int32_t immediate = static_cast<std::int8_t>(code[6]);
                if (source >= static_cast<std::int64_t>(g_image_base) &&
                    static_cast<std::uint64_t>(source) - g_image_base <=
                        g_image_size - sizeof(std::uint32_t) &&
                    destination >= static_cast<std::int64_t>(g_image_base) &&
                    static_cast<std::uint64_t>(destination) - g_image_base <
                        g_image_size) {
                    const bool equal = GuestLoad<std::uint32_t>(source) ==
                                       static_cast<std::uint32_t>(immediate);
                    const bool result = code[8] == 0x94 ? equal : !equal;
                    GuestStore<std::uint8_t>(destination,
                                             static_cast<std::uint8_t>(result));
                    c->r[RAX] = result;
                    c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
                    c->r[RSP] += sizeof(std::uint64_t);
                    return;
                }
            }
        }
        if (matches) {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, code + 3, sizeof(displacement));
            const std::int64_t address =
                static_cast<std::int64_t>(target + 7) + displacement;
            if (address >= static_cast<std::int64_t>(g_image_base) &&
                static_cast<std::uint64_t>(address) - g_image_base <
                    g_image_size) {
                GuestStore<std::uint64_t>(c->r[RCX],
                                          static_cast<std::uint64_t>(address));
                c->r[RAX] = c->r[RCX];
                c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
                c->r[RSP] += sizeof(std::uint64_t);
                return;
            }
        }
    }

    // The executable has compiler-generated static-initializer thunks outside
    // .pdata. This exact pattern normalizes eight byte flags to DWORDs, loads
    // the initializer argument into RCX, and tail-jumps to a regular function.
    constexpr std::size_t kFlagCount = 8;
    constexpr std::size_t kThunkSize = 0x74;
    if (target >= g_image_base && target - g_image_base <= g_image_size &&
        g_image_size - (target - g_image_base) >= kThunkSize) {
        const auto* code = reinterpret_cast<const std::uint8_t*>(target);
        std::uint64_t sources[kFlagCount]{};
        std::uint64_t destinations[kFlagCount]{};
        std::uint64_t argument = 0;
        std::size_t cursor = 0;
        bool matches = true;

        for (std::size_t i = 0; i < kFlagCount && matches; ++i) {
            std::int32_t displacement = 0;
            if (code[cursor] != 0x0F || code[cursor + 1] != 0xB6 ||
                code[cursor + 2] != 0x05) {
                matches = false;
                break;
            }
            std::memcpy(&displacement, code + cursor + 3, sizeof(displacement));
            const std::int64_t source =
                static_cast<std::int64_t>(target + cursor + 7) + displacement;
            if (source < static_cast<std::int64_t>(g_image_base) ||
                static_cast<std::uint64_t>(source) - g_image_base >= g_image_size) {
                matches = false;
                break;
            }
            sources[i] = static_cast<std::uint64_t>(source);
            cursor += 7;

            if (i == 0) {
                if (code[cursor] != 0x48 || code[cursor + 1] != 0x8D ||
                    code[cursor + 2] != 0x0D) {
                    matches = false;
                    break;
                }
                std::memcpy(&displacement, code + cursor + 3, sizeof(displacement));
                const std::int64_t value =
                    static_cast<std::int64_t>(target + cursor + 7) + displacement;
                if (value < static_cast<std::int64_t>(g_image_base) ||
                    static_cast<std::uint64_t>(value) - g_image_base >= g_image_size) {
                    matches = false;
                    break;
                }
                argument = static_cast<std::uint64_t>(value);
                cursor += 7;
            }

            if (code[cursor] != 0x89 || code[cursor + 1] != 0x05) {
                matches = false;
                break;
            }
            std::memcpy(&displacement, code + cursor + 2, sizeof(displacement));
            const std::int64_t destination =
                static_cast<std::int64_t>(target + cursor + 6) + displacement;
            if (destination < static_cast<std::int64_t>(g_image_base) ||
                static_cast<std::uint64_t>(destination) - g_image_base >
                    g_image_size - sizeof(std::uint32_t)) {
                matches = false;
                break;
            }
            destinations[i] = static_cast<std::uint64_t>(destination);
            cursor += 6;
        }

        if (matches && cursor + 5 == kThunkSize && code[cursor] == 0xE9) {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, code + cursor + 1, sizeof(displacement));
            const std::int64_t tail =
                static_cast<std::int64_t>(target + cursor + 5) + displacement;
            if (tail >= static_cast<std::int64_t>(g_image_base) &&
                static_cast<std::uint64_t>(tail) - g_image_base < g_image_size) {
                for (std::size_t i = 0; i < kFlagCount; ++i) {
                    const std::uint32_t value = GuestLoad<std::uint8_t>(sources[i]);
                    GuestStore<std::uint32_t>(destinations[i], value);
                    c->r[RAX] = value;
                }
                c->r[RCX] = argument;
                Dispatch(c, static_cast<std::uint64_t>(tail));
                return;
            }
        }
    }

    if (DispatchPdataLessHelper(c, offset)) return;

    Stop("no recompiled function for this address", offset);
}

// rc->call(c, target, return_address): a real call, so the return address goes
// on the guest stack first.
void ApiCall(CpuContext* c, std::uint64_t target, std::uint64_t ret) {
    ++g_stats.calls;
    c->r[RSP] -= 8;
    GuestStore<std::uint64_t>(c->r[RSP], ret);
    c->rip = target;
    Dispatch(c, target);
}

// rc->tail(c): the stack already looks like the callee's caller, so nothing is
// pushed; the callee's return goes straight back to the original caller.
void ApiTail(CpuContext* c) { Dispatch(c, c->rip); }

void ReturnFromGuestFunction(CpuContext* c) {
    c->rip = GuestLoad<std::uint64_t>(c->r[RSP]);
    c->r[RSP] += sizeof(std::uint64_t);
}

bool DispatchPdataLessHelper(CpuContext* c, std::uint64_t offset) {
    switch (offset) {
        case 0xE62B00: {
            const std::uint64_t stack = c->r[RSP];
            const std::uint64_t record = c->r[RCX];
            GuestStore<std::uint64_t>(record, c->r[RDX]);
            GuestStore<std::uint64_t>(record + 0x08, c->r[R8]);
            GuestStore<std::uint32_t>(record + 0x10,
                                      static_cast<std::uint32_t>(c->r[R9]));
            GuestStore<std::uint32_t>(record + 0x14,
                                      GuestLoad<std::uint32_t>(stack + 0x30));
            GuestStore<std::uint64_t>(record + 0x18,
                                      GuestLoad<std::uint64_t>(stack + 0x38));
            GuestStore<std::uint32_t>(record + 0x20,
                                      GuestLoad<std::uint32_t>(stack + 0x40));
            GuestStore<std::uint64_t>(record + 0x28,
                                      GuestLoad<std::uint64_t>(stack + 0x48));
            GuestStore<std::uint32_t>(record + 0x30,
                                      GuestLoad<std::uint32_t>(stack + 0x50));
            GuestStore<std::uint64_t>(record + 0x38,
                                      GuestLoad<std::uint64_t>(stack + 0x58));
            GuestStore<std::uint64_t>(record + 0x40,
                                      GuestLoad<std::uint64_t>(stack + 0x60));
            GuestStore<std::uint32_t>(record + 0x48,
                                      GuestLoad<std::uint32_t>(stack + 0x68));
            GuestStore<std::uint32_t>(record + 0x4C,
                                      GuestLoad<std::uint32_t>(stack + 0x70));
            c->r[RAX] = record;
            ReturnFromGuestFunction(c);
            return true;
        }
        case 0xE62B60:
            c->r[RAX] = GuestLoad<std::uint64_t>(c->r[RCX]);
            ReturnFromGuestFunction(c);
            return true;
        case 0xE62BD0:
        case 0xE62BE0:
            c->r[RAX] = GuestLoad<std::uint64_t>(c->r[RCX] + 0x08);
            ReturnFromGuestFunction(c);
            return true;
        case 0xE62BF0: {
            std::uint32_t count = 0;
            for (std::uint64_t node = c->r[RCX]; node != 0;
                 node = GuestLoad<std::uint64_t>(node + 0x08)) {
                ++count;
            }
            c->r[RAX] = count;
            ReturnFromGuestFunction(c);
            return true;
        }
        case 0xE68AF0: {
            const std::uint64_t record = c->r[RCX];
            GuestStore<std::uint32_t>(record, static_cast<std::uint32_t>(c->r[RDX]));
            GuestStore<std::uint32_t>(record + 0x04,
                                      static_cast<std::uint32_t>(c->r[R8]));
            GuestStore<std::uint32_t>(record + 0x08,
                                      static_cast<std::uint32_t>(c->r[R9]));
            GuestStore<std::uint32_t>(record + 0x0C,
                                      GuestLoad<std::uint32_t>(c->r[RSP] + 0x28));
            c->r[RAX] = record;
            ReturnFromGuestFunction(c);
            return true;
        }
        case 0xE681E0:
            c->r[RAX] = c->r[RCX];
            ReturnFromGuestFunction(c);
            return true;
        default:
            return false;
    }
}

void ApiBail(CpuContext* /*c*/, std::uint64_t /*entry_rsp*/) {
    Stop("the recompiled function asked to bail out", 0);
}

void ApiInterp(CpuContext* c) {
    ++g_stats.interpreted;
    Stop("instruction needs the interpreter", c->rip - g_image_base);
}

void ApiTrace(std::uint64_t /*off*/, std::uint64_t* /*r*/, CpuContext* /*c*/) {}

RcApi g_api = {
    /* version    */ 4,
    /* image_base */ 0,
    /* call       */ ApiCall,
    /* interp     */ ApiInterp,
    /* bail       */ ApiBail,
    /* tail       */ ApiTail,
    /* trace      */ ApiTrace,
};

}  // namespace

void InstallRcApi(std::uint64_t image_base, std::uint64_t image_size) {
    g_image_base = image_base;
    g_image_size = image_size;
    g_api.image_base = image_base;
    rc = &g_api;
}

void SetFunctionTable(const RcFunction* table, std::size_t count) {
    g_table = table;
    g_count = count;
}

void RegisterFunction(std::uint64_t offset, RcFn fn) { g_registered[offset] = fn; }

bool InitializeGameLibrary() {
    if (bb_recomp_init == nullptr) return false;
    std::size_t count = 0;
    const RcFunction* table = bb_recomp_init(&g_api, &count);
    SetFunctionTable(table, count);
    RC_LOG("[rc] biblioteca recompilada: %zu funcoes", count);
    return table != nullptr && count > 0;
}

bool InterpreterAvailable() { return false; }

bool RunGuest(std::uint64_t entry, std::uint64_t image_base, RunStats* stats) {
    g_image_base = image_base;
    g_api.image_base = image_base;
    g_stats = RunStats{};
    g_reason = "";
    g_reason_offset = 0;

    // 16 MiB of guest stack. The Win64 ABI expects rsp % 16 == 8 on entry.
    static std::vector<std::uint8_t> stack(16u << 20);
    CpuContext context{};
    const std::uint64_t stack_base =
        reinterpret_cast<std::uint64_t>(stack.data()) + stack.size();
    InitializeGuestTeb(context, stack_base);
    context.r[RSP] = (stack_base - 0x100) & ~0xFull;
    context.r[RSP] -= 8;
    context.rip = entry;

    g_stop_ready = true;
    if (setjmp(g_stop) != 0) {
        g_stop_ready = false;
        RC_LOG("[rc] parou: %s (image+0x%llx) calls=%llu thunks=%llu interp=%llu", g_reason,
               static_cast<unsigned long long>(g_reason_offset),
               static_cast<unsigned long long>(g_stats.calls),
               static_cast<unsigned long long>(g_stats.thunk_calls),
               static_cast<unsigned long long>(g_stats.interpreted));
        if (stats != nullptr) *stats = g_stats;
        return false;
    }

    Dispatch(&context, entry);
    g_stop_ready = false;
    if (stats != nullptr) *stats = g_stats;
    RC_LOG("[rc] entrada devolveu normalmente: calls=%llu thunks=%llu",
           static_cast<unsigned long long>(g_stats.calls),
           static_cast<unsigned long long>(g_stats.thunk_calls));
    return true;
}

}  // namespace vigil::recomp
