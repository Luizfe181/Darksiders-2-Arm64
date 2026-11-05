// cpu_context.h -- x86-64 guest state for the Vigil static recompiler (ARM64 / NDK)
//
// Adapted from bloodborne-recomp (bbcpu's `BbCpu`, used by src/recomp/rc.h).
// Every recompiled function has the signature
//
//     void f_<image_offset>(CpuContext *c);
//
// and keeps the registers it touches in C locals (`uint64_t r[16]`, `Vec256 v[16]`),
// spilling back into `*c` only around calls, interpreter fallbacks and returns.
// `c` is therefore not touched on the hot path -- it is the rendezvous point, not
// the working set.
//
// NOTE ON THE TARGET: x86-64 and ARM64 share LP64, so guest pointers are host
// pointers and the game's live objects are used in place (principle 3 of the
// reference project). What does NOT carry over is memory *ordering*: x86 is
// TSO, ARM64 is weakly ordered. Guest loads/stores therefore carry acquire /
// release semantics here (see GuestLoad/GuestStore). That is the one place this
// header does real work on ARM64.
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <type_traits>

namespace vigil::recomp {

// ---------------------------------------------------------------------------
// Vector registers: xmm are 128-bit, ymm 256-bit. Stored 32 bytes wide like the
// reference project's BbVec, so AVX forms have somewhere to live.
// ---------------------------------------------------------------------------
union alignas(32) Vec256 {
    uint8_t  b[32];
    int8_t   sb[32];
    uint16_t w[16];
    int16_t  sw[16];
    uint32_t d[8];
    int32_t  sd[8];
    uint64_t q[4];
    int64_t  sq[4];
    float    f[8];
    double   fd[4];
};
static_assert(sizeof(Vec256) == 32 && alignof(Vec256) == 32, "Vec256");

// ---------------------------------------------------------------------------
// General-purpose registers, in x86 encoding order (the order Zydis and the
// reference generator's `r[]` use). Do not reorder: generated code indexes
// these numerically.
// ---------------------------------------------------------------------------
enum Reg : uint32_t {
    RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    REG_COUNT = 16
};

// RFLAGS bits that guest code observes.
enum Flag : uint64_t {
    F_CF = 1ull << 0,
    F_PF = 1ull << 2,
    F_AF = 1ull << 4,
    F_ZF = 1ull << 6,
    F_SF = 1ull << 7,
    F_TF = 1ull << 8,
    F_IF = 1ull << 9,
    F_DF = 1ull << 10,
    F_OF = 1ull << 11,
    F_ARITH = F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF,
};

// Arithmetic kind, for the shared flag helper (mirrors the reference's FK_*).
enum ArithKind : int { AK_ADD = 0, AK_SUB = 1, AK_LOGIC = 2 };

// ---------------------------------------------------------------------------
// Guest state. `alignas(64)` keeps one context on a cache line; there is one per
// guest thread.
// ---------------------------------------------------------------------------
struct alignas(64) CpuContext {
    uint64_t r[REG_COUNT];   // 0x000  GPR file, encoding order
    uint64_t rip;            // 0x080  guest instruction pointer
    uint64_t flags;          // 0x088  materialised RFLAGS
    Vec256   v[16];          // 0x0A0  xmm/ymm file (16 x 32B)
    uint32_t mxcsr;          // 0x2A0  SSE control/status
    uint32_t fpu_cw;         // 0x2A4  x87 control word (emulated: ARM64 has FPCR)
    uint16_t fpu_sw;         // 0x2A8  x87 status word
    uint16_t fpu_tw;         // 0x2AA  x87 tag word
    uint8_t  fpu_depth;      // 0x2AC  x87 stack depth
    uint8_t  _pad0[3];       // 0x2AD
    uint8_t  st[8][10];      // 0x2B0  x87 registers, 80-bit extended, raw
    uint64_t fs_base;        // 0x300  Win64 TLS base (TEB) -- x86-64 has no fs register
    uint64_t gs_base;        // 0x308
    void    *host_thread;    // 0x310  back-pointer for the runtime
    alignas(16) uint8_t guest_teb[0x100]; // Synthetic Win64 TEB for GS-relative accesses
};

static_assert(offsetof(CpuContext, r) == 0x000, "r offset");
static_assert(offsetof(CpuContext, rip) == 0x080, "rip offset");
static_assert(offsetof(CpuContext, flags) == 0x088, "flags offset");
static_assert(offsetof(CpuContext, v) == 0x0A0, "v offset");
static_assert(offsetof(CpuContext, mxcsr) == 0x2A0, "mxcsr offset");
static_assert(offsetof(CpuContext, fs_base) == 0x300, "fs_base offset");
static_assert(offsetof(CpuContext, gs_base) == 0x308, "gs_base offset");
static_assert(sizeof(CpuContext) % 64 == 0, "CpuContext cache-line sized");

inline void InitializeGuestTeb(CpuContext &context, uint64_t stack_base) noexcept {
    std::memset(context.guest_teb, 0, sizeof(context.guest_teb));
    context.gs_base = reinterpret_cast<uint64_t>(context.guest_teb);
    std::memcpy(context.guest_teb + 0x08, &stack_base, sizeof(stack_base));
    std::memcpy(context.guest_teb + 0x30, &context.gs_base, sizeof(context.gs_base));
}

// ---------------------------------------------------------------------------
// Guest memory. Guest address == host address (image_base + image offset).
//
// x86 gives every load acquire and every store release for free (TSO). ARM64
// does not, and the game publishes data between threads with plain stores, so
// these helpers add the ordering explicitly. On an x86-64 host the compiler
// folds them back to plain movs.
//
// Unaligned accesses are legal in the guest (x86 has no alignment requirement),
// so the unaligned path goes through memcpy + an explicit fence rather than a
// direct typed access (which would fault on ARM64).
// ---------------------------------------------------------------------------
template <typename T>
inline T GuestLoad(uint64_t addr) noexcept {
    static_assert(std::is_trivially_copyable_v<T>, "guest scalar");
    T v;
    if ((addr & (alignof(T) - 1)) == 0) {
        std::memcpy(&v, reinterpret_cast<const void *>(addr), sizeof(T));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    } else {
        std::memcpy(&v, reinterpret_cast<const void *>(addr), sizeof(T));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    }
    return v;
}

template <typename T>
inline void GuestStore(uint64_t addr, T v) noexcept {
    static_assert(std::is_trivially_copyable_v<T>, "guest scalar");
    __atomic_thread_fence(__ATOMIC_RELEASE);
    std::memcpy(reinterpret_cast<void *>(addr), &v, sizeof(T));
}

// 16-byte vector accesses (SSE). Only the low 16 bytes of the 32-byte slot are
// touched, which is what legacy SSE does: the upper half of a ymm is left as it
// was. This build assumes the guest is SSE2-era (no AVX), so the upper half is
// never observable; revisit if AVX forms start appearing.
inline void GuestLoadV(Vec256 &dst, uint64_t addr) noexcept {
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    std::memcpy(&dst, reinterpret_cast<const void *>(addr), 16);
}

inline void GuestStoreV(uint64_t addr, const Vec256 &src) noexcept {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    std::memcpy(reinterpret_cast<void *>(addr), &src, 16);
}

// ---------------------------------------------------------------------------
// Flags. The reference project computes these lazily (a kind tag plus the
// operands, materialised only when something reads them, so clang drops what
// nothing uses). This first version materialises eagerly through one helper;
// switching to the lazy scheme is a local change to the generator's emit.
// ---------------------------------------------------------------------------
inline uint64_t FlagMaskForSize(unsigned size) noexcept {
    return size >= 8 ? ~0ull : ((1ull << (size * 8)) - 1ull);
}

inline uint64_t ArithFlags(uint64_t flags, int kind, uint64_t a, uint64_t b,
                           uint64_t res, unsigned size) noexcept {
    const uint64_t m = FlagMaskForSize(size);
    const unsigned bits = size * 8;
    const uint64_t sign = 1ull << (bits - 1);
    const uint64_t ra = a & m, rb = b & m, rr = res & m;

    uint64_t out = flags & ~(uint64_t)F_ARITH;
    if (rr == 0) out |= F_ZF;
    if (rr & sign) out |= F_SF;
    if ((0x6996u >> ((rr ^ (rr >> 4)) & 0xf)) & 1u) out |= F_PF;  // parity of low byte
    if ((ra ^ rb ^ rr) & 0x10) out |= F_AF;

    if (kind == AK_ADD) {
        if (rr < ra) out |= F_CF;
        if ((~(ra ^ rb) & (ra ^ rr)) & sign) out |= F_OF;
    } else if (kind == AK_SUB) {
        if (ra < rb) out |= F_CF;
        if (((ra ^ rb) & (ra ^ rr)) & sign) out |= F_OF;
    } else {
        out &= ~(uint64_t)(F_CF | F_OF);  // logic: CF = OF = 0
    }
    return out;
}

inline bool Cond(int cc, uint64_t f) noexcept {
    const bool cf = (f & F_CF) != 0, zf = (f & F_ZF) != 0;
    const bool sf = (f & F_SF) != 0, of = (f & F_OF) != 0;
    switch (cc & 0xf) {
        case 0x0: return of;                    // o
        case 0x1: return !of;                   // no
        case 0x2: return cf;                    // b/c
        case 0x3: return !cf;                   // ae/nc
        case 0x4: return zf;                    // e/z
        case 0x5: return !zf;                   // ne/nz
        case 0x6: return cf || zf;              // be
        case 0x7: return !cf && !zf;            // a
        case 0x8: return sf;                    // s
        case 0x9: return !sf;                   // ns
        case 0xa: return (f & F_PF) != 0;        // p
        case 0xb: return (f & F_PF) == 0;        // np
        case 0xc: return sf != of;              // l
        case 0xd: return sf == of;              // ge
        case 0xe: return zf || (sf != of);      // le
        default:  return !zf && (sf == of);     // g
    }
}

// ---------------------------------------------------------------------------
// The runtime interface the generated code calls (bbcpu's `RcApi`, reduced).
// ---------------------------------------------------------------------------
struct RcApi;
using RcFn = void (*)(CpuContext *c);

struct RcFunction {
    uint64_t offset;              // image offset of the guest function
    uint64_t size;                // byte length (from .pdata)
    uint64_t hash;                // of the guest bytes, checked by the loader
    RcFn     fn;                  // f_<offset>
    RcFn    *slot;                // &d_<offset>: filled once the callee is live
};

struct RcApi {
    uint32_t      version;
    uint64_t      image_base;
    // Call guest address `target`; `ret` is the guest return address to push.
    void        (*call)(CpuContext *c, uint64_t target, uint64_t ret);
    // Run one guest instruction at `c->rip` in the interpreter.
    void        (*interp)(CpuContext *c);
    // Leave recompiled code for the translator, restoring the entry stack.
    void        (*bail)(CpuContext *c, uint64_t entry_rsp);
    // Tail call: the callee is reached with the current stack, then returns.
    void        (*tail)(CpuContext *c);
    // Optional trace hook (BB_RECOMP_TRACE).
    void        (*trace)(uint64_t off, uint64_t *r, CpuContext *c);
};

}  // namespace vigil::recomp
