# Vigil static recompiler — blueprint

Adapted from [`bloodborne-recomp`](../../bloodborne-recomp) (PS4 x86-64 → native C).
Same shape, different target: Darksiders II DE is **Windows x86-64 (PE)** and the
host is **ARM64-v8a / NDK**, not PS4/macOS.

## 1. Why a static recompiler fits here

The reference project does not translate x86 to arm64 instruction by instruction
on the fly. It writes each guest function out as **C**, and clang compiles that C
for the host. The compiler does the instruction selection, register allocation and
scheduling. ARM64 vs x86-64 then stops being a translation problem and becomes
only a *semantics* problem: the generated C must reproduce x86-64 behaviour, and
the C compiler handles the rest.

Two properties make that work for Darksiders II as well:

* **LP64 on both sides.** Guest pointers are host pointers; the game's live
  objects are used in place, with their original layout.
* **The guest ABI never reaches the host ABI.** A generated function is
  `void f_<rva>(CpuContext *c)`; arguments travel through `c->r[]` / `c->v[]`,
  not through arm64 registers. x86-64's Win64 convention (rcx, rdx, r8, r9,
  xmm0–3) is just data the generated code moves around.

The one thing that does **not** port for free is **memory ordering**. x86 is TSO;
ARM64 is weakly ordered, and the engine publishes work between threads with plain
stores. `GuestLoad` / `GuestStore` in `include/cpu_context.h` therefore carry
acquire/release semantics. On an x86-64 host they fold back to plain `mov`.

## 2. CpuContext

`include/cpu_context.h`. One per guest thread, 64-byte aligned (832 bytes).

| field | offset | notes |
|---|---:|---|
| `r[16]` | `0x000` | GPR file in x86 **encoding** order: rax rcx rdx rbx rsp rbp rsi rdi r8–r15 |
| `rip` | `0x080` | guest instruction pointer |
| `flags` | `0x088` | materialised RFLAGS |
| `v[16]` | `0x0A0` | xmm/ymm, 32 B each (`Vec256`) |
| `mxcsr` | `0x2A0` | SSE control/status (ARM64 has FPCR, so this is emulated) |
| `st[8][10]` | `0x2B0` | x87, 80-bit raw (ARM64 `long double` is 128-bit, so never use it) |
| `fs_base` | `0x300` | Win64 TLS base — x86-64 has no `fs` register |

The register order matters: generated code indexes `r[]` numerically, exactly as
the reference generator does.

**Registers live in locals, not in the context.** Each generated function declares
`uint64_t r[16]; Vec256 v[16];`, loads them once at entry, works in locals, and
writes them back only around calls, interpreter fallbacks and exits. `CpuContext`
is the rendezvous point, not the working set. (V1 syncs all 16; the reference does
a liveness/dirty fixed-point over the function's `goto` graph and syncs only what
changed — see `bbrecomp.c`, "register sync".)

## 3. Frontend and code generation

`tools/recompiler/main.py`.

**Function discovery** — the PE's `.pdata` (the x64 exception directory,
`RUNTIME_FUNCTION[] {Begin, End, Unwind}`) gives exact bounds for **97,825**
functions in `Darksiders2.exe`. That is the direct analogue of the PS4 unwind
tables `scan.c` uses; no heuristic sweep is needed.

**Decoding** — Capstone, following control flow from each entry within its
`.pdata` bounds. Direct branches inside the function become `goto L_<rva>:`;
returns become `return`, with the guest return address popped from the guest stack.

**Emission** — one C function per guest function:

```c
__attribute__((visibility("hidden"))) void f_1030(CpuContext *c) {
    const uint64_t B = rc->image_base;
    uint64_t r[16];
    Vec256 v[16];
    RC_LOAD();
    { c->flags = ArithFlags(c->flags, 1, r[4], 0x28ull, (r[4] - 0x28ull), 8);
      r[4] = (r[4] - 0x28ull); }
    ...
}
```

Anything not translated becomes a single-instruction interpreter call, so the
output is complete from the first run:

```c
{ c->rip = B + 0x103dull; RC_SAVE(); rc->interp(c); RC_LOAD(); }
```

That is the reference's "always playable" rule: correctness first, coverage grows
by moving forms from `interp` to native C.

## 4. Call resolution and dispatch

Three mechanisms, matching the reference:

1. **Direct calls to a known function** — one `RcFn` slot per function,
   `d_<rva>`, filled by the loader. If the slot is live the generated code calls
   the callee through it, pushing the guest return address first; if not, it falls
   back to the runtime bridge:

   ```c
   { extern RcFn d_10c4; RC_SAVE();
     if (d_10c4) { c->r[RSP] -= 8;
                   GuestStore<uint64_t>(c->r[RSP], B + 0x10d4ull);
                   c->rip = B + 0x10d4ull; d_10c4(c); }
     else rc->call(c, B + 0x10c4ull, B + 0x10d4ull);
     RC_LOAD(); }
   ```

2. **Indirect calls / jumps** — go to `rc->call` / `rc->tail`: the runtime
   resolves the guest address and either enters another recompiled function or
   the translator. Inside one function, a jump table is a `switch (dn - B)` over
   the decoded case addresses (`L_dispatch`); a target that leaves the function is
   a tail call.

3. **The table** — `OUT.c` exports

   ```c
   const RcFunction *bb_recomp_init(const RcApi *api, size_t *count);
   ```

   with `{offset, size, hash, f_<rva>, &d_<rva>}` per function. The loader
   verifies `hash` against the bytes in the player's own image before wiring a
   slot — that is how a patched or hooked function is detected and left to the
   translator.

## 5. Measured on the real image

`Darksiders2.exe`, 33,637,376 bytes, image base `0x140000000`:

| | |
|---|---:|
| Functions from `.pdata` | 97,825 |
| Functions emitted | 97,821 |
| Instructions decoded | 4,635,154 |
| Instructions translated to C | 4,437,427 (**95.7%**) |
| Output | 150 files, ~2 MB each |
| Generation time | ~45 s |

The 4.3% left in the interpreter, by count:

| Form | Count | Why it is still there |
|---|---:|---|
| `lock xadd` / `lock inc` / `lock dec` / `lock add` | 78,234 | must become `rc_cas` compare-and-exchange loops |
| `shufps` | 22,709 | needs the immediate-driven lane permutation table |
| `comiss` / `ucomiss` | 11,746 | raise `#IA` on NaN; goes through the interpreter until the MXCSR model exists |
| `imul` (3-operand), `movd`, `cvtdq2ps`, `movzx` edge forms | ~14,000 | small, mechanical |
| `int3` | 2,383 | deliberate: these are the game's own breakpoints |

No `AVX`/`VEX` forms were needed, which confirms the SSE2 assumption in
`GuestLoadV` / `GuestStoreV`.

## 6. What must be built next

| Piece | Reference | Here |
|---|---|---|
| Runtime (`RcApi`: `call`, `interp`, `tail`, `bail`) | bbcpu `src/recomp/rc.h` | **missing** — `cpu_context.h` declares the interface only |
| x86-64 interpreter (fallback) | bbcpu `src/cpu/interp*` | **missing**; for Darksiders II it is also the Win32/Win64 API surface |
| Whole-program build | `build_library.py` | generate → `ndk-build`/CMake for arm64-v8a |
| Verification | `replay.c`, `fuzz_recomp.c` | record Win64 API calls, replay against generated code |
| Win32/DirectX boundary | PS4 libs | **the real port work**: `D3D11*`/`kernel32`/`user32` become SDL2/Vulkan/GLES calls |

The generator is the easy half. The hard half for this target is that Darksiders II
is a Windows program: its imports are `D3D11`, `kernel32`, `user32`, `xinput`,
not PS4 `libGnm`. Those import stubs are exactly the 660 functions the reference
leaves to its translator — and here they are where the Android port actually lives.
