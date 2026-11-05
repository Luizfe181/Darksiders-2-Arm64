// rc_runtime.h -- the RcApi the recompiled C calls back into.
//
// The generated code never calls the game's functions directly across module
// boundaries: it calls `rc->call(c, target, ret)` / `rc->tail(c)`, and anything
// it could not translate goes to `rc->interp(c)`. This file implements those.
#pragma once

#include <cstddef>
#include <cstdint>

#include "cpu_context.h"

namespace vigil::recomp {

struct RunStats {
    std::uint64_t calls = 0;
    std::uint64_t dispatches = 0;
    std::uint64_t thunk_calls = 0;
    std::uint64_t interpreted = 0;
    std::uint64_t unhandled = 0;
};

// Fills in the process-wide RcApi and points `rc` at it. `rc` is defined by the
// generated OUT.c (or by a test), not here.
void InstallRcApi(std::uint64_t image_base, std::uint64_t image_size);

// Functions the dispatcher may enter, by image offset.
void SetFunctionTable(const RcFunction* table, std::size_t count);
void RegisterFunction(std::uint64_t offset, RcFn fn);

// Registers the table exported by the generated OUT.c, when the library was
// built with the recompiled game. Returns false if there is none.
bool InitializeGameLibrary();

// Runs `entry` (an absolute guest address) on a fresh 16 MiB guest stack.
// Returns false when execution stopped at something not implemented; the offset
// is logged, so the gap is visible instead of silently corrupting state.
bool RunGuest(std::uint64_t entry, std::uint64_t image_base, RunStats* stats);

// Called by the interpreter path once a real interpreter exists.
bool InterpreterAvailable();

}  // namespace vigil::recomp
