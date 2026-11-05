// game_image.h -- maps Darksiders2.exe the way the guest expects it.
//
// Guest memory IS host memory, so the PE is mapped at its preferred base
// (0x140000000) and the game's own pointers stay valid. Two jobs beyond the
// mapping matter for a static recompiler:
//
//   * base relocations, if the image could not be placed at its preferred base;
//   * the import table: every IAT slot is overwritten with one of our synthetic
//     thunks, so the guest's `call [iat]` lands in win32::Dispatch.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vigil::recomp {

struct ImportRef {
    std::string module;
    std::string name;       // "Ordinal_N" for an ordinal import
    std::uint16_t ordinal = 0;
    std::uint64_t iat_slot = 0;   // guest address of the slot we patched
    std::uint64_t thunk = 0;      // what we wrote there (0 = unresolved)
};

class GameImage {
public:
    GameImage() = default;
    ~GameImage();
    GameImage(const GameImage&) = delete;
    GameImage& operator=(const GameImage&) = delete;

    // Maps the file at its ImageBase. Returns false and leaves the object
    // unchanged on failure.
    bool Map(const char* path);

    // Replaces every import slot with a win32 thunk. Unresolved ones are left
    // as they were and listed in imports() with thunk == 0.
    bool PatchImports();

    std::uint64_t base() const { return m_base; }
    std::uint64_t entry() const { return m_entry; }
    std::uint64_t size() const { return m_size; }
    const std::vector<ImportRef>& imports() const { return m_imports; }
    std::size_t unresolved() const;

private:
    std::uint64_t m_base = 0;
    std::uint64_t m_entry = 0;
    std::uint64_t m_size = 0;
    std::vector<ImportRef> m_imports;
};

}  // namespace vigil::recomp
