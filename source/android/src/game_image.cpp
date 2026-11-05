// game_image.cpp -- PE mapping, relocations and import patching.
#include "game_image.h"

#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "win32_stubs.h"

namespace win32 = darksiders2::win32;

namespace vigil::recomp {

namespace {

// Offsets into the PE headers. Parsed by offset rather than by struct: the
// layouts differ between PE32 and PE32+, and a wrong struct is a silent bug.
constexpr std::size_t kDosLfanew = 0x3C;
constexpr std::size_t kFileHeader = 4;             // after "PE\0\0"
constexpr std::size_t kOptHeader = kFileHeader + 20;
constexpr std::size_t kOptMagic = 0;
constexpr std::size_t kOptEntry = 16;
constexpr std::size_t kOptImageBase = 24;
constexpr std::size_t kOptSectionAlign = 32;
constexpr std::size_t kOptFileAlign = 36;
constexpr std::size_t kOptSizeOfImage = 56;
constexpr std::size_t kOptSizeOfHeaders = 60;
constexpr std::size_t kOptDataDir = 112;

constexpr std::uint32_t kDirImport = 1;
constexpr std::uint32_t kDirReloc = 5;

constexpr std::size_t kSectionHeaderSize = 40;

std::uint32_t ReadU32(const std::uint8_t* p) {
    std::uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
std::uint16_t ReadU16(const std::uint8_t* p) {
    std::uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

}  // namespace

GameImage::~GameImage() = default;

bool GameImage::Map(const char* path) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        std::fprintf(stderr, "[image] open(%s) failed\n", path);
        return false;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || st.st_size < 0x200) {
        ::close(fd);
        return false;
    }

    const std::size_t file_size = static_cast<std::size_t>(st.st_size);
    std::uint8_t* raw = static_cast<std::uint8_t*>(
        ::mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
    ::close(fd);
    if (raw == MAP_FAILED) return false;

    bool ok = false;
    do {
        if (raw[0] != 'M' || raw[1] != 'Z') break;
        const std::size_t pe = ReadU32(raw + kDosLfanew);
        if (pe + kOptDataDir > file_size) break;
        if (raw[pe] != 'P' || raw[pe + 1] != 'E') break;

        const std::uint8_t* opt = raw + pe + kOptHeader;
        if (ReadU16(opt + kOptMagic) != 0x20B) break;   // PE32+ only

        const std::uint64_t image_base = *reinterpret_cast<const std::uint64_t*>(opt + kOptImageBase);
        const std::uint32_t entry_rva = ReadU32(opt + kOptEntry);
        const std::uint32_t size_of_image = ReadU32(opt + kOptSizeOfImage);
        const std::uint32_t size_of_headers = ReadU32(opt + kOptSizeOfHeaders);
        const std::uint32_t section_align = ReadU32(opt + kOptSectionAlign);
        const std::uint32_t file_align = ReadU32(opt + kOptFileAlign);
        const std::uint16_t num_sections = ReadU16(raw + pe + kFileHeader + 2);
        const std::uint16_t opt_size = ReadU16(raw + pe + kFileHeader + 16);

        const std::size_t section_table = pe + kOptHeader + opt_size;
        if (section_table + num_sections * kSectionHeaderSize > file_size) break;
        if (size_of_image == 0) break;

        // Reserve the image at its preferred base. MAP_FIXED_NOREPLACE fails
        // instead of silently replacing an existing mapping.
        void* mapped = ::mmap(reinterpret_cast<void*>(image_base), size_of_image,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (mapped == MAP_FAILED) {
            std::fprintf(stderr, "[image] cannot map at 0x%llx\n",
                         static_cast<unsigned long long>(image_base));
            break;
        }
        if (mapped != reinterpret_cast<void*>(image_base)) break;

        std::memset(mapped, 0, size_of_image);
        std::memcpy(mapped, raw, size_of_headers);

        for (std::uint16_t i = 0; i < num_sections; ++i) {
            const std::uint8_t* sh = raw + section_table + i * kSectionHeaderSize;
            const std::uint32_t vsize = ReadU32(sh + 8);
            const std::uint32_t vaddr = ReadU32(sh + 12);
            const std::uint32_t raw_size = ReadU32(sh + 16);
            const std::uint32_t raw_ptr = ReadU32(sh + 20);
            if (raw_size == 0 || raw_ptr + raw_size > file_size) continue;
            if (vaddr + raw_size > size_of_image) continue;
            std::memcpy(static_cast<std::uint8_t*>(mapped) + vaddr, raw + raw_ptr, raw_size);
            (void)vsize;
            (void)section_align;
            (void)file_align;
        }

        // Base relocations, only needed if the image did not land where it wanted.
        const std::uint64_t actual = reinterpret_cast<std::uint64_t>(mapped);
        if (actual != image_base) {
            const std::uint64_t delta = actual - image_base;
            const std::uint32_t reloc_rva = ReadU32(opt + kOptDataDir + kDirReloc * 8);
            const std::uint32_t reloc_size = ReadU32(opt + kOptDataDir + kDirReloc * 8 + 4);
            if (reloc_rva != 0 && reloc_size != 0) {
                std::uint8_t* p = static_cast<std::uint8_t*>(mapped) + reloc_rva;
                std::uint8_t* end = p + reloc_size;
                while (p + 8 <= end) {
                    const std::uint32_t page = ReadU32(p);
                    const std::uint32_t block = ReadU32(p + 4);
                    if (block < 8) break;
                    const std::size_t count = (block - 8) / 2;
                    for (std::size_t k = 0; k < count; ++k) {
                        const std::uint16_t entry = ReadU16(p + 8 + k * 2);
                        const std::uint16_t type = entry >> 12;
                        const std::uint16_t off = entry & 0x0FFF;
                        if (type == 10) {  // IMAGE_REL_BASED_DIR64
                            auto* target = reinterpret_cast<std::uint64_t*>(
                                static_cast<std::uint8_t*>(mapped) + page + off);
                            *target += delta;
                        }
                    }
                    p += block;
                }
            }
        }

        m_base = actual;
        m_entry = actual + entry_rva;
        m_size = size_of_image;
        ok = true;
    } while (false);

    ::munmap(raw, file_size);
    return ok;
}

std::size_t GameImage::unresolved() const {
    std::size_t count = 0;
    for (const ImportRef& ref : m_imports) {
        if (ref.thunk == 0) ++count;
    }
    return count;
}

bool GameImage::PatchImports() {
    if (m_base == 0) return false;

    auto* base = reinterpret_cast<std::uint8_t*>(m_base);
    const std::size_t pe = ReadU32(base + kDosLfanew);
    const std::uint8_t* opt = base + pe + kOptHeader;
    const std::uint32_t import_rva = ReadU32(opt + kOptDataDir + kDirImport * 8);
    if (import_rva == 0) return true;  // nothing to do

    const std::size_t max_descriptors = 4096;  // a runaway table must not hang
    for (std::size_t d = 0; d < max_descriptors; ++d) {
        const std::uint8_t* desc = base + import_rva + d * 20;
        const std::uint32_t original_first_thunk = ReadU32(desc + 0);
        const std::uint32_t name_rva = ReadU32(desc + 12);
        const std::uint32_t first_thunk = ReadU32(desc + 16);
        if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) break;
        if (name_rva == 0 || first_thunk == 0) break;

        const char* module = reinterpret_cast<const char*>(base + name_rva);
        const std::uint32_t thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;

        for (std::size_t i = 0;; ++i) {
            const std::uint64_t entry = *reinterpret_cast<const std::uint64_t*>(
                base + thunk_rva + i * 8);
            if (entry == 0) break;

            ImportRef ref;
            ref.module = module;
            ref.iat_slot = m_base + first_thunk + i * 8;

            const bool by_ordinal = (entry & 0x8000000000000000ull) != 0;
            if (by_ordinal) {
                ref.ordinal = static_cast<std::uint16_t>(entry & 0xFFFF);
                ref.name = "Ordinal_" + std::to_string(ref.ordinal);
            } else {
                const char* name = reinterpret_cast<const char*>(base + (entry & 0x7FFFFFFF) + 2);
                ref.name = name;
            }

            ref.thunk = by_ordinal
                            ? win32::ResolveImportOrdinal(ref.module.c_str(), ref.ordinal)
                            : win32::ResolveImport(ref.module.c_str(), ref.name.c_str());
            if (ref.thunk != 0) {
                *reinterpret_cast<std::uint64_t*>(ref.iat_slot) = ref.thunk;
            }
            m_imports.push_back(ref);
        }
    }
    return true;
}

}  // namespace vigil::recomp
