// obpk_format.h -- Vigil Engine OBPK resource package, on-disk layout
//
// CORRECTED after byte-level analysis of media.upak (Deathinitive Edition).
//
// The single most important fact: the magic is FIVE bytes, "OBPK\0".
// Reading the first field at offset 4 instead of 5 shifts every subsequent
// field one byte left; for little-endian fields followed by 0x00 this
// multiplies the value by 256.  That is why a naive `<QIIII` parse of the
// "TOC" yields multi-gigabyte sizes and offsets past EOF.  There is no
// XOR/LFSR/table-encryption stage anywhere in this header.
//
// Reference: aluigi's quickbms "darksiders.bms" (Darksiders 2 OBPK).
// This build (Deathinitive) uses a 46-byte header and a different body
// codec than the 2012 retail build; see analysis/reports/obpk_format_findings.md
//
// ARM64 notes:
//   * structs are byte-packed; NEVER dereference a packed 64-bit field
//     directly from a file buffer (unaligned LDR is expensive or faults).
//     Always go through the Read<> helpers (memcpy + endian swap).
//   * all integers are little-endian on disk regardless of host endianness.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace vigil::obpk {

inline constexpr std::uint8_t  kMagic[5]    = {'O', 'B', 'P', 'K', 0x00};
inline constexpr std::size_t   kMagicLen    = 5;
inline constexpr std::size_t   kHeaderLen   = 46;      // 5 + 10*4 + 1
inline constexpr std::uint32_t kDataAlign   = 0x1000;  // records are padded to this
inline constexpr std::uint32_t kFlagExtra3  = 0x02;    // record carries 3 extra bytes
inline constexpr std::uint32_t kFlagExtra8  = 0x08;    // record carries 8 extra bytes

// ---------------------------------------------------------------------------
// Header -- exactly 46 bytes, plaintext.
// Field semantics beyond `version` are build-specific; the names below record
// only what was measured, not a guess at meaning.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct Header {
    std::uint8_t  magic[5];   // 0x00  "OBPK\0"
    std::uint32_t version;    // 0x05  9   in media.upak (NOT 2304 -- that is 9<<8)
    std::uint32_t field2;     // 0x09  30  invariant across packs observed
    std::uint32_t field3;     // 0x0D  1353
    std::uint32_t field4;     // 0x11  -> always field3 + field2
    std::uint32_t field5;     // 0x15  652
    std::uint32_t field6;     // 0x19  2048
    std::uint32_t field7;     // 0x1D  1792 invariant across packs observed
    std::uint32_t field8;     // 0x21  7680
    std::uint32_t field9;     // 0x25  112640
    std::uint32_t field10;    // 0x29  0
    std::uint8_t  trailer;    // 0x2D  0
};
#pragma pack(pop)

static_assert(sizeof(Header) == kHeaderLen, "OBPK header must be 46 bytes");

// ---------------------------------------------------------------------------
// Name record:  u64 hash | u32 name_len | char name[name_len]
// Follows aluigi's GET_NAME; present in the 2012 layout. In the DE build the
// body is not plaintext at 0x2E, so these records are not directly reachable
// without first decoding the body.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct NameRecord {
    std::uint64_t hash;
    std::uint32_t name_len;
    // char name[name_len];
};
static_assert(sizeof(NameRecord) == 12);
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Folder record: u64 hash | u32 file_count
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct FolderRecord {
    std::uint64_t hash;
    std::uint32_t file_count;
};
static_assert(sizeof(FolderRecord) == 12);
#pragma pack(pop)

// ---------------------------------------------------------------------------
// File record:  u64 hash | u32 size | u8 flags | u32 dummy | u32 zero
//               [+3 bytes if flags & 0x02] [+8 bytes if flags & 0x08]
//
// There is NO offset field. File offsets are CUMULATIVE:
//     offset[0] = 0
//     offset[i] = offset[i-1] + size[i-1]
// ---------------------------------------------------------------
#pragma pack(push, 1)
struct FileRecord {
    std::uint64_t hash;
    std::uint32_t size;
    std::uint8_t  flags;
    std::uint32_t reserved0;
    std::uint32_t reserved1;
};
static_assert(sizeof(FileRecord) == 21, "FileRecord is 21 bytes + flag extras");
#pragma pack(pop)

inline std::size_t file_record_stride(std::uint8_t flags) noexcept {
    return sizeof(FileRecord)
         + ((flags & kFlagExtra3) ? 3u : 0u)
         + ((flags & kFlagExtra8) ? 8u : 0u);
}

// ---------------------------------------------------------------------------
// Safe unaligned little-endian readers. Use these instead of casting a file
// buffer to the structs above.
// ---------------------------------------------------------------------------
template <typename T>
inline T Read(const std::uint8_t* p) noexcept {
    T v;
    std::memcpy(&v, p, sizeof(T));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    if constexpr (sizeof(T) == 8) {
        v = __builtin_bswap64(v);
    } else if constexpr (sizeof(T) == 4) {
        v = __builtin_bswap32(v);
    } else if constexpr (sizeof(T) == 2) {
        v = __builtin_bswap16(v);
    }
#endif
    return v;
}

// Alignment helper: absolute start of the payload once records end.
inline std::uint64_t AlignUp(std::uint64_t v, std::uint32_t align) noexcept {
    return (v + align - 1) & ~static_cast<std::uint64_t>(align - 1);
}

// Cumulative offset table builder -- the correct replacement for any
// "sector << 9" arithmetic. Returns absolute offsets relative to the
// start of the decompressed image.
inline void BuildCumulativeOffsets(const std::uint32_t* sizes,
                                   std::uint64_t* out_offsets,
                                   std::size_t count) noexcept {
    std::uint64_t running = 0;
    for (std::size_t i = 0; i < count; ++i) {
        out_offsets[i] = running;
        running += sizes[i];
    }
}

}  // namespace vigil::obpk
