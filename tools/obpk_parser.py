"""
OBPK (Vigil Engine resource package) parser -- corrected.

KEY CORRECTION vs. the old extract_upak.py:
  The magic is FIVE bytes: b"OBPK\\x00".
  Parsing fields at offset 4 instead of 5 shifts every field one byte left,
  which multiplies each little-endian value by 256 whenever the following
  byte is 0x00.  That is the sole origin of the "encrypted / >3GB sizes"
  symptom:
      2304   (0x00000900)  is really   9 (0x00000009) << 8
      7680   (0x00001E00)  is really  30 (0x0000001E) << 8
      0x54900(0x00054900)  is really 0x549 = 1353      << 8
  There is NO XOR/LFSR stage in this container.

Reference format (Darksiders 2): aluigi's quickbms 'darksiders.bms'.
This build is the Deathinitive-Edition variant: the plaintext header carries
more fields (46 bytes) than the 2012 layout (30 bytes), but the record model
(64-bit name hashes, folder/file tables, cumulative offsets) is unchanged.
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

MAGIC = b"OBPK\x00"
MAGIC_LEN = 5
PAD_ALIGN = 0x1000

FLAG_EXTRA3 = 0x02   # record carries 3 extra bytes
FLAG_EXTRA8 = 0x08   # record carries 8 extra bytes


class ObpkError(Exception):
    pass


@dataclass
class NameRec:
    hash: int
    name: str


@dataclass
class FolderRec:
    hash: int
    file_count: int
    name: str = ""


@dataclass
class FileRec:
    hash: int
    size: int
    flags: int
    offset: int          # cumulative offset inside the decompressed image
    name: str = ""


@dataclass
class Obpk:
    path: Path
    version: int
    fields: list[int]
    trailer_byte: int
    names: list[NameRec] = field(default_factory=list)
    folders: list[FolderRec] = field(default_factory=list)
    files: list[FileRec] = field(default_factory=list)
    data_offset: int = 0
    data_size: int = 0


class Reader:
    """Bounds-checked little-endian reader over a file."""

    def __init__(self, fh: BinaryIO, size: int):
        self.f = fh
        self.size = size

    def _read(self, n: int) -> bytes:
        b = self.f.read(n)
        if len(b) != n:
            raise ObpkError(f"unexpected EOF reading {n} bytes")
        return b

    def tell(self) -> int:
        return self.f.tell()

    def seek(self, o: int) -> None:
        self.f.seek(o)

    def u8(self) -> int:
        return self._read(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self._read(8))[0]

    def take(self, n: int) -> bytes:
        return self._read(n)

    def skip(self, n: int) -> None:
        if n < 0:
            raise ObpkError("negative skip")
        self.seek(self.tell() + n)


def _read_name(r: Reader, what: str, max_len: int = 4096) -> NameRec:
    h = r.u64()
    ln = r.u32()
    if ln > max_len:
        raise ObpkError(
            f"implausible {what} name length {ln} at 0x{r.tell()-4:X} "
            f"-- header/record layout is not what this parser assumes"
        )
    raw = r.take(ln)
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        name = raw.decode("latin-1")
    if any(ord(c) < 0x20 for c in name):
        raise ObpkError(
            f"non-printable {what} name at 0x{r.tell()-ln:X}: {raw[:24].hex(' ')}"
        )
    return NameRec(h, name)


def parse(path: Path, *, max_files: int = 5_000_000) -> Obpk:
    fh = path.open("rb")
    size = path.stat().st_size
    r = Reader(fh, size)

    magic = r.take(MAGIC_LEN)
    if magic != MAGIC:
        raise ObpkError(f"bad magic {magic!r}, expected {MAGIC!r}")

    # 10 little-endian u32 fields, then one flag byte (Deathinitive layout).
    fields = [r.u32() for _ in range(10)]
    trailer = r.u8()
    header_len = r.tell()

    pkg = Obpk(path=path, version=fields[0], fields=fields[1:],
               trailer_byte=trailer)

    # --- name table -------------------------------------------------------
    n_names = r.u32()
    if n_names > 1_000_000:
        raise ObpkError(f"implausible name count {n_names} at 0x{r.tell()-4:X}")
    pkg.names = [_read_name(r, "name") for _ in range(n_names)]

    # --- optional directory tree -----------------------------------------
    dir_tree_size = r.u32()
    if dir_tree_size > size - r.tell():
        raise ObpkError(f"directory tree size {dir_tree_size} exceeds file")
    r.skip(dir_tree_size)

    # --- folder table -----------------------------------------------------
    n_folders = r.u32()
    if n_folders > 100_000:
        raise ObpkError(f"implausible folder count {n_folders}")
    pkg.folders = [FolderRec(r.u64(), r.u32()) for _ in range(n_folders)]

    # --- file records -----------------------------------------------------
    total_files = sum(fd.file_count for fd in pkg.folders)
    if total_files > max_files:
        raise ObpkError(f"implausible total file count {total_files}")

    running = 0
    for folder in pkg.folders:
        for _ in range(folder.file_count):
            h = r.u64()
            fsize = r.u32()
            flags = r.u8()
            _dummy = r.u32()
            _zero = r.u32()
            if flags & FLAG_EXTRA3:
                r.skip(3)
            if flags & FLAG_EXTRA8:
                r.skip(8)
            pkg.files.append(FileRec(h, fsize, flags, running))
            running += fsize

    # --- padding to 0x1000, then payload length ---------------------------
    aligned = (r.tell() + PAD_ALIGN - 1) & ~(PAD_ALIGN - 1)
    r.seek(aligned)
    pkg.data_offset = r.tell()
    pkg.data_size = r.u32()
    pkg.data_offset = r.tell()

    pkg._header_len = header_len  # type: ignore[attr-defined]
    return pkg


def verify(pkg: Obpk) -> list[str]:
    """Structural invariants that any correct parse must satisfy."""
    problems: list[str] = []
    if pkg.data_offset > pkg.path.stat().st_size:
        problems.append("payload starts past EOF")
    # f[3] == f[2] + f[1] holds for every header observed in media.upak
    f = pkg.fields
    if len(f) >= 4 and f[3] != f[2] + f[1]:
        problems.append(f"invariant f4==f3+f2 violated: {f[3]} != {f[2]}+{f[1]}")
    return problems


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else Path(
        "game_original/media/media.upak")

    # --- misalignment proof (works even if record parsing fails) ----------
    with target.open("rb") as fh:
        head = fh.read(0x30)
    shifted = {
        "version": (struct.unpack_from("<I", head, 0x04)[0],
                    struct.unpack_from("<I", head, 0x05)[0]),
        "count":   (struct.unpack_from("<I", head, 0x08)[0],
                    struct.unpack_from("<I", head, 0x09)[0]),
        "offset":  (struct.unpack_from("<I", head, 0x0C)[0],
                    struct.unpack_from("<I", head, 0x0D)[0]),
    }
    print(f"[*] {target}  ({target.stat().st_size} bytes)")
    print("[*] one-byte-misalignment check (read@0x04 vs correct@0x05):")
    for k, (bad, good) in shifted.items():
        print(f"      {k:<8} {bad:>10} == {good} << 8 : {bad == good << 8}")

    try:
        pkg = parse(target)
    except ObpkError as e:
        print(f"[!] {e}")
        print("[!] Refusing to emit guessed data. Header-level facts above are valid.")
        return 2

    print(f"[+] header {pkg._header_len} bytes, version={pkg.version}")
    print(f"[+] fields={pkg.fields} trailer={pkg.trailer_byte}")
    print(f"[+] names={len(pkg.names)} folders={len(pkg.folders)} files={len(pkg.files)}")
    print(f"[+] payload offset=0x{pkg.data_offset:X} declared size={pkg.data_size}")
    for p in verify(pkg):
        print(f"[!] invariant: {p}")
    if pkg.files[:5]:
        print("[+] first files (cumulative offsets):")
        for fr in pkg.files[:5]:
            print(f"      0x{fr.offset:08X} size={fr.size:<10} flags=0x{fr.flags:02X} hash=0x{fr.hash:016X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
