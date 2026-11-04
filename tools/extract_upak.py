"""
media.upak extractor -- CORRECTED.

The previous version of this file applied an invented XOR key
(`version ^ 0x544F434B`) to 24-byte records at 0x54900. That key does not
exist in the container: the "encrypted TOC" was a one-byte misalignment
caused by the 5-byte magic b"OBPK\\0". See analysis/reports/obpk_format_findings.md.

This version no longer invents a key schedule. It parses the plaintext OBPK
header correctly, validates every structural invariant, and refuses to write
output if the body layout is not what it expects -- rather than silently
emitting multi-gigabyte "sizes".
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from obpk_parser import ObpkError, parse, verify  # noqa: E402

UPAK = Path("game_original/media/media.upak")
REPORT = Path("analysis/reports/upak_toc_decrypted.json")


def main() -> int:
    if not UPAK.exists():
        print(f"[!] not found: {UPAK}")
        return 1

    try:
        pkg = parse(UPAK)
    except ObpkError as e:
        print(f"[!] {UPAK.name}: {e}")
        print("[!] The body of this build is not the plaintext 2012 index layout.")
        print("[!] No data written. Do not trust any 'decrypted TOC' produced earlier.")
        return 2

    problems = verify(pkg)
    if problems:
        for p in problems:
            print(f"[!] invariant failed: {p}")
        return 3

    print(f"[+] {UPAK.name}: version={pkg.version} names={len(pkg.names)} "
          f"folders={len(pkg.folders)} files={len(pkg.files)}")
    print(f"[+] payload at 0x{pkg.data_offset:X}, declared size {pkg.data_size}")
    print(f"[*] report path reserved: {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
