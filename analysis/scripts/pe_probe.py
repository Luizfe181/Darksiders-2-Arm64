#!/usr/bin/env python3
"""Minimal standalone PE probe: headers, sections, data directories, debug/PDB, Rich header, overlay.

No third-party dependencies. Usage:
    python analysis/scripts/pe_probe.py game_original/Darksiders2.exe
"""
import struct
import sys
import uuid

DIRS = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED",
]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def rva_to_off(sections, rva):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
            return s["raw_off"] + (rva - s["va"])
    return None


def rich_header(data):
    rich_off = data.rfind(b"Rich")
    if rich_off < 0:
        return None
    key = u32(data, rich_off + 4)
    # walk backwards for the DanS marker
    start = None
    pos = rich_off - 4
    while pos >= 0x40:
        if (u32(data, pos) ^ key) == 0x536E6144:  # DanS
            start = pos
            break
        pos -= 4
    if start is None:
        return {"rich_offset": rich_off, "key": key, "entries": None}
    entries = []
    p = start + 16
    while p + 8 <= rich_off:
        comp_id = u32(data, p) ^ key
        count = u32(data, p + 4) ^ key
        prod = (comp_id >> 16) & 0xFFFF
        build = comp_id & 0xFFFF
        entries.append({"build": build, "product_id": prod, "count": count})
        p += 8
    return {"rich_offset": rich_off, "key": key, "start": start, "entries": entries}


def main(path):
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        raise SystemExit("not a PE (missing MZ)")
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("missing PE signature")
    fh = pe + 4
    machine = u16(data, fh)
    nsec = u16(data, fh + 2)
    timestamp = u32(data, fh + 4)
    opt_size = u16(data, fh + 16)
    characteristics = u16(data, fh + 18)
    opt = fh + 20
    magic = u16(data, opt)
    image_base = u64(data, opt + 24) if magic == 0x20B else u32(data, opt + 28)
    entry = u32(data, opt + 16)
    size_image = u32(data, opt + 56)
    size_headers = u32(data, opt + 60)
    checksum = u32(data, opt + 64)
    subsystem = u16(data, opt + 68)
    dll_chars = u16(data, opt + 70)
    nrva = u32(data, opt + 108)
    dir_off = opt + 112 if magic == 0x20B else opt + 96

    sections = []
    sec_off = opt + opt_size
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, o + 8)
        chars = u32(data, o + 36)
        sections.append({"name": name, "va": va, "vsize": vsize,
                         "raw_off": raw_off, "raw_size": raw_size, "chars": chars})

    dirs = []
    for i in range(min(nrva, 16)):
        rva = u32(data, dir_off + i * 8)
        size = u32(data, dir_off + i * 8 + 4)
        if rva or size:
            dirs.append({"index": i, "name": DIRS[i], "rva": rva, "size": size,
                         "file_offset": rva_to_off(sections, rva)})

    print(f"file            {path}")
    print(f"bytes           {len(data)}")
    print(f"machine         0x{machine:04X}")
    print(f"timestamp       0x{timestamp:08X} ({timestamp})")
    print(f"image_base      0x{image_base:X}")
    print(f"entry_rva       0x{entry:X}  -> va 0x{image_base + entry:X}")
    print(f"entry_file_off  0x{(rva_to_off(sections, entry) or 0):X}")
    print(f"size_image      0x{size_image:X}   size_headers 0x{size_headers:X}")
    print(f"checksum        0x{checksum:08X}")
    print(f"subsystem       {subsystem}   dll_characteristics 0x{dll_chars:04X}")
    print(f"characteristics 0x{characteristics:04X}")
    print("sections:")
    for s in sections:
        print(f"  {s['name']:10} va=0x{s['va']:08X} vsize=0x{s['vsize']:08X} "
              f"raw=0x{s['raw_off']:08X} rawsize=0x{s['raw_size']:08X} chars=0x{s['chars']:08X}")
    print("data directories:")
    for d in dirs:
        off = f"0x{d['file_offset']:X}" if d["file_offset"] is not None else "unmapped"
        print(f"  [{d['index']:2}] {d['name']:14} rva=0x{d['rva']:08X} size=0x{d['size']:X} off={off}")

    # overlay
    last_end = max((s["raw_off"] + s["raw_size"] for s in sections if s["raw_size"]), default=0)
    print(f"overlay_start   0x{last_end:X}  overlay_bytes={max(0, len(data) - last_end)}")

    # debug directory
    dbg = next((d for d in dirs if d["name"] == "DEBUG"), None)
    if dbg and dbg["file_offset"] is not None:
        n = dbg["size"] // 28
        print(f"debug entries   {n}")
        for i in range(n):
            o = dbg["file_offset"] + i * 28
            chars, ts, major, minor, typ, size, addr_raw, ptr_raw = struct.unpack_from(
                "<IIHHIIII", data, o)
            print(f"  [{i}] type={typ} size=0x{size:X} addr=0x{addr_raw:X} ptr=0x{ptr_raw:X}")
            if typ == 2 and ptr_raw + size <= len(data):
                blob = data[ptr_raw:ptr_raw + size]
                if blob[:4] == b"RSDS":
                    guid = uuid.UUID(bytes_le=blob[4:20])
                    age = u32(blob, 20)
                    pdb = blob[24:].split(b"\0")[0].decode("utf-8", "replace")
                    print(f"       RSDS guid={guid} age={age}")
                    print(f"       pdb={pdb}")
                elif blob[:4] == b"NB10":
                    pdb = blob[16:].split(b"\0")[0].decode("utf-8", "replace")
                    print(f"       NB10 pdb={pdb}")
    else:
        print("debug entries   0")

    rh = rich_header(data)
    if rh and rh.get("entries") is not None:
        print(f"rich header     key=0x{rh['key']:08X} entries={len(rh['entries'])}")
        for e in rh["entries"]:
            print(f"  build={e['build']:<6} product_id={e['product_id']:<5} count={e['count']}")
    else:
        print(f"rich header     {rh}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "game_original/Darksiders2.exe")
