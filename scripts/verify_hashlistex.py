#!/usr/bin/env python3
"""Verify Subaru HASHLISTEX.DAT CRC-32 records against sibling files."""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path


def crc32(path: Path) -> int:
    value = 0
    with path.open("rb") as source:
        while block := source.read(16 * 1024 * 1024):
            value = zlib.crc32(block, value)
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("hashlists", type=Path, nargs="+")
    args = parser.parse_args()

    failed = False
    for hashlist in args.hashlists:
        data = hashlist.read_bytes()
        if len(data) < 16:
            raise ValueError(f"{hashlist}: truncated header")
        header_size, count, record_size, flags = struct.unpack_from(">4H", data)
        name_size = 128
        if header_size != 16 or record_size < name_size + 4 or flags != 0x8000:
            raise ValueError(
                f"{hashlist}: unsupported layout header={header_size}, "
                f"record={record_size}, flags=0x{flags:04x}"
            )
        if len(data) != header_size + count * record_size:
            raise ValueError(f"{hashlist}: record count does not match file length")

        print(hashlist)
        for index in range(count):
            offset = header_size + index * record_size
            raw_name = data[offset : offset + name_size].split(b"\0", 1)[0]
            name = raw_name.decode("utf-8")
            expected = struct.unpack_from(">I", data, offset + name_size)[0]
            target = hashlist.parent / name
            actual = crc32(target)
            status = "OK" if actual == expected else "MISMATCH"
            failed |= actual != expected
            print(f"  {status:8} {name}: stored={expected:08x} actual={actual:08x}")

    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
