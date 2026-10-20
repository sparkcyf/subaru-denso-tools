#!/usr/bin/env python3
"""List or extract the big-endian Subaru ALLUPD package container."""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path, PurePath


GROUP_NAME_SIZE = 32
GROUP_VERSION_SIZE = 32
ENTRY_NAME_SIZE = 128
ENTRY_SIZE = 152


@dataclass(frozen=True)
class Entry:
    group: str
    group_version: str
    name: str
    entry_type: int
    size: int
    offset: int


def be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def be64(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def counted_string(data: bytes, length_offset: int, value_offset: int, capacity: int) -> str:
    length = be32(data, length_offset)
    if length > capacity:
        raise ValueError(f"string at 0x{value_offset:x} is too long: {length} > {capacity}")
    raw = data[value_offset : value_offset + length]
    return raw.rstrip(b"\0").decode("utf-8", errors="strict")


def safe_component(value: str) -> str:
    path = PurePath(value)
    if not value or value in {".", ".."} or path.is_absolute() or len(path.parts) != 1:
        raise ValueError(f"unsafe package path component: {value!r}")
    return value


def parse_package(package: Path) -> tuple[dict[str, object], list[Entry]]:
    package_size = package.stat().st_size
    with package.open("rb") as source:
        prefix = source.read(0x1000)
        if len(prefix) < 0x5C:
            raise ValueError("package is smaller than the fixed header")
        header_size = be32(prefix, 0)
        if not 0x5C <= header_size <= package_size:
            raise ValueError(f"invalid header size: 0x{header_size:x}")
        source.seek(0)
        header = source.read(header_size)

    platform = header[8 : 8 + GROUP_NAME_SIZE].split(b"\0", 1)[0].decode("ascii")
    release = counted_string(header, 0x2C, 0x30, GROUP_VERSION_SIZE)
    format_tag = header[0x54:0x58].decode("ascii", errors="replace")
    group_count = be32(header, 0x58)
    if group_count > (header_size - 0x5C) // 4:
        raise ValueError(f"unreasonable group count: {group_count}")
    group_offsets = [be32(header, 0x5C + 4 * index) for index in range(group_count)]

    entries: list[Entry] = []
    groups: list[dict[str, object]] = []
    for group_offset in group_offsets:
        if group_offset + 0x4C > header_size:
            raise ValueError(f"group header outside package header: 0x{group_offset:x}")
        group_name = counted_string(header, group_offset, group_offset + 4, GROUP_NAME_SIZE)
        group_version = counted_string(
            header,
            group_offset + 0x24,
            group_offset + 0x28,
            GROUP_VERSION_SIZE,
        )
        entry_count = be32(header, group_offset + 0x48)
        entry_base = group_offset + 0x4C
        if entry_base + entry_count * ENTRY_SIZE > header_size:
            raise ValueError(f"entries for {group_name!r} extend outside the header")

        groups.append(
            {"name": group_name, "version": group_version, "entry_count": entry_count}
        )
        for index in range(entry_count):
            offset = entry_base + index * ENTRY_SIZE
            name = counted_string(header, offset, offset + 4, ENTRY_NAME_SIZE)
            entry = Entry(
                group=group_name,
                group_version=group_version,
                name=name,
                entry_type=be32(header, offset + 0x84),
                size=be64(header, offset + 0x88),
                offset=be64(header, offset + 0x90),
            )
            if entry.offset < header_size or entry.offset + entry.size > package_size:
                raise ValueError(
                    f"entry {group_name}/{name} is outside the package: "
                    f"offset=0x{entry.offset:x}, size=0x{entry.size:x}"
                )
            entries.append(entry)

    metadata: dict[str, object] = {
        "package": str(package),
        "package_size": package_size,
        "header_size": header_size,
        "platform": platform,
        "release": release,
        "format_tag": format_tag,
        "groups": groups,
    }
    return metadata, entries


def extract(package: Path, output: Path, entries: list[Entry]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with package.open("rb") as source:
        for entry in entries:
            group = safe_component(entry.group)
            name = safe_component(entry.name)
            target_dir = output / group
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / name
            source.seek(entry.offset)
            remaining = entry.size
            with target.open("wb") as destination:
                while remaining:
                    block = source.read(min(16 * 1024 * 1024, remaining))
                    if not block:
                        raise EOFError(f"unexpected end of package while extracting {entry.name}")
                    destination.write(block)
                    remaining -= len(block)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("--extract", type=Path, metavar="DIRECTORY")
    args = parser.parse_args()

    metadata, entries = parse_package(args.package)
    result = {**metadata, "entries": [asdict(entry) for entry in entries]}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.extract:
        extract(args.package, args.extract, entries)


if __name__ == "__main__":
    main()
