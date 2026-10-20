#!/usr/bin/env python3
"""Build an offline, headless QNX lab image from the FM1 update's own files.

Does not modify inputs, qvm, authentication code, or any physical device.
The input is `ifsdump -u` output plus the original extracted ELF wrapper.
All firmware and drivers must be supplied by the reader from their update.
"""
from __future__ import annotations

import argparse
import array
import hashlib
import json
import stat
import struct
import sys
from pathlib import Path


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def checksum(data: bytes | bytearray) -> int:
    if len(data) % 4:
        raise ValueError("imagefs checksum input must be word aligned")
    words = array.array("I")
    words.frombytes(bytes(data))
    if sys.byteorder != "little":
        words.byteswap()
    return sum(words) & 0xFFFFFFFF


def find_image(data: bytes) -> tuple[int, int, bytearray]:
    signature = struct.pack("<I", 0x00FF7EEB)
    for pos in range(0, min(len(data) - 0x40, 4096), 4):
        if data[pos:pos + 4] != signature:
            continue
        startup_size = u32(data, pos + 0x20)
        image_size = u32(data, pos + 0x2C)
        start = pos + startup_size
        if data[start:start + 7] != b"imagefs":
            continue
        if image_size < 64 or start + image_size > len(data):
            raise ValueError("truncated imagefs")
        imagefs = bytearray(data[start:start + image_size])
        if u32(imagefs, 8) != image_size:
            raise ValueError("startup and imagefs size disagree")
        if checksum(imagefs) != 0:
            raise ValueError("input imagefs checksum is not zero")
        return pos, startup_size, imagefs
    raise ValueError("uncompressed startup + imagefs not found; use ifsdump -u")


def entries(imagefs: bytearray) -> dict[str, tuple[int, int]]:
    result = {}
    pos, end = u32(imagefs, 0x10), u32(imagefs, 0x0C)
    if not 0 < pos < end <= len(imagefs):
        raise ValueError("invalid imagefs directory bounds")
    while pos < end:
        size = struct.unpack_from("<H", imagefs, pos)[0]
        if size == 0:
            break
        if size < 24 or pos + size > end:
            raise ValueError("invalid imagefs directory entry")
        mode = u32(imagefs, pos + 8)
        if stat.S_ISREG(mode):
            name = bytes(imagefs[pos + 32:pos + size]).split(b"\0", 1)[0]
            result[name.decode()] = (pos, size)
        pos += size
    return result


def replace(imagefs: bytearray, index: dict, old: str, data: bytes,
            new: str | None = None) -> dict:
    if old not in index:
        raise ValueError(f"required FM1 imagefs entry missing: {old}")
    pos, size = index[old]
    dest = new or old
    name = dest.encode() + b"\0"
    if len(name) > size - 32:
        raise ValueError(f"destination name does not fit original slot: {dest}")
    old_offset, old_size = struct.unpack_from("<II", imagefs, pos + 24)
    offset = len(imagefs) - 4
    imagefs[-4:] = data + bytes((-len(data)) % 4) + bytes(4)
    struct.pack_into("<II", imagefs, pos + 24, offset, len(data))
    imagefs[pos + 32:pos + size] = name.ljust(size - 32, b"\0")
    struct.pack_into("<I", imagefs, 8, len(imagefs))
    return {"source_entry": old, "lab_entry": dest,
            "original_size": old_size, "new_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--elf", type=Path, required=True)
    ap.add_argument("--uncompressed", type=Path, required=True)
    ap.add_argument("--fhi-dir", type=Path, required=True)
    ap.add_argument("--kernel", type=Path, required=True)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    manifest_path = args.output.with_suffix(".manifest.json")
    if args.output.exists() or manifest_path.exists():
        ap.error("output or manifest already exists; choose a new output name")
    source = args.uncompressed.read_bytes()
    pos, startup_size, imagefs = find_image(source)
    startup = bytearray(source[pos:pos + startup_size])
    elf = args.elf.read_bytes()
    if elf[:6] != b"\x7fELF\x01\x01":
        ap.error("expected little-endian ELF32 startup wrapper")
    phoff = u32(elf, 28)
    phsize, phnum = struct.unpack_from("<HH", elf, 42)
    if phsize != 32 or phnum != 1 or u32(elf, phoff) != 1:
        ap.error("expected one ELF32 PT_LOAD segment")
    segment_offset = u32(elf, phoff + 4)
    if not phoff + 32 <= segment_offset <= pos:
        ap.error("unexpected ELF prefix size")
    if elf[segment_offset:segment_offset + 4] != startup[:4]:
        ap.error("ELF wrapper and uncompressed startup do not match")
    index = entries(imagefs)
    changes = []

    def put(old: str, data: bytes, new: str | None = None) -> None:
        changes.append(replace(imagefs, index, old, data, new))

    put("sbin/devc-serpci", (args.fhi_dir / "sbin/devc-ser8250").read_bytes())
    put("lib/dll/pci/pci_hw-Intel_x86_APL.so.2.1",
        (args.fhi_dir / "lib/dll/pci/pci_hw-Intel_x86.so.2.0").read_bytes())
    serial_setup = (b"#!/bin/sh\n"
                    b"devc-serpci 3f8,4 &\n"
                    b"devc-serpci 2f8,3 &\n"
                    b"waitfor /dev/ser1\n"
                    b"waitfor /dev/ser2\n"
                    b"on -C0 -C1 sh </dev/ser1 >/dev/ser1 2>&1 &\n")
    put("scripts/emmc-setup.sh", serial_setup)
    noop = b"#!/bin/sh\nexit 0\n"
    for script in ("mount-setup", "qnxapp-start", "graphics-setup",
                   "ocpbridge-setup", "guestos-setup", "network-setup",
                   "audio-setup", "metermid-setup"):
        put(f"scripts/{script}.sh", noop)
    put("sbin/i2c-baytrail", args.kernel.read_bytes(), "scripts/bzImage")
    put("lib/dll/screen-debug.so", args.config.read_bytes(), "scripts/linux.config")

    struct.pack_into("<I", imagefs, len(imagefs) - 4,
                     (-checksum(imagefs[:-4])) & 0xFFFFFFFF)
    startup[6] &= ~0x1C
    total = len(startup) + len(imagefs)
    for off, value in ((0x1C, total), (0x24, total), (0x2C, len(imagefs))):
        struct.pack_into("<I", startup, off, value)
    prefix = bytearray(elf[:segment_offset])
    struct.pack_into("<II", prefix, phoff + 16, total, total)
    output = bytes(prefix) + bytes(startup) + bytes(imagefs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as destination:
        destination.write(output)
    manifest_path.write_text(json.dumps({
        "purpose": "offline headless QNX lab; qvm unchanged",
        "input_elf_sha256": hashlib.sha256(elf).hexdigest(),
        "input_uncompressed_sha256": hashlib.sha256(source).hexdigest(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "changes": changes,
    }, indent=2) + "\n")
    print(f"output: {args.output}; manifest: {manifest_path}")


if __name__ == "__main__":
    main()
