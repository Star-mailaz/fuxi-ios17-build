#!/usr/bin/env python3
"""Build the raw image flashed to the fuxi userdata partition.

Layout (offsets from the first byte of the userdata partition):
  0x000000  manifest block (4096 bytes), zero padded to 1 MiB
  0x100000  window "OS"        the whole attached OS disk image, 1 MiB aligned
   ....     window "SystemOS"  the whole attached SystemOS disk image
   ....     object "OS.hashes", "SystemOS.hashes"  the header-only VerifiedRoot tables

Manifest: "SHNGROOT", u32 version=2, u32 count, u64 imageBytes, then count 128 byte
entries {char name[32], u64 offset, u64 size, u32 blockSize, u32 flags, u8 sha256[32],
40 reserved}, then at byte 4064 the SHA-256 of bytes 0..4063.
Windows use blockSize 512 and flags 1, data objects blockSize 4096 and flags 3.
"""
import argparse
import hashlib
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

MIB = 1024 * 1024
COMPONENTS = (("OS", ("OS",)), ("SystemOS", ("Cryptex1,SystemOS", "SystemOS")))


def pick_members(build_manifest):
    identities = build_manifest.get("BuildIdentities") or []
    if not identities:
        raise SystemExit("BuildManifest.plist has no BuildIdentities")
    manifest = identities[0].get("Manifest") or {}
    chosen = []
    for label, keys in COMPONENTS:
        entry = None
        for key in keys:
            if key in manifest:
                entry = manifest[key]
                print("component", label, "->", key)
                break
        if entry is None:
            raise SystemExit(label + ": no component among " + ",".join(keys))
        path = (entry.get("Info") or {}).get("Path")
        if not path:
            raise SystemExit(label + ": component has no Info.Path")
        chosen.append((label, path))
    return chosen


def extract(ipsw, members, work):
    work.mkdir(parents=True, exist_ok=True)
    out = []
    with zipfile.ZipFile(ipsw) as archive:
        names = set(archive.namelist())
        for label, path in members:
            if path not in names:
                raise SystemExit(label + ": " + path + " is not in the IPSW")
            target = work / (label + ".dmg")
            if not target.is_file():
                print("extracting", path)
                with archive.open(path) as source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink, 8 * 1024 * 1024)
            print(label, target, target.stat().st_size)
            out.append((label, target))
    return out


def to_raw(dmg):
    raw = dmg.with_suffix(".raw")
    if raw.is_file() and raw.stat().st_size:
        return raw
    result = subprocess.run(["dmg2img", "-i", str(dmg), "-o", str(raw)],
                            capture_output=True, text=True)
    print("dmg2img", dmg.name, "rc", result.returncode, result.stdout[-300:], result.stderr[-300:])
    if result.returncode or not raw.is_file():
        raise SystemExit("dmg2img failed for " + dmg.name)
    return raw


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_into(image, raw, offset):
    digest = hashlib.sha256()
    total = 0
    with open(raw, "rb") as source, open(image, "r+b") as sink:
        sink.seek(offset)
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
            sink.write(block)
            total += len(block)
    return total, digest.hexdigest()


def entry(name, offset, size, block_size, flags, digest_hex):
    blob = bytearray(128)
    encoded = name.encode("ascii")
    blob[0:len(encoded)] = encoded
    struct.pack_into("<QQII", blob, 32, offset, size, block_size, flags)
    blob[56:88] = bytes.fromhex(digest_hex)
    return bytes(blob)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipsw", type=Path, required=True)
    parser.add_argument("--policies", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=Path("disks"))
    args = parser.parse_args()

    with zipfile.ZipFile(args.ipsw) as archive:
        build_manifest = plistlib.loads(archive.read("BuildManifest.plist"))
    members = pick_members(build_manifest)
    disks = extract(args.ipsw, members, args.work)

    raws = []
    for label, dmg in disks:
        raw = to_raw(dmg)
        size = raw.stat().st_size
        print(label, "raw", size, "aligned", size % 4096 == 0)
        raws.append((label, raw, size))

    hashes = {}
    for label, _ in raws:
        table = args.policies / label.lower() / "hashes.bin"
        if not table.is_file():
            raise SystemExit("missing hash table " + str(table))
        hashes[label] = table

    offset = MIB
    windows = []
    for label, raw, size in raws:
        offset = (offset + MIB - 1) // MIB * MIB
        windows.append((label, raw, size, offset))
        offset += size
    objects = []
    for label, _raw, size, _off in windows:
        offset = (offset + 4095) // 4096 * 4096
        table = hashes[label]
        objects.append((label + ".hashes", table, table.stat().st_size, offset))
        offset += table.stat().st_size
    image_bytes = (offset + 4095) // 4096 * 4096
    print("imageBytes", image_bytes, "aligned", image_bytes % 4096 == 0)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "wb") as handle:
        handle.truncate(image_bytes)

    written = []
    for label, raw, size, off in windows:
        total, digest = copy_into(args.out, raw, off)
        print(label, "wrote", total, "sha256", digest)
        recorded = args.policies / label.lower() / "manifest.json"
        if recorded.is_file():
            expected = json.loads(recorded.read_text()).get("image_sha256")
            print(label, "policy sha256", expected, "match", expected == digest)
            if expected and expected != digest:
                raise SystemExit(label + ": the window bytes differ from the signed policy")
        written.append((label, size, off, digest))

    for name, table, size, off in objects:
        total, digest = copy_into(args.out, table, off)
        print(name, "wrote", total, "at", off)

    entries = []
    for label, size, off, digest in written:
        entries.append(entry(label, off, size, 512, 1, digest))
    for name, table, size, off in objects:
        entries.append(entry(name, off, size, 4096, 3, sha256_file(table)))

    block = bytearray(4096)
    block[0:8] = b"SHNGROOT"
    struct.pack_into("<IIQ", block, 8, 2, len(entries), image_bytes)
    for index, blob in enumerate(entries):
        block[24 + 128 * index:24 + 128 * (index + 1)] = blob
    block[4064:4096] = hashlib.sha256(bytes(block[0:4064])).digest()
    with open(args.out, "r+b") as handle:
        handle.seek(0)
        handle.write(bytes(block))

    report = {"image": str(args.out), "image_bytes": image_bytes,
              "windows": [{"name": l, "offset": o, "size": s, "sha256": d} for l, s, o, d in written],
              "objects": [{"name": n, "offset": o, "size": s} for n, _t, s, o in objects]}
    args.out.with_name("userdata-root.json").write_text(json.dumps(report, indent=2) + chr(10))
    print("done", args.out, image_bytes)


if __name__ == "__main__":
    sys.exit(main())
