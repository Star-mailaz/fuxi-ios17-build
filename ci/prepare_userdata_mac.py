#!/usr/bin/env python3
"""Build the fuxi userdata image on macOS, streaming the IPSW members by range.

The full 8.1 GB restore zip never lands on disk: HttpFile exposes the remote zip
as a seekable file for zipfile, so each member is decompressed straight into a
temporary dmg, attached read-only, streamed into the output, and deleted.

Two output files, concatenated in order to get the flashed image:
  part0  manifest block + zero fill to 1 MiB + window "OS"
  part1  window "SystemOS" + objects "OS.hashes" and "SystemOS.hashes"

The manifest needs the digest of every window, so it is written into part0 only
after both parts are complete.
"""
import argparse
import hashlib
import io
import json
import plistlib
import re
import shutil
import struct
import subprocess
import urllib.request
import zipfile
from pathlib import Path

MIB = 1024 * 1024


class HttpFile(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        request = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(request, timeout=60) as response:
            self.size = int(response.headers["Content-Length"])
        self.pos = 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def seek(self, offset, whence=0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        else:
            self.pos = self.size + offset
        return self.pos

    def tell(self):
        return self.pos

    def read(self, count=-1):
        if count is None or count < 0:
            count = self.size - self.pos
        if count == 0 or self.pos >= self.size:
            return b""
        end = min(self.pos + count, self.size) - 1
        request = urllib.request.Request(self.url, headers={"Range": "bytes=%d-%d" % (self.pos, end)})
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
        self.pos += len(data)
        return data


def pick_members(build_manifest):
    identities = build_manifest.get("BuildIdentities") or []
    manifest = identities[0].get("Manifest") or {}
    chosen = []
    for label, keys in (("OS", ("OS",)), ("SystemOS", ("Cryptex1,SystemOS", "SystemOS"))):
        entry = None
        for key in keys:
            if key in manifest:
                entry = manifest[key]
                print("component", label, "->", key)
                break
        if entry is None:
            raise SystemExit(label + ": no component")
        chosen.append((label, (entry.get("Info") or {}).get("Path")))
    return chosen


def extract_member(archive, member, target):
    print("extracting", member, "->", target, flush=True)
    with archive.open(member) as source, target.open("wb") as sink:
        shutil.copyfileobj(source, sink, 8 * 1024 * 1024)
    print("done", target.stat().st_size, flush=True)


def image_bytes_of(dmg):
    result = subprocess.run(["hdiutil", "imageinfo", "-plist", str(dmg)],
                            capture_output=True, check=True)
    return int(plistlib.loads(result.stdout)["Size Information"]["Total Bytes"])


def attach(dmg):
    result = subprocess.run(["hdiutil", "attach", "-nomount", "-readonly", "-noverify",
                             "-noautofsck", str(dmg)], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        match = re.match(r"(/dev/disk\d+)\s", line)
        if match:
            return match.group(1)
    raise SystemExit("attach did not report a device")


def detach(device):
    subprocess.run(["hdiutil", "detach", device], capture_output=True)


def stream_window(device, size, sink, offset):
    digest = hashlib.sha256()
    written = 0
    raw = Path(device.replace("/dev/disk", "/dev/rdisk"))
    with raw.open("rb", buffering=8 * 1024 * 1024) as source:
        sink.seek(offset)
        while written < size:
            chunk = source.read(min(8 * 1024 * 1024, size - written))
            if not chunk:
                raise SystemExit("short read at %d" % written)
            digest.update(chunk)
            sink.write(chunk)
            written += len(chunk)
    return digest.hexdigest()


def manifest_entry(name, offset, size, block_size, flags, digest_hex):
    blob = bytearray(128)
    blob[0:len(name)] = name.encode("ascii")
    struct.pack_into("<QQII", blob, 32, offset, size, block_size, flags)
    blob[56:88] = bytes.fromhex(digest_hex)
    return bytes(blob)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--policies", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=Path("disks"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)

    remote = HttpFile(args.url)
    print("remote zip", remote.size, "bytes", flush=True)
    archive = zipfile.ZipFile(remote)
    build_manifest = plistlib.loads(archive.read("BuildManifest.plist"))
    members = pick_members(build_manifest)

    sizes = {}
    for label, member in members:
        dmg = args.work / (label + ".dmg")
        if not dmg.is_file():
            extract_member(archive, member, dmg)
        sizes[label] = image_bytes_of(dmg)
        print(label, "image bytes", sizes[label], flush=True)

    tables = {label: args.policies / label.lower() / "hashes.bin" for label, _ in members}
    table_digest = {}
    for label, table in tables.items():
        if not table.is_file():
            raise SystemExit("missing " + str(table))
        table_digest[label] = hashlib.sha256(table.read_bytes()).hexdigest()

    os_size = sizes["OS"]
    sys_size = sizes["SystemOS"]
    os_offset = MIB
    sys_offset = os_offset + os_size
    os_hash_offset = sys_offset + sys_size
    sys_hash_offset = os_hash_offset + tables["OS"].stat().st_size
    total = sys_hash_offset + tables["SystemOS"].stat().st_size
    total = (total + 4095) // 4096 * 4096
    print("offsets", os_offset, sys_offset, os_hash_offset, sys_hash_offset, "total", total, flush=True)

    part0 = args.out / "userdata-part0.img"
    part1 = args.out / "userdata-part1.img"
    digests = {}

    with part0.open("wb") as sink:
        sink.truncate(os_offset + os_size)
        dmg = args.work / "OS.dmg"
        device = attach(dmg)
        try:
            digests["OS"] = stream_window(device, os_size, sink, os_offset)
        finally:
            detach(device)
    dmg.unlink()
    print("OS sha256", digests["OS"], flush=True)
    recorded = json.loads((args.policies / "os" / "manifest.json").read_text())["image_sha256"]
    print("policy sha256", recorded, "match", recorded == digests["OS"], flush=True)
    if recorded != digests["OS"]:
        raise SystemExit("OS bytes differ from the signed policy")
    print("part0", part0.stat().st_size, flush=True)

    with part1.open("wb") as sink:
        sink.truncate(total - sys_offset)
        dmg = args.work / "SystemOS.dmg"
        device = attach(dmg)
        try:
            digests["SystemOS"] = stream_window(device, sys_size, sink, 0)
        finally:
            detach(device)
        sink.seek(os_hash_offset - sys_offset)
        sink.write(tables["OS"].read_bytes())
        sink.seek(sys_hash_offset - sys_offset)
        sink.write(tables["SystemOS"].read_bytes())
    dmg.unlink()
    print("SystemOS sha256", digests["SystemOS"], flush=True)
    recorded = json.loads((args.policies / "systemos" / "manifest.json").read_text())["image_sha256"]
    print("policy sha256", recorded, "match", recorded == digests["SystemOS"], flush=True)
    if recorded != digests["SystemOS"]:
        raise SystemExit("SystemOS bytes differ from the signed policy")
    print("part1", part1.stat().st_size, flush=True)

    entries = [
        manifest_entry("OS", os_offset, os_size, 512, 1, digests["OS"]),
        manifest_entry("SystemOS", sys_offset, sys_size, 512, 1, digests["SystemOS"]),
        manifest_entry("OS.hashes", os_hash_offset, tables["OS"].stat().st_size, 4096, 3, table_digest["OS"]),
        manifest_entry("SystemOS.hashes", sys_hash_offset, tables["SystemOS"].stat().st_size, 4096, 3, table_digest["SystemOS"]),
    ]
    block = bytearray(4096)
    block[0:8] = b"SHNGROOT"
    struct.pack_into("<IIQ", block, 8, 2, len(entries), total)
    for index, blob in enumerate(entries):
        block[24 + 128 * index:24 + 128 * (index + 1)] = blob
    block[4064:4096] = hashlib.sha256(bytes(block[0:4064])).digest()
    with part0.open("r+b") as handle:
        handle.seek(0)
        handle.write(bytes(block))
    print("manifest written into part0", flush=True)

    report = {"total_bytes": total, "os_offset": os_offset, "systemos_offset": sys_offset,
              "os_hashes_offset": os_hash_offset, "systemos_hashes_offset": sys_hash_offset,
              "os_size": os_size, "systemos_size": sys_size, "digests": digests,
              "table_bytes": {k: tables[k].stat().st_size for k in tables}}
    (args.out / "userdata-root.json").write_text(json.dumps(report, indent=2) + chr(10))
    print("done", total, flush=True)


if __name__ == "__main__":
    main()
