#!/usr/bin/env python3
"""Build the VerifiedRoot owner policies for the iPhone15,2 iOS 17.7 21H16 IPSW.

Runs on macOS. hdiutil attaches the IPSW's OS and Cryptex1,SystemOS disk images
read-only, the whole-disk block stream is hashed 4096 bytes at a time, and
kits/VerifiedRoot's manifest.make signs the table with a 3072-bit RSA owner key
that this step generates once and keeps in the runner cache.

Output, per component: header.bin (160), signature.bin (384), trusted-key.bin,
hashes.bin and manifest.bin, plus manifest.json.
"""
import argparse
import importlib.util
import json
import plistlib
import re
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path

COMPONENTS = (
    ('os', ('OS',)),
    ('systemos', ('Cryptex1,SystemOS', 'Cryptex1,SystemOS1', 'SystemOS')),
)


def sh(cmd):
    return subprocess.run([str(part) for part in cmd], capture_output=True,
                          text=True, check=False)


def pick_members(build_manifest):
    identities = build_manifest.get('BuildIdentities') or []
    if not identities:
        raise SystemExit('BuildManifest.plist has no BuildIdentities')
    manifest = identities[0].get('Manifest') or {}
    chosen = []
    for name, keys in COMPONENTS:
        entry = None
        for key in keys:
            if key in manifest:
                entry = manifest[key]
                print('component %s -> %s' % (name, key))
                break
        if entry is None:
            near = [k for k in manifest if 'yptex' in k.lower() or 'os' in k.lower()]
            raise SystemExit('%s: no component %s, available: %s'
                             % (name, '/'.join(keys), ', '.join(sorted(near)[:20])))
        info = entry.get('Info') or {}
        path = info.get('Path')
        if not path:
            raise SystemExit('%s: the component has no Info.Path' % name)
        digest = info.get('Digest')
        chosen.append((name, path, digest))
    return chosen


def extract(ipsw, members, work):
    work.mkdir(parents=True, exist_ok=True)
    out = []
    with zipfile.ZipFile(ipsw) as archive:
        names = set(archive.namelist())
        for name, path, digest in members:
            if path not in names:
                raise SystemExit('%s: %s is not in the IPSW' % (name, path))
            target = work / Path(path).name
            if not target.is_file():
                print('extracting', path)
                with archive.open(path) as source, target.open('wb') as sink:
                    while True:
                        chunk = source.read(8 * 1024 * 1024)
                        if not chunk:
                            break
                        sink.write(chunk)
            print('%s: %s (%d bytes)' % (name, target, target.stat().st_size))
            out.append((name, target, digest))
    return out


def imageinfo(dmg):
    result = sh(['hdiutil', 'imageinfo', '-plist', dmg])
    if result.returncode:
        raise SystemExit('hdiutil imageinfo failed: %s' % result.stderr[-800:])
    return int(plistlib.loads(result.stdout.encode())['Size Information']['Total Bytes'])


def attach(dmg):
    result = sh(['hdiutil', 'attach', '-nomount', '-readonly', '-noverify',
                 '-noautofsck', dmg])
    if result.returncode:
        raise SystemExit('hdiutil attach failed: %s' % result.stderr[-800:])
    for line in result.stdout.splitlines():
        match = re.match(r'(/dev/disk\d+)\s', line)
        if match:
            return match.group(1)
    raise SystemExit('attach did not report a device for %s' % dmg)


def detach(device):
    sh(['hdiutil', 'detach', device])


def volume_uuid(device, seed):
    """Volume UUID recorded in the signed header.

    vr_open_header only copies it into the view; it is never compared with the
    mounted volume, so a synthetic value still produces a valid policy.
    """
    disk = Path(device).name
    result = sh(['diskutil', 'apfs', 'list', '-plist'])
    if result.returncode == 0:
        try:
            data = plistlib.loads(result.stdout.encode())
            for container in data.get('Containers') or []:
                reference = container.get('APFSContainerReference')
                if reference and reference != disk:
                    continue
                for volume in container.get('Volumes') or []:
                    value = volume.get('APFSVolumeUUID')
                    if value:
                        return uuid.UUID(value), 'apfs-container-list'
        except Exception as error:  # noqa: BLE001
            print('diskutil apfs list parse failed:', error)
    for candidate in (device, device + 's1', device + 's2'):
        info = sh(['diskutil', 'info', '-plist', candidate])
        if info.returncode:
            continue
        try:
            record = plistlib.loads(info.stdout.encode())
        except Exception as error:  # noqa: BLE001
            print('diskutil info parse failed:', error)
            continue
        if record.get('VolumeUUID'):
            return uuid.UUID(record['VolumeUUID']), 'diskutil-info'
    synthetic = uuid.uuid5(uuid.NAMESPACE_URL, seed)
    print('no APFS volume UUID readable on %s, using synthetic %s' % (device, synthetic))
    return synthetic, 'synthetic'


def ensure_keys(keys):
    keys.mkdir(parents=True, exist_ok=True)
    private, public = keys / 'owner.pem', keys / 'owner-public.pem'
    if private.is_file() and public.is_file():
        print('reusing the cached owner key')
        return private, public
    for cmd in (['openssl', 'genrsa', '-out', private, '3072'],
                ['openssl', 'rsa', '-in', private, '-pubout', '-out', public]):
        result = sh(cmd)
        if result.returncode:
            raise SystemExit('openssl failed: %s' % result.stderr[-800:])
    print('generated a fresh 3072-bit owner key')
    return private, public


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipsw', type=Path, required=True)
    parser.add_argument('--manifest-module', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--work', type=Path, default=Path('disks'))
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location('verified_manifest', args.manifest_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with zipfile.ZipFile(args.ipsw) as archive:
        manifest_bytes = archive.read('BuildManifest.plist')
    build_manifest = plistlib.loads(manifest_bytes)
    identity = (build_manifest.get('BuildIdentities') or [{}])[0]
    print('product', identity.get('Info', {}).get('ProductType'),
          'build', identity.get('Info', {}).get('BuildNumber'))

    members = pick_members(build_manifest)
    disks = extract(args.ipsw, members, args.work)
    private, public = ensure_keys(args.keys)

    summary = {}
    for name, dmg, digest in disks:
        output = args.out / name
        size = imageinfo(dmg)
        device = attach(dmg)
        try:
            volume, source = volume_uuid(device, str(dmg.name))
            print('%s: %d bytes, volume %s (%s)' % (name, size, volume, source))
            raw = Path(device.replace('/dev/disk', '/dev/rdisk'))
            with raw.open('rb', buffering=1024 * 1024) as stream:
                record = module.make(stream, size, private, public, volume, 1, output)
        finally:
            detach(device)
        record['ipsw_member'] = str(dmg.name)
        record['ipsw_info_digest'] = digest
        record['volume_uuid_source'] = source
        summary[name] = record
        print('%s: %d blocks, image %s' % (name, record['block_count'],
                                          record['image_sha256'][:16]))

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('done')


if __name__ == '__main__':
    sys.exit(main())
