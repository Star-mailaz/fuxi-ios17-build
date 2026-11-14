#!/usr/bin/env python3
"""Patch the UniXNU build inputs for the GitHub Actions build.

Every copy of each target file under the given root is patched: the build tree
assembles its scripts from unixnu/scripts and the device overlays.

1. build-libpthread-kernel.py: accept arm64e bootstrap objects (the XNU recipe
   compiles that one with --target=arm64e-apple-ios17.0 -arch arm64e).

2. build-ios17-verified-root.py: zero sample blocks when userdata-root.img is absent.

3. Drop the USB debug archive: the pinned QcomXnuUsbDebug has no
   SXNU_CONTROL_VERB_REBOOT_FASTBOOT verb, so its prepare step aborts.

4. Drop the Adreno GPU archives and CONFIG_XNU_NATIVE_ADRENO: clang 24 from the
   Linux XNU toolchain segfaults in ParseBraceInitializer while compiling
   NativeAdrenoService.cpp. The GPU layer is not needed for the first boot.
"""
import sys
from pathlib import Path

LIBPTHREAD_OLD = """    data = destination.read_bytes()
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit('Unexpected pthread object architecture')
"""

LIBPTHREAD_NEW = """    data = destination.read_bytes()
    words = struct.unpack_from('<4I', data)
    subtype = words[2] & 0x00ffffff
    if words[0] != 0xfeedfacf or words[1] != 0x100000c or words[3] != 1 or subtype not in (0, 2):
        log = destination.with_suffix('.log')
        detail = 'file=%s words=%s head=%s log=%s' % (
            destination.name, tuple(hex(word) for word in words), data[:32].hex(), log)
        tail = ''
        if log.is_file():
            tail = ' logtail=' + log.read_text()[-1200:].replace(chr(10), ' | ')
        raise SystemExit('Unexpected pthread object architecture [%s] cmd=%s%s'
                         % (detail, ' '.join(command), tail))
    print('CI-ARCH %s subtype=%s arm64e=%s' % (destination.name, subtype, bool(words[2] & 0x80000000)))
"""

VERIFIED_REPORT_OLD = "report = json.loads(IMAGE.with_name('userdata-root.json').read_text())"
VERIFIED_REPORT_NEW = "report = (json.loads(IMAGE.with_name('userdata-root.json').read_text()) if IMAGE.with_name('userdata-root.json').is_file() else {'windows': [{'name': 'OS', 'offset': 0, 'size': records[0]['block_count'] * 4096}]})"
VERIFIED_OPEN_OLD = "with IMAGE.open('rb') as stream:"
VERIFIED_OPEN_NEW = "with (IMAGE.open('rb') if IMAGE.is_file() else open(os.devnull, 'rb')) as stream:"

USB_ARCHIVE = '"build-fuxi-usb-debug.py",'
USB_LINK = ' {tree}/.cache/fuxi-qud-build/libQcomXnuUsbDebug.a'

ADRENO_ARCHIVES = [
    '"build-arm-driver.py Adreno740",',
    '"build-adreno740-kits.py",',
    '"build-adreno740-accelerator.py",',
]
ADRENO_CONFIG_OLD = 'CONFIG_XNU_NATIVE_ADRENO=y'
ADRENO_CONFIG_NEW = 'CONFIG_XNU_NATIVE_ADRENO=n'

EDITS = (
    ('build-libpthread-kernel.py', [(LIBPTHREAD_OLD, LIBPTHREAD_NEW)], 'CI-ARCH ', True),
    ('build-ios17-verified-root.py',
     [(VERIFIED_REPORT_OLD, VERIFIED_REPORT_NEW), (VERIFIED_OPEN_OLD, VERIFIED_OPEN_NEW)],
     'os.devnull', True),
    ('board.toml', [(USB_ARCHIVE, '')] + [(name, '') for name in ADRENO_ARCHIVES], None, False),
    ('fuxi_ios17_kernel_defconfig', [(USB_LINK, ''), (ADRENO_CONFIG_OLD, ADRENO_CONFIG_NEW)], None, False),
)


def candidates(root, name):
    for path in sorted(root.rglob(name)):
        if not path.is_file():
            continue
        if '.git' in path.parts or 'node_modules' in path.parts:
            continue
        yield path


def main(root):
    base = Path(root)
    failures = 0
    for name, edits, marker, required in EDITS:
        patched = already = skipped = 0
        for path in candidates(base, name):
            text = path.read_text(errors='replace')
            if marker and marker in text:
                already += 1
                continue
            present = [(old, new) for old, new in edits if old in text]
            if not present:
                skipped += 1
                continue
            for old, new in present:
                text = text.replace(old, new, 1)
            path.write_text(text)
            print('PATCHED', path, '(%d edits)' % len(present))
            patched += 1
        print('%s: patched=%d already=%d skipped=%d' % (name, patched, already, skipped))
        if required and patched == 0 and already == 0:
            failures += 1
            print('FAILED', name)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
