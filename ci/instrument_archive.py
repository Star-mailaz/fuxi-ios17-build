#!/usr/bin/env python3
"""Patch the UniXNU archive builders for the GitHub Actions build.

Every copy of each target file under the given root is patched: the build tree
assembles its scripts from unixnu/scripts and the device overlays, so the source
of a given script differs per file.

1. build-libpthread-kernel.py asserts every object header is exactly
   (MH_MAGIC_64, CPU_TYPE_ARM64, subtype 0, MH_OBJECT). The bootstrap object is
   compiled from the XNU build recipe, which carries --target=arm64e-apple-ios17.0
   -arch arm64e, so it comes out arm64e (subtype 2 plus the ptrauth ABI bit).
   Accept arm64 and arm64e, and keep the full diagnostic for anything else.

2. build-ios17-verified-root.py reads four sample blocks out of userdata-root.img,
   which only exists on the author's machine. The samples are only referenced by
   the offline-owner-root-check boot argument, so fall back to zero blocks when the
   image is absent. Two single-line edits keep the rest of the script intact.
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
VERIFIED_REPORT_NEW = ("report = (json.loads(IMAGE.with_name('userdata-root.json').read_text())
"
                       "          if IMAGE.with_name('userdata-root.json').is_file() else
"
                       "          {'windows': [{'name': 'OS', 'offset': 0,
"
                       "                        'size': records[0]['block_count'] * 4096}]})")

VERIFIED_OPEN_OLD = "with IMAGE.open('rb') as stream:"
VERIFIED_OPEN_NEW = "with (IMAGE.open('rb') if IMAGE.is_file() else open(os.devnull, 'rb')) as stream:"

EDITS = (
    ('build-libpthread-kernel.py', [(LIBPTHREAD_OLD, LIBPTHREAD_NEW)], 'CI-ARCH '),
    ('build-ios17-verified-root.py',
     [(VERIFIED_REPORT_OLD, VERIFIED_REPORT_NEW), (VERIFIED_OPEN_OLD, VERIFIED_OPEN_NEW)],
     'os.devnull'),
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
    for name, edits, marker in EDITS:
        patched = already = skipped = 0
        for path in candidates(base, name):
            text = path.read_text(errors='replace')
            if marker in text:
                already += 1
                continue
            missing = [old for old, _ in edits if old not in text]
            if missing:
                skipped += 1
                print('skip', path, '(%d bytes, no anchor: %r)' % (len(text), missing[0][:60]))
                continue
            for old, new in edits:
                text = text.replace(old, new, 1)
            path.write_text(text)
            print('PATCHED', path)
            patched += 1
        print('%s: patched=%d already=%d skipped=%d' % (name, patched, already, skipped))
        if patched == 0 and already == 0:
            failures += 1
            print('FAILED', name)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
