#!/usr/bin/env python3
"""Add diagnostics to upstream archive scripts that abort with a bare SystemExit."""
import sys
from pathlib import Path

RECIPE = """    data = destination.read_bytes()
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit('Unexpected pthread object architecture')
"""

REPLACEMENT = """    data = destination.read_bytes()
    words = struct.unpack_from('<4I', data)
    if words != (0xfeedfacf, 0x100000c, 0, 1):
        log = destination.with_suffix('.log')
        detail = 'file=%s words=%s head=%s log=%s' % (
            destination.name, tuple(hex(word) for word in words), data[:32].hex(), log)
        tail = ''
        if log.is_file():
            tail = ' logtail=' + log.read_text()[-1200:].replace(chr(10), ' | ')
        raise SystemExit('Unexpected pthread object architecture [%s] cmd=%s%s'
                         % (detail, ' '.join(command), tail))
"""

EDITS = [('scripts/build-libpthread-kernel.py', RECIPE, REPLACEMENT)]
MARKER = 'pthread object architecture ['


def main(root):
    base = Path(root)
    failures = 0
    for relative, old, new in EDITS:
        path = base / relative
        if not path.is_file():
            print('MISSING', path)
            failures += 1
            continue
        text = path.read_text()
        if MARKER in text:
            print('ALREADY PATCHED', path)
        elif old in text:
            path.write_text(text.replace(old, new, 1))
            print('PATCHED', path)
        else:
            print('ANCHOR NOT FOUND', path)
            failures += 1
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
