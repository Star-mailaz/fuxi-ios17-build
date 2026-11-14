#!/usr/bin/env python3
"""Extract the raw kernelcache from an IM4P (IMG4) kernelcache file.

usage: extract_kernelcache.py <kernelcache.release.*> -o <out>

Parses the DER wrapper, takes the krnl OCTET STRING payload and decompresses it
(LZFSE 'bvx2' / LZSS 'complzss'), or passes it through when it is already a Mach-O.
"""
import argparse, struct, sys

def der_items(buf, start=0, end=None):
    """Yield (tag, value_offset, value_len) for a DER sequence body."""
    i = start
    end = len(buf) if end is None else end
    while i < end:
        tag = buf[i]; i += 1
        if i >= end: return
        l = buf[i]; i += 1
        if l & 0x80:
            n = l & 0x7F
            l = int.from_bytes(buf[i:i+n], 'big'); i += n
        yield tag, i, l
        i += l

def im4p_payload(buf):
    # SEQUENCE { IA5String 'IM4P', IA5String type, IA5String desc, OCTET STRING payload }
    tag, off, ln = next(der_items(buf))
    assert tag == 0x30, 'not a DER sequence'
    items = list(der_items(buf, off, off + ln))
    names = [(t, buf[o:o+l]) for t, o, l in items]
    print('  IM4P members:', [(hex(t), bytes(v)[:8]) for t, v in names])
    for t, o, l in items:
        if t == 0x04 and l > 4096:
            return buf[o:o+l]
    raise SystemExit('no payload OCTET STRING found')

def lzss_decompress(data):
    # Apple LZSS: 'complzss' + u32 uncompressed size + u32 compressed size, then blocks
    assert data[:8] == b'complzss', data[:8]
    out_size = struct.unpack('>I', data[8:12])[0]
    src = data[12:]
    out = bytearray()
    i = 0
    while len(out) < out_size:
        flags = src[i]; i += 1
        for bit in range(8):
            if len(out) >= out_size: break
            if flags & (0x80 >> bit):
                n = src[i] << 8 | src[i+1]; i += 2
                dist = n & 0x0FFF
                count = (n >> 12) + 3
                for _ in range(count):
                    out.append(out[-dist])
            else:
                out.append(src[i]); i += 1
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image')
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args()
    buf = open(a.image, 'rb').read()
    print('input', a.image, len(buf), 'bytes, magic', buf[:8])
    payload = im4p_payload(buf)
    print('payload', len(payload), 'bytes, magic', payload[:8])
    if payload[:4] == b'\xcf\xfa\xed\xfe' or payload[:4] == b'\xce\xfa\xed\xfe':
        out = payload
        print('already a Mach-O')
    elif payload[:8] == b'complzss':
        out = lzss_decompress(payload)
        print('lzss ->', len(out))
    elif payload[:4] == b'bvx2':
        try:
            import lzfse
        except ImportError:
            raise SystemExit('needs the lzfse module: python3 -m pip install lzfse')
        out = lzfse.decompress(payload)
        print('lzfse ->', len(out))
    else:
        out = payload
        print('unknown container, writing payload as-is')
    open(a.output, 'wb').write(out)
    print('wrote', a.output, len(out), 'bytes, magic', out[:8].hex())

if __name__ == '__main__':
    main()
