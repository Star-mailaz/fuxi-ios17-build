#!/usr/bin/env python3
"""Encrypt build outputs to an RSA public key, openssl-compatible (Salted__ + PBKDF2-SHA256).

usage: pack_secret.py <recipient.pem> <out_dir> <file>...

Each <file> becomes <out_dir>/<name>.enc plus <name>.sha256; the random passphrase is
written once as <out_dir>/key.enc (RSA-OAEP-SHA256). Nothing leaves in the clear.
"""
import hashlib, os, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def main():
    pem, out_dir, *files = sys.argv[1:]
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    pub = serialization.load_pem_public_key(Path(pem).read_bytes())
    key = os.urandom(32)
    passphrase = key.hex().encode()
    for f in files:
        data = Path(f).read_bytes()
        salt = os.urandom(8)
        dk = hashlib.pbkdf2_hmac('sha256', passphrase, salt, 200000, 48)
        enc = Cipher(algorithms.AES(dk[:32]), modes.CBC(dk[32:])).encryptor()
        ct = enc.update(data) + enc.finalize()
        blob = b'Salted__' + salt + ct
        name = Path(f).name
        (out / (name + '.enc')).write_bytes(blob)
        (out / (name + '.sha256')).write_text(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
        print('encrypted', name, len(data), '->', len(blob))
    wrapped = pub.encrypt(passphrase,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    (out / 'key.enc').write_bytes(wrapped)
    print('wrote', out / 'key.enc')

if __name__ == '__main__':
    main()
