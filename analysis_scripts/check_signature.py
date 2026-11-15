#!/usr/bin/env python3
"""Test the candidate public key and ECDSA curve against the stock image.

Requires cryptography. The key location comes from the experimental Ghidra
bootloader mapping; no private key or modification of the image is involved.
"""
import hashlib
import pathlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

boot = pathlib.Path(sys.argv[1]).read_bytes()
image = pathlib.Path(sys.argv[2]).read_bytes()
key = boot[0x37094:0x37094 + 64]
signature = image[-64:]
digest = hashlib.sha256(image[:-64]).digest()
print('sha256(image without last 64 bytes):', digest.hex())
successes = 0
for curve in (ec.SECP256K1(), ec.SECP256R1()):
    for key_endian in ('big', 'little'):
        x = int.from_bytes(key[:32], key_endian)
        y = int.from_bytes(key[32:], key_endian)
        try:
            public = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        except ValueError:
            continue
        for sig_endian in ('big', 'little'):
            r = int.from_bytes(signature[:32], sig_endian)
            s = int.from_bytes(signature[32:], sig_endian)
            try:
                public.verify(utils.encode_dss_signature(r, s), digest,
                              ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            except InvalidSignature:
                continue
            print('VERIFIED', curve.name, 'key endian:', key_endian,
                  'signature endian:', sig_endian)
            altered = bytearray(image[:-64])
            altered[len(altered) // 2] ^= 1
            altered_digest = hashlib.sha256(altered).digest()
            try:
                public.verify(utils.encode_dss_signature(r, s), altered_digest,
                              ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            except InvalidSignature:
                print('PASS: modified image rejected by offline verification')
            else:
                raise RuntimeError('modified image unexpectedly verified')
            successes += 1
if not successes:
    print('No tested combination verified; this is not proof signatures are absent.')
    sys.exit(1)
