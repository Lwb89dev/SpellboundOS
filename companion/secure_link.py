"""Pure-Python RFC 8439 ChaCha20-Poly1305 + HKDF-SHA256 secure link for SpellboundFit.

Byte-exact companion mirror of kernel/crypto.c and kernel/secure_link.c with zero
external dependencies beyond Python's standard library.
"""
import hashlib
import hmac
import os
import struct

SECURE_MSG_HELLO = 0x01
SECURE_MSG_HELLO_ACK = 0x02
SECURE_MSG_DATA = 0x03
KDF_INFO = b'SpellboundFit-v1-session'
PROOF_LABEL = b'WATCH-OK'


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    assert len(key) == 32 and len(nonce) == 12
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st.extend(struct.unpack('<8I', key))
    st.append(counter & 0xFFFFFFFF)
    st.extend(struct.unpack('<3I', nonce))
    w = list(st)
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13)
        _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12)
        _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    out = [(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *out)


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    for off in range(0, len(data), 64):
        ks = chacha20_block(key, counter, nonce)
        counter += 1
        chunk = data[off:off + 64]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
    return bytes(out)


def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    assert len(key) == 32
    r = int.from_bytes(key[:16], 'little') & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], 'little')
    p = (1 << 130) - 5
    acc = 0
    for off in range(0, len(msg), 16):
        blk = msg[off:off + 16]
        n = int.from_bytes(blk + b'\x01', 'little')
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


def _pad16(data: bytes) -> bytes:
    rem = len(data) & 15
    return b'' if rem == 0 else b'\x00' * (16 - rem)


def chacha20_poly1305_seal(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
    poly_key = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, 1, nonce, pt)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack('<QQ', len(aad), len(ct))
    return ct, poly1305_mac(poly_key, mac_data)


def chacha20_poly1305_open(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack('<QQ', len(aad), len(ct))
    expected = poly1305_mac(poly_key, mac_data)
    if not hmac.compare_digest(expected, tag):
        raise ValueError('Poly1305 tag verification failed')
    return chacha20_xor(key, 1, nonce, ct)


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b''
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


class SecureSession:
    """Phone-side encrypted session matching kernel/secure_link.c."""

    def __init__(self, psk: bytes) -> None:
        if len(psk) != 32:
            raise ValueError('PSK must be 32 bytes')
        self.psk = psk
        self.phone_nonce = b''
        self.watch_nonce = b''
        self.tx_key = b''
        self.rx_key = b''
        self.tx_counter = 0
        self.rx_next_counter = 0
        self.established = False

    def build_hello(self, phone_nonce: bytes | None = None) -> bytes:
        nonce = os.urandom(16) if phone_nonce is None else phone_nonce
        if len(nonce) != 16:
            raise ValueError('nonce must be 16 bytes')
        self.phone_nonce = nonce
        self.established = False
        self.tx_counter = 0
        self.rx_next_counter = 0
        return bytes([SECURE_MSG_HELLO]) + nonce

    def finish_handshake(self, hello_ack: bytes) -> None:
        if len(hello_ack) != 49 or hello_ack[0] != SECURE_MSG_HELLO_ACK:
            raise ValueError('invalid HELLO_ACK packet')
        self.watch_nonce = hello_ack[1:17]
        proof = hello_ack[17:49]
        salt = self.phone_nonce + self.watch_nonce
        okm = hkdf_sha256(salt, self.psk, KDF_INFO, 64)
        self.tx_key = okm[:32]
        self.rx_key = okm[32:]
        expected = hmac.new(self.rx_key, PROOF_LABEL + salt, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, proof):
            self.tx_key = self.rx_key = b''
            raise ValueError('watch authentication proof mismatch')
        self.tx_counter = 0
        self.rx_next_counter = 0
        self.established = True

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.established:
            raise RuntimeError('session not established')
        ctr = self.tx_counter
        self.tx_counter += 1
        aad = struct.pack('<BQ', SECURE_MSG_DATA, ctr)
        nonce = b'\x00\x00\x00\x00' + struct.pack('<Q', ctr)
        ct, tag = chacha20_poly1305_seal(self.tx_key, nonce, aad, plaintext)
        return aad + ct + tag

    def decrypt(self, packet: bytes) -> bytes:
        if not self.established:
            raise RuntimeError('session not established')
        if len(packet) < 25 or packet[0] != SECURE_MSG_DATA:
            raise ValueError('invalid encrypted packet')
        ctr, = struct.unpack('<Q', packet[1:9])
        if ctr < self.rx_next_counter:
            raise ValueError(f'replayed counter {ctr} < {self.rx_next_counter}')
        aad = packet[:9]
        ct = packet[9:-16]
        tag = packet[-16:]
        nonce = b'\x00\x00\x00\x00' + struct.pack('<Q', ctr)
        pt = chacha20_poly1305_open(self.rx_key, nonce, aad, ct, tag)
        self.rx_next_counter = ctr + 1
        return pt
