"""Exercise trust-anchor extraction with generated keys, not vendor firmware."""
import hashlib
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from analysis_scripts.bootloader_root_key import (
    SECP256K1_P, extract_key, on_secp256k1_curve, public_key_from_bytes)
from analysis_scripts.verify_ota_signatures import verify


def public_xy(public_key):
    numbers = public_key.public_numbers()
    return numbers.x.to_bytes(32, 'big') + numbers.y.to_bytes(32, 'big')


class ExtractKeyTest(unittest.TestCase):
    def test_extracts_64_bytes_at_offset(self):
        key = bytes(range(64))
        body = b'\x00' * 100 + key + b'\xff' * 100
        self.assertEqual(extract_key(body, offset=100), key)

    def test_short_bootloader_rejected(self):
        with self.assertRaises(ValueError):
            extract_key(b'\x00' * 40, offset=0)


class CurvePointTest(unittest.TestCase):
    def test_generated_point_is_on_curve(self):
        key_bytes = public_xy(ec.generate_private_key(ec.SECP256K1()).public_key())
        self.assertTrue(on_secp256k1_curve(key_bytes))
        # The same bytes must build a usable public key object.
        self.assertIsNotNone(public_key_from_bytes(key_bytes))

    def test_tampered_point_is_off_curve(self):
        key_bytes = bytearray(public_xy(
            ec.generate_private_key(ec.SECP256K1()).public_key()))
        key_bytes[63] ^= 1  # perturb y: no longer satisfies y^2 = x^3 + 7
        self.assertFalse(on_secp256k1_curve(bytes(key_bytes)))

    def test_out_of_field_and_zero_rejected(self):
        self.assertFalse(on_secp256k1_curve(b'\x00' * 64))
        self.assertFalse(on_secp256k1_curve(SECP256K1_P.to_bytes(32, 'big') * 2))

    def test_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            on_secp256k1_curve(b'\x01' * 63)


class AnchorCrossCheckTest(unittest.TestCase):
    """The embedded key is the anchor only if downstream images verify under it."""

    def _signed_image(self, private_key, payload):
        digest = hashlib.sha256(payload).digest()
        der = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return payload + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    def test_embedded_key_verifies_its_own_images(self):
        anchor = ec.generate_private_key(ec.SECP256K1())
        key_bytes = public_xy(anchor.public_key())
        # A bootloader body that carries the anchor at a known offset.
        bootloader = b'MHBZ' * 7 + key_bytes + b'tail'
        recovered = public_key_from_bytes(extract_key(bootloader, offset=28))
        image = self._signed_image(anchor, b'downstream firmware')
        self.assertTrue(verify(image, recovered))

    def test_foreign_image_is_not_anchored(self):
        anchor = ec.generate_private_key(ec.SECP256K1())
        key_bytes = public_xy(anchor.public_key())
        recovered = public_key_from_bytes(extract_key(key_bytes, offset=0))
        foreign = self._signed_image(
            ec.generate_private_key(ec.SECP256K1()), b'downstream firmware')
        self.assertFalse(verify(foreign, recovered))


if __name__ == '__main__':
    unittest.main()
