"""Exercise signature validation with generated keys, not vendor firmware."""
import hashlib
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from analysis_scripts.verify_ota_signatures import verify


class SignatureVerificationTest(unittest.TestCase):
    def test_valid_modified_and_wrong_key(self):
        key = ec.generate_private_key(ec.SECP256K1())
        payload = b'fictional firmware payload'
        digest = hashlib.sha256(payload).digest()
        der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        image = payload + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        self.assertTrue(verify(image, key.public_key()))
        self.assertFalse(verify(b'X' + image[1:], key.public_key()))
        self.assertFalse(verify(image, ec.generate_private_key(ec.SECP256K1()).public_key()))

    def test_short_image_rejected(self):
        key = ec.generate_private_key(ec.SECP256K1())
        with self.assertRaises(ValueError):
            verify(b'', key.public_key())


if __name__ == '__main__':
    unittest.main()
