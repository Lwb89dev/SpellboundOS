"""Build and run the portable RTL8763 HCI, RFC crypto and secure_link host tests."""
import os
import subprocess
import tempfile
import unittest


class BtCryptoHostTest(unittest.TestCase):
    def test_bt_and_crypto(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            binary = os.path.join(directory, 'test_bt_crypto')
            result = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'),
                 os.path.join(root, 'tests', 'test_bt_crypto.c'), '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: RTL8763 HCI framing, RFC crypto and secure_link',
                          result.stdout)


if __name__ == '__main__':
    unittest.main()
