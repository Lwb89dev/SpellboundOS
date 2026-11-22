"""Build and run the portable power manager and watch UI compositor host tests."""
import os
import subprocess
import tempfile
import unittest


class UiPowerHostTest(unittest.TestCase):
    def test_ui_and_power(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            binary = os.path.join(directory, 'test_ui_power')
            result = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'),
                 os.path.join(root, 'tests', 'test_ui_power.c'), '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: power manager, watch UI compositor and Bip 6 descriptor',
                          result.stdout)


if __name__ == '__main__':
    unittest.main()
