"""Build and run the portable ALS, charger, motor, fb and ICNA3311 host tests."""
import os
import subprocess
import tempfile
import unittest


class PeriphDisplayHostTest(unittest.TestCase):
    def test_peripherals_and_display(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            binary = os.path.join(directory, 'test_periph_display')
            result = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'),
                 os.path.join(root, 'tests', 'test_periph_display.c'), '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: STK31E60 ALS, CW6305/AW32012 chargers, motor, fb and ICNA3311',
                          result.stdout)


if __name__ == '__main__':
    unittest.main()
