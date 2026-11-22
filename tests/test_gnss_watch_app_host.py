"""Build and run the portable AG3335 GNSS and watch_app runtime host tests."""
import os
import subprocess
import tempfile
import unittest


class GnssWatchAppHostTest(unittest.TestCase):
    def test_gnss_and_watch_app(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            binary = os.path.join(directory, 'test_gnss_watch_app')
            result = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'),
                 os.path.join(root, 'tests', 'test_gnss_watch_app.c'), '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: AG3335 GNSS PAIR/NMEA and unified watch_app runtime',
                          result.stdout)


if __name__ == '__main__':
    unittest.main()
