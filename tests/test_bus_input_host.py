"""Build and run the portable syscon, bus, input and gpio_keys host tests."""
import os
import subprocess
import tempfile
import unittest


class BusInputHostTest(unittest.TestCase):
    def test_bus_and_input(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            binary = os.path.join(directory, 'test_bus_input')
            result = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'),
                 os.path.join(root, 'tests', 'test_bus_input.c'), '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: syscon, bus', result.stdout)


if __name__ == '__main__':
    unittest.main()
