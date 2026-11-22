"""Build and run the portable sensor, LSM6DSO IMU and ZTW622 touch host tests."""
import os
import subprocess
import tempfile
import unittest


class SensorsTouchHostTest(unittest.TestCase):
    def test_sensors_and_touch(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            binary = os.path.join(directory, 'test_sensors_touch')
            result = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'),
                 os.path.join(root, 'tests', 'test_sensors_touch.c'), '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: sensor queue, LSM6DSO SPI IMU and ZTW622 I2C touch', result.stdout)


if __name__ == '__main__':
    unittest.main()
