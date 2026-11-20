"""Compile and run the host unit test for the kernel heap (kernel/kmem.c)."""
import os
import subprocess
import tempfile
import unittest


class KmemHostTest(unittest.TestCase):
    def test_kmem_allocator(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = os.path.join(root, 'tests', 'test_kmem.c')
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, 'test_kmem')
            compile_ = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'), src, '-o', binary],
                capture_output=True, text=True)
            self.assertEqual(compile_.returncode, 0, compile_.stderr)
            run = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('PASS: kmem', run.stdout)


if __name__ == '__main__':
    unittest.main()
