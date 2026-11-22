"""Compile all Android SpellboundFit Java sources against android.jar and verify
JVM unit tests plus live Java <-> C encrypted wire interoperability."""
import os
import shutil
import subprocess
import tempfile
import unittest

from tests.test_companion_secure import C_SECURE_WATCH_SRC

ANDROID_JAR = '/home/antona89/Android/Sdk/platforms/android-35/android.jar'


class AndroidCompanionTest(unittest.TestCase):
    def test_compile_android_app_and_java_c_encrypted_interop(self):
        if shutil.which('javac') is None or shutil.which('java') is None:
            self.skipTest('JDK (javac/java) not available in PATH')
        if not os.path.exists(ANDROID_JAR):
            self.skipTest(f'Android SDK jar not found at {ANDROID_JAR}')

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        java_main = os.path.join(root, 'android', 'SpellboundFit', 'app', 'src', 'main', 'java')
        java_test = os.path.join(root, 'android', 'SpellboundFit', 'app', 'src', 'test', 'java')

        sources = []
        for base in (java_main, java_test):
            for dirpath, _, filenames in os.walk(base):
                for fn in filenames:
                    if fn.endswith('.java'):
                        sources.append(os.path.join(dirpath, fn))
        self.assertGreaterEqual(len(sources), 6)

        with tempfile.TemporaryDirectory() as tmp:
            classes = os.path.join(tmp, 'classes')
            os.makedirs(classes)

            # 1. Compile ALL Android app + test classes against android-35/android.jar
            comp = subprocess.run(
                ['javac', '-Xlint:all', '-Xlint:-deprecation', '-Werror',
                 '-cp', ANDROID_JAR, '-d', classes] + sources,
                capture_output=True, text=True)
            self.assertEqual(comp.returncode, 0, comp.stderr)

            # 2. Run pure-JVM self-test (CRC32, RFC 8439 ChaCha20-Poly1305, Roadstr EN/IT)
            unit = subprocess.run(
                ['java', '-cp', classes, 'dev.spellboundfit.SpellboundFitSelfTest'],
                capture_output=True, text=True)
            self.assertEqual(unit.returncode, 0, unit.stdout + unit.stderr)
            self.assertIn('PASS: Android SpellboundFit Java', unit.stdout)

            # 3. Compile real C watch binary and run LIVE Java <-> C encrypted session!
            c_src = os.path.join(tmp, 'c_watch.c')
            c_bin = os.path.join(tmp, 'c_watch')
            with open(c_src, 'w', encoding='utf-8') as f:
                f.write(C_SECURE_WATCH_SRC)
            cc = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'), c_src, '-o', c_bin],
                capture_output=True, text=True)
            self.assertEqual(cc.returncode, 0, cc.stderr)

            # Wire Java phone <-> C watch bidirectionally through two OS pipes
            p_c2j_r, p_c2j_w = os.pipe()
            p_j2c_r, p_j2c_w = os.pipe()
            try:
                watch_proc = subprocess.Popen(
                    [c_bin], stdin=p_j2c_r, stdout=p_c2j_w, stderr=subprocess.PIPE
                )
                phone_proc = subprocess.Popen(
                    ['java', '-cp', classes, 'dev.spellboundfit.SpellboundFitSelfTest', '--interop'],
                    stdin=p_c2j_r, stdout=p_j2c_w, stderr=subprocess.PIPE
                )
                os.close(p_j2c_r)
                os.close(p_c2j_w)
                os.close(p_c2j_r)
                os.close(p_j2c_w)

                phone_err = phone_proc.stderr.read().decode('utf-8', 'replace')
                watch_err = watch_proc.stderr.read().decode('utf-8', 'replace')
                phone_rc = phone_proc.wait(timeout=10)
                watch_rc = watch_proc.wait(timeout=10)
                phone_proc.stderr.close()
                watch_proc.stderr.close()

                self.assertEqual(phone_rc, 0, f'Java phone failed ({phone_rc}): {phone_err}')
                self.assertEqual(watch_rc, 0, f'C watch failed ({watch_rc}): {watch_err}')
            finally:
                for fd in (p_c2j_r, p_c2j_w, p_j2c_r, p_j2c_w):
                    try:
                        os.close(fd)
                    except OSError:
                        pass


if __name__ == '__main__':
    unittest.main()
