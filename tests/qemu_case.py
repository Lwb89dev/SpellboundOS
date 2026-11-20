#!/usr/bin/env python3
"""Check a QEMU guest report, with an optional pattern for fatal traps."""
import re
import select
import subprocess
import sys
import time

qemu, elf, name, *expected = sys.argv[1:]
success = re.compile(expected[0].encode() if expected else
                     re.escape(('PASS: ' + name + '\r\n').encode()))
failure = ('FAIL: ' + name + '\r\n').encode()
process = subprocess.Popen(
    [qemu, '-machine', 'virt', '-bios', 'none', '-nographic',
     '-monitor', 'none', '-kernel', elf],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
output = bytearray()
try:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.2)
        if readable:
            chunk = process.stdout.read1(4096)
            if not chunk:
                break
            output.extend(chunk)
            if success.search(output):
                print('PASS: RV32 ' + name)
                break
            if failure in output:
                break
    else:
        raise RuntimeError(name + ' test timed out: ' + repr(output))
    if not success.search(output):
        raise RuntimeError(name + ' test failed: ' + repr(output))
finally:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
