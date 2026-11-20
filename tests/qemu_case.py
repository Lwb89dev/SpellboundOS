#!/usr/bin/env python3
"""Run a QEMU guest until it reports its named PASS or FAIL marker."""
import select
import subprocess
import sys
import time

qemu, elf, name = sys.argv[1:]
success = ('PASS: ' + name + '\r\n').encode()
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
            if success in output:
                print('PASS: RV32 ' + name)
                break
            if failure in output:
                break
    else:
        raise RuntimeError(name + ' test timed out: ' + repr(output))
    if success not in output:
        raise RuntimeError(name + ' test failed: ' + repr(output))
finally:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
