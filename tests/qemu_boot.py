#!/usr/bin/env python3
"""Check guest startup, UART echo and the periodic timer tick without relying on
host timeouts. Requires a system QEMU (qemu-system-riscv32)."""
import select
import subprocess
import sys
import time

qemu, elf = sys.argv[1:]
p = subprocess.Popen([qemu, '-machine', 'virt', '-bios', 'none', '-nographic',
                      '-monitor', 'none', '-kernel', elf], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
output = bytearray()
try:
    deadline = time.monotonic() + 15
    sent = False
    echoed = False
    while time.monotonic() < deadline:
        readable, _, _ = select.select([p.stdout], [], [], 0.2)
        if readable:
            chunk = p.stdout.read1(4096)
            if not chunk:
                break
            output.extend(chunk)
        if not sent and b'Type a character to echo: ' in output:
            p.stdin.write(b'Z')
            p.stdin.flush()
            sent = True
        if sent and not echoed and b'echo: Z' in output:
            echoed = True
        if echoed and b'tick 1\n' in output:
            print('PASS: RV32 boot, UART echo and 100 Hz timer tick')
            break
    else:
        raise RuntimeError('QEMU boot, echo or timer tick timed out')
    if not (echoed and b'tick 1\n' in output):
        raise RuntimeError('QEMU exited before the echo and first tick')
finally:
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
