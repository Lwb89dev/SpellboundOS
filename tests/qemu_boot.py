#!/usr/bin/env python3
"""Check guest startup and UART input/output without relying on host timeouts."""
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
    deadline = time.monotonic() + 10
    sent = False
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
        if sent and output.endswith(b'echo: Z'):
            print('PASS: RV32 boot, UART banner and echoed byte')
            break
    else:
        raise RuntimeError('QEMU boot or echo timed out')
    if not (sent and output.endswith(b'echo: Z')):
        raise RuntimeError('QEMU exited or failed to echo')
finally:
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    if p.returncode and not output:
        print('QEMU produced no output', file=sys.stderr)
    if not (sent and output.endswith(b'echo: Z')):
        print(output.decode(errors='replace'), file=sys.stderr)
