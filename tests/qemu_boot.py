#!/usr/bin/env python3
"""Check guest startup, UART echo, the cooperative scheduler and the periodic
timer tick without relying on host timeouts. Requires a system QEMU
(qemu-system-riscv32)."""
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
        scheduled = b'A1\nB1\nA2\nB2\nA3\nB3\n' in output and b'all tasks done' in output
        if echoed and scheduled and b'tick 1\n' in output:
            print('PASS: RV32 boot, UART echo, round-robin scheduler and 100 Hz tick')
            break
    else:
        raise RuntimeError('QEMU boot, echo, scheduler or timer tick timed out')
    done = (echoed and b'A1\nB1\nA2\nB2\nA3\nB3\n' in output
            and b'all tasks done' in output and b'tick 1\n' in output)
    if not done:
        raise RuntimeError('QEMU exited before the echo, scheduler run and first tick')
finally:
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
