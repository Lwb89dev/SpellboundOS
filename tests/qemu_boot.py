#!/usr/bin/env python3
"""Check guest startup, interrupt-driven UART echo, scheduling and timer ticks."""
import select
import subprocess
import sys
import time

qemu, elf = sys.argv[1:]
p = subprocess.Popen([qemu, '-machine', 'virt', '-bios', 'none', '-nographic',
                      '-monitor', 'none', '-kernel', elf], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
output = bytearray()
bursts = (b'burst-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ',
          b'wrap-9876543210-abcdefghijklmnopqrstuvwxyz')
try:
    deadline = time.monotonic() + 15
    sent = False
    echoed = False
    sent_bursts = received_bursts = 0
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
            if received_bursts < sent_bursts and bursts[received_bursts] in output:
                received_bursts += 1
            if (received_bursts == len(bursts) and b'tick 2\n' in output
                    and b'console: RX interrupts enabled' in output):
                print('PASS: RV32 boot, UART RX interrupts and burst echo, scheduler and timer')
                break
            if sent_bursts == received_bursts and sent_bursts < len(bursts):
                p.stdin.write(bursts[sent_bursts])
                p.stdin.flush()
                sent_bursts += 1
    else:
        raise RuntimeError('QEMU boot test timed out: ' + repr(output))
    done = (received_bursts == len(bursts) and b'tick 2\n' in output
            and b'console: RX interrupts enabled' in output)
    if not done:
        raise RuntimeError('QEMU exited before completing the boot test: ' + repr(output))
finally:
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
