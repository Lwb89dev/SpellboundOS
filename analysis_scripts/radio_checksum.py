#!/usr/bin/env python3
"""Independent offline checksum model for the candidate radio transport routine."""

def checksum(data, seed=0):
    value = seed & 0xffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xa001 if value & 1 else 0)
    return value
