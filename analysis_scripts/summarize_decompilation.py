#!/usr/bin/env python3
"""Summarize local Ghidra exports; completion does not mean semantic correctness."""
import csv
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = [('boot','bootloader-from-0x400.bin'),('recovery','recovery_sign.bin'),
           ('sensor','sensorhub@mhs003_sign.bin'),('factory','fct_test_sign.bin'),
           ('main','firmware_sign.bin'),('ramdump','ramdump.bin')]
results = []
for name, image in TARGETS:
    folder = ROOT/'firmware/decompiled'/name
    with (folder/'functions.tsv').open() as source:
        rows = list(csv.DictReader(source, delimiter='\t'))
    warnings = 0
    custom = 0
    for path in folder.glob('*.c'):
        content = path.read_text()
        warnings += int('WARNING:' in content)
        custom += int('custom0' in content or 'custom1' in content or 'custom2' in content or 'custom3' in content)
    input_path = ROOT/'firmware/bulk-inputs'/image
    if not input_path.exists(): input_path = ROOT/'firmware/components'/image
    data = input_path.read_bytes()
    log = (ROOT/f'firmware/bulk-{name}.log').read_text()
    results.append({'target': name, 'input_sha256': hashlib.sha256(data).hexdigest(),
                    'input_bytes': len(data), 'recognized_functions': len(rows),
                    'decompiler_completed': sum(x['status']=='completed' for x in rows),
                    'functions_with_warning_comments': warnings,
                    'functions_with_generic_custom_ops': custom,
                    'import_succeeded': 'REPORT: Import succeeded' in log,
                    'analysis_timeout_reported': 'analysis timed out' in log.lower() or 'analysis timeout' in log.lower()})
print(json.dumps({'profile': 'RISCV:LE:32:AndeStar_v5',
                  'meaning': 'Counts refer to inferred functions, not complete byte or behavioral coverage.',
                  'targets': results}, indent=2))
