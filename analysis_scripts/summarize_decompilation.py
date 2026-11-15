#!/usr/bin/env python3
"""Summarize local Ghidra exports; completion does not mean semantic correctness."""
import csv
import hashlib
import json
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = [('boot','bootloader-from-0x400.bin'),('recovery','recovery_sign.bin'),
           ('sensor','sensorhub@mhs003_sign.bin'),('factory','fct_test_sign.bin'),
           ('main','firmware_sign.bin'),('ramdump','ramdump.bin'),('radio',None)]
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
    if image is None:
        with zipfile.ZipFile(ROOT/'firmware/bip6-4.6.0.3.zip') as archive:
            data = archive.read('META/extfw/pamir/rtl8763_pack.bin')
    else:
        input_path = ROOT/'firmware/bulk-inputs'/image
        if not input_path.exists(): input_path = ROOT/'firmware/components'/image
        data = input_path.read_bytes()
    log = (ROOT/f'firmware/bulk-{name}.log').read_text()
    continued_path = ROOT/f'firmware/bulk-{name}-continued.log'
    continued_log = continued_path.read_text() if continued_path.exists() else None
    final_log = continued_log if continued_log is not None else log
    results.append({'target': name, 'profile': 'ARM:LE:32:Cortex' if name == 'radio' else 'RISCV:LE:32:AndeStar_v5', 'input_sha256': hashlib.sha256(data).hexdigest(),
                    'input_bytes': len(data), 'recognized_functions': len(rows),
                    'decompiler_completed': sum(x['status']=='completed' for x in rows),
                    'functions_with_warning_comments': warnings,
                    'functions_with_generic_custom_ops': custom,
                    'import_succeeded': 'REPORT: Import succeeded' in log,
                    'initial_analysis_timeout_reported': 'analysis timed out' in log.lower() or 'analysis timeout' in log.lower(),
                    'continued_analysis': continued_log is not None,
                    'final_analysis_timeout_reported': 'analysis timed out' in final_log.lower(),
                    'final_analysis_succeeded_reported': 'REPORT: Analysis succeeded' in final_log})
print(json.dumps({'meaning': 'Counts refer to inferred functions, not complete byte or behavioral coverage.',
                  'targets': results}, indent=2))
