#!/usr/bin/env python3
"""Compare metadata of local broad and startup/ABI-aware targeted C exports."""
import argparse
import hashlib
import json
import pathlib
import re


def metrics(path, address):
    if not path.exists():
        return None
    text = path.read_text()
    code = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    header = re.search(r'\b(?:FUN_ram_|candidate_)' + address + r'\s*\((.*?)\)\s*\{', code, re.S)
    if header is None:
        raise ValueError(f'unrecognized function declaration in {path}')
    parameters = header[1].strip()
    return {'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'source_bytes': len(text.encode()),
            'parameter_count': 0 if parameters in ('void', '') else parameters.count(',') + 1,
            'nonreturn_warning_count': text.count('Subroutine does not return'),
            'stub_result_assignments': len(re.findall(r'=\s*FUN_ram_709462(?:64|6c|7a|94)\(', code)),
            'injected_stub_warning_count': text.count('replaced with injection:'),
            'unreachable_block_warning_count': text.count('Removing unreachable block')}


def analyze(before, after):
    rows = []
    for path in sorted(pathlib.Path(after).glob('*.c')):
        if not re.fullmatch(r'[0-9a-f]{8}', path.stem):
            continue
        rows.append({'address': int(path.stem, 16),
                     'before': metrics(pathlib.Path(before) / ('ram_' + path.name), path.stem),
                     'after': metrics(path, path.stem)})
    return {'functions': rows, 'summary': {
        'targeted_exports': len(rows),
        'with_previous_export': sum(r['before'] is not None for r in rows),
        'before_nonreturn_warnings': sum(r['before']['nonreturn_warning_count'] for r in rows if r['before']),
        'after_nonreturn_warnings': sum(r['after']['nonreturn_warning_count'] for r in rows),
        'before_stub_result_assignments': sum(r['before']['stub_result_assignments'] for r in rows if r['before']),
        'after_stub_result_assignments': sum(r['after']['stub_result_assignments'] for r in rows)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(args.before, args.after), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
