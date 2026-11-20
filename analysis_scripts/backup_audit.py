"""Check local backup bytes against a previously recorded inventory."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

KINDS = {'stock_ota', 'device_readback', 'device_export'}


def audit(directory, inventory):
    """Compare exact lengths and SHA-256 values. Return only artifact counts."""
    if not isinstance(inventory, dict) or inventory.get('schema') != 1:
        raise ValueError('unsupported inventory schema')
    entries = inventory.get('artifacts')
    if not isinstance(entries, list) or not entries:
        raise ValueError('inventory must contain artifacts')
    names = set()
    verified = Counter()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f'invalid artifact entry {index}')
        name, kind = entry.get('file'), entry.get('kind')
        size, digest = entry.get('size'), entry.get('sha256')
        if (not isinstance(name, str) or name in ('', '.', '..') or
                Path(name).name != name or '\\' in name or '\0' in name or name in names):
            raise ValueError(f'invalid or duplicate artifact name in entry {index}')
        if (not isinstance(kind, str) or kind not in KINDS or type(size) is not int or
                size <= 0 or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError(f'invalid artifact metadata in entry {index}')
        names.add(name)
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'missing or non-regular file for entry {index}')
        with path.open('rb') as source:
            if source.seek(0, 2) != size:
                raise ValueError(f'length mismatch for entry {index}')
            source.seek(0)
            if hashlib.file_digest(source, 'sha256').hexdigest() != digest:
                raise ValueError(f'SHA-256 mismatch for entry {index}')
        verified[kind] += 1
    return {'integrity_verified': True, 'verified_artifacts': dict(verified),
            'device_restore_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    try:
        report = audit(args.directory, json.loads(args.inventory.read_bytes()))
    except (ValueError, OSError) as error:
        parser.exit(2, f'Cannot audit backup: {error}\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
