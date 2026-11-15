#!/usr/bin/env python3
"""Classify OTA workload by literal headers and extensions, without executing it."""
import argparse
import collections
import hashlib
import json
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    counts = collections.Counter()
    sizes = collections.Counter()
    binaries, javascript, nested = [], [], []
    with open(args.archive, 'rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    with zipfile.ZipFile(args.archive) as archive:
        for info in archive.infolist():
            if info.is_dir(): continue
            extension = info.filename.rsplit('.', 1)[-1].lower() if '.' in info.filename else '(none)'
            counts[extension] += 1
            sizes[extension] += info.file_size
            if extension not in ('bin', 'js', 'zip'): continue
            data = archive.read(info)
            entry = {'member': info.filename, 'size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            if extension == 'bin':
                kind = ('ELF' if data.startswith(b'\x7fELF') else
                        'RIFF' if data.startswith(b'RIFF') else
                        'LCPU' if data.startswith(b'LCPU') else
                        'HDRZ' if data.startswith(b'HDRZ') or data[4:8] == b'HDRZ' else
                        'GM' if data.startswith(b'GM') else 'unclassified')
                entry.update(header_kind=kind, prefix_hex=data[:16].hex())
                binaries.append(entry)
            elif extension == 'js': javascript.append(entry)
            else: nested.append(entry)
    print(json.dumps({'archive_sha256': digest,
                      'extensions': [{'extension': x, 'count': counts[x], 'uncompressed_bytes': sizes[x]} for x in sorted(counts)],
                      'binary_members': binaries, 'javascript_members': javascript,
                      'nested_archives': nested}, indent=2))

if __name__ == '__main__': main()
