#!/usr/bin/env python3
"""Analyze candidate radio segments with an experimental ARM Thumb mapping."""
import argparse
import pathlib
import subprocess
import zipfile
from inspect_radio_package import inspect, MEMBER


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    inputs = root/'firmware/radio-analysis-inputs'
    with zipfile.ZipFile(root/'firmware/bip6-4.6.0.3.zip') as archive:
        data = archive.read(MEMBER)
    inventory = inspect(data)
    if inventory['sha256'] != '47c41063ca2eaa1bac730d5ca1b7f5338c43152d83aa173ca5038956b36708c4':
        raise ValueError('candidate mapping is specific to the investigated OTA radio package')
    inputs.mkdir(exist_ok=False)
    mapping = []
    for index, record in enumerate(inventory['candidate_records']):
        start = record['candidate_payload_offset'] + 0x200
        size = record['word_1'] - 0x200
        if size <= 0:
            raise ValueError('image too short for the candidate 512-byte prefix')
        path = inputs/f'{index:02d}-body.bin'
        path.write_bytes(data[start:start+size])
        if index != 3:
            mapping.append(f'{record["word_0"]:x}\t{path}')
    manifest = inputs/'mapping.tsv'
    manifest.write_text('\n'.join(mapping)+'\n')
    projects = root/'firmware/ghidra-radio-repro'
    projects.mkdir(exist_ok=False)
    command = [str(pathlib.Path(args.ghidra).resolve()), str(projects), 'radio',
               '-import', str(inputs/'03-body.bin'), '-loader', 'BinaryLoader',
               '-loader-baseAddr', '0x0209a000', '-processor', 'ARM:LE:32:Cortex',
               '-cspec', 'default', '-scriptPath', str(root/'analysis_scripts'),
               '-preScript', 'SeedRadio.java', str(manifest),
               '-postScript', 'ExportFunctions.java', str(root/'firmware/decompiled/radio-repro'),
               '-analysisTimeoutPerFile', '300', '-log', str(root/'firmware/radio-repro.log')]
    return subprocess.run(command).returncode

if __name__ == '__main__':
    raise SystemExit(main())
