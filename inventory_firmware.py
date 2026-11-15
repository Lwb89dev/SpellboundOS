#!/usr/bin/env python3
"""Produce a reproducible, static inventory of selected OTA binaries.

String hits are clues about bundled code, not proof of fitted hardware or drivers.
Offsets refer to uncompressed members, not to addresses in device memory.
"""
import argparse
import hashlib
import json
import re
import zipfile

MEMBERS = (
    'META/firmware_sign.bin', 'META/bootloader_sign.bin',
    'META/extfw/recovery_sign.bin', 'META/extfw/sensorhub@mhs003_sign.bin',
)
PATTERNS = {
    'board_and_os': r'board_mhs003|MHS003_A[123]|freertos/portable/GCC/mhs003',
    'touch': r'ztw622|dev_touch|drv_touch',
    'ambient_light': r'stk31e60|drv_als',
    'motion': r'lsm6dso|bmi2xx|akm09918|mmc5603',
    'power': r'cw6305|drv_pmic|dev_pmic|drv_charger|dev_charger',
    'display': r'drv_display|dev_display|display_panel|hal_display|dev_lcd',
    'memory': r'drv_flash|dev_flash|drv_nand|dev_nand|drv_psram|dev_psram',
    'communications': r'rtl8763|mhs_i2c|mhs_uart|sens_i2c|sens_spi',
    'boot_integrity': r'firmware secure verify failed|sign verify not pass|archive verify failed|found firmware signed header|verify_image',
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive')
    p.add_argument('--output', required=True)
    args = p.parse_args()
    patterns = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
    with open(args.archive, 'rb') as src:
        archive_hash = hashlib.file_digest(src, 'sha256').hexdigest()
    result = {'archive_sha256': archive_hash, 'members': {}}
    with zipfile.ZipFile(args.archive) as archive:
        for name in MEMBERS:
            data = archive.read(name)
            hits = {category: [] for category in patterns}
            for match in re.finditer(rb'[\x20-\x7e]{4,}', data):
                value = match.group().decode('ascii')
                for category, pattern in patterns.items():
                    if pattern.search(value):
                        hits[category].append({'offset': match.start(), 'text': value})
            result['members'][name] = {'sha256': hashlib.sha256(data).hexdigest(),
                                       'size': len(data), 'hits': hits}
    with open(args.output, 'w', encoding='utf-8') as out:
        json.dump(result, out, indent=2, ensure_ascii=False)
        out.write('\n')


if __name__ == '__main__':
    main()
