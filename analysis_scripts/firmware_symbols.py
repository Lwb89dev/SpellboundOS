#!/usr/bin/env python3
"""Inventory firmware subsystem symbol families from embedded name strings.

Many logging, assertion and registration strings in the main firmware contain
C symbol names. Grouping them by prefix sketches the subsystem structure:
the inter-processor RPC, the audio DSP command set, the Bluetooth host stack,
and the app command handlers.

These are literal strings compiled into the image (log tags and assert
expressions), not disassembled call graphs. A symbol's presence does not prove
the code runs or that the grouping is exhaustive. The tool only reports the
names it can see.
"""
import argparse
import hashlib
import json
import re
import zipfile

FIRMWARE = 'META/firmware_sign.bin'

# family -> (description, byte-regex). Each regex matches whole symbol strings.
FAMILIES = {
    'zrpc_rpmsg': ('rpmsg-lite inter-processor RPC links and channels',
                   rb'\bzrpc[_.][a-z0-9_]+'),
    'audio_dsp_ipc': ('audio DSP inter-processor command set',
                      rb'AUD_IPC_CMD_[A-Z0-9_]+'),
    'bt_host': ('bx_core Bluetooth host stack (GAP/GATT, LE and classic)',
                rb'bx_core_[a-z0-9_]+'),
    'app_cmd_handlers': ('app-layer channel command handlers',
                         rb'app_handle_[a-z_]+_cmd'),
}

# Companion data modules: presence markers for phone-facing features.
COMPANION_MARKERS = {
    'weather': rb'_weather_[a-z_]+',
    'contacts': rb'app_contacts[a-z_]*',
    'world_clock': rb'[a-zA-Z]*[Ww]orld_?[Cc]lock[a-zA-Z]*',
    'music': rb'music_data[a-z_]*',
    'find_device': rb'find[_ ]?device[a-z_]*',
}


def inventory(data):
    families = {}
    for name, (desc, pattern) in FAMILIES.items():
        symbols = sorted({m.group().decode('latin1')
                          for m in re.finditer(pattern, data)})
        families[name] = {'description': desc, 'count': len(symbols),
                          'symbols': symbols}
    companion = {}
    for name, pattern in COMPANION_MARKERS.items():
        symbols = sorted({m.group().decode('latin1').strip()
                          for m in re.finditer(pattern, data)})
        companion[name] = {'present': bool(symbols), 'count': len(symbols),
                           'examples': symbols[:8]}
    return {'families': families, 'companion_modules': companion}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--member', default=FIRMWARE)
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(args.member)
    result = inventory(data)
    result['member'] = args.member
    result['member_size'] = len(data)
    result['member_sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
