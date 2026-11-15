#!/usr/bin/env python3
"""Map the native API surface declared by the shipped ZeppOS DeviceRuntimeCore.

This inspector reads ``META/js_apps/framework.js`` from the OTA archive without
executing it. It records the runtime banner, the native module methods the
runtime calls (``hmApp.*`` etc.), the ``device:os.*`` permission namespaces, the
wrapped BLE master-role surface (``ble.*``), the framed message-protocol sizes,
and the message header field layout parsed from ``getProtocolHeader``.

These are literal static observations of the vendor runtime's own call sites and
buffer reads, not a validated implementation. Names are kept as the minified
file spells them; only module objects and the BLE wrapper are unmangled because
the runtime references native globals by their real names.
"""
import argparse
import hashlib
import json
import re
import zipfile

FRAMEWORK = 'META/js_apps/framework.js'

# Native global modules the runtime calls into. hmTimer is exposed as `timer`.
NATIVE_MODULES = ('hmApp', 'hmBle', 'hmUI', 'hmSetting', 'hmFS', 'hmSensor',
                  'hmMedia', 'hmCrypto', 'hmSysApi', 'hmVAD')

BANNER_FIELDS = ('project', 'version', 'api_level', 'build-date', 'commit')


def parse_banner(text):
    """Return the leading block-comment metadata as a dict."""
    banner = {}
    head = text[:600]
    for field in BANNER_FIELDS:
        match = re.search(rf'\*\s*{re.escape(field)}\s+(\S.*?)\s*$', head, re.M)
        if match:
            banner[field] = match.group(1)
    return banner


def module_methods(text, module):
    """Sorted unique method names invoked as ``module.<name>``."""
    return sorted(set(re.findall(rf'\b{re.escape(module)}\.([A-Za-z_]\w*)', text)))


def permission_namespaces(text):
    """Sorted ``device:os.*`` and ``data:os.*`` capability strings."""
    return sorted(set(re.findall(r'"((?:device|data):os\.[A-Za-z_.]+)"', text)))


def ble_wrapper_methods(text):
    """Sorted method names called on the wrapped BLE object (``ble.<name>``)."""
    return sorted(set(re.findall(r'\bble\.([A-Za-z_]\w*)', text)))


def message_protocol(text):
    """Framed-message sizes and the parsed header field layout.

    ``getProtocolHeader`` reads fixed-width little-endian fields in order; this
    recovers each field's name, byte width and offset from that read sequence.
    """
    sizes = {}
    for key, name in (('messageSize', 'message_size'),
                      ('messagePayloadSize', 'payload_size'),
                      ('messageHeaderSize', 'header_size')):
        match = re.search(rf'get {key}\(\)\{{return (\d+)\}}', text)
        if match:
            sizes[name] = int(match.group(1))

    header = []
    body = re.search(r'getProtocolHeader\(e\)\{(.*?)\}encode\(', text)
    if body:
        offset = 0
        widths = {'readUInt8': 1, 'readUInt16LE': 2, 'readUInt32LE': 4}
        # Pair each field read with the name it is assigned to in the returned
        # object literal, preserving read order.
        reads = re.findall(r'(?:const|var)\s+(\w+)\s*=\s*t\.(readUInt\d+(?:LE)?)\(',
                           body.group(1))
        returned = re.search(r'return[^{]*\{([^}]*)\}', body.group(1))
        name_by_var = {}
        if returned:
            for field, var in re.findall(r'(\w+):(\w+)', returned.group(1)):
                name_by_var[var] = field
        for var, read in reads:
            width = widths[read]
            header.append({'field': name_by_var.get(var, var), 'offset': offset,
                           'bytes': width, 'read': read})
            offset += width
    return {'sizes': sizes, 'header': header}


def protocol_constants(text):
    """Flag/type/version constants and the invoke/close predicates."""
    match = re.search(r'const U=(\d+),M=(\d+),G=(\d+),k=(\d+),W=(\d+);', text)
    if not match:
        return {}
    u, m, g, k, w = (int(x) for x in match.groups())
    return {'flag_invoke': m, 'type_invoke': g, 'type_close': k, 'version': w,
            'is_invoke_protocol1': {'flag': m, 'type': g, 'version': w},
            'is_close_protocol1': {'flag': m, 'type': k, 'version': w}}


def inspect(text):
    return {
        'banner': parse_banner(text),
        'native_modules': {m: module_methods(text, m) for m in NATIVE_MODULES},
        'permission_namespaces': permission_namespaces(text),
        'ble_wrapper_methods': ble_wrapper_methods(text),
        'message_protocol': message_protocol(text),
        'protocol_constants': protocol_constants(text),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(FRAMEWORK)
    result = inspect(data.decode('utf-8', 'replace'))
    result['member'] = FRAMEWORK
    result['size'] = len(data)
    result['sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
