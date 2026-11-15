#!/usr/bin/env python3
"""Notification field ownership, reverse messages and private diagnostic checks.

Host only. The optional capture check decrypts in memory and emits allowlisted
metadata/booleans about the deliberately synthetic test. It never emits keys,
counter values, notification IDs, message contents or arbitrary log lines.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import zipfile

if __package__:
    from .application_payloads import Reader, decode_notification, string
    from .native_channel import BASE, MEMBER, uint
    from .sensorhub_memory import StartupMemory
    from .verify_gadgetbridge_channel import KEY, verify
else:
    from application_payloads import Reader, decode_notification, string
    from native_channel import BASE, MEMBER, uint
    from sensorhub_memory import StartupMemory
    from verify_gadgetbridge_channel import KEY, verify

ANDROID_API = 0x70f63e50
API_ROLES = ('initialize', 'initialize_with_options', 'send_action', 'send_text_reply',
             'request_app_logo', 'register_settings', 'register_focus', 'request_message_image')
FIELD_LABELS = {0x70a679f8: 'unique id', 0x70a67a0c: 'category id', 0x70a67a1c: 'event id',
                0x70a67a2c: 'app id', 0x70a67a38: 'title strlen', 0x70a67a4c: 'message strlen',
                0x70a67a60: 'app name strlen', 0x70a67a74: 'message image flags',
                0x70a67a8c: 'phone number', 0x70a67a9c: 'reply', 0x70a67aa8: 'eventflags'}


def named_notification(data):
    raw = decode_notification(data)
    fields = raw['fields']
    return {'identifier': raw['identifier'], 'category_id': raw['kind'], 'event_id': raw['subtype'],
            'app_id': fields[0], 'title': fields[1], 'message': fields[2], 'app_name': fields[3],
            'phone_number': fields[4] if raw['kind'] == 3 else None,
            'reply_available': raw['boolean0'], 'event_flags': raw['optional_byte'],
            'message_image_present': raw['optional_bool'], 'extra_string': raw['optional_string'],
            'ignored_trailing': raw['ignored_trailing']}


def encode_action(action, notification_id=None):
    data = bytes((5, uint(action, 8)))
    if action == 3:
        data += struct.pack('<I', uint(notification_id, 32))
    elif notification_id is not None:
        raise ValueError('native serializer includes an ID only for action 3')
    return data


def decode_action(data):
    reader = Reader(data)
    if reader.integer(1) != 5:
        raise ValueError('expected action opcode 5')
    action = reader.integer(1)
    identifier = reader.integer(4) if action == 3 else None
    return {'action': action, 'identifier': identifier, 'ignored_trailing': reader.remaining()}


def encode_reply(notification_id, text):
    encoded = string(text)
    if len(encoded) - 1 > 32767:
        raise ValueError('host reply limit avoids the native signed-16-bit length overflow')
    return b'\x04' + struct.pack('<I', uint(notification_id, 32)) + encoded


def decode_reply(data):
    reader = Reader(data)
    if reader.integer(1) != 4:
        raise ValueError('expected text-reply opcode 4')
    identifier, text = reader.integer(4), reader.string()
    return {'identifier': identifier, 'text': text, 'ignored_trailing': reader.remaining()}


def decode_reply_result(data):
    reader = Reader(data)
    if reader.integer(1) != 6:
        raise ValueError('expected reply-result opcode 6')
    return {'identifier': reader.integer(4), 'result_raw': reader.integer(1),
            'ignored_trailing': reader.remaining()}


def decode_image_request(data):
    reader = Reader(data)
    opcode = reader.integer(1)
    if opcode not in (0x10, 0x19):
        raise ValueError('expected logo/message-image request')
    app_id = reader.string()
    identifier = reader.integer(4) if opcode == 0x19 else None
    image_format, width, height = reader.integer(1), reader.integer(2), reader.integer(2)
    if not app_id or not 1 <= image_format <= 10 or width == 0 or (opcode == 0x10 and height == 0):
        raise ValueError('invalid image request parameters')
    return {'opcode': opcode, 'app_id': app_id, 'identifier': identifier,
            'format_raw': image_format, 'width': width, 'height': height,
            'ignored_trailing': reader.remaining()}


def decode_logo_response(data):
    reader = Reader(data)
    if reader.integer(1) != 0x11:
        raise ValueError('expected logo-response opcode 17')
    return {'app_id': reader.string(), 'status_raw': reader.integer(1),
            'ignored_trailing': reader.remaining()}


def decode_capabilities(data):
    reader = Reader(data)
    if reader.integer(1) != 2:
        raise ValueError('expected capabilities opcode 2')
    version, maximum = reader.integer(1), reader.integer(2)
    capability_byte = reader.integer(1) if version > 2 else None
    feature_present, feature_bytes = None, b''
    if version > 3:
        feature_present = reader.integer(1)
        if feature_present:
            size = reader.integer(2)
            if len(reader.remaining()) < size:
                raise ValueError('truncated feature blob')
            feature_bytes = reader.data[reader.pos:reader.pos + size]
            reader.pos += size
    flags = tuple(reader.integer(1) for _ in range(4))
    return {'version': version, 'maximum': maximum, 'capability_byte': capability_byte,
            'feature_present': feature_present, 'feature_bytes': feature_bytes,
            'tail_flags': flags, 'ignored_trailing': reader.remaining()}


def diagnostic_capture(text, key_capture):
    keys = set(KEY.findall(key_capture))
    if len(keys) != 1:
        raise ValueError('expected one session key in prior private capture')
    observations = []
    def observe(**transfer):
        if transfer['module_id'] != 0x1e:
            return
        payload = transfer['payload']
        if transfer['direction'] == '>@' and payload[0] == 3:
            notification = named_notification(payload)
            if notification['title'] != b'Spellbound_RE_test':
                return
            observations.append({'kind': 'synthetic_notification', 'encrypted': transfer['encrypted'],
                'payload_size': len(payload), 'category_id': notification['category_id'],
                'event_id': notification['event_id'],
                'expected_fields_match': notification['app_id'] == b'nodomain.freeyourgadget.gadgetbridge'
                    and notification['message'] == b'Notification body' and notification['app_name'] == b'Gadgetbridge',
                'reply_available': notification['reply_available'], 'event_flags': notification['event_flags'],
                'message_image_present': notification['message_image_present'],
                'extra_string_size': len(notification['extra_string'] or b''),
                'trailing_size': len(notification['ignored_trailing'])})
        elif transfer['direction'] == '<@' and payload[0] == 0x10:
            image = decode_image_request(payload)
            if image['app_id'] == b'nodomain.freeyourgadget.gadgetbridge':
                observations.append({'kind': 'app_logo_request', 'format_raw': image['format_raw'],
                                     'width': image['width'], 'height': image['height']})
        elif transfer['direction'] == '>@' and payload[0] == 0x11:
            response = decode_logo_response(payload)
            if response['app_id'] == b'nodomain.freeyourgadget.gadgetbridge':
                observations.append({'kind': 'app_logo_response', 'status_raw': response['status_raw']})
    report = verify('Shared Session Key: ' + next(iter(keys)) + '\n' + text, on_transfer=observe)
    if sum(item['kind'] == 'synthetic_notification' for item in observations) != 1:
        raise ValueError('expected exactly one controlled synthetic notification')
    # No observer contents enter verify()'s public report. This observer emits
    # only known diagnostic booleans and non-personal image dimensions/status.
    return {'transport': report, 'observations': observations,
            'logo_transfer_finished_in_client_log': 'Finished sending notification://logo?app_id=nodomain.freeyourgadget.gadgetbridge' in text,
            'display_observed': False, 'watch_action_observed': False, 'watch_text_reply_observed': False}


def roadstr_evidence(root):
    """Read only the selected public notification adapter/policy source files."""
    prefix = Path('android/app/src/main/kotlin/app/roadstr/service')
    policy_path = prefix / 'notifications/NativeNavigationNotificationPolicy.kt'
    service_path = prefix / 'navigation/NativeNavigationForegroundService.kt'
    policy, service = (root / policy_path).read_text(), (root / service_path).read_text()
    channel = re.search(r'const val CHANNEL_ID = "([a-z_]+)"', policy)
    identifier = re.search(r'const val NOTIFICATION_ID = (\d+)', policy)
    interval = re.search(r'const val MIN_INTERVAL_MILLIS = ([0-9_]+)L', policy)
    mapping = bool(re.search(r'NativeNavigationNotification\(title\s*=\s*instruction,\s*body\s*=\s*distance\)', policy)
                   and '.setContentTitle(update.title)' in service and '.setContentText(update.body)' in service)
    if not channel or not identifier or not interval or not mapping:
        raise ValueError('Roadstr source no longer matches the reviewed notification surface')
    commit = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True).stdout.strip()
    state = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--', str(policy_path), str(service_path)],
                           capture_output=True, text=True, check=True).stdout
    return {'git_head': commit, 'selected_files_clean': not state.strip(),
            'source_sha256': {str(path): hashlib.sha256((root / path).read_bytes()).hexdigest()
                              for path in (policy_path, service_path)},
            'channel_id': channel[1], 'notification_id': int(identifier[1]),
            'minimum_distance_update_interval_ms': int(interval[1].replace('_', '')),
            'title_source': 'instruction', 'body_source': 'distance',
            'native_canary_scope': 'source adapter; active installed build and permissions not observed',
            'bridge_status': 'candidate Android notification input; no Roadstr/watch integration executed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    parser.add_argument('--capture', type=Path)
    parser.add_argument('--key-capture', type=Path)
    parser.add_argument('--roadstr-root', type=Path)
    args = parser.parse_args()
    if bool(args.capture) != bool(args.key_capture):
        parser.error('--capture and --key-capture must be supplied together')
    try:
        with zipfile.ZipFile(args.archive) as archive:
            image = archive.read(MEMBER)
        memory = StartupMemory(image, BASE, 0x270, 4, 0x2a0, 2)
        api = struct.unpack('<8I', memory.read(ANDROID_API, 32))
        labels = {}
        for address, prefix in FIELD_LABELS.items():
            text = memory.string(address)
            if not text.startswith(prefix + ':'):
                raise ValueError('unexpected native field label')
            labels[prefix] = {'address': address, 'sha256': hashlib.sha256(text.encode()).hexdigest()}
        addresses = ['70388dce', '7038820c', '7038866c', '70388468', '703888ac', '70388798',
                     '70388296', '70279f1a', '70279fa8', '704d6a5e', '704d6aaa', '703d06b6', '703d0ede', '7036ccf0']
        sources = {f'runtime-android-notification/{address}.c': hashlib.sha256(
            (args.decompiled / 'runtime-android-notification' / f'{address}.c').read_bytes()).hexdigest()
            for address in addresses}
        for directory, address in [('runtime-notification-actions', '70388088'),
                                   ('runtime-notification-actions', '7038a0dc'),
                                   ('runtime-service-dispatch', '7038946a')]:
            sources[f'{directory}/{address}.c'] = hashlib.sha256((args.decompiled / directory / f'{address}.c').read_bytes()).hexdigest()
        report = {'member': MEMBER, 'member_sha256': hashlib.sha256(image).hexdigest(),
                  'android_api_table': {'address': ANDROID_API, 'callbacks': dict(zip(API_ROLES, api))},
                  'field_label_evidence': labels, 'source_sha256': sources,
                  'reviewed_action_roles': {'1': 'call UI hangup', '2': 'call UI ignore', '3': 'carries notification ID; detailed action semantics unverified'},
                  'synthetic_vectors': {'reply': encode_reply(0x12345678, b'OK').hex(),
                    'action_without_id': encode_action(2).hex(), 'action_with_id': encode_action(3, 0x12345678).hex()},
                  'scope': 'native serializers and selected parsers; no SMS or call action executed'}
        if args.capture:
            raw, key_raw = args.capture.read_bytes(), args.key_capture.read_bytes()
            report['diagnostic_capture'] = diagnostic_capture(raw.decode(), key_raw.decode())
            report['capture_sha256'] = hashlib.sha256(raw).hexdigest()
            report['key_source_capture_sha256'] = hashlib.sha256(key_raw).hexdigest()
            capabilities = []
            def observe_capabilities(**transfer):
                if transfer['module_id'] == 0x1e and transfer['direction'] == '<@' and transfer['payload'][0] == 2:
                    value = decode_capabilities(transfer['payload'])
                    capabilities.append({name: value[name] for name in ('version', 'maximum', 'capability_byte', 'feature_present', 'tail_flags')}
                                        | {'feature_blob_size': len(value['feature_bytes'])})
            verify(key_raw.decode(), on_transfer=observe_capabilities)
            report['prior_session_notification_capabilities'] = capabilities
        if args.roadstr_root:
            report['roadstr_source_evidence'] = roadstr_evidence(args.roadstr_root)
    except (OSError, ValueError, KeyError, ImportError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        parser.exit(2, f'Cannot inspect notification protocol: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
