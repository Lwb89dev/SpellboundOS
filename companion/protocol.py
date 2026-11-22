"""SpellboundFit v1 binary framed link protocol (companion side).

Wire format (matches kernel/proto.h and kernel/proto.c byte-for-byte):
  [0..1]   Magic: b'SB' (0x53, 0x42)
  [2]      Version: 1
  [3]      Message type (MsgType)
  [4..5]   Sequence number (uint16 LE)
  [6..7]   Payload length (uint16 LE, <= 256)
  [8..8+N) Payload bytes
  [8+N..12+N) IEEE 802.3 CRC-32 (uint32 LE) over header + payload
"""
from dataclasses import dataclass, field
from enum import IntEnum
import struct
import zlib

PROTO_MAGIC = b'SB'
PROTO_VERSION = 1
PROTO_MAX_PAYLOAD = 256


class MsgType(IntEnum):
    PING = 0x01
    PONG = 0x02
    ACK = 0x03
    NACK = 0x04
    TIME_SYNC = 0x10
    NOTIFY_POST = 0x20
    NOTIFY_DISMISS = 0x21
    NOTIFY_ACTION = 0x22
    NAV_UPDATE = 0x30
    NAV_CLEAR = 0x31
    CALL_STATE = 0x40
    TELEMETRY = 0x50


class NavManeuver(IntEnum):
    NONE = 0
    STRAIGHT = 1
    SLIGHT_LEFT = 2
    LEFT = 3
    SHARP_LEFT = 4
    SLIGHT_RIGHT = 5
    RIGHT = 6
    SHARP_RIGHT = 7
    UTURN = 8
    ROUNDABOUT = 9
    ARRIVE = 10


class CallState(IntEnum):
    IDLE = 0
    RINGING = 1
    ACTIVE = 2


@dataclass
class Frame:
    msg_type: int
    seq: int
    payload: bytes = b''
    version: int = PROTO_VERSION


@dataclass
class Telemetry:
    battery_pct: int
    charging: bool
    steps: int
    hr_bpm: int
    uptime_sec: int


@dataclass
class NotifyActionEvent:
    notif_id: int
    action_index: int


def _pack_len_str(text: str, max_bytes: int) -> bytes:
    raw = text.encode('utf-8')[:max_bytes]
    return bytes([len(raw)]) + raw


def encode_frame(msg_type: int, seq: int, payload: bytes = b'') -> bytes:
    if len(payload) > PROTO_MAX_PAYLOAD:
        raise ValueError(f'payload too large: {len(payload)}')
    header = struct.pack('<2sBBHH', PROTO_MAGIC, PROTO_VERSION, int(msg_type),
                         seq & 0xFFFF, len(payload))
    body = header + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack('<I', crc)


def encode_ping(seq: int) -> bytes:
    return encode_frame(MsgType.PING, seq)


def encode_time_sync(seq: int, unix_sec: int, tz_offset_min: int = 0) -> bytes:
    payload = struct.pack('<qh', unix_sec, tz_offset_min)
    return encode_frame(MsgType.TIME_SYNC, seq, payload)


def encode_notify_post(seq: int, notif_id: int, app: str, title: str, body: str,
                       timestamp_sec: int = 0, actions: list[str] | None = None) -> bytes:
    acts = (actions or [])[:4]
    parts = [
        struct.pack('<II', notif_id & 0xFFFFFFFF, timestamp_sec & 0xFFFFFFFF),
        _pack_len_str(app, 23),
        _pack_len_str(title, 47),
        _pack_len_str(body, 127),
        bytes([len(acts)]),
    ]
    for a in acts:
        parts.append(_pack_len_str(a, 19))
    return encode_frame(MsgType.NOTIFY_POST, seq, b''.join(parts))


def encode_notify_dismiss(seq: int, notif_id: int) -> bytes:
    return encode_frame(MsgType.NOTIFY_DISMISS, seq, struct.pack('<I', notif_id & 0xFFFFFFFF))


def encode_nav_update(seq: int, maneuver: NavManeuver, distance_m: int, eta_min: int,
                      street: str, next_street: str = '', roundabout_exit: int = 0) -> bytes:
    payload = (
        struct.pack('<BBIH', int(maneuver), roundabout_exit & 0xFF,
                    distance_m & 0xFFFFFFFF, eta_min & 0xFFFF)
        + _pack_len_str(street, 63)
        + _pack_len_str(next_street, 47)
    )
    return encode_frame(MsgType.NAV_UPDATE, seq, payload)


def encode_nav_clear(seq: int) -> bytes:
    return encode_frame(MsgType.NAV_CLEAR, seq)


def encode_call_state(seq: int, state: CallState, caller: str = '', number: str = '') -> bytes:
    payload = (
        bytes([int(state)])
        + _pack_len_str(caller, 47)
        + _pack_len_str(number, 23)
    )
    return encode_frame(MsgType.CALL_STATE, seq, payload)


def decode_telemetry(payload: bytes) -> Telemetry:
    if len(payload) < 12:
        raise ValueError('telemetry payload too short')
    bat, chg, steps, hr, up = struct.unpack('<BBIHI', payload[:12])
    return Telemetry(battery_pct=bat, charging=bool(chg), steps=steps, hr_bpm=hr, uptime_sec=up)


def decode_notify_action(payload: bytes) -> NotifyActionEvent:
    if len(payload) < 5:
        raise ValueError('notify action payload too short')
    nid, idx = struct.unpack('<IB', payload[:5])
    return NotifyActionEvent(notif_id=nid, action_index=idx)


class StreamDecoder:
    """Incremental byte-stream frame decoder matching kernel/proto.c."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.crc_errors = 0
        self.framing_errors = 0

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        frames: list[Frame] = []
        while True:
            idx = self._buf.find(PROTO_MAGIC)
            if idx < 0:
                if self._buf and self._buf[-1:] == b'S':
                    self._buf = bytearray(b'S')
                else:
                    self._buf.clear()
                break
            if idx > 0:
                del self._buf[:idx]
            if len(self._buf) < 8:
                break
            _, ver, mtype, seq, plen = struct.unpack('<2sBBHH', self._buf[:8])
            if ver != PROTO_VERSION or plen > PROTO_MAX_PAYLOAD:
                self.framing_errors += 1
                del self._buf[:2]
                continue
            total = 8 + plen + 4
            if len(self._buf) < total:
                break
            raw = bytes(self._buf[:total])
            expected_crc, = struct.unpack('<I', raw[-4:])
            calc_crc = zlib.crc32(raw[:-4]) & 0xFFFFFFFF
            if calc_crc != expected_crc:
                self.crc_errors += 1
                del self._buf[:2]
                continue
            frames.append(Frame(msg_type=mtype, seq=seq, payload=raw[8:-4], version=ver))
            del self._buf[:total]
        return frames
