"""Desktop SpellboundOS Watch Simulator driving the real C kernel via ctypes."""
import ctypes
import os
import struct
import subprocess
import zlib

from companion.protocol import (
    CallState,
    Frame,
    StreamDecoder,
    encode_call_state,
    encode_nav_clear,
    encode_notify_post,
    encode_ping,
    encode_time_sync,
)
from companion.roadstr import parse_roadstr_notification
from companion.secure_link import SecureSession

# Input key actions (matching kernel/input.h)
KEY_SHORT_CLICK = 3
KEY_LONG_PRESS = 4
KEY_DOUBLE_CLICK = 5

# UI screen IDs (matching kernel/ui.h)
SCREEN_WATCHFACE = 0
SCREEN_NOTIFICATIONS = 1
SCREEN_NAVIGATION = 2
SCREEN_QUICK_SETTINGS = 3
SCREEN_CALL = 4


def _png_chunk(tag: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
    return struct.pack('>I', len(payload)) + tag + payload + struct.pack('>I', crc)


def rgb888_to_png(width: int, height: int, rgb: bytes) -> bytes:
    """Encode an RGB888 buffer into a valid PNG image using stdlib zlib only."""
    rows = bytearray()
    stride = width * 3
    for y in range(height):
        rows.append(0)  # filter type 0 (None)
        rows.extend(rgb[y * stride:(y + 1) * stride])
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(rows), level=6)
    return (
        b'\x89PNG\r\n\x1a\n'
        + _png_chunk(b'IHDR', ihdr)
        + _png_chunk(b'IDAT', idat)
        + _png_chunk(b'IEND', b'')
    )


def build_sim_library(out_so: str | None = None) -> str:
    """Compile companion/sim_host.c + kernel/*.c into a host shared library."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if out_so is None:
        build_dir = os.path.join(root, 'build', 'host')
        os.makedirs(build_dir, exist_ok=True)
        out_so = os.path.join(build_dir, 'libspellbound_sim.so')
    src = os.path.join(root, 'companion', 'sim_host.c')
    cmd = [
        'clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
        '-fPIC', '-shared',
        '-I', os.path.join(root, 'kernel'),
        src, '-o', out_so,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f'Failed to build simulator library:\n{res.stderr}')
    return out_so


class WatchSimulator:
    """High-level Python controller over the compiled C SpellboundOS watch stack."""

    def __init__(self, psk: bytes | None = None, start_unix_sec: int = 1795255200,
                 so_path: str | None = None) -> None:
        self.psk = psk if psk is not None else bytes((0x40 + i) & 0xFF for i in range(32))
        self.so_path = build_sim_library(so_path)
        self.lib = ctypes.CDLL(self.so_path)
        self._bind_signatures()
        self.session = SecureSession(self.psk)
        self.seq = 0

        rc = self.lib.sim_init(self.psk, ctypes.c_uint64(start_unix_sec))
        if rc != 0:
            raise RuntimeError(f'sim_init failed: {rc}')
        self.width = self.lib.sim_width()
        self.height = self.lib.sim_height()

    def _bind_signatures(self) -> None:
        L = self.lib
        L.sim_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
        L.sim_init.restype = ctypes.c_int
        L.sim_width.restype = ctypes.c_int
        L.sim_height.restype = ctypes.c_int
        L.sim_handle_secure_hello.argtypes = [ctypes.c_char_p, ctypes.c_uint32,
                                              ctypes.c_char_p, ctypes.c_char_p]
        L.sim_handle_secure_hello.restype = ctypes.c_int
        L.sim_feed_packet.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        L.sim_feed_packet.restype = ctypes.c_int
        L.sim_pop_out_packet.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        L.sim_pop_out_packet.restype = ctypes.c_int
        L.sim_inject_key.argtypes = [ctypes.c_uint8, ctypes.c_uint16]
        L.sim_inject_touch.argtypes = [ctypes.c_uint8, ctypes.c_int16, ctypes.c_int16]
        L.sim_inject_accel.argtypes = [ctypes.c_int16, ctypes.c_int16, ctypes.c_int16]
        L.sim_inject_als.argtypes = [ctypes.c_uint32]
        L.sim_inject_battery.argtypes = [ctypes.c_uint8, ctypes.c_bool]
        L.sim_inject_hr.argtypes = [ctypes.c_uint16]
        L.sim_set_screen.argtypes = [ctypes.c_uint8]
        L.sim_set_aod.argtypes = [ctypes.c_bool]
        L.sim_step.argtypes = [ctypes.c_uint32]
        L.sim_get_rgb888.argtypes = [ctypes.c_char_p]
        L.sim_shell_exec.argtypes = [ctypes.c_char_p]
        L.sim_shell_exec.restype = ctypes.c_char_p
        L.sim_current_screen.restype = ctypes.c_uint8
        L.sim_brightness.restype = ctypes.c_uint8
        L.sim_steps.restype = ctypes.c_uint32
        L.sim_flushes.restype = ctypes.c_uint32
        L.sim_motor_active.restype = ctypes.c_bool

    def establish_secure_link(self, phone_nonce: bytes | None = None,
                              watch_nonce: bytes | None = None) -> None:
        hello = self.session.build_hello(phone_nonce)
        wn = watch_nonce if watch_nonce is not None else bytes(range(0x80, 0x90))
        ack_buf = ctypes.create_string_buffer(49)
        rc = self.lib.sim_handle_secure_hello(hello, len(hello), wn, ack_buf)
        if rc != 49:
            raise RuntimeError(f'secure_watch_accept_hello failed: {rc}')
        self.session.finish_handshake(ack_buf.raw)

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def send_frame(self, raw_frame: bytes) -> list[Frame]:
        wire = self.session.encrypt(raw_frame) if self.session.established else raw_frame
        rc = self.lib.sim_feed_packet(wire, len(wire))
        if rc < 0:
            raise RuntimeError(f'sim_feed_packet rejected packet: {rc}')
        return self.drain_outbound()

    def drain_outbound(self) -> list[Frame]:
        frames: list[Frame] = []
        buf = ctypes.create_string_buffer(512)
        while True:
            n = self.lib.sim_pop_out_packet(buf, 512)
            if n <= 0:
                break
            pkt = buf.raw[:n]
            pt = self.session.decrypt(pkt) if self.session.established else pkt
            frames.extend(StreamDecoder().feed(pt))
        return frames

    def ping(self) -> list[Frame]:
        return self.send_frame(encode_ping(self._next_seq()))

    def sync_time(self, unix_sec: int, tz_offset_min: int = 60) -> list[Frame]:
        return self.send_frame(encode_time_sync(self._next_seq(), unix_sec, tz_offset_min))

    def send_notification(self, notif_id: int, app: str, title: str, body: str,
                          actions: list[str] | None = None) -> list[Frame]:
        return self.send_frame(encode_notify_post(
            self._next_seq(), notif_id, app, title, body, actions=actions
        ))

    def send_roadstr(self, title: str, body: str) -> list[Frame]:
        inst = parse_roadstr_notification(title, body)
        if inst is None:
            raise ValueError(f'Not a recognizable Roadstr instruction: {title!r} / {body!r}')
        return self.send_frame(inst.to_frame(self._next_seq()))

    def clear_roadstr(self) -> list[Frame]:
        return self.send_frame(encode_nav_clear(self._next_seq()))

    def send_call(self, state: CallState, caller: str = '', number: str = '') -> list[Frame]:
        return self.send_frame(encode_call_state(self._next_seq(), state, caller, number))

    def step(self, delta_ticks: int = 10) -> list[Frame]:
        self.lib.sim_step(delta_ticks)
        return self.drain_outbound()

    def press_key(self, action: int = KEY_SHORT_CLICK, code: int = 0) -> None:
        self.lib.sim_inject_key(action, code)

    def simulate_walk(self, steps_count: int = 5) -> None:
        for _ in range(steps_count):
            self.lib.sim_inject_accel(0, 0, 5600)
            self.lib.sim_step(10)
            self.lib.sim_inject_accel(0, 0, 4096)
            self.lib.sim_step(40)

    def shell(self, command: str) -> str:
        return self.lib.sim_shell_exec(command.encode('utf-8')).decode('utf-8')

    def capture_rgb888(self) -> bytes:
        buf = ctypes.create_string_buffer(self.width * self.height * 3)
        self.lib.sim_get_rgb888(buf)
        return buf.raw

    def save_png(self, path: str) -> None:
        png = rgb888_to_png(self.width, self.height, self.capture_rgb888())
        with open(path, 'wb') as f:
            f.write(png)
