"""End-to-end Python <-> C interoperability tests for SpellboundFit v1 protocol & Roadstr."""
import os
import subprocess
import tempfile
import unittest

from companion.protocol import (
    CallState,
    MsgType,
    NavManeuver,
    StreamDecoder,
    decode_notify_action,
    decode_telemetry,
    encode_call_state,
    encode_nav_clear,
    encode_notify_dismiss,
    encode_notify_post,
    encode_ping,
    encode_time_sync,
)
from companion.roadstr import parse_roadstr_notification

C_BRIDGE_SRC = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
static inline uint32_t irq_save(void) { return 0; }
static inline void irq_restore(uint32_t p) { (void)p; }

#include "notify.c"
#include "proto.c"

static int stdout_send(const uint8_t *data, uint32_t len, void *ctx) {
    (void)ctx;
    fwrite(data, 1, len, stdout);
    return 0;
}

int main(void) {
    notify_reset();
    struct proto_decoder dec;
    proto_decoder_init(&dec);
    struct proto_frame frame;
    struct proto_tx tx = {.send = stdout_send, .ctx = NULL};

    int64_t synced_sec = 0;
    int16_t synced_tz = 0;
    int ch;
    while ((ch = getchar()) != EOF) {
        if (proto_decoder_feed(&dec, (uint8_t)ch, &frame) == 1) {
            (void)proto_dispatch(&frame, &tx, &synced_sec, &synced_tz);
        }
    }

    /* Verify watch state populated from Python frames and emit watch -> phone frames. */
    struct notification n;
    struct nav_state nav;
    struct call_info ci;
    if (synced_sec != 1795255200LL || synced_tz != 60) return 2;
    if (!notify_find(42, &n) || strcmp(n.app, "WhatsApp") != 0 || n.action_count != 2) return 3;
    if (!nav_get(&nav) || nav.maneuver != NAV_ROUNDABOUT || nav.roundabout_exit != 2 ||
        nav.distance_m != 1200 || nav.eta_min != 14) return 4;
    if (!call_get(&ci) || ci.state != CALL_RINGING || strcmp(ci.caller, "Luca") != 0) return 5;

    uint8_t out[64];
    int n1 = proto_encode_notify_action(out, sizeof out, 90, 42, 1);
    if (n1 > 0) fwrite(out, 1, (size_t)n1, stdout);
    int n2 = proto_encode_telemetry(out, sizeof out, 91, 84, true, 6120, 74, 3600);
    if (n2 > 0) fwrite(out, 1, (size_t)n2, stdout);
    return 0;
}
"""


class CompanionProtoHostTest(unittest.TestCase):
    def test_roadstr_parser_english_and_italian(self):
        inst = parse_roadstr_notification(
            'Roadstr', 'Turn left in 250 m onto Via Emilia • ETA 8 min'
        )
        self.assertIsNotNone(inst)
        self.assertEqual(inst.maneuver, NavManeuver.LEFT)
        self.assertEqual(inst.distance_m, 250)
        self.assertEqual(inst.eta_min, 8)
        self.assertEqual(inst.street, 'Via Emilia')

        inst_it = parse_roadstr_notification(
            'Rotonda tra 1,2 km', 'Prendi la 2a uscita su Corso Italia (Arrivo 14 min)'
        )
        self.assertIsNotNone(inst_it)
        self.assertEqual(inst_it.maneuver, NavManeuver.ROUNDABOUT)
        self.assertEqual(inst_it.roundabout_exit, 2)
        self.assertEqual(inst_it.distance_m, 1200)
        self.assertEqual(inst_it.eta_min, 14)
        self.assertEqual(inst_it.street, 'Corso Italia')

        arr = parse_roadstr_notification('Roadstr', 'You have arrived at destination')
        self.assertIsNotNone(arr)
        self.assertEqual(arr.maneuver, NavManeuver.ARRIVE)

        self.assertIsNone(parse_roadstr_notification('Weather', 'Sunny 22C'))

    def test_python_to_c_kernel_wire_interop(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            src_path = os.path.join(directory, 'bridge.c')
            bin_path = os.path.join(directory, 'bridge')
            with open(src_path, 'w', encoding='utf-8') as f:
                f.write(C_BRIDGE_SRC)

            comp = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'), src_path, '-o', bin_path],
                capture_output=True, text=True)
            self.assertEqual(comp.returncode, 0, comp.stderr)

            nav = parse_roadstr_notification(
                'Rotonda tra 1,2 km', 'Prendi la 2a uscita su Corso Italia (Arrivo 14 min)'
            )
            self.assertIsNotNone(nav)

            wire_in = b''.join([
                b'\x00\xFFnoise',
                encode_ping(1),
                encode_time_sync(2, 1795255200, 60),
                encode_notify_post(3, 42, 'WhatsApp', 'Anna', 'Ci vediamo alle 18?',
                                   timestamp_sec=1795255200, actions=['OK', 'Chiamo dopo']),
                nav.to_frame(4),
                encode_call_state(5, CallState.RINGING, 'Luca', '+39340111222'),
            ])

            run = subprocess.run([bin_path], input=wire_in, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr.decode('utf-8', 'replace'))

            dec = StreamDecoder()
            frames = dec.feed(run.stdout)
            self.assertEqual(dec.crc_errors, 0)
            self.assertEqual(dec.framing_errors, 0)
            # Expect: PONG(1), ACK(2), ACK(3), ACK(4), ACK(5), NOTIFY_ACTION(90), TELEMETRY(91)
            self.assertEqual([f.msg_type for f in frames], [
                MsgType.PONG, MsgType.ACK, MsgType.ACK, MsgType.ACK, MsgType.ACK,
                MsgType.NOTIFY_ACTION, MsgType.TELEMETRY,
            ])
            act = decode_notify_action(frames[5].payload)
            self.assertEqual((act.notif_id, act.action_index), (42, 1))
            tel = decode_telemetry(frames[6].payload)
            self.assertEqual((tel.battery_pct, tel.charging, tel.steps, tel.hr_bpm, tel.uptime_sec),
                             (84, True, 6120, 74, 3600))

    def test_stream_decoder_corruption_recovery(self):
        good = encode_notify_dismiss(7, 123)
        bad = bytearray(encode_nav_clear(8))
        bad[-1] ^= 0xFF
        dec = StreamDecoder()
        out = dec.feed(bytes(bad) + good)
        self.assertEqual(dec.crc_errors, 1)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].msg_type, MsgType.NOTIFY_DISMISS)
        self.assertEqual(out[0].seq, 7)


if __name__ == '__main__':
    unittest.main()
