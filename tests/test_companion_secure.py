"""End-to-end Python <-> C encrypted companion session interoperability tests."""
import os
import struct
import subprocess
import tempfile
import unittest

from companion.protocol import MsgType, StreamDecoder, encode_notify_post
from companion.roadstr import parse_roadstr_notification
from companion.secure_link import SecureSession, chacha20_poly1305_seal

C_SECURE_WATCH_SRC = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
static inline uint32_t irq_save(void) { return 0; }
static inline void irq_restore(uint32_t p) { (void)p; }

#include "crypto.c"
#include "secure_link.c"
#include "notify.c"
#include "proto.c"

static struct secure_session g_sess;

static void write_pkt(const uint8_t *buf, uint32_t len) {
    uint8_t hdr[2] = {(uint8_t)(len & 0xFFu), (uint8_t)(len >> 8)};
    fwrite(hdr, 1, 2, stdout);
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}

static int read_pkt(uint8_t *buf, uint32_t cap) {
    uint8_t hdr[2];
    if (fread(hdr, 1, 2, stdin) != 2) return -1;
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8);
    if (len > cap) return -2;
    if (fread(buf, 1, len, stdin) != len) return -3;
    return (int)len;
}

static int enc_send(const uint8_t *data, uint32_t len, void *ctx) {
    (void)ctx;
    uint8_t out[512];
    int n = secure_encrypt(&g_sess, data, len, out, sizeof out);
    if (n <= 0) return -1;
    write_pkt(out, (uint32_t)n);
    return 0;
}

int main(void) {
    uint8_t psk[32], w_nonce[16];
    for (unsigned i = 0; i < 32u; i++) psk[i] = (uint8_t)(0x33u + i);
    for (unsigned i = 0; i < 16u; i++) w_nonce[i] = (uint8_t)(0x90u + i);

    notify_reset();
    secure_session_init(&g_sess, SECURE_ROLE_WATCH, psk);

    uint8_t pkt[512], pt[512], ack[SECURE_HELLO_ACK_LEN];
    int len = read_pkt(pkt, sizeof pkt);
    if (len != SECURE_HELLO_LEN) return 10;
    if (secure_watch_accept_hello(&g_sess, pkt, (size_t)len, w_nonce, ack) != SECURE_HELLO_ACK_LEN) {
        return 11;
    }
    write_pkt(ack, sizeof ack);

    struct proto_decoder dec;
    proto_decoder_init(&dec);
    struct proto_tx tx = {.send = enc_send, .ctx = NULL};

    while ((len = read_pkt(pkt, sizeof pkt)) > 0) {
        int pt_len = secure_decrypt(&g_sess, pkt, (size_t)len, pt, sizeof pt);
        if (pt_len < 0) continue; /* reject replayed/tampered */
        struct proto_frame frame;
        for (int i = 0; i < pt_len; i++) {
            if (proto_decoder_feed(&dec, pt[i], &frame) == 1) {
                (void)proto_dispatch(&frame, &tx, NULL, NULL);
            }
        }
    }

    struct notification n;
    struct nav_state nav;
    if (!notify_find(88, &n) || strcmp(n.title, "Secret") != 0) return 20;
    if (!nav_get(&nav) || nav.maneuver != NAV_LEFT || nav.distance_m != 300) return 21;
    if (g_sess.replay_rejects != 1) return 22;
    return 0;
}
"""


class CompanionSecureLinkTest(unittest.TestCase):
    def test_python_chacha20_poly1305_rfc8439(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex('070000004041424344454647')
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        pt = (b"Ladies and Gentlemen of the class of '99: "
              b"If I could offer you only one tip for the future, sunscreen would be it.")
        ct, tag = chacha20_poly1305_seal(key, nonce, aad, pt)
        self.assertEqual(tag, bytes.fromhex('1ae10b594f09e26a7e902ecbd0600691'))
        self.assertEqual(len(ct), len(pt))

    def test_python_to_c_encrypted_session_interop(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as directory:
            src_path = os.path.join(directory, 'sec_watch.c')
            bin_path = os.path.join(directory, 'sec_watch')
            with open(src_path, 'w', encoding='utf-8') as f:
                f.write(C_SECURE_WATCH_SRC)

            comp = subprocess.run(
                ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-I', os.path.join(root, 'kernel'), src_path, '-o', bin_path],
                capture_output=True, text=True)
            self.assertEqual(comp.returncode, 0, comp.stderr)

            psk = bytes((0x33 + i) & 0xFF for i in range(32))
            phone = SecureSession(psk)

            proc = subprocess.Popen([bin_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            try:
                def send_pkt(data: bytes) -> None:
                    proc.stdin.write(struct.pack('<H', len(data)) + data)
                    proc.stdin.flush()

                def recv_pkt() -> bytes:
                    hdr = proc.stdout.read(2)
                    self.assertEqual(len(hdr), 2)
                    plen, = struct.unpack('<H', hdr)
                    body = proc.stdout.read(plen)
                    self.assertEqual(len(body), plen)
                    return body

                # 1. Handshake
                send_pkt(phone.build_hello(bytes(range(0x10, 0x20))))
                ack = recv_pkt()
                phone.finish_handshake(ack)
                self.assertTrue(phone.established)

                # 2. Send encrypted notification
                f1 = encode_notify_post(1, 88, 'Signal', 'Secret', 'Encrypted payload', actions=['OK'])
                enc1 = phone.encrypt(f1)
                send_pkt(enc1)
                dec1 = StreamDecoder().feed(phone.decrypt(recv_pkt()))
                self.assertEqual(len(dec1), 1)
                self.assertEqual(dec1[0].msg_type, MsgType.ACK)

                # 3. Replay enc1 (watch must silently reject and count replay_rejects == 1)
                send_pkt(enc1)

                # 4. Send encrypted Roadstr nav update
                nav = parse_roadstr_notification('Roadstr', 'Turn left in 300 m onto Via Po')
                self.assertIsNotNone(nav)
                send_pkt(phone.encrypt(nav.to_frame(2)))
                dec2 = StreamDecoder().feed(phone.decrypt(recv_pkt()))
                self.assertEqual(len(dec2), 1)
                self.assertEqual(dec2[0].msg_type, MsgType.ACK)

                proc.stdin.close()
                rc = proc.wait(timeout=5)
                self.assertEqual(rc, 0)
            finally:
                if proc.stdout:
                    proc.stdout.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == '__main__':
    unittest.main()
