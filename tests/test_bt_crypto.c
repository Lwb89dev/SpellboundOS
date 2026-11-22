/* Host unit tests for RTL8763 HCI framing, RFC crypto primitives and secure_link. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/drivers/rtl8763.c"
#include "../kernel/crypto.c"
#include "../kernel/secure_link.c"

static void test_rtl8763(void) {
    /* Verified CRC16/MODBUS check value from analysis/MAIN_BT_HCI_CRC.md */
    const uint8_t check[9] = {'1','2','3','4','5','6','7','8','9'};
    assert(rtl8763_crc16_modbus(0xFFFFu, check, 9) == 0x4B37u);
    /* Chained two-chunk update matches single pass */
    uint16_t c = rtl8763_crc16_modbus(0xFFFFu, check, 4);
    c = rtl8763_crc16_modbus(c, check + 4, 5);
    assert(c == 0x4B37u);

    uint8_t cmd[32];
    const uint8_t params[3] = {0xAA, 0xBB, 0xCC};
    int n = rtl8763_h4_build_vendor_crc_cmd(cmd, sizeof cmd, 0xFC20u, params, 3);
    assert(n == 9 && cmd[0] == HCI_H4_CMD && cmd[1] == 0x20 && cmd[2] == 0xFC && cmd[3] == 5);
    uint8_t crc_input[5] = {0x20, 0xFC, 0xAA, 0xBB, 0xCC};
    uint16_t expected_crc = rtl8763_crc16_modbus(0xFFFFu, crc_input, 5);
    assert(cmd[7] == (expected_crc & 0xFFu) && cmd[8] == (expected_crc >> 8));

    /* SLIP framing round-trip with embedded 0xC0 and 0xDB bytes */
    const uint8_t payload[6] = {0x01, SLIP_END, 0x42, SLIP_ESC, 0x99, SLIP_END};
    uint8_t slip[32];
    int slen = rtl8763_slip_encode(payload, sizeof payload, slip, sizeof slip);
    assert(slen == 11 && slip[0] == SLIP_END && slip[slen - 1] == SLIP_END);

    struct rtl8763_slip_decoder dec;
    rtl8763_slip_init(&dec);
    uint8_t decoded[32];
    int got = 0;
    for (int i = 0; i < slen; i++) {
        got = rtl8763_slip_feed(&dec, slip[i], decoded, sizeof decoded);
    }
    assert(got == 6 && memcmp(decoded, payload, 6) == 0 && dec.frames_ok == 1 && dec.errors == 0);
}

static void test_rfc_crypto_vectors(void) {
    /* FIPS 180-4 SHA-256("abc") */
    const uint8_t exp_sha256[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
    };
    uint8_t dig[32];
    sha256((const uint8_t *)"abc", 3, dig);
    assert(memcmp(dig, exp_sha256, 32) == 0);

    /* RFC 4231 HMAC-SHA256 Test Case 1 */
    uint8_t hkey[20];
    memset(hkey, 0x0b, 20);
    const uint8_t exp_hmac[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7,
    };
    uint8_t mac[32];
    hmac_sha256(hkey, 20, (const uint8_t *)"Hi There", 8, mac);
    assert(memcmp(mac, exp_hmac, 32) == 0);

    /* RFC 5869 HKDF-SHA256 Test Case 1 */
    uint8_t ikm[22]; memset(ikm, 0x0b, 22);
    const uint8_t salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    const uint8_t exp_okm[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65,
    };
    uint8_t okm[42];
    assert(hkdf_sha256(salt, 13, ikm, 22, info, 10, okm, 42) == 0);
    assert(memcmp(okm, exp_okm, 42) == 0);

    /* RFC 8439 Section 2.8.2 ChaCha20-Poly1305 AEAD vector */
    const uint8_t aead_key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    const uint8_t aead_nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    };
    const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    };
    const char *pt_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const uint8_t exp_ct[114] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16,
    };
    const uint8_t exp_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    };
    uint8_t ct[114], dec[114], tag[16];
    assert(strlen(pt_str) == 114);
    chacha20_poly1305_seal(aead_key, aead_nonce, aad, 12, (const uint8_t *)pt_str, 114, ct, tag);
    assert(memcmp(ct, exp_ct, 114) == 0);
    assert(memcmp(tag, exp_tag, 16) == 0);
    assert(chacha20_poly1305_open(aead_key, aead_nonce, aad, 12, ct, 114, tag, dec));
    assert(memcmp(dec, pt_str, 114) == 0);

    /* Tampered ciphertext fails and zeroes plaintext buffer */
    ct[10] ^= 0x01u;
    assert(!chacha20_poly1305_open(aead_key, aead_nonce, aad, 12, ct, 114, tag, dec));
    assert(dec[0] == 0 && dec[113] == 0);
}

static void test_secure_link(void) {
    uint8_t psk[32], wrong_psk[32], p_nonce[16], w_nonce[16];
    for (unsigned i = 0; i < 32u; i++) { psk[i] = (uint8_t)(0xA0u + i); wrong_psk[i] = (uint8_t)(0x50u + i); }
    for (unsigned i = 0; i < 16u; i++) { p_nonce[i] = (uint8_t)(0x10u + i); w_nonce[i] = (uint8_t)(0x20u + i); }

    struct secure_session phone, watch, bad_phone;
    secure_session_init(&phone, SECURE_ROLE_PHONE, psk);
    secure_session_init(&watch, SECURE_ROLE_WATCH, psk);
    secure_session_init(&bad_phone, SECURE_ROLE_PHONE, wrong_psk);

    uint8_t hello[SECURE_HELLO_LEN], ack[SECURE_HELLO_ACK_LEN];
    assert(secure_phone_build_hello(&phone, p_nonce, hello) == SECURE_HELLO_LEN);
    assert(secure_phone_build_hello(&bad_phone, p_nonce, hello) == SECURE_HELLO_LEN);
    assert(secure_watch_accept_hello(&watch, hello, sizeof hello, w_nonce, ack) == SECURE_HELLO_ACK_LEN);

    /* Wrong PSK fails watch proof verification */
    assert(secure_phone_finish(&bad_phone, ack, sizeof ack) == -2 && !bad_phone.established);
    assert(secure_phone_finish(&phone, ack, sizeof ack) == 0 && phone.established && watch.established);

    /* Phone -> Watch encrypted exchange */
    const uint8_t msg1[] = "SpellboundFit notification payload";
    uint8_t pkt[128], out[128];
    int plen = secure_encrypt(&phone, msg1, sizeof msg1, pkt, sizeof pkt);
    assert(plen == (int)(sizeof msg1 + SECURE_DATA_OVERHEAD));
    int dlen = secure_decrypt(&watch, pkt, (size_t)plen, out, sizeof out);
    assert(dlen == (int)sizeof msg1 && memcmp(out, msg1, sizeof msg1) == 0);

    /* Replay of same packet rejected with -3 */
    assert(secure_decrypt(&watch, pkt, (size_t)plen, out, sizeof out) == -3);
    assert(watch.replay_rejects == 1);

    /* Watch -> Phone encrypted exchange */
    const uint8_t msg2[] = "Action reply #1";
    plen = secure_encrypt(&watch, msg2, sizeof msg2, pkt, sizeof pkt);
    assert(plen > 0);
    /* Bit-flip rejected with -2 without advancing counter */
    pkt[12] ^= 0x80u;
    assert(secure_decrypt(&phone, pkt, (size_t)plen, out, sizeof out) == -2);
    assert(phone.auth_failures == 1 && phone.rx_next_counter == 0);
    pkt[12] ^= 0x80u;
    assert(secure_decrypt(&phone, pkt, (size_t)plen, out, sizeof out) == (int)sizeof msg2);
    assert(memcmp(out, msg2, sizeof msg2) == 0);
}

int main(void) {
    test_rtl8763();
    test_rfc_crypto_vectors();
    test_secure_link();
    printf("PASS: RTL8763 HCI framing, RFC crypto and secure_link\n");
    return 0;
}
