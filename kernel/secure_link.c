/* Authenticated & encrypted SpellboundFit companion link (ChaCha20-Poly1305 + HKDF). */
#include "secure_link.h"

static const uint8_t kdf_info[] = "SpellboundFit-v1-session";
static const uint8_t proof_label[] = "WATCH-OK";

static void wr_le64_sl(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8u; i++) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static uint64_t rd_le64_sl(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; i++) {
        v |= ((uint64_t)p[i]) << (8u * i);
    }
    return v;
}

static void derive_keys_and_proof(struct secure_session *s, uint8_t watch_proof[32]) {
    uint8_t salt[32];
    for (unsigned i = 0; i < 16u; i++) {
        salt[i] = s->phone_nonce[i];
        salt[16u + i] = s->watch_nonce[i];
    }
    uint8_t okm[64];
    (void)hkdf_sha256(salt, sizeof salt, s->psk, CRYPTO_KEY_LEN,
                      kdf_info, sizeof kdf_info - 1u, okm, sizeof okm);

    /* okm[0..31] = phone->watch key; okm[32..63] = watch->phone key */
    if (s->role == SECURE_ROLE_PHONE) {
        for (unsigned i = 0; i < 32u; i++) {
            s->tx_key[i] = okm[i];
            s->rx_key[i] = okm[32u + i];
        }
    } else {
        for (unsigned i = 0; i < 32u; i++) {
            s->rx_key[i] = okm[i];
            s->tx_key[i] = okm[32u + i];
        }
    }

    /* Watch proof = HMAC-SHA256(watch_to_phone_key, "WATCH-OK" || salt) */
    uint8_t msg[8 + 32];
    for (unsigned i = 0; i < 8u; i++) msg[i] = proof_label[i];
    for (unsigned i = 0; i < 32u; i++) msg[8u + i] = salt[i];
    hmac_sha256(&okm[32], 32u, msg, sizeof msg, watch_proof);

    crypto_zero(okm, sizeof okm);
    crypto_zero(msg, sizeof msg);
}

void secure_session_init(struct secure_session *s, enum secure_role role,
                         const uint8_t psk[CRYPTO_KEY_LEN]) {
    if (!s || !psk) return;
    crypto_zero(s, sizeof *s);
    s->role = role;
    for (unsigned i = 0; i < CRYPTO_KEY_LEN; i++) s->psk[i] = psk[i];
}

void secure_session_reset(struct secure_session *s) {
    if (!s) return;
    enum secure_role role = s->role;
    uint8_t psk[CRYPTO_KEY_LEN];
    for (unsigned i = 0; i < CRYPTO_KEY_LEN; i++) psk[i] = s->psk[i];
    secure_session_init(s, role, psk);
    crypto_zero(psk, sizeof psk);
}

int secure_phone_build_hello(struct secure_session *s, const uint8_t phone_nonce[16],
                             uint8_t out[SECURE_HELLO_LEN]) {
    if (!s || !phone_nonce || !out || s->role != SECURE_ROLE_PHONE) return -1;
    s->established = false;
    s->tx_counter = 0;
    s->rx_next_counter = 0;
    out[0] = SECURE_MSG_HELLO;
    for (unsigned i = 0; i < 16u; i++) {
        s->phone_nonce[i] = phone_nonce[i];
        out[1u + i] = phone_nonce[i];
    }
    return SECURE_HELLO_LEN;
}

int secure_watch_accept_hello(struct secure_session *s, const uint8_t *hello, size_t hello_len,
                              const uint8_t watch_nonce[16], uint8_t out[SECURE_HELLO_ACK_LEN]) {
    if (!s || !hello || hello_len != SECURE_HELLO_LEN || hello[0] != SECURE_MSG_HELLO ||
        !watch_nonce || !out || s->role != SECURE_ROLE_WATCH) {
        return -1;
    }
    for (unsigned i = 0; i < 16u; i++) {
        s->phone_nonce[i] = hello[1u + i];
        s->watch_nonce[i] = watch_nonce[i];
    }
    uint8_t proof[32];
    derive_keys_and_proof(s, proof);
    s->tx_counter = 0;
    s->rx_next_counter = 0;
    s->established = true;

    out[0] = SECURE_MSG_HELLO_ACK;
    for (unsigned i = 0; i < 16u; i++) out[1u + i] = watch_nonce[i];
    for (unsigned i = 0; i < 32u; i++) out[17u + i] = proof[i];
    crypto_zero(proof, sizeof proof);
    return SECURE_HELLO_ACK_LEN;
}

int secure_phone_finish(struct secure_session *s, const uint8_t *ack, size_t ack_len) {
    if (!s || !ack || ack_len != SECURE_HELLO_ACK_LEN || ack[0] != SECURE_MSG_HELLO_ACK ||
        s->role != SECURE_ROLE_PHONE) {
        return -1;
    }
    for (unsigned i = 0; i < 16u; i++) {
        s->watch_nonce[i] = ack[1u + i];
    }
    uint8_t expected[32];
    derive_keys_and_proof(s, expected);
    bool ok = crypto_ct_eq(expected, &ack[17], 32u);
    crypto_zero(expected, sizeof expected);
    if (!ok) {
        s->auth_failures++;
        crypto_zero(s->tx_key, CRYPTO_KEY_LEN);
        crypto_zero(s->rx_key, CRYPTO_KEY_LEN);
        return -2;
    }
    s->tx_counter = 0;
    s->rx_next_counter = 0;
    s->established = true;
    return 0;
}

static void build_nonce(uint64_t counter, uint8_t nonce[CRYPTO_NONCE_LEN]) {
    nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
    wr_le64_sl(&nonce[4], counter);
}

int secure_encrypt(struct secure_session *s, const uint8_t *pt, size_t pt_len,
                   uint8_t *out, size_t out_cap) {
    if (!s || !s->established || !out || (pt_len > 0 && !pt)) return -1;
    if (out_cap < pt_len + SECURE_DATA_OVERHEAD) return -1;
    uint64_t ctr = s->tx_counter++;
    out[0] = SECURE_MSG_DATA;
    wr_le64_sl(&out[1], ctr);
    uint8_t nonce[CRYPTO_NONCE_LEN];
    build_nonce(ctr, nonce);
    chacha20_poly1305_seal(s->tx_key, nonce, out, 9u, pt, pt_len,
                           &out[9], &out[9u + pt_len]);
    return (int)(pt_len + SECURE_DATA_OVERHEAD);
}

int secure_decrypt(struct secure_session *s, const uint8_t *pkt, size_t pkt_len,
                   uint8_t *pt_out, size_t pt_cap) {
    if (!s || !s->established || !pkt || pkt_len < SECURE_DATA_OVERHEAD ||
        pkt[0] != SECURE_MSG_DATA) {
        return -1;
    }
    size_t ct_len = pkt_len - SECURE_DATA_OVERHEAD;
    if (ct_len > pt_cap || (ct_len > 0 && !pt_out)) return -1;

    uint64_t ctr = rd_le64_sl(&pkt[1]);
    if (ctr < s->rx_next_counter) {
        s->replay_rejects++;
        return -3; /* replayed or stale counter */
    }
    uint8_t nonce[CRYPTO_NONCE_LEN];
    build_nonce(ctr, nonce);
    if (!chacha20_poly1305_open(s->rx_key, nonce, pkt, 9u,
                                &pkt[9], ct_len, &pkt[9u + ct_len], pt_out)) {
        s->auth_failures++;
        return -2; /* authentication failure */
    }
    s->rx_next_counter = ctr + 1u;
    return (int)ct_len;
}
