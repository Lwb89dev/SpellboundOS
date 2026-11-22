/* Authenticated & encrypted SpellboundFit companion link (ChaCha20-Poly1305 + HKDF). */
#ifndef SPELLBOUND_SECURE_LINK_H
#define SPELLBOUND_SECURE_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define SECURE_MSG_HELLO      0x01u
#define SECURE_MSG_HELLO_ACK  0x02u
#define SECURE_MSG_DATA       0x03u

#define SECURE_HELLO_LEN      17u /* type(1) + phone_nonce(16) */
#define SECURE_HELLO_ACK_LEN  49u /* type(1) + watch_nonce(16) + proof(32) */
#define SECURE_DATA_OVERHEAD  25u /* type(1) + counter_le64(8) + tag(16) */

enum secure_role {
    SECURE_ROLE_PHONE = 0,
    SECURE_ROLE_WATCH = 1,
};

struct secure_session {
    enum secure_role role;
    bool established;
    uint8_t psk[CRYPTO_KEY_LEN];
    uint8_t phone_nonce[16];
    uint8_t watch_nonce[16];
    uint8_t tx_key[CRYPTO_KEY_LEN];
    uint8_t rx_key[CRYPTO_KEY_LEN];
    uint64_t tx_counter;
    uint64_t rx_next_counter;
    uint32_t replay_rejects;
    uint32_t auth_failures;
};

void secure_session_init(struct secure_session *s, enum secure_role role,
                         const uint8_t psk[CRYPTO_KEY_LEN]);
void secure_session_reset(struct secure_session *s);

/* Phone starts handshake with 16-byte nonce -> emits 17-byte SECURE_MSG_HELLO. */
int secure_phone_build_hello(struct secure_session *s, const uint8_t phone_nonce[16],
                             uint8_t out[SECURE_HELLO_LEN]);

/* Watch handles HELLO with its own 16-byte nonce -> derives keys, marks established,
 * and emits 49-byte SECURE_MSG_HELLO_ACK carrying HMAC proof. */
int secure_watch_accept_hello(struct secure_session *s, const uint8_t *hello, size_t hello_len,
                              const uint8_t watch_nonce[16], uint8_t out[SECURE_HELLO_ACK_LEN]);

/* Phone verifies watch's HELLO_ACK proof -> derives keys and marks established. */
int secure_phone_finish(struct secure_session *s, const uint8_t *ack, size_t ack_len);

/* Encrypt plaintext into [0x03, counter_le64, ct, tag16]. Returns packet length or -1. */
int secure_encrypt(struct secure_session *s, const uint8_t *pt, size_t pt_len,
                   uint8_t *out, size_t out_cap);

/* Decrypt & authenticate packet, enforcing strict monotonic anti-replay counter.
 * Returns plaintext length (>= 0) or negative on error/replay/bad tag. */
int secure_decrypt(struct secure_session *s, const uint8_t *pkt, size_t pkt_len,
                   uint8_t *pt_out, size_t pt_cap);

#endif /* SPELLBOUND_SECURE_LINK_H */
