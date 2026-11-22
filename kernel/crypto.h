/* Freestanding cryptographic primitives: SHA-256, HMAC-SHA256, HKDF-SHA256,
 * and RFC 8439 ChaCha20-Poly1305 AEAD. Zero heap, zero FPU, zero libgcc. */
#ifndef SPELLBOUND_CRYPTO_H
#define SPELLBOUND_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SHA256_LEN  32u
#define CRYPTO_KEY_LEN     32u
#define CRYPTO_NONCE_LEN   12u
#define CRYPTO_TAG_LEN     16u

struct sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buf[64];
    uint32_t buf_len;
};

/* Constant-time byte comparison and volatile secret zeroization. */
bool crypto_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);
void crypto_zero(void *ptr, size_t len);

/* FIPS 180-4 SHA-256 */
void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t digest[CRYPTO_SHA256_LEN]);
void sha256(const uint8_t *data, size_t len, uint8_t digest[CRYPTO_SHA256_LEN]);

/* RFC 2104 HMAC-SHA256 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[CRYPTO_SHA256_LEN]);

/* RFC 5869 HKDF-SHA256 (up to 255 * 32 bytes; returns 0 on success, -1 on error). */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/* RFC 8439 ChaCha20 stream cipher */
void chacha20_xor(const uint8_t key[CRYPTO_KEY_LEN], uint32_t counter,
                  const uint8_t nonce[CRYPTO_NONCE_LEN],
                  const uint8_t *in, uint8_t *out, size_t len);

/* RFC 8439 Poly1305 one-time authenticator */
void poly1305_mac(const uint8_t key[CRYPTO_KEY_LEN],
                  const uint8_t *msg, size_t len,
                  uint8_t tag[CRYPTO_TAG_LEN]);

/* RFC 8439 ChaCha20-Poly1305 AEAD */
void chacha20_poly1305_seal(const uint8_t key[CRYPTO_KEY_LEN],
                            const uint8_t nonce[CRYPTO_NONCE_LEN],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[CRYPTO_TAG_LEN]);

/* Returns true if tag verifies in constant time; zeroes pt on failure. */
bool chacha20_poly1305_open(const uint8_t key[CRYPTO_KEY_LEN],
                            const uint8_t nonce[CRYPTO_NONCE_LEN],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[CRYPTO_TAG_LEN],
                            uint8_t *pt);

#endif /* SPELLBOUND_CRYPTO_H */
