/* Freestanding SHA-256, HMAC-SHA256, HKDF-SHA256 and RFC 8439 ChaCha20-Poly1305. */
#include "crypto.h"

bool crypto_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

void crypto_zero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

static inline uint32_t ld_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void st_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint32_t ld_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void st_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void st_le64(uint8_t *p, uint64_t v) {
    st_le32(p, (uint32_t)v);
    st_le32(p + 4, (uint32_t)(v >> 32));
}

/* ---- SHA-256 (FIPS 180-4) ---- */

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static void sha256_transform(struct sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16u; i++) {
        w[i] = ld_be32(&block[i * 4u]);
    }
    for (unsigned i = 16u; i < 64u; i++) {
        uint32_t s0 = rotr32(w[i - 15u], 7) ^ rotr32(w[i - 15u], 18) ^ (w[i - 15u] >> 3);
        uint32_t s1 = rotr32(w[i - 2u], 17) ^ rotr32(w[i - 2u], 19) ^ (w[i - 2u] >> 10);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (unsigned i = 0; i < 64u; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(struct sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bit_count = 0;
    ctx->buf_len = 0;
}

void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len) {
    if (!data || len == 0) return;
    ctx->bit_count += (uint64_t)len << 3;
    size_t off = 0;
    if (ctx->buf_len > 0) {
        while (off < len && ctx->buf_len < 64u) {
            ctx->buf[ctx->buf_len++] = data[off++];
        }
        if (ctx->buf_len == 64u) {
            sha256_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (off + 64u <= len) {
        sha256_transform(ctx, &data[off]);
        off += 64u;
    }
    while (off < len) {
        ctx->buf[ctx->buf_len++] = data[off++];
    }
}

void sha256_final(struct sha256_ctx *ctx, uint8_t digest[CRYPTO_SHA256_LEN]) {
    ctx->buf[ctx->buf_len++] = 0x80u;
    if (ctx->buf_len > 56u) {
        while (ctx->buf_len < 64u) ctx->buf[ctx->buf_len++] = 0;
        sha256_transform(ctx, ctx->buf);
        ctx->buf_len = 0;
    }
    while (ctx->buf_len < 56u) ctx->buf[ctx->buf_len++] = 0;
    st_be32(&ctx->buf[56], (uint32_t)(ctx->bit_count >> 32));
    st_be32(&ctx->buf[60], (uint32_t)ctx->bit_count);
    sha256_transform(ctx, ctx->buf);
    for (unsigned i = 0; i < 8u; i++) {
        st_be32(&digest[i * 4u], ctx->state[i]);
    }
    crypto_zero(ctx, sizeof *ctx);
}

void sha256(const uint8_t *data, size_t len, uint8_t digest[CRYPTO_SHA256_LEN]) {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ---- HMAC-SHA256 & HKDF-SHA256 ---- */

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[CRYPTO_SHA256_LEN]) {
    uint8_t kpad[64];
    for (unsigned i = 0; i < 64u; i++) kpad[i] = 0;
    if (key_len > 64u) {
        sha256(key, key_len, kpad);
    } else if (key && key_len > 0) {
        for (size_t i = 0; i < key_len; i++) kpad[i] = key[i];
    }

    uint8_t ipad[64], opad[64];
    for (unsigned i = 0; i < 64u; i++) {
        ipad[i] = (uint8_t)(kpad[i] ^ 0x36u);
        opad[i] = (uint8_t)(kpad[i] ^ 0x5Cu);
    }

    struct sha256_ctx ctx;
    uint8_t inner[CRYPTO_SHA256_LEN];
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64u);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64u);
    sha256_update(&ctx, inner, CRYPTO_SHA256_LEN);
    sha256_final(&ctx, out);

    crypto_zero(kpad, sizeof kpad);
    crypto_zero(ipad, sizeof ipad);
    crypto_zero(opad, sizeof opad);
    crypto_zero(inner, sizeof inner);
}

int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    if (!okm || okm_len == 0 || okm_len > 255u * CRYPTO_SHA256_LEN) {
        return -1;
    }
    uint8_t zero_salt[CRYPTO_SHA256_LEN] = {0};
    const uint8_t *use_salt = (salt && salt_len > 0) ? salt : zero_salt;
    size_t use_salt_len = (salt && salt_len > 0) ? salt_len : CRYPTO_SHA256_LEN;

    uint8_t prk[CRYPTO_SHA256_LEN];
    hmac_sha256(use_salt, use_salt_len, ikm, ikm_len, prk);

    uint8_t t[CRYPTO_SHA256_LEN];
    size_t t_len = 0;
    size_t produced = 0;
    uint8_t counter = 1u;

    /* Expand step using HMAC(PRK, T(n-1) || info || counter). */
    while (produced < okm_len) {
        uint8_t ipad[64], opad[64];
        for (unsigned i = 0; i < 64u; i++) {
            uint8_t kb = i < CRYPTO_SHA256_LEN ? prk[i] : 0u;
            ipad[i] = (uint8_t)(kb ^ 0x36u);
            opad[i] = (uint8_t)(kb ^ 0x5Cu);
        }
        struct sha256_ctx ctx;
        uint8_t inner[CRYPTO_SHA256_LEN];
        sha256_init(&ctx);
        sha256_update(&ctx, ipad, 64u);
        if (t_len > 0) sha256_update(&ctx, t, t_len);
        if (info && info_len > 0) sha256_update(&ctx, info, info_len);
        sha256_update(&ctx, &counter, 1u);
        sha256_final(&ctx, inner);

        sha256_init(&ctx);
        sha256_update(&ctx, opad, 64u);
        sha256_update(&ctx, inner, CRYPTO_SHA256_LEN);
        sha256_final(&ctx, t);
        t_len = CRYPTO_SHA256_LEN;

        size_t take = okm_len - produced;
        if (take > CRYPTO_SHA256_LEN) take = CRYPTO_SHA256_LEN;
        for (size_t i = 0; i < take; i++) okm[produced + i] = t[i];
        produced += take;
        counter++;

        crypto_zero(ipad, sizeof ipad);
        crypto_zero(opad, sizeof opad);
        crypto_zero(inner, sizeof inner);
    }
    crypto_zero(prk, sizeof prk);
    crypto_zero(t, sizeof t);
    return 0;
}

/* ---- ChaCha20 (RFC 8439) ---- */

static inline void qr(uint32_t s[16], unsigned a, unsigned b, unsigned c, unsigned d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t st[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        ld_le32(&key[0]),  ld_le32(&key[4]),  ld_le32(&key[8]),  ld_le32(&key[12]),
        ld_le32(&key[16]), ld_le32(&key[20]), ld_le32(&key[24]), ld_le32(&key[28]),
        counter,
        ld_le32(&nonce[0]), ld_le32(&nonce[4]), ld_le32(&nonce[8]),
    };
    uint32_t w[16];
    for (unsigned i = 0; i < 16u; i++) w[i] = st[i];
    for (unsigned i = 0; i < 10u; i++) {
        qr(w, 0, 4, 8, 12);  qr(w, 1, 5, 9, 13);
        qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12);
        qr(w, 2, 7, 8, 13);  qr(w, 3, 4, 9, 14);
    }
    for (unsigned i = 0; i < 16u; i++) {
        st_le32(&out[i * 4u], w[i] + st[i]);
    }
}

void chacha20_xor(const uint8_t key[CRYPTO_KEY_LEN], uint32_t counter,
                  const uint8_t nonce[CRYPTO_NONCE_LEN],
                  const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        chacha20_block(key, counter++, nonce, ks);
        size_t n = len - off;
        if (n > 64u) n = 64u;
        for (size_t i = 0; i < n; i++) {
            out[off + i] = (uint8_t)((in ? in[off + i] : 0u) ^ ks[i]);
        }
        off += n;
    }
    crypto_zero(ks, sizeof ks);
}

/* ---- Poly1305 (RFC 8439, 5 x 26-bit limbs) ---- */

struct poly1305_state {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buf[16];
    size_t leftover;
};

static void poly1305_init(struct poly1305_state *st, const uint8_t key[32]) {
    uint32_t t0 = ld_le32(&key[0])  & 0x0FFFFFFFu;
    uint32_t t1 = ld_le32(&key[4])  & 0x0FFFFFFCu;
    uint32_t t2 = ld_le32(&key[8])  & 0x0FFFFFFCu;
    uint32_t t3 = ld_le32(&key[12]) & 0x0FFFFFFCu;

    st->r[0] = t0 & 0x3FFFFFFu;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFFu;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFFu;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFFu;
    st->r[4] = (t3 >> 8) & 0x00FFFFFFu;

    for (unsigned i = 0; i < 5u; i++) st->h[i] = 0;
    st->pad[0] = ld_le32(&key[16]);
    st->pad[1] = ld_le32(&key[20]);
    st->pad[2] = ld_le32(&key[24]);
    st->pad[3] = ld_le32(&key[28]);
    st->leftover = 0;
}

static void poly1305_block(struct poly1305_state *st, const uint8_t m[16], bool is_final) {
    uint32_t hibit = is_final ? 0u : (1u << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;

    uint32_t t0 = ld_le32(&m[0]);
    uint32_t t1 = ld_le32(&m[4]);
    uint32_t t2 = ld_le32(&m[8]);
    uint32_t t3 = ld_le32(&m[12]);

    uint32_t h0 = st->h[0] + (t0 & 0x3FFFFFFu);
    uint32_t h1 = st->h[1] + (((t0 >> 26) | (t1 << 6)) & 0x3FFFFFFu);
    uint32_t h2 = st->h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3FFFFFFu);
    uint32_t h3 = st->h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3FFFFFFu);
    uint32_t h4 = st->h[4] + (t3 >> 8) + hibit;

    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3FFFFFFu; d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3FFFFFFu; d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3FFFFFFu; d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3FFFFFFu; d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3FFFFFFu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3FFFFFFu; h1 += c;

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(struct poly1305_state *st, const uint8_t *m, size_t len) {
    if (!m || len == 0) return;
    size_t off = 0;
    if (st->leftover > 0) {
        while (off < len && st->leftover < 16u) {
            st->buf[st->leftover++] = m[off++];
        }
        if (st->leftover == 16u) {
            poly1305_block(st, st->buf, false);
            st->leftover = 0;
        }
    }
    while (off + 16u <= len) {
        poly1305_block(st, &m[off], false);
        off += 16u;
    }
    while (off < len) {
        st->buf[st->leftover++] = m[off++];
    }
}

static void poly1305_finish(struct poly1305_state *st, uint8_t tag[16]) {
    if (st->leftover > 0) {
        st->buf[st->leftover++] = 1u;
        while (st->leftover < 16u) st->buf[st->leftover++] = 0u;
        poly1305_block(st, st->buf, true);
    }

    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3FFFFFFu; h2 += c;
    c = h2 >> 26; h2 &= 0x3FFFFFFu; h3 += c;
    c = h3 >> 26; h3 &= 0x3FFFFFFu; h4 += c;
    c = h4 >> 26; h4 &= 0x3FFFFFFu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3FFFFFFu; h1 += c;

    /* Compute h - p = h + 5 - 2^130 */
    uint32_t g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3FFFFFFu;
    uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3FFFFFFu;
    uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3FFFFFFu;
    uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3FFFFFFu;
    uint32_t g4 = h4 + c - (1u << 26);

    /* Select g if g4 did not borrow (MSB == 0), else h */
    uint32_t mask = (g4 >> 31) - 1u;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* Reassemble 128-bit h and add pad */
    uint32_t f0 = (h0 | (h1 << 26));
    uint32_t f1 = ((h1 >> 6) | (h2 << 20));
    uint32_t f2 = ((h2 >> 12) | (h3 << 14));
    uint32_t f3 = ((h3 >> 18) | (h4 << 8));

    uint64_t f;
    f = (uint64_t)f0 + st->pad[0];                st_le32(&tag[0], (uint32_t)f);
    f = (uint64_t)f1 + st->pad[1] + (f >> 32);    st_le32(&tag[4], (uint32_t)f);
    f = (uint64_t)f2 + st->pad[2] + (f >> 32);    st_le32(&tag[8], (uint32_t)f);
    f = (uint64_t)f3 + st->pad[3] + (f >> 32);    st_le32(&tag[12], (uint32_t)f);

    crypto_zero(st, sizeof *st);
}

void poly1305_mac(const uint8_t key[CRYPTO_KEY_LEN],
                  const uint8_t *msg, size_t len,
                  uint8_t tag[CRYPTO_TAG_LEN]) {
    struct poly1305_state st;
    poly1305_init(&st, key);
    poly1305_update(&st, msg, len);
    poly1305_finish(&st, tag);
}

/* ---- ChaCha20-Poly1305 AEAD (RFC 8439) ---- */

static void aead_compute_tag(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ct, size_t ct_len,
                             uint8_t tag[16]) {
    uint8_t poly_key[64];
    chacha20_block(key, 0u, nonce, poly_key);

    struct poly1305_state st;
    poly1305_init(&st, poly_key);
    static const uint8_t zeros[16] = {0};

    if (aad && aad_len > 0) {
        poly1305_update(&st, aad, aad_len);
        size_t pad = (16u - (aad_len & 15u)) & 15u;
        if (pad > 0) poly1305_update(&st, zeros, pad);
    }
    if (ct && ct_len > 0) {
        poly1305_update(&st, ct, ct_len);
        size_t pad = (16u - (ct_len & 15u)) & 15u;
        if (pad > 0) poly1305_update(&st, zeros, pad);
    }
    uint8_t lens[16];
    st_le64(&lens[0], (uint64_t)aad_len);
    st_le64(&lens[8], (uint64_t)ct_len);
    poly1305_update(&st, lens, 16u);
    poly1305_finish(&st, tag);
    crypto_zero(poly_key, sizeof poly_key);
}

void chacha20_poly1305_seal(const uint8_t key[CRYPTO_KEY_LEN],
                            const uint8_t nonce[CRYPTO_NONCE_LEN],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[CRYPTO_TAG_LEN]) {
    chacha20_xor(key, 1u, nonce, pt, ct, pt_len);
    aead_compute_tag(key, nonce, aad, aad_len, ct, pt_len, tag);
}

bool chacha20_poly1305_open(const uint8_t key[CRYPTO_KEY_LEN],
                            const uint8_t nonce[CRYPTO_NONCE_LEN],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[CRYPTO_TAG_LEN],
                            uint8_t *pt) {
    uint8_t calc[CRYPTO_TAG_LEN];
    aead_compute_tag(key, nonce, aad, aad_len, ct, ct_len, calc);
    bool ok = crypto_ct_eq(calc, tag, CRYPTO_TAG_LEN);
    crypto_zero(calc, sizeof calc);
    if (!ok) {
        if (pt && ct_len > 0) crypto_zero(pt, ct_len);
        return false;
    }
    chacha20_xor(key, 1u, nonce, ct, pt, ct_len);
    return true;
}
