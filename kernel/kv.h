/* Power-fail-safe append-only log key-value settings store with CRC-32 records. */
#ifndef SPELLBOUND_KV_H
#define SPELLBOUND_KV_H

#include <stdbool.h>
#include <stdint.h>

#define KV_MAX_KEY_LEN  24u
#define KV_MAX_VAL_LEN  64u
#define KV_MAX_ENTRIES  32u

struct kv_backend {
    uint32_t capacity;
    int (*read)(uint32_t offset, uint8_t *out, uint32_t len, void *ctx);
    int (*write)(uint32_t offset, const uint8_t *data, uint32_t len, void *ctx);
    int (*erase)(void *ctx);
    void *ctx;
};

struct kv_entry_meta {
    bool valid;
    uint8_t key_len;
    uint8_t val_len;
    char key[KV_MAX_KEY_LEN];
    uint32_t val_offset; /* byte offset of value payload in backend */
};

struct kv_store {
    struct kv_backend backend;
    bool mounted;
    uint32_t write_cursor;
    uint32_t entry_count;
    uint32_t corrupt_tail_records;
    struct kv_entry_meta entries[KV_MAX_ENTRIES];
};

/* Scan backend log, rebuild active index and stop cleanly at any torn/corrupt tail. */
int kv_mount(struct kv_store *kv, const struct kv_backend *backend);

int kv_set(struct kv_store *kv, const char *key, const void *val, uint8_t val_len);
int kv_get(const struct kv_store *kv, const char *key, void *out, uint8_t out_cap, uint8_t *actual_len);
int kv_delete(struct kv_store *kv, const char *key);
bool kv_exists(const struct kv_store *kv, const char *key);
uint32_t kv_count(const struct kv_store *kv);
uint32_t kv_free_bytes(const struct kv_store *kv);

/* Rewrite only live entries using caller-supplied scratch buffer (>= backend.capacity or
 * enough for live records) and erase+rewrite backend. */
int kv_compact(struct kv_store *kv, uint8_t *scratch, uint32_t scratch_cap);

int kv_set_u32(struct kv_store *kv, const char *key, uint32_t value);
bool kv_get_u32(const struct kv_store *kv, const char *key, uint32_t *out);

#endif /* SPELLBOUND_KV_H */
