/* Power-fail-safe append-only log key-value settings store with CRC-32 records. */
#include "kv.h"
#include "proto.h"
#include <stddef.h>

#define KV_REC_MAGIC_0    0x53u /* 'S' */
#define KV_REC_MAGIC_1    0x4Bu /* 'K' */
#define KV_FLAG_ACTIVE    0x01u
#define KV_FLAG_TOMBSTONE 0x02u
#define KV_REC_HDR_LEN    5u    /* magic(2), flags(1), key_len(1), val_len(1) */
#define KV_REC_CRC_LEN    4u

static uint32_t kv_strlen(const char *s) {
    uint32_t n = 0;
    while (s && s[n] != '\0') n++;
    return n;
}

static bool kv_key_eq(const struct kv_entry_meta *e, const char *key, uint8_t len) {
    if (e->key_len != len) return false;
    for (uint8_t i = 0; i < len; i++) {
        if (e->key[i] != key[i]) return false;
    }
    return true;
}

static uint32_t kv_rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void kv_wr_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static int kv_find_slot(const struct kv_store *kv, const char *key, uint8_t key_len) {
    for (uint32_t i = 0; i < KV_MAX_ENTRIES; i++) {
        if (kv->entries[i].valid && kv_key_eq(&kv->entries[i], key, key_len)) {
            return (int)i;
        }
    }
    return -1;
}

static int kv_apply_index(struct kv_store *kv, uint8_t flags, const char *key,
                          uint8_t key_len, uint8_t val_len, uint32_t val_offset) {
    int slot = kv_find_slot(kv, key, key_len);
    if (flags == KV_FLAG_TOMBSTONE) {
        if (slot >= 0) {
            kv->entries[slot].valid = false;
            kv->entry_count--;
        }
        return 0;
    }
    if (slot < 0) {
        for (uint32_t i = 0; i < KV_MAX_ENTRIES; i++) {
            if (!kv->entries[i].valid) {
                slot = (int)i;
                break;
            }
        }
        if (slot < 0) return -1;
        kv->entry_count++;
    }
    kv->entries[slot].valid = true;
    kv->entries[slot].key_len = key_len;
    kv->entries[slot].val_len = val_len;
    for (uint8_t i = 0; i < key_len; i++) kv->entries[slot].key[i] = key[i];
    kv->entries[slot].val_offset = val_offset;
    return 0;
}

int kv_mount(struct kv_store *kv, const struct kv_backend *backend) {
    if (!kv || !backend || !backend->read || !backend->write || backend->capacity < 32u) {
        return -1;
    }
    kv->backend = *backend;
    kv->mounted = false;
    kv->write_cursor = 0;
    kv->entry_count = 0;
    kv->corrupt_tail_records = 0;
    for (uint32_t i = 0; i < KV_MAX_ENTRIES; i++) {
        kv->entries[i].valid = false;
    }

    uint32_t off = 0;
    while (off + KV_REC_HDR_LEN + KV_REC_CRC_LEN <= backend->capacity) {
        uint8_t hdr[KV_REC_HDR_LEN];
        if (backend->read(off, hdr, KV_REC_HDR_LEN, backend->ctx) != 0) {
            return -2;
        }
        /* Unwritten erased flash/memory (0xFF or 0x00) marks clean end-of-log. */
        if ((hdr[0] == 0xFFu && hdr[1] == 0xFFu) || (hdr[0] == 0x00u && hdr[1] == 0x00u)) {
            break;
        }
        if (hdr[0] != KV_REC_MAGIC_0 || hdr[1] != KV_REC_MAGIC_1) {
            kv->corrupt_tail_records++;
            break;
        }
        uint8_t flags = hdr[2];
        uint8_t klen = hdr[3];
        uint8_t vlen = hdr[4];
        if ((flags != KV_FLAG_ACTIVE && flags != KV_FLAG_TOMBSTONE) ||
            klen == 0 || klen > KV_MAX_KEY_LEN || vlen > KV_MAX_VAL_LEN) {
            kv->corrupt_tail_records++;
            break;
        }
        uint32_t rec_len = KV_REC_HDR_LEN + (uint32_t)klen + (uint32_t)vlen + KV_REC_CRC_LEN;
        if (off + rec_len > backend->capacity) {
            kv->corrupt_tail_records++;
            break;
        }
        uint8_t rec[KV_REC_HDR_LEN + KV_MAX_KEY_LEN + KV_MAX_VAL_LEN + KV_REC_CRC_LEN];
        if (backend->read(off, rec, rec_len, backend->ctx) != 0) {
            return -2;
        }
        uint32_t expected = kv_rd_le32(&rec[rec_len - KV_REC_CRC_LEN]);
        uint32_t calc = proto_crc32(rec, rec_len - KV_REC_CRC_LEN);
        if (calc != expected) {
            kv->corrupt_tail_records++;
            break;
        }
        (void)kv_apply_index(kv, flags, (const char *)&rec[KV_REC_HDR_LEN],
                             klen, vlen, off + KV_REC_HDR_LEN + klen);
        off += rec_len;
    }

    kv->write_cursor = off;
    kv->mounted = true;
    return 0;
}

static int kv_append_record(struct kv_store *kv, uint8_t flags,
                            const char *key, uint8_t klen,
                            const uint8_t *val, uint8_t vlen) {
    uint32_t rec_len = KV_REC_HDR_LEN + (uint32_t)klen + (uint32_t)vlen + KV_REC_CRC_LEN;
    if (kv->write_cursor + rec_len > kv->backend.capacity) {
        return -3; /* out of space; caller should kv_compact() */
    }
    uint8_t rec[KV_REC_HDR_LEN + KV_MAX_KEY_LEN + KV_MAX_VAL_LEN + KV_REC_CRC_LEN];
    rec[0] = KV_REC_MAGIC_0;
    rec[1] = KV_REC_MAGIC_1;
    rec[2] = flags;
    rec[3] = klen;
    rec[4] = vlen;
    for (uint8_t i = 0; i < klen; i++) rec[KV_REC_HDR_LEN + i] = (uint8_t)key[i];
    for (uint8_t i = 0; i < vlen; i++) rec[KV_REC_HDR_LEN + klen + i] = val[i];
    uint32_t crc = proto_crc32(rec, rec_len - KV_REC_CRC_LEN);
    kv_wr_le32(&rec[rec_len - KV_REC_CRC_LEN], crc);

    if (kv->backend.write(kv->write_cursor, rec, rec_len, kv->backend.ctx) != 0) {
        return -2;
    }
    uint32_t val_off = kv->write_cursor + KV_REC_HDR_LEN + klen;
    if (kv_apply_index(kv, flags, key, klen, vlen, val_off) != 0) {
        return -3;
    }
    kv->write_cursor += rec_len;
    return 0;
}

int kv_set(struct kv_store *kv, const char *key, const void *val, uint8_t val_len) {
    if (!kv || !kv->mounted || !key || (val_len > 0 && !val) || val_len > KV_MAX_VAL_LEN) {
        return -1;
    }
    uint32_t klen = kv_strlen(key);
    if (klen == 0 || klen > KV_MAX_KEY_LEN) {
        return -1;
    }
    if (kv_find_slot(kv, key, (uint8_t)klen) < 0 && kv->entry_count >= KV_MAX_ENTRIES) {
        return -3;
    }
    return kv_append_record(kv, KV_FLAG_ACTIVE, key, (uint8_t)klen,
                            (const uint8_t *)val, val_len);
}

int kv_get(const struct kv_store *kv, const char *key, void *out, uint8_t out_cap,
           uint8_t *actual_len) {
    if (!kv || !kv->mounted || !key) return -1;
    uint32_t klen = kv_strlen(key);
    if (klen == 0 || klen > KV_MAX_KEY_LEN) return -1;
    int slot = kv_find_slot(kv, key, (uint8_t)klen);
    if (slot < 0) return -4; /* not found */
    const struct kv_entry_meta *e = &kv->entries[slot];
    if (actual_len) *actual_len = e->val_len;
    if (e->val_len > out_cap) return -1;
    if (e->val_len > 0) {
        if (!out) return -1;
        if (kv->backend.read(e->val_offset, (uint8_t *)out, e->val_len, kv->backend.ctx) != 0) {
            return -2;
        }
    }
    return 0;
}

int kv_delete(struct kv_store *kv, const char *key) {
    if (!kv || !kv->mounted || !key) return -1;
    uint32_t klen = kv_strlen(key);
    if (klen == 0 || klen > KV_MAX_KEY_LEN) return -1;
    if (kv_find_slot(kv, key, (uint8_t)klen) < 0) return -4;
    return kv_append_record(kv, KV_FLAG_TOMBSTONE, key, (uint8_t)klen, NULL, 0);
}

bool kv_exists(const struct kv_store *kv, const char *key) {
    if (!kv || !kv->mounted || !key) return false;
    uint32_t klen = kv_strlen(key);
    if (klen == 0 || klen > KV_MAX_KEY_LEN) return false;
    return kv_find_slot(kv, key, (uint8_t)klen) >= 0;
}

uint32_t kv_count(const struct kv_store *kv) {
    return (kv && kv->mounted) ? kv->entry_count : 0;
}

uint32_t kv_free_bytes(const struct kv_store *kv) {
    if (!kv || !kv->mounted || kv->write_cursor >= kv->backend.capacity) return 0;
    return kv->backend.capacity - kv->write_cursor;
}

int kv_compact(struct kv_store *kv, uint8_t *scratch, uint32_t scratch_cap) {
    if (!kv || !kv->mounted || !kv->backend.erase || !scratch) {
        return -1;
    }
    /* Serialize all live entries into scratch buffer first. */
    uint32_t out_off = 0;
    for (uint32_t i = 0; i < KV_MAX_ENTRIES; i++) {
        if (!kv->entries[i].valid) continue;
        const struct kv_entry_meta *e = &kv->entries[i];
        uint32_t rec_len = KV_REC_HDR_LEN + (uint32_t)e->key_len + (uint32_t)e->val_len + KV_REC_CRC_LEN;
        if (out_off + rec_len > scratch_cap || out_off + rec_len > kv->backend.capacity) {
            return -3;
        }
        uint8_t *rec = &scratch[out_off];
        rec[0] = KV_REC_MAGIC_0;
        rec[1] = KV_REC_MAGIC_1;
        rec[2] = KV_FLAG_ACTIVE;
        rec[3] = e->key_len;
        rec[4] = e->val_len;
        for (uint8_t k = 0; k < e->key_len; k++) rec[KV_REC_HDR_LEN + k] = (uint8_t)e->key[k];
        if (e->val_len > 0 &&
            kv->backend.read(e->val_offset, &rec[KV_REC_HDR_LEN + e->key_len],
                             e->val_len, kv->backend.ctx) != 0) {
            return -2;
        }
        uint32_t crc = proto_crc32(rec, rec_len - KV_REC_CRC_LEN);
        kv_wr_le32(&rec[rec_len - KV_REC_CRC_LEN], crc);
        out_off += rec_len;
    }

    if (kv->backend.erase(kv->backend.ctx) != 0) {
        return -2;
    }
    if (out_off > 0 && kv->backend.write(0, scratch, out_off, kv->backend.ctx) != 0) {
        return -2;
    }
    return kv_mount(kv, &kv->backend);
}

int kv_set_u32(struct kv_store *kv, const char *key, uint32_t value) {
    uint8_t buf[4];
    kv_wr_le32(buf, value);
    return kv_set(kv, key, buf, 4);
}

bool kv_get_u32(const struct kv_store *kv, const char *key, uint32_t *out) {
    if (!out) return false;
    uint8_t buf[4];
    uint8_t len = 0;
    if (kv_get(kv, key, buf, 4, &len) != 0 || len != 4) {
        return false;
    }
    *out = kv_rd_le32(buf);
    return true;
}
