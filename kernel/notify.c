/* Watch services: notification store, Roadstr navigation state and call state. */
#include "notify.h"
#include <stddef.h>

#ifndef SPELLBOUND_HOST_TEST
#include "arch/riscv/riscv.h"
#endif

static struct notification notif_items[NOTIFY_MAX_ITEMS];
static uint32_t notif_len;
static notify_action_cb action_cb;
static void *action_cb_ctx;

static struct nav_state current_nav;
static struct call_info current_call;

static void copy_cstr(char *dst, uint32_t dst_cap, const char *src) {
    if (dst_cap == 0) return;
    uint32_t i = 0;
    if (src) {
        while (i + 1u < dst_cap && src[i] != '\0') {
            dst[i] = src[i];
            i++;
        }
    }
    dst[i] = '\0';
}

static void sanitize_notification(struct notification *dst, const struct notification *src) {
    dst->id = src->id;
    dst->timestamp_sec = src->timestamp_sec;
    dst->unread = src->unread;
    copy_cstr(dst->app, NOTIFY_APP_MAX, src->app);
    copy_cstr(dst->title, NOTIFY_TITLE_MAX, src->title);
    copy_cstr(dst->body, NOTIFY_BODY_MAX, src->body);
    uint8_t cnt = src->action_count;
    if (cnt > NOTIFY_MAX_ACTIONS) cnt = NOTIFY_MAX_ACTIONS;
    dst->action_count = cnt;
    for (uint8_t i = 0; i < NOTIFY_MAX_ACTIONS; i++) {
        if (i < cnt) {
            copy_cstr(dst->actions[i], NOTIFY_ACTION_MAX, src->actions[i]);
        } else {
            dst->actions[i][0] = '\0';
        }
    }
}

void notify_reset(void) {
    uint32_t prev = irq_save();
    notif_len = 0;
    action_cb = NULL;
    action_cb_ctx = NULL;
    current_nav = (struct nav_state){0};
    current_call = (struct call_info){0};
    irq_restore(prev);
}

int notify_post(const struct notification *n) {
    if (!n || n->id == 0) {
        return -1;
    }
    uint32_t prev = irq_save();
    /* If ID exists, remove old slot so the updated copy moves to index 0 (newest). */
    for (uint32_t i = 0; i < notif_len; i++) {
        if (notif_items[i].id == n->id) {
            for (uint32_t j = i; j + 1u < notif_len; j++) {
                notif_items[j] = notif_items[j + 1u];
            }
            notif_len--;
            break;
        }
    }
    /* Shift right to make room at index 0; drop oldest if full. */
    uint32_t keep = notif_len < NOTIFY_MAX_ITEMS ? notif_len : (NOTIFY_MAX_ITEMS - 1u);
    for (uint32_t i = keep; i > 0; i--) {
        notif_items[i] = notif_items[i - 1u];
    }
    sanitize_notification(&notif_items[0], n);
    notif_len = keep + 1u;
    irq_restore(prev);
    return 0;
}

bool notify_dismiss(uint32_t id) {
    uint32_t prev = irq_save();
    bool found = false;
    for (uint32_t i = 0; i < notif_len; i++) {
        if (notif_items[i].id == id) {
            for (uint32_t j = i; j + 1u < notif_len; j++) {
                notif_items[j] = notif_items[j + 1u];
            }
            notif_len--;
            found = true;
            break;
        }
    }
    irq_restore(prev);
    return found;
}

void notify_clear_all(void) {
    uint32_t prev = irq_save();
    notif_len = 0;
    irq_restore(prev);
}

bool notify_mark_read(uint32_t id) {
    uint32_t prev = irq_save();
    bool found = false;
    for (uint32_t i = 0; i < notif_len; i++) {
        if (notif_items[i].id == id) {
            notif_items[i].unread = false;
            found = true;
            break;
        }
    }
    irq_restore(prev);
    return found;
}

uint32_t notify_count(void) {
    uint32_t prev = irq_save();
    uint32_t c = notif_len;
    irq_restore(prev);
    return c;
}

uint32_t notify_unread_count(void) {
    uint32_t prev = irq_save();
    uint32_t u = 0;
    for (uint32_t i = 0; i < notif_len; i++) {
        if (notif_items[i].unread) u++;
    }
    irq_restore(prev);
    return u;
}

bool notify_get_at(uint32_t index, struct notification *out) {
    if (!out) return false;
    uint32_t prev = irq_save();
    bool ok = false;
    if (index < notif_len) {
        *out = notif_items[index];
        ok = true;
    }
    irq_restore(prev);
    return ok;
}

bool notify_find(uint32_t id, struct notification *out) {
    if (!out) return false;
    uint32_t prev = irq_save();
    bool ok = false;
    for (uint32_t i = 0; i < notif_len; i++) {
        if (notif_items[i].id == id) {
            *out = notif_items[i];
            ok = true;
            break;
        }
    }
    irq_restore(prev);
    return ok;
}

void notify_set_action_cb(notify_action_cb cb, void *ctx) {
    uint32_t prev = irq_save();
    action_cb = cb;
    action_cb_ctx = ctx;
    irq_restore(prev);
}

bool notify_trigger_action(uint32_t id, uint8_t action_index) {
    uint32_t prev = irq_save();
    notify_action_cb cb = NULL;
    void *ctx = NULL;
    char label[NOTIFY_ACTION_MAX] = {0};
    bool ok = false;
    for (uint32_t i = 0; i < notif_len; i++) {
        if (notif_items[i].id == id) {
            if (action_index < notif_items[i].action_count) {
                copy_cstr(label, NOTIFY_ACTION_MAX, notif_items[i].actions[action_index]);
                notif_items[i].unread = false;
                cb = action_cb;
                ctx = action_cb_ctx;
                ok = true;
            }
            break;
        }
    }
    irq_restore(prev);
    if (ok && cb) {
        cb(id, action_index, label, ctx);
    }
    return ok;
}

/* ---- Roadstr turn-by-turn navigation ---- */

void nav_update(const struct nav_state *state) {
    if (!state) return;
    uint32_t prev = irq_save();
    uint32_t next_rev = current_nav.revision + 1u;
    current_nav.active = state->active;
    current_nav.maneuver = state->maneuver <= NAV_ARRIVE ? state->maneuver : NAV_NONE;
    current_nav.roundabout_exit = state->roundabout_exit;
    current_nav.distance_m = state->distance_m;
    current_nav.eta_min = state->eta_min;
    current_nav.revision = next_rev;
    copy_cstr(current_nav.street, NAV_STREET_MAX, state->street);
    copy_cstr(current_nav.next_street, NAV_NEXT_MAX, state->next_street);
    irq_restore(prev);
}

void nav_clear(void) {
    uint32_t prev = irq_save();
    uint32_t next_rev = current_nav.revision + 1u;
    current_nav = (struct nav_state){0};
    current_nav.revision = next_rev;
    irq_restore(prev);
}

bool nav_get(struct nav_state *out) {
    if (!out) return false;
    uint32_t prev = irq_save();
    *out = current_nav;
    bool active = current_nav.active;
    irq_restore(prev);
    return active;
}

const char *nav_maneuver_name(enum nav_maneuver m) {
    switch (m) {
    case NAV_NONE:         return "NONE";
    case NAV_STRAIGHT:     return "STRAIGHT";
    case NAV_SLIGHT_LEFT:  return "SLIGHT LEFT";
    case NAV_LEFT:         return "TURN LEFT";
    case NAV_SHARP_LEFT:   return "SHARP LEFT";
    case NAV_SLIGHT_RIGHT: return "SLIGHT RIGHT";
    case NAV_RIGHT:        return "TURN RIGHT";
    case NAV_SHARP_RIGHT:  return "SHARP RIGHT";
    case NAV_UTURN:        return "U-TURN";
    case NAV_ROUNDABOUT:   return "ROUNDABOUT";
    case NAV_ARRIVE:       return "ARRIVE";
    }
    return "UNKNOWN";
}

/* ---- Call info ---- */

void call_update(const struct call_info *info) {
    if (!info) return;
    uint32_t prev = irq_save();
    current_call.state = info->state <= CALL_ACTIVE ? info->state : CALL_IDLE;
    copy_cstr(current_call.caller, CALL_CALLER_MAX, info->caller);
    copy_cstr(current_call.number, CALL_NUMBER_MAX, info->number);
    irq_restore(prev);
}

bool call_get(struct call_info *out) {
    if (!out) return false;
    uint32_t prev = irq_save();
    *out = current_call;
    bool active = current_call.state != CALL_IDLE;
    irq_restore(prev);
    return active;
}
