/* Watch services: notification store, Roadstr turn-by-turn navigation state and call info. */
#ifndef SPELLBOUND_NOTIFY_H
#define SPELLBOUND_NOTIFY_H

#include <stdbool.h>
#include <stdint.h>

#define NOTIFY_MAX_ITEMS    16u
#define NOTIFY_APP_MAX      24u
#define NOTIFY_TITLE_MAX    48u
#define NOTIFY_BODY_MAX     128u
#define NOTIFY_MAX_ACTIONS  4u
#define NOTIFY_ACTION_MAX   20u

#define NAV_STREET_MAX      64u
#define NAV_NEXT_MAX        48u
#define CALL_CALLER_MAX     48u
#define CALL_NUMBER_MAX     24u

struct notification {
    uint32_t id;
    uint64_t timestamp_sec;
    bool unread;
    char app[NOTIFY_APP_MAX];
    char title[NOTIFY_TITLE_MAX];
    char body[NOTIFY_BODY_MAX];
    uint8_t action_count;
    char actions[NOTIFY_MAX_ACTIONS][NOTIFY_ACTION_MAX];
};

typedef void (*notify_action_cb)(uint32_t notif_id, uint8_t action_index,
                                 const char *label, void *ctx);

void notify_reset(void);
int notify_post(const struct notification *n);
bool notify_dismiss(uint32_t id);
void notify_clear_all(void);
bool notify_mark_read(uint32_t id);
uint32_t notify_count(void);
uint32_t notify_unread_count(void);
/* Index 0 is the most recently posted/updated notification. */
bool notify_get_at(uint32_t index, struct notification *out);
bool notify_find(uint32_t id, struct notification *out);
void notify_set_action_cb(notify_action_cb cb, void *ctx);
bool notify_trigger_action(uint32_t id, uint8_t action_index);

/* ---- Roadstr turn-by-turn navigation state ---- */

enum nav_maneuver {
    NAV_NONE = 0,
    NAV_STRAIGHT = 1,
    NAV_SLIGHT_LEFT = 2,
    NAV_LEFT = 3,
    NAV_SHARP_LEFT = 4,
    NAV_SLIGHT_RIGHT = 5,
    NAV_RIGHT = 6,
    NAV_SHARP_RIGHT = 7,
    NAV_UTURN = 8,
    NAV_ROUNDABOUT = 9,
    NAV_ARRIVE = 10,
};

struct nav_state {
    bool active;
    uint8_t maneuver;
    uint8_t roundabout_exit;
    uint32_t distance_m;
    uint16_t eta_min;
    uint32_t revision;
    char street[NAV_STREET_MAX];
    char next_street[NAV_NEXT_MAX];
};

void nav_update(const struct nav_state *state);
void nav_clear(void);
bool nav_get(struct nav_state *out);
const char *nav_maneuver_name(enum nav_maneuver m);

/* ---- Incoming/active call state ---- */

enum call_state {
    CALL_IDLE = 0,
    CALL_RINGING = 1,
    CALL_ACTIVE = 2,
};

struct call_info {
    uint8_t state;
    char caller[CALL_CALLER_MAX];
    char number[CALL_NUMBER_MAX];
};

void call_update(const struct call_info *info);
bool call_get(struct call_info *out);

#endif /* SPELLBOUND_NOTIFY_H */
