/* Freestanding interactive console command shell for SpellboundOS. */
#include "shell.h"
#include "driver.h"
#include "input.h"
#include "kmem.h"
#include "notify.h"
#include "rtc.h"
#include "sensor.h"
#include <stddef.h>

#ifndef SPELLBOUND_HOST_TEST
#include "board.h"
#include "arch/riscv/timer.h"
#endif

static void sh_puts(const struct shell_io *io, const char *s) {
    if (io && io->puts && s) {
        io->puts(s, io->ctx);
    }
}

static void sh_put_u32(const struct shell_io *io, uint32_t v) {
    char buf[12];
    unsigned n = 0;
    if (v == 0) {
        buf[n++] = '0';
    } else {
        char rev[12];
        while (v > 0) {
            rev[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        for (unsigned i = 0; i < n; i++) {
            buf[i] = rev[n - 1u - i];
        }
    }
    buf[n] = '\0';
    sh_puts(io, buf);
}

static void sh_put_2d(const struct shell_io *io, uint8_t v) {
    char buf[3] = {
        (char)('0' + (v / 10u) % 10u),
        (char)('0' + (v % 10u)),
        '\0',
    };
    sh_puts(io, buf);
}

static bool sh_streq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (*a != *b) return false;
        a++; b++;
    }
    return *a == *b;
}

static bool sh_parse_u32(const char *s, uint32_t *out) {
    if (!s || !*s || !out) return false;
    uint32_t v = 0;
    while (*s) {
        if (*s < '0' || *s > '9') return false;
        uint32_t d = (uint32_t)(*s - '0');
        if (v > (0xFFFFFFFFu - d) / 10u) return false;
        v = v * 10u + d;
        s++;
    }
    *out = v;
    return true;
}

/* ---- Built-in commands ---- */

static int cmd_uptime(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    uint64_t t = timer_ticks();
    sh_puts(io, "uptime ticks: ");
    sh_put_u32(io, (uint32_t)t);
    sh_puts(io, "\n");
    return 0;
}

static int cmd_date(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    if (!rtc_is_bound()) {
        sh_puts(io, "rtc: unbound\n");
        return -1;
    }
    struct rtc_datetime dt;
    rtc_unix_to_datetime(rtc_read_sec(), &dt);
    sh_put_u32(io, dt.year);
    sh_puts(io, "-"); sh_put_2d(io, dt.month);
    sh_puts(io, "-"); sh_put_2d(io, dt.day);
    sh_puts(io, " "); sh_put_2d(io, dt.hour);
    sh_puts(io, ":"); sh_put_2d(io, dt.minute);
    sh_puts(io, ":"); sh_put_2d(io, dt.second);
    sh_puts(io, " UTC\n");
    return 0;
}

static int cmd_heap(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    struct kmem_stats st;
    kmem_get_stats(&st);
    sh_puts(io, "heap: free ");
    sh_put_u32(io, st.free_bytes);
    sh_puts(io, " B in ");
    sh_put_u32(io, st.free_blocks);
    sh_puts(io, " blocks (total ");
    sh_put_u32(io, st.total);
    sh_puts(io, " B)\n");
    return 0;
}

static int cmd_drivers(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    sh_puts(io, "devices registered: ");
    sh_put_u32(io, (uint32_t)device_count());
    sh_puts(io, "\n");
    return 0;
}

static int cmd_sensors(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    sh_puts(io, "sensors: pending=");
    sh_put_u32(io, sensor_pending());
    sh_puts(io, " dropped=");
    sh_put_u32(io, sensor_dropped());
    sh_puts(io, "\n");
    return 0;
}

static int cmd_input(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    sh_puts(io, "input: pending=");
    sh_put_u32(io, input_pending());
    sh_puts(io, " dropped=");
    sh_put_u32(io, input_dropped());
    sh_puts(io, "\n");
    return 0;
}

static int cmd_notify(int argc, char **argv, const struct shell_io *io) {
    if (argc < 2 || sh_streq(argv[1], "list")) {
        uint32_t n = notify_count();
        sh_puts(io, "notifications: ");
        sh_put_u32(io, n);
        sh_puts(io, " (unread ");
        sh_put_u32(io, notify_unread_count());
        sh_puts(io, ")\n");
        for (uint32_t i = 0; i < n; i++) {
            struct notification item;
            if (notify_get_at(i, &item)) {
                sh_puts(io, "  #");
                sh_put_u32(io, item.id);
                sh_puts(io, " ["); sh_puts(io, item.app); sh_puts(io, "] ");
                sh_puts(io, item.title); sh_puts(io, ": ");
                sh_puts(io, item.body); sh_puts(io, "\n");
            }
        }
        return 0;
    }
    if (sh_streq(argv[1], "add") && argc >= 6) {
        uint32_t id = 0;
        if (!sh_parse_u32(argv[2], &id) || id == 0) {
            sh_puts(io, "notify: invalid id\n");
            return -1;
        }
        struct notification item = {.id = id, .unread = true};
        for (uint32_t i = 0; i + 1u < NOTIFY_APP_MAX && argv[3][i]; i++) item.app[i] = argv[3][i];
        for (uint32_t i = 0; i + 1u < NOTIFY_TITLE_MAX && argv[4][i]; i++) item.title[i] = argv[4][i];
        for (uint32_t i = 0; i + 1u < NOTIFY_BODY_MAX && argv[5][i]; i++) item.body[i] = argv[5][i];
        if (notify_post(&item) != 0) return -1;
        sh_puts(io, "notify: posted #"); sh_put_u32(io, id); sh_puts(io, "\n");
        return 0;
    }
    if (sh_streq(argv[1], "dismiss") && argc >= 3) {
        uint32_t id = 0;
        if (!sh_parse_u32(argv[2], &id)) return -1;
        sh_puts(io, notify_dismiss(id) ? "notify: dismissed\n" : "notify: not found\n");
        return 0;
    }
    if (sh_streq(argv[1], "clear")) {
        notify_clear_all();
        sh_puts(io, "notify: cleared\n");
        return 0;
    }
    sh_puts(io, "usage: notify [list|add <id> <app> <title> <body>|dismiss <id>|clear]\n");
    return -1;
}

static int cmd_nav(int argc, char **argv, const struct shell_io *io) {
    if (argc < 2 || sh_streq(argv[1], "status")) {
        struct nav_state st;
        if (!nav_get(&st)) {
            sh_puts(io, "nav: inactive\n");
            return 0;
        }
        sh_puts(io, "nav: ");
        sh_puts(io, nav_maneuver_name((enum nav_maneuver)st.maneuver));
        sh_puts(io, " in "); sh_put_u32(io, st.distance_m);
        sh_puts(io, "m onto "); sh_puts(io, st.street);
        sh_puts(io, " (ETA "); sh_put_u32(io, st.eta_min); sh_puts(io, "m)\n");
        return 0;
    }
    if (sh_streq(argv[1], "set") && argc >= 6) {
        uint32_t m = 0, dist = 0, eta = 0;
        if (!sh_parse_u32(argv[2], &m) || !sh_parse_u32(argv[3], &dist) ||
            !sh_parse_u32(argv[4], &eta)) {
            sh_puts(io, "nav: invalid numeric argument\n");
            return -1;
        }
        struct nav_state st = {
            .active = true,
            .maneuver = (uint8_t)m,
            .distance_m = dist,
            .eta_min = (uint16_t)eta,
        };
        for (uint32_t i = 0; i + 1u < NAV_STREET_MAX && argv[5][i]; i++) st.street[i] = argv[5][i];
        nav_update(&st);
        sh_puts(io, "nav: updated\n");
        return 0;
    }
    if (sh_streq(argv[1], "clear")) {
        nav_clear();
        sh_puts(io, "nav: cleared\n");
        return 0;
    }
    sh_puts(io, "usage: nav [status|set <maneuver> <dist_m> <eta_min> <street>|clear]\n");
    return -1;
}

static int cmd_poweroff(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    sh_puts(io, "powering off...\n");
    board_poweroff();
    return 0;
}

static int cmd_reboot(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    sh_puts(io, "rebooting...\n");
    board_reboot();
    return 0;
}

static const struct shell_cmd builtin_cmds[] = {
    {"uptime",   "show timer ticks",           cmd_uptime},
    {"date",     "show UTC RTC time",          cmd_date},
    {"heap",     "show kernel heap stats",     cmd_heap},
    {"drivers",  "show device count",          cmd_drivers},
    {"sensors",  "show sensor queue stats",    cmd_sensors},
    {"input",    "show input queue stats",     cmd_input},
    {"notify",   "inspect/manage alerts",      cmd_notify},
    {"nav",      "inspect/manage Roadstr nav", cmd_nav},
    {"poweroff", "power off board",            cmd_poweroff},
    {"reboot",   "reboot board",               cmd_reboot},
};

void shell_init(struct shell_state *sh, const struct shell_io *io, bool echo) {
    if (!sh) return;
    sh->io = io ? *io : (struct shell_io){0};
    sh->echo = echo;
    sh->line[0] = '\0';
    sh->line_len = 0;
    sh->extra_count = 0;
    sh->commands_run = 0;
}

int shell_register_cmd(struct shell_state *sh, const struct shell_cmd *cmd) {
    if (!sh || !cmd || !cmd->name || !cmd->fn || sh->extra_count >= SHELL_MAX_EXTRA_CMD) {
        return -1;
    }
    sh->extra_cmds[sh->extra_count++] = cmd;
    return 0;
}

void shell_prompt(const struct shell_state *sh) {
    if (sh) {
        sh_puts(&sh->io, "sbos> ");
    }
}

static int tokenize(char *buf, char **argv, int max_args) {
    int argc = 0;
    char *p = buf;
    while (*p && argc < max_args) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (*p == '"') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        } else {
            argv[argc++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }
    }
    return argc;
}

int shell_exec_line(struct shell_state *sh, const char *line) {
    if (!sh || !line) return -1;
    char copy[SHELL_LINE_MAX];
    uint32_t i = 0;
    while (i + 1u < SHELL_LINE_MAX && line[i] != '\0') {
        copy[i] = line[i];
        i++;
    }
    copy[i] = '\0';

    char *argv[SHELL_MAX_ARGS];
    int argc = tokenize(copy, argv, SHELL_MAX_ARGS);
    if (argc == 0) {
        return 0;
    }

    if (sh_streq(argv[0], "help")) {
        sh_puts(&sh->io, "commands:\n");
        for (unsigned k = 0; k < sizeof builtin_cmds / sizeof builtin_cmds[0]; k++) {
            sh_puts(&sh->io, "  ");
            sh_puts(&sh->io, builtin_cmds[k].name);
            sh_puts(&sh->io, " - ");
            sh_puts(&sh->io, builtin_cmds[k].help);
            sh_puts(&sh->io, "\n");
        }
        for (uint32_t k = 0; k < sh->extra_count; k++) {
            sh_puts(&sh->io, "  ");
            sh_puts(&sh->io, sh->extra_cmds[k]->name);
            sh_puts(&sh->io, " - ");
            sh_puts(&sh->io, sh->extra_cmds[k]->help ? sh->extra_cmds[k]->help : "");
            sh_puts(&sh->io, "\n");
        }
        sh->commands_run++;
        return 0;
    }

    for (unsigned k = 0; k < sizeof builtin_cmds / sizeof builtin_cmds[0]; k++) {
        if (sh_streq(argv[0], builtin_cmds[k].name)) {
            sh->commands_run++;
            return builtin_cmds[k].fn(argc, argv, &sh->io);
        }
    }
    for (uint32_t k = 0; k < sh->extra_count; k++) {
        if (sh_streq(argv[0], sh->extra_cmds[k]->name)) {
            sh->commands_run++;
            return sh->extra_cmds[k]->fn(argc, argv, &sh->io);
        }
    }

    sh_puts(&sh->io, "unknown command: ");
    sh_puts(&sh->io, argv[0]);
    sh_puts(&sh->io, "\n");
    return -1;
}

void shell_feed_char(struct shell_state *sh, char c) {
    if (!sh) return;
    if (c == '\r' || c == '\n') {
        if (sh->echo) sh_puts(&sh->io, "\n");
        sh->line[sh->line_len] = '\0';
        if (sh->line_len > 0) {
            (void)shell_exec_line(sh, sh->line);
            sh->line_len = 0;
        }
        shell_prompt(sh);
        return;
    }
    if (c == '\b' || (unsigned char)c == 0x7Fu) {
        if (sh->line_len > 0) {
            sh->line_len--;
            if (sh->echo) sh_puts(&sh->io, "\b \b");
        }
        return;
    }
    if ((unsigned char)c >= 0x20u && (unsigned char)c <= 0x7Eu) {
        if (sh->line_len + 1u < SHELL_LINE_MAX) {
            sh->line[sh->line_len++] = c;
            if (sh->echo) {
                char s[2] = {c, '\0'};
                sh_puts(&sh->io, s);
            }
        }
    }
}
