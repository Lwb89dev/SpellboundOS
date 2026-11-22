/* Freestanding interactive console command shell for SpellboundOS. */
#ifndef SPELLBOUND_SHELL_H
#define SPELLBOUND_SHELL_H

#include <stdbool.h>
#include <stdint.h>

#define SHELL_LINE_MAX      128u
#define SHELL_MAX_ARGS      12u
#define SHELL_MAX_EXTRA_CMD 12u

struct shell_io {
    void (*puts)(const char *s, void *ctx);
    void *ctx;
};

struct shell_cmd {
    const char *name;
    const char *help;
    int (*fn)(int argc, char **argv, const struct shell_io *io);
};

struct shell_state {
    struct shell_io io;
    bool echo;
    char line[SHELL_LINE_MAX];
    uint32_t line_len;
    const struct shell_cmd *extra_cmds[SHELL_MAX_EXTRA_CMD];
    uint32_t extra_count;
    uint32_t commands_run;
};

void shell_init(struct shell_state *sh, const struct shell_io *io, bool echo);
int shell_register_cmd(struct shell_state *sh, const struct shell_cmd *cmd);
void shell_prompt(const struct shell_state *sh);

/* Feed one received serial byte (handles editing, CR/LF execution, echo). */
void shell_feed_char(struct shell_state *sh, char c);

/* Parse and execute one command line immediately. Returns command status or -1. */
int shell_exec_line(struct shell_state *sh, const char *line);

#endif /* SPELLBOUND_SHELL_H */
