/* Runtime check for SpellboundFit proto, notify/nav services and shell on RV32 QEMU virt. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/console.h"
#include "../kernel/input.h"
#include "../kernel/kmem.h"
#include "../kernel/notify.h"
#include "../kernel/proto.h"
#include "../kernel/sensor.h"
#include "../kernel/shell.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"

static uint8_t heap_buf[4096];
static uint8_t tx_buf[64];
static uint32_t tx_len;
static uint32_t shell_bytes;

static int capture_tx(const uint8_t *data, uint32_t len, void *ctx) {
    (void)ctx;
    tx_len = len > sizeof tx_buf ? (uint32_t)sizeof tx_buf : len;
    for (uint32_t i = 0; i < tx_len; i++) tx_buf[i] = data[i];
    return 0;
}

static void capture_shell_puts(const char *s, void *ctx) {
    (void)ctx;
    while (*s++) shell_bytes++;
}

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);
    kmem_init(heap_buf, sizeof heap_buf);
    notify_reset();

    /* Encode PING, feed byte-by-byte through decoder, dispatch -> expect PONG */
    uint8_t wire[32];
    int n = proto_encode(wire, sizeof wire, PROTO_PING, 7, NULL, 0);
    if (n <= 0) failures++;

    struct proto_decoder dec;
    struct proto_frame frame;
    proto_decoder_init(&dec);
    int got = 0;
    for (int i = 0; i < n; i++) {
        got = proto_decoder_feed(&dec, wire[i], &frame);
    }
    struct proto_tx tx = {.send = capture_tx};
    if (got != 1 || proto_dispatch(&frame, &tx, NULL, NULL) != 0 ||
        tx_len != 12u || tx_buf[3] != PROTO_PONG) {
        failures++;
    }

    /* Run shell commands manipulating notifications and Roadstr nav */
    struct shell_state sh;
    struct shell_io io = {.puts = capture_shell_puts};
    shell_init(&sh, &io, false);
    if (shell_exec_line(&sh, "notify add 42 Roadstr \"Turn\" \"Left in 200m\"") != 0 ||
        notify_count() != 1 ||
        shell_exec_line(&sh, "nav set 3 200 5 \"Via Roma\"") != 0) {
        failures++;
    }
    struct nav_state nav;
    if (!nav_get(&nav) || nav.maneuver != NAV_LEFT || nav.distance_m != 200u ||
        shell_exec_line(&sh, "help") != 0 || shell_bytes == 0) {
        failures++;
    }

    console_puts(failures ? "FAIL: services, proto and shell\n" :
                            "PASS: services, proto and shell\n");
    board_poweroff();
}
