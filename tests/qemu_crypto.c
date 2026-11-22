/* Runtime check for RTL8763 CRC16/SLIP, RFC 8439 ChaCha20-Poly1305 and secure_link on RV32. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/console.h"
#include "../kernel/crypto.h"
#include "../kernel/secure_link.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/rtl8763.h"

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    const uint8_t check[9] = {'1','2','3','4','5','6','7','8','9'};
    if (rtl8763_crc16_modbus(0xFFFFu, check, 9) != 0x4B37u) {
        failures++;
    }

    uint8_t psk[32], pn[16], wn[16];
    for (unsigned i = 0; i < 32u; i++) psk[i] = (uint8_t)(i + 1u);
    for (unsigned i = 0; i < 16u; i++) { pn[i] = (uint8_t)(0x10u + i); wn[i] = (uint8_t)(0x20u + i); }

    struct secure_session phone, watch;
    secure_session_init(&phone, SECURE_ROLE_PHONE, psk);
    secure_session_init(&watch, SECURE_ROLE_WATCH, psk);

    uint8_t hello[SECURE_HELLO_LEN], ack[SECURE_HELLO_ACK_LEN];
    uint8_t pkt[64], out[64];
    const uint8_t msg[8] = {'R','V','3','2','A','E','A','D'};

    if (secure_phone_build_hello(&phone, pn, hello) != SECURE_HELLO_LEN ||
        secure_watch_accept_hello(&watch, hello, sizeof hello, wn, ack) != SECURE_HELLO_ACK_LEN ||
        secure_phone_finish(&phone, ack, sizeof ack) != 0) {
        failures++;
    }
    int plen = secure_encrypt(&phone, msg, sizeof msg, pkt, sizeof pkt);
    if (plen <= 0 || secure_decrypt(&watch, pkt, (size_t)plen, out, sizeof out) != 8 ||
        !crypto_ct_eq(msg, out, 8) ||
        secure_decrypt(&watch, pkt, (size_t)plen, out, sizeof out) != -3) {
        failures++;
    }

    console_puts(failures ? "FAIL: RTL8763 and ChaCha20-Poly1305 secure link\n" :
                            "PASS: RTL8763 and ChaCha20-Poly1305 secure link\n");
    board_poweroff();
}
