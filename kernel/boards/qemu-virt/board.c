#include "../../board.h"
#include "../../driver.h"
#include "../../arch/riscv/riscv.h"
#include "../../drivers/goldfish_rtc.h"
#include "../../drivers/plic.h"
#include "../../drivers/sifive_test.h"
#include "../../drivers/uart16550.h"

const struct board_timer_config board_timer = {
    .time = 0x0200bff8u,
    .compare = 0x02004000u,
    .frequency = 10000000u,
};

static struct device uart = {
    .name = "uart0",
    .driver = UART16550_DRIVER_NAME,
    .base = 0x10000000u,
    .irq = 10,
};

static struct device rtc = {
    .name = "rtc0",
    .driver = GOLDFISH_RTC_DRIVER_NAME,
    .base = 0x00101000u,
    .irq = 11,
};

static struct device syscon = {
    .name = "syscon0",
    .driver = SIFIVE_TEST_DRIVER_NAME,
    .base = 0x00100000u,
    .irq = -1,
};

int board_init(void) {
    if (plic_init(0x0c000000u, 0, 95) != 0 ||
        driver_register(&uart16550_driver) != 0 || device_register(&uart) != 0 ||
        driver_register(&goldfish_rtc_driver) != 0 || device_register(&rtc) != 0 ||
        driver_register(&sifive_test_driver) != 0 || device_register(&syscon) != 0) {
        return -1;
    }
    drivers_probe();
    return uart.bound == &uart16550_driver && rtc.bound == &goldfish_rtc_driver &&
           syscon.bound == &sifive_test_driver ? 0 : -1;
}

int board_console_rx_irq(void (*notify)(void *), void *context) {
    return uart16550_enable_rx_irq(&uart, notify, context);
}

static _Noreturn void park_hart(void) {
    clear_csr(mstatus, MSTATUS_MIE);
    write_csr(mie, 0u);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

_Noreturn void board_poweroff(void) {
    clear_csr(mstatus, MSTATUS_MIE);
    (void)sifive_test_poweroff();
    park_hart();
}

_Noreturn void board_reboot(void) {
    clear_csr(mstatus, MSTATUS_MIE);
    (void)sifive_test_reboot();
    park_hart();
}
