#include "../../board.h"
#include "../../driver.h"
#include "../../drivers/plic.h"
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

int board_init(void) {
    if (plic_init(0x0c000000u, 0, 95) != 0 ||
        driver_register(&uart16550_driver) != 0 || device_register(&uart) != 0) {
        return -1;
    }
    drivers_probe();
    return uart.bound == &uart16550_driver ? 0 : -1;
}

int board_console_rx_irq(void) {
    return uart16550_enable_rx_irq(&uart);
}
