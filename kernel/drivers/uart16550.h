#ifndef SPELLBOUND_UART16550_H
#define SPELLBOUND_UART16550_H

#include "../driver.h"

#define UART16550_DRIVER_NAME "uart16550"
extern const struct driver uart16550_driver;
int uart16550_enable_rx_irq(struct device *dev);

#endif
