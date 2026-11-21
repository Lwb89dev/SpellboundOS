/* SiFive Test syscon driver (QEMU virt poweroff/reboot finisher). */
#ifndef SPELLBOUND_SIFIVE_TEST_H
#define SPELLBOUND_SIFIVE_TEST_H

#include <stdint.h>
#include "../driver.h"

#define SIFIVE_TEST_DRIVER_NAME "sifive-test"
#define SIFIVE_TEST_FAIL 0x3333u
#define SIFIVE_TEST_PASS 0x5555u
#define SIFIVE_TEST_RESET 0x7777u

extern const struct driver sifive_test_driver;

int sifive_test_poweroff(void);
int sifive_test_reboot(void);
int sifive_test_fail(uint16_t code);

#endif /* SPELLBOUND_SIFIVE_TEST_H */
