/* Device/driver registration and binding. Drivers register by name; devices
 * name the driver they need; a probe pass binds each device to its driver.
 * Portable and freestanding so the registry logic is host-testable. */
#ifndef SPELLBOUND_DRIVER_H
#define SPELLBOUND_DRIVER_H

#include <stdint.h>

struct device;

struct driver {
    const char *name;
    int (*probe)(struct device *dev); /* 0 on success */
};

struct device {
    const char *name;           /* instance name, e.g. "imu0" */
    const char *driver;         /* driver name to bind */
    uintptr_t base;             /* MMIO base (board-specific) */
    int irq;                    /* interrupt line, or -1 */
    void *drvdata;              /* set by the driver's probe */
    const struct driver *bound; /* set once bound */
};

/* Objects and their names must remain valid until reset. Returns -1 for invalid
 * input, duplicate names, or a full table. Registration is not thread-safe. */
int driver_register(const struct driver *drv);
int device_register(struct device *dev);

/* Bind each unbound device to the driver whose name matches and call its probe.
 * Returns the number of devices successfully bound in this pass. */
int drivers_probe(void);

struct device *device_find(const char *name); /* NULL if unknown */
int device_count(void);

/* Clears bindings, but does not release driver resources or clear drvdata. */
void driver_registry_reset(void);

#endif /* SPELLBOUND_DRIVER_H */
