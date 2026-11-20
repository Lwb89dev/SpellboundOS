/* Device/driver registry: fixed tables, name matching, one probe pass. */
#include "driver.h"
#include <stddef.h>

#define MAX_DRIVERS 16
#define MAX_DEVICES 16

static const struct driver *drivers[MAX_DRIVERS];
static int driver_n;
static struct device *devices[MAX_DEVICES];
static int device_n;

static int str_eq(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return a == b;
    }
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return *a == *b;
}

int driver_register(const struct driver *drv) {
    if (driver_n >= MAX_DRIVERS || drv == NULL || drv->name == NULL ||
        drv->name[0] == '\0') {
        return -1;
    }
    for (int i = 0; i < driver_n; i++) {
        if (str_eq(drivers[i]->name, drv->name)) return -1;
    }
    drivers[driver_n++] = drv;
    return 0;
}

int device_register(struct device *dev) {
    if (device_n >= MAX_DEVICES || dev == NULL || dev->name == NULL ||
        dev->name[0] == '\0' || dev->driver == NULL || dev->driver[0] == '\0') {
        return -1;
    }
    for (int i = 0; i < device_n; i++) {
        if (devices[i] == dev || str_eq(devices[i]->name, dev->name)) return -1;
    }
    dev->bound = NULL;
    devices[device_n++] = dev;
    return 0;
}

static const struct driver *find_driver(const char *name) {
    for (int i = 0; i < driver_n; i++) {
        if (str_eq(drivers[i]->name, name)) {
            return drivers[i];
        }
    }
    return NULL;
}

int drivers_probe(void) {
    int bound = 0;
    for (int i = 0; i < device_n; i++) {
        struct device *dev = devices[i];
        if (dev->bound != NULL) {
            continue;
        }
        const struct driver *drv = find_driver(dev->driver);
        if (drv == NULL) {
            continue;
        }
        int rc = drv->probe ? drv->probe(dev) : 0;
        if (rc == 0) {
            dev->bound = drv;
            bound++;
        }
    }
    return bound;
}

struct device *device_find(const char *name) {
    for (int i = 0; i < device_n; i++) {
        if (str_eq(devices[i]->name, name)) {
            return devices[i];
        }
    }
    return NULL;
}

int device_count(void) {
    return device_n;
}

void driver_registry_reset(void) {
    for (int i = 0; i < device_n; i++) {
        devices[i]->bound = NULL;
    }
    driver_n = 0;
    device_n = 0;
}
