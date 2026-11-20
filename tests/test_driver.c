/* Host unit test for the device/driver registry (kernel/driver.c). */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/driver.c"

static int probe_calls;
static struct device *last_probed;

static int ok_probe(struct device *dev) {
    probe_calls++;
    last_probed = dev;
    dev->drvdata = (void *)0x1234;
    return 0;
}

static int fail_probe(struct device *dev) {
    (void)dev;
    probe_calls++;
    return -1;
}

static const struct driver imu_drv = {.name = "lsm6dso", .probe = ok_probe};
static const struct driver touch_drv = {.name = "ztw622", .probe = fail_probe};

int main(void) {
    driver_registry_reset();
    probe_calls = 0;

    assert(driver_register(&imu_drv) == 0);
    assert(driver_register(&touch_drv) == 0);

    static struct device imu = {.name = "imu0", .driver = "lsm6dso", .base = 0x80f62000, .irq = 43};
    static struct device touch = {.name = "touch0", .driver = "ztw622", .base = 0x40000000, .irq = 21};
    static struct device gps = {.name = "gps0", .driver = "ag3335", .base = 0, .irq = -1};
    assert(device_register(&imu) == 0);
    assert(device_register(&touch) == 0);
    assert(device_register(&gps) == 0);
    assert(device_count() == 3);

    int bound = drivers_probe();
    /* imu binds (ok_probe), touch's probe fails, gps has no matching driver. */
    assert(bound == 1);
    assert(probe_calls == 2); /* imu + touch probes called; gps unmatched, not called */
    assert(imu.bound == &imu_drv);
    assert(imu.drvdata == (void *)0x1234);
    assert(touch.bound == NULL);
    assert(gps.bound == NULL);
    assert(last_probed == &imu);

    /* Lookup. */
    assert(device_find("imu0") == &imu);
    assert(device_find("touch0") == &touch);
    assert(device_find("nope") == NULL);
    assert(driver_register(&imu_drv) == -1);
    assert(device_register(&imu) == -1);
    struct device duplicate = {.name = "imu0", .driver = "lsm6dso"};
    struct device invalid = {.name = "invalid"};
    assert(device_register(&duplicate) == -1);
    assert(device_register(&invalid) == -1);
    assert(imu.bound == &imu_drv);

    /* A second probe pass does not re-probe the already-bound device. */
    int before = probe_calls;
    int bound2 = drivers_probe();
    assert(bound2 == 0);
    assert(probe_calls == before + 1); /* touch retried, imu skipped */

    driver_registry_reset();
    assert(device_count() == 0);
    assert(imu.bound == NULL);
    assert(driver_register(&imu_drv) == 0);
    assert(device_register(&imu) == 0);
    assert(drivers_probe() == 1);

    printf("PASS: driver registry bind/probe/lookup\n");
    return 0;
}
