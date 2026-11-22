CLANG ?= clang
LLD ?= ld.lld
OBJCOPY ?= llvm-objcopy
QEMU ?= qemu-system-riscv32
BUILD := build/qemu-virt
.DEFAULT_GOAL := all
CFLAGS := --target=riscv32-unknown-elf -march=rv32imac_zicsr -mabi=ilp32 -ffreestanding -fno-stack-protector -fno-pic -fno-builtin -Wall -Wextra -Werror -O2 -MMD -MP

BOOT_OBJS := $(addprefix $(BUILD)/,start.o kstring.o board.o plic.o ringbuf.o uart16550.o rtc.o goldfish_rtc.o sifive_test.o console.o driver.o)
OBJS := $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o main.o trap.o timer.o sched.o sync.o bus.o input.o gpio_keys.o sensor.o lsm6dso.o ztw622.o stk31e60.o charger.o motor.o fb.o icna3311.o notify.o proto.o shell.o power.o ui.o kv.o activity.o ag3335.o watch_app.o kmem.o)

-include $(wildcard $(BUILD)/*.d)

.PHONY: all qemu test test-host clean
all: $(BUILD)/spellbound.elf $(BUILD)/spellbound.bin

$(BUILD):
	mkdir -p $@

$(BUILD)/start.o: kernel/arch/riscv/start.S | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/kstring.o: kernel/kstring.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/board.o: kernel/boards/qemu-virt/board.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/uart16550.o: kernel/drivers/uart16550.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/plic.o: kernel/drivers/plic.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/ringbuf.o: kernel/ringbuf.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/rtc.o: kernel/rtc.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/goldfish_rtc.o: kernel/drivers/goldfish_rtc.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sifive_test.o: kernel/drivers/sifive_test.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/bus.o: kernel/bus.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/input.o: kernel/input.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/gpio_keys.o: kernel/drivers/gpio_keys.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sensor.o: kernel/sensor.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/lsm6dso.o: kernel/drivers/lsm6dso.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/ztw622.o: kernel/drivers/ztw622.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/stk31e60.o: kernel/drivers/stk31e60.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/charger.o: kernel/drivers/charger.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/motor.o: kernel/drivers/motor.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/fb.o: kernel/fb.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/icna3311.o: kernel/drivers/icna3311.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/notify.o: kernel/notify.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/proto.o: kernel/proto.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/shell.o: kernel/shell.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/power.o: kernel/power.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/ui.o: kernel/ui.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/kv.o: kernel/kv.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/activity.o: kernel/activity.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/ag3335.o: kernel/drivers/ag3335.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/watch_app.o: kernel/watch_app.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/trap_vector.o: kernel/arch/riscv/trap.S | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sched.o: kernel/sched.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sync.o: kernel/sync.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/kmem.o: kernel/kmem.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/driver.o: kernel/driver.c kernel/driver.h | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/main.o: kernel/main.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/scheduler_test.o: tests/qemu_scheduler.c kernel/sched.h | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/scheduler_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o scheduler_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/preemption_test.o: tests/qemu_preemption.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/preemption_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o preemption_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/timer_test.o: tests/qemu_timer.c kernel/arch/riscv/timer.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/timer_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o sched.o timer_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/heap_test.o: tests/qemu_heap.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/heap_test.elf: $(BOOT_OBJS) $(BUILD)/kmem.o $(BUILD)/heap_test.o kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/trap_test.o: tests/qemu_trap.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/trap_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o trap_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/plic_test.o: tests/qemu_plic.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/plic_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o plic_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/sync_test.o: tests/qemu_sync.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sync_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o sync_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/rtc_test.o: tests/qemu_rtc.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/rtc_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o rtc_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/input_test.o: tests/qemu_input.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/input_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o bus.o input.o gpio_keys.o input_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/sensors_test.o: tests/qemu_sensors.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sensors_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o bus.o input.o sensor.o lsm6dso.o ztw622.o sensors_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/display_test.o: tests/qemu_display.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/display_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o bus.o sensor.o stk31e60.o charger.o motor.o fb.o icna3311.o display_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/shell_test.o: tests/qemu_shell.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/shell_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o input.o sensor.o kmem.o notify.o proto.o shell.o shell_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/ui_test.o: tests/qemu_ui.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/ui_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o input.o fb.o icna3311.o notify.o proto.o power.o ui.o ui_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/activity_test.o: tests/qemu_activity.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/activity_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o sensor.o notify.o proto.o kv.o activity.o activity_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/watch_app_test.o: tests/qemu_watch_app.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/watch_app_test.elf: $(BOOT_OBJS) $(addprefix $(BUILD)/,trap_vector.o trap.o timer.o sched.o sync.o bus.o input.o sensor.o fb.o icna3311.o motor.o notify.o proto.o power.o ui.o kv.o activity.o ag3335.o watch_app.o watch_app_test.o) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/console.o: kernel/console.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/trap.o: kernel/arch/riscv/trap.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/timer.o: kernel/arch/riscv/timer.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/spellbound.elf: $(OBJS) kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(OBJS)

$(BUILD)/spellbound.bin: $(BUILD)/spellbound.elf
	$(OBJCOPY) -O binary $< $@

qemu: $(BUILD)/spellbound.elf
	$(QEMU) -machine virt -bios none -nographic -monitor none -kernel $<

test: all $(addprefix $(BUILD)/,scheduler_test.elf preemption_test.elf timer_test.elf heap_test.elf trap_test.elf plic_test.elf sync_test.elf rtc_test.elf input_test.elf sensors_test.elf display_test.elf shell_test.elf ui_test.elf activity_test.elf watch_app_test.elf)
	python3 tests/qemu_boot.py $(QEMU) $(BUILD)/spellbound.elf
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/scheduler_test.elf 'scheduler lifecycle'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/preemption_test.elf 'timer preemption'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/timer_test.elf 'timer rollover'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/heap_test.elf 'heap boundaries'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/trap_test.elf 'illegal instruction' 'trap: mcause=0x00000002 mepc=0x8[0-9a-f]{7} mtval=0x00000000'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/plic_test.elf 'PLIC UART interrupts'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/sync_test.elf 'sync mutex and msgq'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/rtc_test.elf 'Goldfish RTC and alarm'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/input_test.elf 'bus, input and syscon'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/sensors_test.elf 'LSM6DSO and ZTW622 drivers'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/display_test.elf 'peripherals and display'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/shell_test.elf 'services, proto and shell'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/ui_test.elf 'watch UI and power manager'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/activity_test.elf 'KV store and activity pipeline'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/watch_app_test.elf 'GNSS and watch_app runtime'

test-host: | $(BUILD)
	clang -std=c11 -Wall -Wextra -O2 -fsanitize=address,undefined -I kernel tests/test_kmem.c -o $(BUILD)/test_kmem
	$(BUILD)/test_kmem
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_driver.c -o $(BUILD)/test_driver
	$(BUILD)/test_driver
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_ringbuf.c -o $(BUILD)/test_ringbuf
	$(BUILD)/test_ringbuf
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_sync.c -o $(BUILD)/test_sync
	$(BUILD)/test_sync
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_rtc.c -o $(BUILD)/test_rtc
	$(BUILD)/test_rtc
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_bus_input.c -o $(BUILD)/test_bus_input
	$(BUILD)/test_bus_input
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_sensors_touch.c -o $(BUILD)/test_sensors_touch
	$(BUILD)/test_sensors_touch
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_periph_display.c -o $(BUILD)/test_periph_display
	$(BUILD)/test_periph_display
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_services_shell.c -o $(BUILD)/test_services_shell
	$(BUILD)/test_services_shell
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_ui_power.c -o $(BUILD)/test_ui_power
	$(BUILD)/test_ui_power
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_activity_kv.c -o $(BUILD)/test_activity_kv
	$(BUILD)/test_activity_kv
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_gnss_watch_app.c -o $(BUILD)/test_gnss_watch_app
	$(BUILD)/test_gnss_watch_app

clean:
	rm -rf $(BUILD)
