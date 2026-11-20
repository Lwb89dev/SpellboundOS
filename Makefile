CLANG ?= clang
LLD ?= ld.lld
OBJCOPY ?= llvm-objcopy
QEMU ?= qemu-system-riscv32
BUILD := build/qemu-virt
.DEFAULT_GOAL := all
CFLAGS := --target=riscv32-unknown-elf -march=rv32imac_zicsr -mabi=ilp32 -ffreestanding -fno-stack-protector -fno-pic -fno-builtin -Wall -Wextra -Werror -O2 -MMD -MP

OBJS := $(BUILD)/start.o $(BUILD)/trap_vector.o $(BUILD)/switch.o $(BUILD)/main.o $(BUILD)/console.o $(BUILD)/trap.o $(BUILD)/timer.o $(BUILD)/sched.o $(BUILD)/kmem.o $(BUILD)/driver.o

-include $(wildcard $(BUILD)/*.d)

.PHONY: all qemu test test-host clean
all: $(BUILD)/spellbound.elf $(BUILD)/spellbound.bin

$(BUILD):
	mkdir -p $@

$(BUILD)/start.o: kernel/arch/riscv/start.S | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/trap_vector.o: kernel/arch/riscv/trap.S | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/switch.o: kernel/arch/riscv/switch.S | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/sched.o: kernel/sched.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/kmem.o: kernel/kmem.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/driver.o: kernel/driver.c kernel/driver.h | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/main.o: kernel/main.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/scheduler_test.o: tests/qemu_scheduler.c kernel/sched.h | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/scheduler_test.elf: $(BUILD)/start.o $(BUILD)/trap_vector.o $(BUILD)/trap.o $(BUILD)/timer.o $(BUILD)/switch.o $(BUILD)/sched.o $(BUILD)/console.o $(BUILD)/scheduler_test.o kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/timer_test.o: tests/qemu_timer.c kernel/arch/riscv/timer.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/timer_test.elf: $(BUILD)/start.o $(BUILD)/trap_vector.o $(BUILD)/trap.o $(BUILD)/console.o $(BUILD)/timer_test.o kernel/boards/qemu-virt/linker.ld
	$(LLD) -m elf32lriscv -T kernel/boards/qemu-virt/linker.ld -o $@ $(filter %.o,$^)

$(BUILD)/heap_test.o: tests/qemu_heap.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD)/heap_test.elf: $(BUILD)/start.o $(BUILD)/console.o $(BUILD)/kmem.o $(BUILD)/heap_test.o kernel/boards/qemu-virt/linker.ld
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

test: all $(BUILD)/scheduler_test.elf $(BUILD)/timer_test.elf $(BUILD)/heap_test.elf
	python3 tests/qemu_boot.py $(QEMU) $(BUILD)/spellbound.elf
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/scheduler_test.elf 'scheduler lifecycle'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/timer_test.elf 'timer rollover'
	python3 tests/qemu_case.py $(QEMU) $(BUILD)/heap_test.elf 'heap boundaries'

test-host: | $(BUILD)
	clang -std=c11 -Wall -Wextra -O2 -fsanitize=address,undefined -I kernel tests/test_kmem.c -o $(BUILD)/test_kmem
	$(BUILD)/test_kmem
	clang -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-sanitize-recover=all -I kernel tests/test_driver.c -o $(BUILD)/test_driver
	$(BUILD)/test_driver

clean:
	rm -rf $(BUILD)
