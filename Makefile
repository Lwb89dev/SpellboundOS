CLANG ?= clang
LLD ?= ld.lld
OBJCOPY ?= llvm-objcopy
QEMU ?= qemu-system-riscv32
BUILD := build/qemu-virt
CFLAGS := --target=riscv32-unknown-elf -march=rv32imac_zicsr -mabi=ilp32 -ffreestanding -fno-stack-protector -fno-pic -fno-builtin -Wall -Wextra -Werror -O2

OBJS := $(BUILD)/start.o $(BUILD)/trap_vector.o $(BUILD)/switch.o $(BUILD)/main.o $(BUILD)/console.o $(BUILD)/trap.o $(BUILD)/timer.o $(BUILD)/sched.o $(BUILD)/kmem.o

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

$(BUILD)/main.o: kernel/main.c | $(BUILD)
	$(CLANG) $(CFLAGS) -c $< -o $@

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

test: all
	python3 tests/qemu_boot.py $(QEMU) $(BUILD)/spellbound.elf

test-host:
	clang -std=c11 -Wall -Wextra -O2 -fsanitize=address,undefined -I kernel tests/test_kmem.c -o $(BUILD)/test_kmem
	$(BUILD)/test_kmem

clean:
	rm -rf $(BUILD)
