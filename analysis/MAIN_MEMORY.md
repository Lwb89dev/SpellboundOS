# Main-image startup mappings and recovered RAM code

Startup `0x701637ec` copies four records from `0x70160270`–`0x701602a0`, then
zeros two ranges described at `0x701602a0`–`0x701602b0`. Reconstructing those
tables explains many previously unmapped `0x80c...` / `0x80d...` references.
Their bytes are present in the main OTA member; these destinations need not
be external ROM or missing firmware.

| Operation | Source | Destination | Declared bytes | Effective bytes |
| --- | --- | --- | ---: | ---: |
| Copy | `0x70d9daf4` | `0x70f60000` | `0x2df01` | `0x2df04` |
| Copy | `0x70dcb9f8` | `0x80c00000` | `0x2a64` | `0x2a64` |
| Copy | `0x70dce45c` | `0x80d32e00` | `0x14d38` | `0x14d38` |
| Empty copy | `0x70de3198` | `0x70160000` | 0 | 0 |
| Zero | — | `0x70f8df08` | `0x64678` | `0x64678` |
| Zero | — | `0x80c02a68` | `0x7cccc` | `0x7cccc` |

The first copy is deliberately rounded up to a word: the observed loop tests
`offset < declared_size` and copies four bytes on each iteration. The next
source starts just after those rounded bytes. The empty record makes no
write. The shared memory reader now handles both cases, with a synthetic
regression test; sensor-hub records retain their original aligned sizes.

## Concrete consequence

Runtime address `0x80d361fc`, previously shown in broad exports as
`SUB_ram_80d361fc`, corresponds to original member offset `0xc71858`.
At its runtime address the bytes decode as argument setup followed by a tail
jump to `0x80d3c2f4`, within the same copied region. The wrapper supplies
constant `0x1fd` and a PC-relative string pointer; interpreting these bytes at
their source address gives the wrong PC-relative targets.

The startup-called addresses `0x80d411ac` and `0x80d45a18`, plus allocator and
synchronization-looking `0x80d3...` calls in peripheral and JS paths, are also
covered. Their exact function contracts remain to be analyzed. This corrects
the mapping assumption, not the entire decompilation.

The capability-table range at `0x70fd6078` is initially zeroed. It must be
populated or otherwise changed before table-based capability checks succeed;
initial data alone cannot tell which capabilities are enabled at runtime.

## Reproduction and local ELF output

```sh
python3 analysis_scripts/main_memory.py firmware/bip6-4.6.0.3.zip \
  > analysis/main-memory.json
python3 analysis_scripts/export_startup_elf.py firmware/bip6-4.6.0.3.zip \
  --image main --output firmware/main-runtime.elf
python3 analysis_scripts/export_startup_elf.py firmware/bip6-4.6.0.3.zip \
  --image sensor --output firmware/sensor-runtime.elf
llvm-readelf -l firmware/main-runtime.elf
llvm-objdump -d --start-address=0x80d361fc --stop-address=0x80d36230 \
  --mattr=+c firmware/main-runtime.elf
```

[main-memory.json](main-memory.json) records the original member hash, table
addresses, effective ranges and runtime-to-file translations. The exporter
builds an ELF32 RISC-V analysis container with the original image, copied
sections, zero sections, load segments and a section-name table. It does not
modify the archive. Both generated ELFs embed vendor bytes and stay under
ignored `firmware/`.

ELF segment permissions are analysis conveniences; they are not reconstructed
MPU protections. Entry addresses are the existing candidate mappings. These
files are not installable watch firmware and have not been booted. Two
synthetic ELF tests validate load bytes, zero-fill sizes, rounded copies,
section naming and rejection of an unmapped entry; LLVM independently accepts
both real-image ELFs. The full startup/address-space model still needs the
bootloader, relocation and hardware context.
