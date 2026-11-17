# Registered storage reads through ready EFTL, NAND and QSPI

All **24 native cases** pass in **37,927 instruction/service steps** (maximum
3,765 for a two-page storage read). Original storage entry `0x80c24446` and
bounds/owner helper `0x80c24218` execute through the original EFTL callback,
ready logical map, page/partition/driver/context/BBT layers and QSPI/FIFO with
selected DMA. Observations and 62 code/export plus twelve data hashes are in
[storage-eftl-stack.json](storage-eftl-stack.json).

All **425 prior native cases reproduce byte for byte**. Eighteen new host tests
bring the suite to **1,361 passing tests**. No phone or watch was accessed.
Registry bindings, ready mapping, runtime capacity/span variants, RTOS and
peripheral effects remain authored; this is not physical storage validation.

## Original registry rows and backend callback

The original sixteen 60-byte partition records at `0x80c33a38` are cloned into
emulator RAM. The host reconstructs all bytes from the existing storage inventory
and verifies equality with the image before publishing evidence. These cases
select the original EFTL-backed rows:

| Partition | Backend byte offset | Declared span |
| --- | ---: | ---: |
| `nvms` | 0 | `0x40000` |
| `envbak` | `0x40000` | `0x40000` |
| `recovery` | `0x80000` | `0x80000` |

The original 76-byte EFTL descriptor at `0x80d80fb8` is cloned too. Its read
callback at +`0x2c` remains original `0x80c23252`. Runtime capacity is explicitly
authored as one MiB to match the eight-slot logical-map backing. Named span
variants change only the selected cloned record's span; original records and
descriptor bytes are separately hash guarded.

An authored owner array and registry table/count globals bind those clones.
Actual registry setup, allocation, ownership lifetime and reconstruction of the
ready EFTL map are outside this pass. Reads of the three selected rows enter
the real callback with the original row offset added to the caller offset.

## Bounds and count propagation

The original owner helper validates the handle against the registered table,
loads the owner, derives a zero span from owner capacity when needed, and
requires the caller offset to be **strictly less** than the effective span.
It clips the count when offset-plus-count exceeds that span or wraps.

At `nvms` offset `0x40000 - 8`, a request for 32 bytes reaches EFTL as eight bytes
and returns eight. A request for `0xffffffff` bytes at the same offset also
clips to eight before reaching the backend. An explicitly authored 64-byte span
clips a request at offset 60 to four bytes without requiring page alignment.

Offset equal to or after the end returns `-1` before the callback. A zero-sized
request at end therefore fails, while a zero-sized request at an interior offset
still calls the original ready EFTL wrapper and returns zero without NAND
dispatch. Missing owner logs that failure and returns `-1` before backend access.

Null handle/output and handles below/above the table stop at the original
assertions after a supplied diagnostic service. These cases do not test arbitrary
misaligned pointers inside the table or owner-array corruption.

## Logical gaps and lower failures reach the upper caller

The registered read wrapper accepts any nonnegative callback result. A first
unmapped EFTL slot fills the requested output with `0xff` and returns zero,
which the storage wrapper passes through without a read-error log. A gap after
eight bytes returns eight after filling the remaining 24 requested bytes with
`0xff`; the wrapper does not require a full-length result.

Negative logical read results propagate as `-1` and add the original storage
read-error log. Lower ECC failure may already have transferred cache bytes,
so the upper caller can receive an error with its output buffer modified.
The prior successful bytes are not rolled back. A missing NAND driver crosses
both EFTL and storage error logs; the explicitly authored fast context still
bypasses that driver check through the original fast page adapter.

Two-page and deferred-platform-init cases execute through all selected layers.
Private DMA copies deliver the authored private-buffer sentinel; direct FIFO
transfers deliver authored bytes. Neither control-path success nor these buffer
hashes establish physical NAND content or persistence.

## Validation boundary

The registered partition table, backend and owner-array hashes are compared
after execution. Table/backend/owner, EFTL context/map/scratch, caller and lower
NAND/DMA guards are checked, as are ABI canaries on normal return. The diagnostic
leaf is supplied; the original assertions and storage/EFTL/NAND policies execute.
Fixtures allow at most 64 delivered bytes and the first eight EFTL mapping slots.

The read path now connects selected storage API callers to original lower
hardware-control code. Remaining work includes broader callers/partitions,
registry and map reconstruction, write/erase/rewrite and repair atomicity,
complete mutex/IRQ/cache/concurrency behavior, physical chip/partition/BBT/ECC/
data corroboration, persistence, device-specific backup/restoration and
standalone boot.
