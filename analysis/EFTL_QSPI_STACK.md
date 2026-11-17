# Ready EFTL mapped/page/OOB reads through the original NAND/QSPI stack

All **32 native cases** pass in **78,825 instruction/service steps** (maximum
4,224 for a two-page fast read). Original EFTL translation, ready read wrapper,
page/OOB adapters and extraction connect partition/driver/context wrappers,
BBT/page policy, bus/QSPI/FIFO and selected DMA. Observations and 60 code/export
plus ten data hashes are in [eftl-qspi-stack.json](eftl-qspi-stack.json).

All **393 prior native cases reproduce byte for byte**. Nineteen new host checks
bring the suite to **1,343 passing tests**. The EFTL ready flag, eight mapping
slots and context/RTOS/peripheral data are authored; map reconstruction and
physical NAND effects are unverified. No device was accessed.

## Connected address layers

Original `0x80c0219a` splits a logical byte read at page boundaries. These fixtures
use original first-candidate geometry: 2,048 bytes/page and 64 pages/block. For
each portion it selects an authored mapping entry, forms the mapped page number
and calls original adapter `0x80c0278a`.

The generic adapter enters actual partition read and original driver callback.
For logical offset 16, mapping entry 3 gives page 192; partition base page 512
gives 704; actual BBT entries `[1, 3, 7]` then give page 896 before opcode `0x13`.
The actual context/mutex wrapper determines direct versus private transfer.

The adapter's authored fast flag instead calls page read directly, adding the
context's base page and forcing mode 1. It bypasses driver availability/context/
mutex checks. A missing-driver fixture therefore fails the generic map read but
does not prevent its fast counterpart. An authored `0xffffffff` fast base wraps
before BBT mapping. No safe concurrent use of this bypass is established.

The ready wrapper `0x80c23252` executes with the ready flag already set and
reaches actual translation. EFTL initialization and persistent mapping recovery
are not executed by this pass.

## Multi-page output and error behavior

Two-page and cross-block reads execute every original lower transaction. Distinct
32-byte private copies target different output offsets, with both parts compared
against the final caller-buffer hash. The peripheral model does not simulate
DMA movement, so these copies deliver the private `0xa5` sentinel. Direct FIFO
reads deliver an authored byte stream. Different hashes are expected outcomes,
not evidence of valid physical NAND content.

An unmapped `0xffff` entry logs the gap, fills **all remaining requested bytes**
with `0xff`, and returns the length preceding the gap. A first-slot gap therefore
returns zero after filling the output. A cross-block fixture returns 8 after
delivering eight authored bytes and filling the remaining 24 bytes with `0xff`.

A negative lower read return becomes `-1` and an EFTL page-error log. The failing
second page can already have transferred cache bytes before returning ECC error;
the final buffer may therefore be fully modified even though logical read
returns `-1`. Earlier successful bytes are not rolled back.

A zero-length logical read returns zero without driver dispatch. A direct
page-adapter request of zero length instead reaches original page validation
and returns `-1`.

The old isolated read pass explored logical-index alias and column truncation
using synthetic small/large geometry. With the selected original geometry here,
the maximum 32-bit logical offset cannot reach logical block 65,536, and columns
remain below 2,048. Those earlier synthetic examples do not identify equivalent
reachable cases for this geometry.

## OOB data reaches the original extractor

Original OOB adapter `0x80c027b0` reads the 64-byte spare area into its scratch
buffer through the same generic/fast routes. Original first-candidate metadata
declares ECC total 16, unit 4 and positions `[4, 20, 36, 52]`; the original
extractor selects four bytes at spare offset 20.

The generic normal-context case copies authored DMA sentinel bytes into scratch
and extracts four `0xa5` bytes. Fast or context-direct cases deliver FIFO bytes
and extract the corresponding four bytes. This confirms connection to extraction,
not physical OOB metadata or ECC correctness.

Explicit metadata variants exercise segmented unit-2 copies, marker skipping,
zero unit and insufficient ECC total. Supplied generic copies check each
source/output offset, including a zero-length marker copy. Zero unit can return
success while leaving output unchanged. Insufficient ECC total stops at the
original assertion after the spare read.

If page read returns ECC error, scratch may already contain new bytes but the
adapter skips extraction and leaves the caller's metadata output unchanged.
The missing-driver case returns `-6` without reading scratch.

## Evidence boundary

Normal-return ABI, caller/scratch/context/mapping guards and immutable expected
context/map bytes are checked along with the existing lower-stack guards.
Supplied copy/fill services have bounded pointers and lengths. The fixtures
cover reads of at most 64 bytes and eight logical mapping slots, not arbitrary
mapping sizes or the full storage address space.

Higher storage entry/bounds integration, mapping reconstruction/provenance,
program/repair atomicity, physical chip/BBT/ECC/OOB/persistence, concurrency and
cache/IRQ behavior, backup/restoration and standalone boot remain open.

The subsequent [registered storage read pass](STORAGE_EFTL_STACK.md) connects
original owner/bounds/read entry and EFTL callback for selected nvms/envbak/
recovery records, with authored registry/ready state.
