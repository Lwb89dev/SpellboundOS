# Native EFTL translation and page-read dispatch

All 24 bounded native cases pass, totaling 2,159 steps (maximum 199). Actual
translation `0x80c0219a`, the ready EFTL wrapper `0x80c23252` and page adapter
`0x80c0278a` execute against authored geometry and eight translation slots.
Complete action/state observations and provenance are in
[eftl-read.json](eftl-read.json).

The two lower page services supply status and procedural bytes. They perform no
hardware access. NAND geometry, ECC, bus/DMA behavior, mapping reconstruction,
physical data and persistence are not established. These cases start EFTL ready;
the [preceding registry/lazy-init pass](STORAGE_REGISTRY_AND_LAZY_EFTL.md) covers
that separate gate with supplied geometry discovery.

## Context and address translation

The selected context fields are:

| Offset | Use in the executed path |
| --- | --- |
| `+0` | NAND handle passed to the generic page service |
| `+6` | Nonzero selects the alternate page service |
| `+8` | Pages per block |
| `+0c` | Page size |
| `+18` | Base page added on the alternate route |
| `+30` | Pointer to the u16 logical-to-mapped-block table |

For each requested segment, actual code computes the logical page and column
from the byte offset, obtains the logical block, reads its u16 mapped block,
and computes `mapped_block * pages_per_block + page_within_block`. Requests
split at page boundaries; crossing a logical block uses the next mapping slot.

An independently checked example uses four pages/block, 32-byte pages and
mapping `[3, 1, 4, 0xffff, 2, 0, 5, 6]`. Offset 120, length 48 reads:

| Mapped page | Column | Count |
| --- | --- | --- |
| 15 | 24 | 8 |
| 4 | 0 | 32 |
| 5 | 0 | 8 |

Output bytes, exact service calls, order and request count match the host
contract. These are authored logical/mapped-page fixtures, not recovered NAND
placement or real page dimensions.

## Gaps, errors and supplied partial copies

Mapping value `0xffff` means no mapped block in this path. On reaching it, the
routine fills **all remaining requested bytes** with `ff`, stops and returns the
number of bytes processed before the gap. It does not continue into a later
mapped block. A first-block gap returns zero; a gap after an eight-byte prefix
returns eight while filling the remainder.

A negative page-service result logs an error and returns `-1`, preserving bytes
already copied by earlier page calls. A direct page-adapter call instead returns
the supplied lower-service status unchanged. Nonnegative page statuses are
accepted without treating them as byte counts; successful translation returns
the requested length. A supplied service that copies only three bytes while
returning nonnegative status is therefore not detected by this loop. This is a
fault fixture, not an assertion about the actual page-service contract.

Zero-length translation makes no page call. Repeated reads leave context and
translation entries unchanged.

## Generic and alternate page routes

Actual `0x80c0278a(context, output, mapped_page, column, count)` tail-dispatches:

- Clear byte +6: `0x80c29532(nand_handle, output, mapped_page, column, count)`.
- Nonzero byte +6: `0x80c28a98(output, base_page + mapped_page, column, count, 1)`.

Both target entries are supplied services in this pass. The alternate base
addition and trailing flag 1 are checked, including 32-bit base addition wrap.
The generic target's own partition/alignment/bus work remains outside coverage;
its input page must not be described as a final physical NAND address.

## Selected integer limits

The executed loop masks logical-block table indices, page-within-block indices,
page-service column and segment length to 16 bits at their respective uses.
An authored request in logical block 65,536 aliases slot zero. A separate
131,072-byte-page fixture passes a column of 65,536 as zero to the page service.
Both execute and match the host contract.

These fixtures describe selected arithmetic without establishing that such
geometry or caller requests occur on the watch. Higher-level bounds and real
geometry must be recovered before assigning hardware consequences.

## Reproduction and verification

Use startup-aware `boot-runtime.elf`, apply `SeedEftlRead.java`, then export
`eftl_read.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-eftl-read`. The seed guards translation
bytes, declares the reviewed argument registers and marks the three reviewed
tail jumps as call/return metadata. It changes no image bytes.

```sh
python3 analysis_scripts/eftl_read.py \
  --vectors-output firmware/eftl-read-native-vectors.json
```

Run headless with:

```text
-postScript ValidateEftlRead.java firmware/eftl-read-native-vectors.json firmware/eftl-read-native-validation.json
```

```sh
python3 analysis_scripts/eftl_read.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-read \
  --vectors firmware/eftl-read-native-vectors.json \
  --validation firmware/eftl-read-native-validation.json > analysis/eftl-read.json
python3 -m unittest discover -s tests -p 'test_eftl_read.py' -q
```

The runner pins three code ranges, rejects unexpected PCs and service arguments,
caps each case at 100,000 steps, checks return ABI and full service/log traces,
and compares complete output hashes with an independent host contract. Context
and mapping bytes remain immutable; output guards are verified. Three fresh
export hashes are recorded. Twenty new host checks pass; the full suite reaches
793 passing tests after both storage passes.

Next work includes actual geometry discovery and mapping reconstruction from
NAND/OOB metadata, allocation/error paths there, program/erase/rewrite semantics,
the lower NAND services and SFTL behavior. Full boot, device-specific restoration
and physical persistence remain open.

The subsequent [OOB reconstruction pass](EFTL_OOB_MAPPING_RESUME.md) executes
the actual mapping scan and checksum verifier in 27 cases with supplied metadata
services. Physical OOB provenance and the complete initializer remain open.
