# zrpc branches and initial shared-memory pools

The impossible mask comparisons in earlier zrpc exports have a specific tool
cause. Ghidra 12.1.2 implements AndeStar `bbs` using `(register & mask) == 1`.
For bit indices above zero that predicate cannot succeed. The intended operation
tests whether the selected bit is set. Renode independently performs that bit
test. Sources: [Ghidra release definition](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Processors/RISCV/data/languages/andestar_v5.instr.sinc),
[Renode implementation](https://github.com/renode/renode-infrastructure/blob/master/src/Emulator/Cores/RiscV/Andes_AndeStarV5Extension.cs).

An independent RV32 branch decoder now recovers selected operands and targets,
using nonzero for `bbs` and zero for `bbc`. No Ghidra installation was patched
or full corpus re-export performed. Earlier exports containing `bbs` at bit 1
or higher need review before their control flow is relied on. Snapshots of the
external sources stay in ignored `firmware/tool-evidence/`; exact source/image
hashes, decoded words and pool values are recorded in
[zrpc-control-flow.json](zrpc-control-flow.json).

## Selected recovered control flow

These are explicit instruction starts checked against surrounding LLVM
instructions, not arbitrary scan hits:

| Address | Decoded branch | Role in reviewed context |
| --- | --- | --- |
| `0x704e8f3e` | `bbs x15,1,0x704e9000` | delivery helper enters CRC checking |
| `0x704ea2a2` | `bbs x15,2,0x704ea3a8` | send flags select an override path lost in pseudocode |
| `0x704e9bc0` | `bbc x15,1,0x704e9c40` | skip CRC when flag bit 1 is clear |
| `0x704e9bee` | `bbs x15,1,0x704e9c20` | copied buffer can reach checksum recheck |
| `0x704e9d92` | `bbs x15,0,0x704ea0c4` | complete packet goes directly to delivery |
| `0x704e9f86` | `bbs x15,1,0x704e9ee2` | await another fragment |
| `0x704ea71c` | `bbc x15,0,0x704ea862` | skip session-ACK waiting |

At `0x704e9f86` the tested value comes from the packed state at data-header
offset 8. Set bit 1 returns to the receive loop; clear bit 1 proceeds to
concatenation and full-payload CRC. The codec's `bit1_raw` therefore has the
reviewed role **more fragments**. The field stays compatible; a native
reassembler has not been implemented.

On ACK timeout, instructions `0x704ea75a`–`0x704ea760` allow another attempt
when the counter is at most one; `0x704ea82e`–`0x704ea834` increment it.
Full ownership, retry/error handling and scheduling still require corrected
native exports. No device execution is claimed.

## Exact-multiple boundary

Chunk capacity is link MTU minus 24. Instructions at
`0x704ea550`–`0x704ea560` compare total length with offset plus capacity.
The signed `bge` at `0x704ea554` skips clearing the more-fragments state
when these are equal; the state clears only for a smaller remainder.
Combined with the receive bit test, this is a potential stock compatibility
defect for exact-capacity final chunks.

Active MTU, caller constraints and such message sizes have not been observed.
No padding workaround, extra chunk or invented termination rule was added to
the codec. Interoperability evidence is needed before choosing that behavior.

## Matching rpmsg pool tables

Main initializer `0x704eb4c0` reads three 16-byte records at `0x70c0e8f4`.
Sensor initializer `0x80f9ecb8` reads identical records at `0x80fe38d0`.
Fields are instance ID, shared base, buffer count and payload bytes.
Manager `0x707bf25e` checks power-of-two conditions, computes allocation size
and rejects overlap. Its calculated extents are:

| Instance | Base | Buffers | Payload | Stride | Total bytes | Exclusive end |
| --- | --- | ---: | ---: | ---: | --- | --- |
| 0 | `0x80f00000` | 64 | 240 | 256 | `0x46c0` | `0x80f046c0` |
| 1 | `0x80f05000` | 16 | 1008 | 1024 | `0x41e0` | `0x80f091e0` |
| 2 | `0x80f0a000` | 2 | 4080 | 4096 | `0x2080` | `0x80f0c080` |

For valid non-overflowing inputs the reviewed arithmetic is:

```text
ring = align_down((count & ~1) + 23, 16)
     + align_down((count >> 1) * 8 + 29, 16)
     + (count >> 1) * 16
total = 2 * ring + (payload + 16) * count
```

The regions do not overlap and finish below the first sensor startup-copy
destination `0x80f0d000`. These are configured addresses and calculated
extents; physical memory/cache properties and live ownership remain open.
Instance IDs differ from node, sensor, module and endpoint IDs.

## Reproduction and scope

```sh
python3 analysis_scripts/zrpc_control_flow.py firmware/bip6-4.6.0.3.zip \
  --ghidra-sinc firmware/tool-evidence/ghidra-12.1.2-andestar_v5.instr.sinc \
  --renode-source firmware/tool-evidence/renode-Andes_AndeStarV5Extension.cs \
  > analysis/zrpc-control-flow.json
python3 -m unittest discover -s tests -p 'test_zrpc_control_flow.py' -v
```

The extractor guards both image/source hashes and compares the pool tables.
Five tests cover the bit-1 regression, bit-0/2 decisions, constant comparisons,
signed offsets/address wrap, encoding guards and all three pool sizes.
All 217 Python tests pass with signature/cipher dependencies. The JSON
reproduces byte-for-byte. These checks exercise independent host models.

Next: correct `bbs` in a local Ghidra installation and regenerate targeted
exports; recover endpoints, vrings and cache behavior; observe the suspected
fragment boundary before implementing native transport compatibility.
