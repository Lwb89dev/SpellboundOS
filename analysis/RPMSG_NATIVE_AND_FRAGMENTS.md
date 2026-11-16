# Corrected zrpc exports, rpmsg queues and host fragment model

Follow-up: [interrupt, volatile I/O and queue control](IPC_DOORBELL_AND_MMIO.md)
connects queue tokens to the ISR on both processors, restores register side
effects omitted without volatile metadata, and models selected synchronization
and notification-suppression decisions. Live cache/coherency remains open.

Three consecutive blocks extend the sensor IPC investigation: a local BBS
repair with fresh native exports, queue/endpoint/buffer ownership recovery,
and a bounded independent model of stock chunk production and reassembly.
These are offline results for OTA 4.6.0.3. No hardware memory, firmware or
phone configuration was changed.

## Corrected analysis

The official Ghidra 12.1.2 archive was reacquired and checked against published
SHA-256 `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d`.
Tool [repair_ghidra_bbs.py](../analysis_scripts/repair_ghidra_bbs.py) guards the
exact original instruction-source hash, replaces the single BBS predicate
with a nonzero test, and accepts its own corrected output idempotently.
Modified/unknown source is rejected. Ghidra's Sleigh compiler rebuilt the
language successfully. The corrected source hash is
`b88e19a2ed21e641c683a1780aa739e1d9662106234a02b37fb4e949b4827a03`.

A fresh startup-aware main project at `firmware/ghidra-bbs/main-bbs` avoids
reusing instruction metadata from the faulty language. `DecompileWithAbi.java`
also installs the existing guarded save/restore fixups and returning logger.
Thirty-six targeted exports completed in three passes. Their hashes and the
compiled language hash are in [rpmsg-layout.json](rpmsg-layout.json).
Export count measures emitted output, not semantic coverage.

The corrected code corroborates CRC checks in `0x704e8f28`, the more-fragments
branch in `0x704e9a48`, and the channel-bit-2 branch in `0x704ea184`.
Some inferred types/indirect signatures remain underspecified. Earlier
evidence groups were preserved; the full corpus and sensor-hub exports have
not been regenerated with this repair.

Channel bit 2 forces the fifth send argument to 1. The resulting queue selector
is 2 in `0x704e8ea0`; worker `0x704e9664` scans queues 2, 1, then 0. This is
a priority path, separate from channel bit 1's CRC request. ACK packets use
queue 1; ordinary data can use queue 0. No scheduling fairness is inferred.

## Queues, roles and endpoints

Manager `0x707bfa74` converts each pool's total buffer count to half that count
for each queue. Each descriptor is 16 bytes. Constructor `0x707c0442` places
the descriptor array first, the available ring next, and the used ring at the
next 16-byte boundary after the available header and entries:

```text
n = pool_buffer_count / 2
descriptors = queue_base
available = queue_base + 16*n
used = align_up(available + 4 + 2*n, 16)
used_entries_end = used + 4 + 8*n
```

The manager's reserved ring extent also includes padding/trailer space; the
calculated used-entry end is not the complete reserved ring size. For pool 0:

| Region | Queue 0 | Queue 1 |
| --- | --- | --- |
| queue ID | 0 | 1 |
| entries | 32 | 32 |
| descriptors | `0x80f00000` | `0x80f00360` |
| available | `0x80f00200` | `0x80f00560` |
| used | `0x80f00250` | `0x80f005b0` |

Buffers begin at `0x80f006c0`, with 256-byte stride. The JSON includes all
six queues and all three pools. Queue IDs are `(instance << 1) | ring_index`.

Master initializer `0x707bffac` uses the first ring for RX and second for TX;
remote initializer `0x707c024a` reverses those roles. Endpoint creation
`0x707bfc0a` stores a local address, callback and context. The zrpc wrapper
chooses local endpoint 0 or 1 from its runtime role and the inverse as peer.
The role predicate `0x80d341d8` reads CSR `0xfc1` and tests mask `0x1c0`.
No live CSR value or active endpoint was observed. Endpoint addresses are
distinct from the zrpc node IDs 1/2 and sensor module 2.

## Lower packet header and buffer ownership

Send routines `0x707bfcc4` and `0x707bfe94` construct a 16-byte lower header:

| Offset | Type | Meaning |
| --- | --- | --- |
| 0 | u32 | source endpoint |
| 4 | u32 | destination endpoint |
| 8 | u32 | raw reserved/bookkeeping word |
| 12 | u16 | payload length |
| 14 | u16 | sender writes zero flags |
| 16 | bytes | zrpc link packet |

Allocator `0x707bfdf4` returns a pointer after this header, subtracts 16 from
capacity, and stores a local descriptor token at raw buffer offset 10.
Release `0x707bff4c` retrieves the token at payload pointer minus 6.
The zero-copy sender also retrieves that token. Initialization of every
reserved byte is not established: the host encoder requires an explicit raw
reserved value and does not assume native buffers are zeroed.

Receive callback `0x707bfb98` finds the endpoint using destination word `+4`,
then passes payload, length, source endpoint and context to its callback.
Return 1 retains the buffer and stores its descriptor token for later release;
other returns release it immediately. zrpc callback `0x704eb13a` converts
successful upper callback return 0 into this retain result. This explains how
the receive queue can keep the lower buffer until the zrpc worker copies and
releases it.

Reviewed ordering hooks `0x707bf672`/`0x707bf678` contain `fence.i`; the
reviewed address-conversion thunk resolves to an empty return. This does not
establish data-cache clean/invalidate policy, physical aliases or coherency
on the device. Those remain hardware-driver requirements.

## Fragment rules and bounded host behavior

[zrpc_fragments.py](../analysis_scripts/zrpc_fragments.py) models the selected
stock producer: payload fits when `size + 24 <= mtu`, otherwise a 12-byte
descriptor precedes numbered chunks of capacity `mtu - 24`. A smaller final
chunk clears more-fragments. The exact-multiple rule is preserved, so a full
final chunk retains more-fragments. This agrees with the fresh corrected
sender and receiver exports, and is still not an observed device failure.

Synthetic examples at MTU 40 demonstrate the boundary:

| Payload bytes | Sequences, including descriptor | More bits | Host result |
| --- | --- | --- | --- |
| 35 | 0, 1, 2, 3 | 1, 1, 1, 0 | delivers original payload |
| 32 | 0, 1, 2 | 1, 1, 1 | remains pending |

The independent reassembler limits memory to 65511 bytes, accepts one transfer
in sequence, checks route/session, lengths, count and CRC, and discards state
on malformed input. It rejects a zero whole-payload CRC in the descriptor,
matching the reviewed native descriptor guard. It is stricter than native RX
about sequence arrival order, accumulated size and final count. It does not
emulate retries, timers, allocator ownership or all native error behavior.

The corrected ACK receive branch looks up session word `+4` and signals its
waiter without inspecting status byte `+3` in that branch. An ACK arrival alone
therefore must not be described as proof of successful application processing.
No reply-status workaround is added to the host packet codec.

## Reproduction and validation

Use the pinned official release linked in [NATIVE_REPAIR.md](NATIVE_REPAIR.md).
With `GHIDRA` pointing to a writable local extraction:

```sh
python3 analysis_scripts/repair_ghidra_bbs.py \
  "$GHIDRA/Ghidra/Processors/RISCV/data/languages/andestar_v5.instr.sinc"
"$GHIDRA/support/sleigh" \
  "$GHIDRA/Ghidra/Processors/RISCV/data/languages/andestar_v5.slaspec"
```

Import `firmware/main-runtime.elf` into a fresh AndeStar/gcc project with
`-noanalysis`. Export `rpmsg_layout.py:EXPORTS` with `DecompileWithAbi.java` to
`runtime-zrpc-bbs`, and `BOUNDARY` to `runtime-rpmsg-boundary`, using one
Ghidra process at a time. Logs are `firmware/ghidra-zrpc-bbs-stdout.log`,
`firmware/ghidra-rpmsg-boundary-stdout.log` and
`firmware/ghidra-rpmsg-priority-stdout.log`.

```sh
python3 analysis_scripts/rpmsg_layout.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled \
  --language firmware/tool-evidence/bbs-corrected > analysis/rpmsg-layout.json
python3 -m unittest discover -s tests -p 'test_rpmsg_transport.py' -v
```

The retained language files are ignored tool evidence. Eight new tests cover
the lower header/token, queue offsets/roles, malformed layouts, fragment
boundary/order/session/CRC/length/limit handling and the zero-CRC descriptor.
All 225 Python tests pass with signature/cipher dependencies. The report
regenerates identically, including synthetic outcomes and 36 export hashes.
The next driver work is interrupt/doorbell and cache behavior, active endpoint
validation, and a device-backed decision for the full-final-chunk case.
