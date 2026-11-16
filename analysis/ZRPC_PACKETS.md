# Sensor IPC: zrpc packet headers and CRC

Follow-up: [corrected native IPC analysis](RPMSG_NATIVE_AND_FRAGMENTS.md)
confirms channel bit 2 selects the priority send path, maps lower queues and
buffer ownership, and adds a bounded host fragment model.

The main and sensor-hub images contain matching zrpc channel/link packet
layouts. The previously recovered sensor payload now has a concrete outer
representation: a 16-byte data-channel header inside an 8-byte link header.
The CRC tables in both images are identical and match all 256 entries generated
by reflected polynomial `0xa001`, initial value `0xffff`, no final XOR.

This is static OTA 4.6.0.3 evidence, recorded in
[zrpc-packets.json](zrpc-packets.json). There was no device interaction.
The independently authored [codec](../analysis_scripts/zrpc_packets.py)
implements bounded packet encoding/decoding; it does not run an rpmsg link or
implement native fragment/retry state machines.

## Connecting sensor payloads to the channel

Sensor serializer caller `0x80f99c26` obtains the interface from `0x80f95226`
and invokes its `+0x10` send callback. Send wrapper `0x80f94c0a` creates the
six-byte channel-information object. It takes its local source ID from
`0x80f9d4c6`, which returns 2, and increments a separate 14-bit request counter.
Wrapper `0x80f9e3f0` forwards to channel sender `0x80f9de06`.
Main getter `0x704e9580` returns 1; main sender `0x704ea184` requires local
source 1, while the sensor sender requires local source 2. Destination/link
selection remains caller-dependent.

The sensor call sets the module field to 2 and passes timeout-like value
`0x4b0`. The four-byte optical process payload `10 06 00 00` remains the
sensor opcode/sensor-ID/reason format described in
[PPG_FIFO_AND_IPC.md](PPG_FIFO_AND_IPC.md). Request counter, channel session,
sensor ID and module ID belong to different fields.

## Link header

Main sender `0x704ea8f2` prepends this header. All words are little endian:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 2 | magic `0x7a72`, serialized `72 7a` |
| 2 | 2 | CRC-16 of channel bytes when requested, otherwise zero |
| 4 | 2 | sender writes zero; decoder retains raw value |
| 6 | 2 | total link length, including this 8-byte header |
| 8 | variable | channel packet |

Checksum checker `0x704eb056` uses header length minus 8, excludes the link
header, and compares the result with word `+2`. CRC routine `0x704eb946`
updates two byte accumulators through tables at `0x70c0e944` and `0x70c0ea44`.
Sensor equivalent `0x80f9f022` uses `0x80fe3900` and `0x80fe3a00`.
The independent bitwise implementation gives `123456789 -> 4b37`.

Raw LLVM instructions `0x704ea9ee`–`0x704eaa3e` corroborate the header stores
and CRC call. The CRC instruction loop is `0x704eb946`–`0x704eb986`.
Both ranges are fingerprinted, along with selected data-header stores.

## Data and ACK packets

Main sender `0x704ea184` and sensor sender `0x80f9de06` construct type 1:

| Channel offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 1 | type 1, data |
| 1 | 1 | source node |
| 2 | 1 | destination/link selector |
| 3 | 1 | flags: bit 0 requests session ACK, bit 1 requests link CRC; bit 2 left unassigned |
| 4 | 2 | request word copied from channel information |
| 6 | 2 | channel session ID |
| 8 | 2 | packed state: bit 0 complete/unfragmented, bit 1 retained raw, bits 2–15 sequence |
| 10 | 2 | sender writes zero |
| 12 | 2 | module word; reviewed sender zero-extends its byte module ID |
| 14 | 2 | channel packet length, including its 16-byte header |
| 16 | variable | application payload or fragment information |

The host decoder preserves the full received module word. Native delivery
looks up its low byte; it should not be assumed to support 65536 modules.
The host caps data payloads at 65511 bytes so channel plus link headers fit a
u16 total. Native casts and allocation/error behavior are not emulated.

Delivery/ACK helper `0x704e8f28` constructs a different eight-byte type-2
packet: `02 source:u8 destination:u8 status:u8 session:u16 zero:u16`.
It swaps the received source/destination bytes and copies the data session
from `+6` into ACK offset `+4`. Receive worker `0x704e9a48` uses that ACK
session to find the waiting sender and release its semaphore. The host retains
status as a raw byte; complete status/error policy remains open.

A deliberately synthetic optical process packet is recorded in the JSON.
It uses source 2, chosen destination 1, CRC flag 2, request 7, session 9,
module 2 and packed state 1. Its 28 link bytes are not a watch capture or
proof that this routing is active on the device.

## Fragmentation and transport boundary

The sender compares payload length plus 24 against the link MTU. When larger,
it reserves 24 bytes of headers per chunk and first sends a 12-byte fragment
descriptor, making a 28-byte channel packet. Descriptor fields are:

```text
total_payload:u16 chunk_count:u16 payload_crc16:u16 reserved:u16 timeout:u32
```

The descriptor has sequence zero; data chunk sequences begin at one and use
14 bits. Receive worker `0x704e9a48` keeps session and chunk lists, checks
duplicate/out-of-range sequence values, and computes a whole-payload CRC
before delivery. Timeout and retry/session counters are present. These are
reviewed structural observations, not a complete recovered state machine.

Several broad exports render bit tests as impossible expressions, such as
`(flags & 2) == 1`. The corresponding LLVM output contains undecoded
AndeStar branch/bit instructions. The temporary Ghidra installation is absent
in this session, so those branches were not freshly regenerated. In particular,
bit-1 termination behavior, exact-multiple chunk boundaries, retry policy and
fragment-list delivery order remain unresolved. The codec exposes descriptor
fields and raw packed bits without inventing a native reassembler.

Follow-up: [branches and shared memory](ZRPC_BRANCHES_AND_MEMORY.md) identifies
the Ghidra `bbs` defect, decodes selected branches, assigns packed bit 1 to
more-fragments and recovers the identical three-pool rpmsg configuration.

Main rpmsg registration `0x704eb7dc` creates a link object with operation table
at `0x70c0e8e0`. Initializer `0x704eb4c0` creates endpoint callbacks, tracks
connection notification and updates the link MTU. Allocation `0x704eb350`
calls the lower allocator `0x707bfdf4` and checks its returned capacity.
Send `0x704eb422` calls `0x707bfe94`; release `0x704eb476` calls
`0x707bff4c`. This establishes the wrapper route, while virtqueue layout,
shared-memory addresses, endpoint ownership and device behavior still need
independent recovery. No native sensor samples have been transported by our
code.

## Reproduction and validation

```sh
python3 analysis_scripts/zrpc_packets.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled > analysis/zrpc-packets.json
python3 -m unittest discover -s tests -p 'test_zrpc_packets.py' -v
llvm-objdump -d --start-address=0x704eb946 --stop-address=0x704eb986 \
  firmware/main-runtime.elf
```

The extractor guards both image hashes, compares the two CRC table pairs,
checks every generated table entry and hashes the reviewed exports. The JSON
is reproducible from the retained ignored firmware inputs. Eight synthetic
tests cover fixed header bytes, CRC reference values, corrupt packets,
checksum policy, ACK layout, raw fragment fields, truncation and length limits.
All 212 Python tests pass with the existing signature/cipher dependencies.
Tests exercise the independent host codec, not execution of vendor routines.
