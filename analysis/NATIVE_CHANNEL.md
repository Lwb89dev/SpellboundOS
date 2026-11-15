# Native Bluetooth channel codec and crypto delegate

The startup-aware, ABI/logger-corrected exports connect the native packet
layer behind custom `0016`/`0017` to the authentication component. This is
static evidence from OTA 4.6.0.3, main member SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.
It establishes framing and the registered encryption callbacks, not a working
phone/watch session or a recovered pairing protocol.

## Wire representation

Parser `0x7036d0ae` allocates a 24-byte packet structure; serializer
`0x7036d368` emits the following layouts. All multibyte fields are little
endian. Names for app/session/sequence follow their uses in the manager.

| Type | Serialized bytes | Observed parsing |
| --- | --- | --- |
| 1 | `01` | Consumes one byte; trailing bytes ignored |
| 2 | `02 field1 field2 field3 word:u16` | Consumes only `02 field1`; remaining bytes ignored |
| 3 | `03 flags app:u8 session:u8 sequence:u8 [total:u32 module:u16] payload` | Extended fields only with flag `0x01`; all remaining bytes become payload |
| 4 | `04 app:u8 session:u8 status:u8 sequence:u8` | Consumes five bytes; trailing bytes ignored |

The type-2 asymmetry survives the corrected export; it is not silently repaired
in the host decoder. On type 1 reception, the manager constructs a type-2
response whose fields are `2`, the delegate's enabled byte, `1`, and word `1`.
With encryption enabled this serializes to `02 02 01 01 01 00`. Full negotiation
semantics and the peer's type-2 implementation remain open.

The module field is two bytes on wire, but the parser stores only its low byte
at packet offset `0x0c`; the serializer zero-extends that byte. The host decoder
records both values. Unknown types and truncated headers fail. The parser can
construct type 3 with an empty payload; the serializer and receive manager
reject it. Type 3 payload size is stored as u32, but the manager copies only
its low 16 bits per received chunk. The host reassembler rejects oversized
chunks rather than reproducing silent truncation.

These are native channel packets, distinct from the separately recovered
[16-byte JS header](JS_RUNTIME_API.md) and [sensor IPC](PPG_FIFO_AND_IPC.md).
Their complete payload-level linkage remains to be established.

## Routing, chunking and acknowledgements

Custom IDs expand as in [GATT_REGISTRATION.md](GATT_REGISTRATION.md).
UUID direction is specific to the path:

| Native path | Types 1/3 | Types 2/4 |
| --- | --- | --- |
| Receive filter `0x7036d928` | accepts `0017` | accepts `0016` |
| Local server transmitter `0x7036e1da` | sends via `0017` | sends via `0016` |
| Client transmitter `0x7036d9e4` | writes via `0016` | writes via `0017` |

The flags used by TX manager `0x7036b430` and RX manager `0x7036b8be` are:

| Bit | Observed role |
| --- | --- |
| `0x01` | Start: adds total plaintext size and module ID |
| `0x02` | End: accumulated bytes must equal expected transfer size |
| `0x04` | Request ACK: successful RX generates type 4 with status 1 |
| `0x08` | Encrypted transfer; must agree with receiver task policy |

TX reserves 11 bytes on the first chunk and five on later chunks. The budget
comes from a native transport callback, not a proven ATT MTU. Sequence starts
at zero and wraps as a byte. Non-final ACK requests occur when
`(sequence + 1) % (7808 / capacity) == 0` for capacities below 244, using integer
division, or every 32 sequence values otherwise. Final ACK depends on a send
option. The model excludes capacities that cannot carry the extended header.

RX validates initial nonzero size/zero sequence, module authorization policy,
matching app/session and incrementing sequence, nonempty chunks, no size
overflow, and exact final size. It allocates a larger buffer when encrypted.
Failure ACK status values observed include 2 session, 3 sequence, 4 size or
plaintext-policy errors, 5 module missing, 6 allocation, 8 authorization,
9 encryption flag, 10 CRC, 11 counter, and 12 crypto callback failure.
These labels describe specific branches, not an exhaustive error specification.
The TX ACK path checks connection, app, session and status; no sequence-byte
comparison appears in that branch. Retransmission and queue lifecycle are not
implemented in the host model.

## Concrete authentication/crypto connection

Initializer `0x7021766c` registers a 28-byte delegate through `0x7036c3ce`.
Byte 0 is an enabled flag from a configuration query. The registrar checks
six function pointers and copies the structure to the global at `0x70fa6f2c`.

| Offset | Callback | Observed role |
| --- | --- | --- |
| `+4` | `0x70215946` | Read per-app key and TX counter |
| `+8` | `0x70215c9c` | Encrypt bytes in place through a temporary buffer |
| `+12` | `0x702158e0` | Increment TX counter if app context exists |
| `+16` | `0x70215902` | Read per-app key and RX counter |
| `+20` | `0x702159ac` | Decrypt bytes in place through a temporary buffer |
| `+24` | `0x7021624c` | Set RX counter only on success |

The getters read a 16-byte key at context offset `+8`, RX counter at `+0x18`,
and TX counter at `+0x1c`. TX additionally checks context byte `+5`. TX counter
increment does not consume the success/value arguments passed by the manager;
RX update does check success. Module registration requires authorization when
requesting encryption. Send path `0x7036cac0` selects encryption only when the
module requests it, the delegate is enabled, and connection ID is not `0xfe`.

Helper `0x7036d64a` XORs **all sixteen key bytes** with the session byte; the
result is the block-cipher key, not an initialization vector. Before encryption
TX constructs:

```text
app payload || counter:u32 || CRC32(payload || counter):u32 || padding
```

The total is rounded up to a multiple of 16, with zero padding *length* when
already aligned. Padding contents are not established: the manager does not
initialize that tail, and allocator behavior has not been resolved. The host
builder requires explicit padding bytes; it does not assume PKCS#7 or zeros.
The extended total field remains the original app payload size.

Encryption wrapper `0x70215b60` initializes a 128-bit key schedule and calls
block routine `0x702838de` separately on each 16-byte block with mode 1.
Decryption uses key setup `0x70282ef8` and mode 0, again block by block.
Key setup `0x70282c9c` selects ten rounds for 128 bits; the block routine uses
AES-shaped substitution/round tables. The observed wrapper is consistent with
AES-128 ECB. No IV or chaining state is passed between blocks. A vendor-routine
known-answer execution and peer interoperability check remain outstanding;
the host model does not supply a cipher. Decryption's loop count includes a
16-bit length mask, another reason not to infer unrestricted message sizes.

RX decrypts complete blocks as they arrive and verifies the CRC on End. Its
counter predicate at `0x7036d672` accepts an unsigned forward delta in
`[0,100000]`, including wrap, and successful RX stores received counter plus
one. This is an observed acceptance window, not a proof of replay protection
across reconnects or power cycles. Pairing, key derivation, counter initialization
and persistence must be traced separately.

## Independent CRC and corrected function signature

All 256 words at `0x709bc4fc` match the reflected CRC-32 polynomial
`0xedb88320`; the 1024-byte table hash is
`12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86`.
The caller supplies `0xffffffff` and complements the returned accumulator.
This matches the standard `123456789 -> cbf43926` vector and `zlib.crc32`.

Raw instructions show `0x703d0fe0 -> 0x703bf368 -> 0x70161360`. At
`0x70161378`, AndeStar `bfoz a5,a5,#2,#9` masks to eight bits and shifts left
two for table indexing; its p-code and the surrounding loads independently
corroborate the update. The earlier inferred `void` return erased the entire
accumulator calculation from pseudocode. `SeedChannelCrc.java` hashes the exact
38-byte loop before setting its uint return and three argument types. A fresh
export now retains the update and return. It changes analysis metadata only.

## Reproduction and validation

Use the startup-aware main ELF, Ghidra 12.1.2 AndeStar v5 and the corrected
save/restore/logger setup in [NATIVE_REPAIR.md](NATIVE_REPAIR.md). Four export
groups are enumerated in `native_channel.py:SOURCES`; their private logs are
`firmware/ghidra-runtime-channel{,-policy,-crypto,-aes}-stdout.log`.
For the additional CRC group, execute `SeedChannelCrc.java` before
`DecompileWithAbi.java firmware/decompiled/runtime-channel-crc
0x70161360 0x703d0fe0 0x703bf368`. The instruction inspection uses
`InspectInstructions.java 0x70161378 0x7016137c`.

```sh
python3 analysis_scripts/native_channel.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled > analysis/native-channel.json
python3 -m unittest discover -s tests -p 'test_native_channel.py' -v
```

[native-channel.json](native-channel.json) records original bytes, CRC-table
verification, reviewed function roles, export hashes and synthetic wire vectors.
Function roles are reviewed findings, not automatically inferred by the script.
Fourteen synthetic tests cover golden bytes, parser asymmetry/truncation,
fragmentation, sequencing/wrap, routing, malformed inputs, host bounds, explicit
padding, CRC corruption and counter-window boundaries. The complete Python
suite passes 129 tests with the signature dependencies. These tests validate
the host models; they do not execute the watch firmware. No device interaction
or device-secret extraction was performed.
