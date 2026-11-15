# Native GATT registration and qualified identifiers

The corrected main-image builder at `0x7035e766` supplies eight service specs
to registrar `0x703b2236` along its nested all-success branch. The previous
broad export stopped at a falsely non-returning logger before its last two
services. A fresh ABI/logger-corrected pass recovers the full observed branch.
This is a registration attempt path, not a live advertised/service discovery
result, and does not cover services registered elsewhere or by later apps.

## Service and characteristic ownership

Custom short IDs below expand to `0000xxxx-0000-3512-2118-0009af100700`.
Plain four-digit UUIDs remain plain four-digit identifiers.

| Service | Characteristics in builder order |
| --- | --- |
| `1811` | `2a46` |
| `180a` | `2a23`, `2a25`, `2a27`, `2a28`, `2a50`, `2a29` |
| `fee0` | `2a2b`, custom `0016`, `0017`, `0001`, `0002`, `0004`, `0005`, `0006` |
| custom `1530` | custom `1531`, `1532`, `0023`, `0024` |
| `180d` | `2a37` |
| `fee1` | `fedd`, `fede` |
| `1812` | `2a4e`, `2a4b`, `2a4a`, `2a4c`, qualified `2a4d11`, `2a4d21`, `2a22`, `2a32` |
| `180f` | `2a19` |

There are 31 characteristic specs. The public
[gatt-service-builder.json](gatt-service-builder.json) includes their raw
property/permission fields, candidate maximum-length fields, extra bytes and
conditional descriptor UUIDs. It resolves registry pointers independently from
the original member bytes, SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.

The registrar consumes a service UUID pointer, count and characteristic-array
pointer, then copies each 12-byte characteristic spec to an 84-byte internal
record. Observed property bits `0x10` or `0x20` cause preparation of descriptor
UUID `2902`; bit `0x400` prepares `2908` and copies the spec's two extra bytes.
Full bit/permission semantics and runtime handle assignment remain unresolved.
The length field must not be treated as a negotiated ATT MTU.

## Qualified short identifiers

`2a4d11` and `2a4d21` are internal six-hex-character identifiers. UUID
conversion `0x703b1f20` accepts strings of length 4, 6 or 36. In its six-digit
branch, raw instructions shift the parsed number right by 8 before writing
the 16-bit UUID bytes. Both therefore map to wire UUID `2a4d`; the full
identifiers remain distinct in the inventory. Their characteristic specs also
carry different extra-byte pairs, `[1,1]` and `[2,1]`.

LLVM shows the shift at `0x703b1f9a`; Ghidra's AndeStar profile decodes the
custom instruction at `0x703b1fa2` as `bfoz a5,a5,#0xf,#0x8`, extracting the
next UUID byte. `InspectInstructions.java` records the exact p-code in private
`firmware/ghidra-gatt-uuid-stdout.log`. Treating six-digit strings as literal
24-bit Bluetooth UUIDs would misrepresent the conversion path.

## Native transport bindings

The connection/transmitter setup at `0x7036e282` registers modules for custom
UUIDs `0016` and `0017`. Client-path receive handler `0x7036d928` compares the
actual UUID before dispatch: `0016` accepts native packet types 2 or 4; `0017`
accepts 1 or 3. The local GATT server has separate callbacks: `0x7036e5d8` on
`0016` accepts types 1/3, while `0x7036e554` on `0017` accepts 2/4. This
direction distinction is confirmed by the live phone-write/watch-notification
capture in [LIVE_GADGETBRIDGE.md](LIVE_GADGETBRIDGE.md).

Parser `0x7036d0ae` and serializer `0x7036d368` describe a lower channel layer
with types 1–4. Type 3 has flags and optional extended fields plus payload.
The corrected exports now confirm the type-2 asymmetry: serialization emits
six bytes, while this parser consumes only two. A host codec and bounded
plaintext fragmentation/reassembly model preserve that behavior; see
[NATIVE_CHANNEL.md](NATIVE_CHANNEL.md). These packets must not be conflated
with the separately recovered 16-byte JS message header or sensor-hub zrpc.

The custom UUID `0022` has a different observed use: `0x703654ac` registers it
as `BT_PORT` through RFCOMM registrar `0x703b8fa2`. Its existence in the UUID
string inventory did not by itself establish a BLE GATT characteristic.
The custom UUID `0025` exists in the firmware but is absent from this builder.

The authentication initializer is now concretely linked to the native crypto
delegate, including per-app key/counter lookups and integrity checks; see
[NATIVE_CHANNEL.md](NATIVE_CHANNEL.md). Pairing/key provisioning, persistence,
phone-side notification packets and the active watch configuration remain open.
The on-disk `auth_keys` store still requires tracing through the provider and
session setup. No stored device secrets were read.

## Reproduction and validation

Process the startup-aware main ELF with `DecompileWithAbi.java`, writing a
separate private `firmware/decompiled/runtime-ble` output, for targets
`0x7035e766 0x703b2236 0x7036d928 0x7036e282 0x703654ac 0x703bd2c0`.
See [NATIVE_REPAIR.md](NATIVE_REPAIR.md) for the command structure. The actual
private log is `firmware/ghidra-runtime-ble-stdout.log`.

```sh
python3 analysis_scripts/gatt_service_builder.py firmware/bip6-4.6.0.3.zip \
  --source firmware/decompiled/runtime-ble/7035e766.c \
  > analysis/gatt-service-builder.json
python3 -m unittest discover -s tests -p 'test_gatt_service_builder.py' -v
```

The inspector reconstructs only explicit stack assignments, zeroing, partial
word updates and `CONCAT22` in this targeted export. It follows the declared
all-success branch without executing C or calling native code. Unsupported
expressions/control flow, missing bytes and invalid pointers fail. Its input
is the reviewed export, not arbitrary C source; it is not a general C parser
or a proof that every possible stack mutation was accounted for.

Five synthetic tests cover layouts, partial updates, zeroing, qualified UUIDs,
descriptor conditions and malformed inputs. The complete Python suite passes
115 tests with signature dependencies. The JSON regenerates byte-for-byte
from the same source text and original member; the source-text hash is stored
in the report. No Bluetooth/device interaction was performed.
