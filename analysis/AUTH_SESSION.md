# Authentication module, request layouts and ECDH key material

The native Bluetooth channel ([NATIVE_CHANNEL.md](NATIVE_CHANNEL.md)) carries an
authentication component addressed as native module `0x82`. This records its
request wire layouts, the public elliptic-curve parameters it uses, the observed
session-key and cloud-binding derivations, and the persistent per-app key store.
It is static evidence from OTA 4.6.0.3, main member SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`. It does not
pair, derive private scalars, run vendor crypto, read stored device keys or send
Bluetooth packets. The host helpers accept only caller-supplied bytes; the tests
use synthetic material.

## Module and request layouts

The reviewed controller is `0x7035cb58` and its dispatcher `0x7035be3e`; auth
payloads ride inside native channel type-3 packets with module ID `0x82`
(`encode_data(..., module_id=0x82)`). The first payload byte is an opcode. The
observed request layouts are:

| Opcode | Extra header | Fixed values | Inferred role |
| ---: | --- | --- | --- |
| 0 | — | — | query version |
| 1 | `api:u16` | one 16-byte value | — |
| 2 | `api:u16` | one 48-byte value | — |
| 3 | — | one 64-byte value | — |
| 4 | `api:u16`, `mode:u8` | one 48-byte value | request authorize |
| 5 | — | two 16-byte values | authorize |
| 6 | — | — | — |
| 7 | — | two 16-byte values | — |
| 8–11 | — | — | — |

Opcodes 1, 2 and 4 carry a little-endian API-level word whose low byte is the
effective level (so `0x0102` reduces to level 2); opcode 4 additionally carries
a mode byte, where the controller accepts only values 1 and 2. Trailing bytes
past a request's fixed values are retained as `ignored_trailing` rather than
rejected. Decoding fails on an empty payload, an unsupported opcode, or any
truncated header or value. `decode_request`/`encode_request` are exact inverses
over the documented layouts.

## Public curve parameters

The auth component uses a binary-field curve. Five parameter words sit in RAM,
each stored as six little-endian 32-bit words (24 bytes). The tool reads them
from the image and compares each with the public **sect163r2** parameters,
independently taken from the installed OpenSSL's explicit curve encoding:

| Parameter | Address |
| --- | --- |
| group order | `0x709e8b10` |
| generator Y | `0x709e8b28` |
| generator X | `0x709e8b40` |
| curve coefficient `b` | `0x709e8b58` |
| field polynomial | `0x709e8b70` |

All five match sect163r2 exactly (`all_parameters_match_sect163r2` is true), and
the script aborts if any does not. sect163r2 is a 163-bit curve over GF(2^163);
the field polynomial is `x^163 + x^7 + x^6 + x^3 + 1`. These are public domain
parameters, not device secrets.

## Session-key and cloud-binding derivation

After the native scalar-multiplication routine writes a shared point as
`X || Y` (each 24 bytes, little endian), only the first 24 bytes (`X`) enter the
channel context. The observed post-processing, modelled by `derive_material`,
is slicing and XOR, not ECDH itself:

- the session channel key is the 16-byte persistent key XOR'd with bytes
  `8..24` of the shared point;
- the first eight bytes of the shared point become the initial RX and TX
  counters (two little-endian `u32`).

`Y` is not consumed, confirmed by the test feeding a zero `Y`. A separate
cloud-binding digest is `SHA-256(device_address[6] || watch_public_point[48])`,
with the 6-byte address in firmware order (display/MAC byte reversal is
unresolved).

## Persistent per-app key store

Keys are stored in a 144-byte table of eight 18-byte records: a validity byte,
a one-byte app ID, then a 16-byte key. `load_key` returns the key of the first
valid record matching the app ID. `save_key` writes into the first record that
already holds the app ID or is free, invalidates any later duplicate by setting
its first two bytes to `00 ff` (while keeping its 16 key bytes), and raises when
the table is full. App IDs are bounded to one byte and keys to 16 bytes.

## Authentication provider callbacks

A provider structure at `0x70f60f70` holds eight function pointers into the main
image. Their roles follow the provider's use sites, not symbols:

| Slot | Inferred role |
| --- | --- |
| 0 | initialize |
| 1 | save key |
| 2 | load key |
| 3 | query app IDs |
| 4 | insert context |
| 5 | remove connection |
| 6 | lookup app context |
| 7 | list contexts |

The tool checks that all eight are halfword-aligned, in-image pointers before
reporting them.

## Reproduction and validation

Use the startup-aware main ELF and the corrected exports from
[NATIVE_REPAIR.md](NATIVE_REPAIR.md) and [NATIVE_CHANNEL.md](NATIVE_CHANNEL.md).
The five reviewed export groups are enumerated in `auth_session.py:SOURCES`
(`runtime-auth-context`, `-lifecycle`, `-proof`, `-module`, `-wire`).

```sh
python3 analysis_scripts/auth_session.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled > analysis/auth-session.json
python3 -m unittest discover -s tests -p 'test_auth_session.py' -v
```

[auth-session.json](auth-session.json) records the provider callbacks, the five
curve-parameter hashes with their sect163r2 match, the reviewed function roles,
export hashes and synthetic request vectors. Because the script imports
`native_channel` and `sensorhub_memory`, run it from the repository root without
Python's isolated mode (which drops the script directory from the import path).
The ten tests cover the golden authorize request, API-level truncation, the
module-`0x82` channel framing, every request length, the session-material byte
order and unused `Y`, the key-store round trip, duplicate invalidation, capacity
failure and the cloud digest. They validate the host models; they do not execute
the watch firmware. No pairing, device-secret extraction or crypto execution was
performed.

## Limitations

This describes request structure, public parameters and observed post-processing.
It does not establish the full pairing handshake, how the persistent key is first
provisioned, counter initialization and persistence across reconnects, or the
peer's implementation. The session-key derivation is the observed slicing/XOR
around a native routine, not a verified ECDH agreement, and the block cipher
itself is modelled in [NATIVE_CHANNEL.md](NATIVE_CHANNEL.md) without a
known-answer or interoperability check. Opcodes 3, 6–11 have layouts but no
established role.

A later [live Gadgetbridge capture](LIVE_GADGETBRIDGE.md) observes API level 2,
mode 2 authorization, its 67-byte challenge/public-point response, 33-byte proof
and successful `10 05 01` reply. The second proof matches AES encryption of the
challenge with the logged ephemeral session key. It also verifies 69 encrypted
channel transfers; initial pairing, persistent-key provisioning and ECDH scalar
generation remain unverified by that session.
