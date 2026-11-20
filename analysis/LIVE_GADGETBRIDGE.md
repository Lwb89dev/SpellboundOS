# First live Bip 6 session through the Android phone

On 2026-11-15 the user connected the phone over USB ADB and authorized continuing
the investigation with Gadgetbridge. The observed phone is SM-S921B, Android 17
(SDK 37), running Gadgetbridge 2026.11.1. ADB terminates on the phone; the watch
is reached by Gadgetbridge over Bluetooth. This is not watch shell/flash access.

Initially the app showed the already-associated Bip 6 as disconnected, while
Android retained a BLE link. Reconnecting its existing card completed
authentication and initialization. The final app state is connected. No new
bond, firmware installation, boot command, recovery operation or flash backup
was performed. Normal Gadgetbridge initialization did send its own protocol
requests/configuration writes; this was not a strictly passive RF capture.

## Observed GATT and application layers

The log lists 19 characteristic UUIDs; every listed property bitmask matches
the low byte of a spec in the static eight-service/31-characteristic builder.
The 12 unlogged specs are **unobserved**, not established absent from the watch.
Gadgetbridge's logging filters and the current configuration limit coverage.
[gadgetbridge-session.json](gadgetbridge-session.json) records only allowlisted
metadata and source hashes; it does not contain device names/addresses or data.

The link negotiated MTU 247. During initialization Gadgetbridge temporarily
uses a 23-byte MTU budget before requesting 247 again. The native data packets
observed during authentication are at most 20 bytes on phone writes, consistent
with an ATT payload budget of 20. MTU and the native transport capacity remain
different quantities.

The watch announces 62 **application services** through Zepp OS module 0. This
is separate from GATT service discovery. Application modules use native
type-3 messages over custom `0016`/`0017`, including authentication module `0x82`.

## Captured native protocol verification

A bounded debug-log snapshot contains 114 native packets: 113 type 3 and one
type 4. The independently authored verifier checks all routing, headers,
start/end lengths, app/session consistency, sequence order and encrypted flags.
It completes 103 transfers with none left pending:

| Check | Observed result |
| --- | ---: |
| Complete plaintext transfers | 34 |
| Complete encrypted transfers with valid size and CRC | 69 |
| Phone-to-watch complete transfers | 52 |
| Watch-to-phone complete transfers | 51 |
| Subsequent encrypted-counter checks | 67 |
| Exact counter successors among those checks | 67 |
| UUID/type route checks | 114 |

For each encrypted transfer, the verifier takes the ephemeral 16-byte session
key that Gadgetbridge itself logged, XORs every key byte with the transfer's
session byte, decrypts with a standard AES-128 ECB implementation, and checks
the reconstructed payload/counter/CRC envelope. All 69 pass in both directions.
This provides a live interoperability check for the statically recovered
wrapper, key mixing and CRC. It does not execute the native binary in a host
emulator or prove pairing-key generation. First counters are not independently
known; checks begin with the second encrypted message in each direction/app.

The captured auth request is opcode 4, API level 2, mode 2, with a 48-byte
public point. Its 67-byte response starts `10 04 01` and includes a 16-byte
challenge and 48-byte watch point. The 33-byte opcode-5 proof carries two
16-byte values. Encrypting the challenge with the logged, **unmixed** session
key matches the second proof. The first proof uses the persistent key and is
not independently checked here. The watch returns `10 05 01`, and Gadgetbridge
logs authentication success. Initial provisioning, scalar generation and the
complete ECDH/key derivation remain separate tasks.

The capture also corrected a direction ambiguity in earlier reports. Local
GATT server callbacks `0x7036e5d8`/`0x7036e554`, re-exported with ABI/logger
corrections, accept types 1/3 on `0016` and 2/4 on `0017`. Receive filter
`0x7036d928` belongs to the client-side direction. In this session phone writes
data on `0016` and watch notifications carry data on `0017`.

## Local handling and reproduction

Gadgetbridge file logging was initially off. It was enabled temporarily through
the app, one normal disconnect/reconnect was captured, then it was restored
off and verified. The generated log and UI dump were removed from the phone
after copying. The phone/watch association remains connected.

Raw package/service/Bluetooth/UI/log captures live only in ignored
`firmware/device-session-20261115/`, with directory mode 0700 and files 0600.
The debug log contains an ephemeral session key, traffic and potentially
personal data; do not publish it. Public outputs contain counts, booleans,
protocol UUIDs/module IDs and hashes of complete input files. They contain no
key or key hash, nonce values, addresses, names, payloads or padding.

```sh
python3 analysis_scripts/gadgetbridge_session.py \
  --logcat firmware/device-session-20261115/gadgetbridge-connected-logcat.txt \
  --ui firmware/device-session-20261115/gadgetbridge-connected-ui.xml \
  --package firmware/device-session-20261115/gadgetbridge-package.txt \
  > analysis/gadgetbridge-session.json
python3 analysis_scripts/verify_gadgetbridge_channel.py \
  firmware/device-session-20261115/gadgetbridge-session-debug-complete.log \
  > analysis/gadgetbridge-channel-verification.json
```

The second command needs `cryptography`. Its output is
[gadgetbridge-channel-verification.json](gadgetbridge-channel-verification.json).
Both JSON reports regenerate identically from the private snapshots. Eight
synthetic tests cover live/static property matching, exclusion of private
fields, malformed capture metadata, a standard AES known-answer vector,
bidirectional envelopes, counter wrap/regression, CRC corruption, routing,
incomplete sessions and the session-key challenge proof. All 173 Python tests
pass with the existing signature/cipher dependencies.

The channel report also verifies that the authorization request, challenge,
proof and success response occur exactly once in order on the same app channel.
The recorded reconnect satisfies this check. Synthetic tests reject reordered,
duplicated and cross-channel observations that still contain a matching proof
and a success response. The capture starts with an existing pairing, so first
pairing, key provisioning and counter initialization still need fresh evidence.

This first runtime session closes a specific transport-validation gap. It does
not establish a safe standalone boot path, physical flash/ROM backup, pinout,
sensor accuracy, fresh pairing or all notification/call behavior.
