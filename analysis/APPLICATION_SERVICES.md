# Application-service announcement and native dispatch

Every one of the **62 application services** announced in the saved Bip 6
session now has a matching native descriptor candidate in OTA 4.6.0.3. All 62
encryption-policy bytes agree. This maps module IDs and callback ownership;
it does not establish complete behavior for each service.

The inputs are the same main member and private session used in
[LIVE_GADGETBRIDGE.md](LIVE_GADGETBRIDGE.md). No phone or watch was accessed for
this follow-up. Original code, decompilations, traffic and keys remain under
ignored `firmware/`; the public reports contain metadata and synthetic examples.

## Module 0: discovery protocol

Dispatcher `0x7036a4b6` responds to opcode **3** by reading the channel registry
through `0x7036cab2` and serializing:

```text
04 count:u16le (module_id:u16le require_encryption:u8)[count]
```

The first field of a native descriptor is a byte; the announcement zero-extends
it into a u16 wire ID. The captured response is exactly 189 bytes:
`3 + 62 × 3`. The inspector reassembles the native plaintext response, requires
it to match Gadgetbridge's decoded module-0 log, parses all records, and checks
their order/IDs/flags against the 62 service classifications logged by the app.
These are application modules carried inside native type 3, not GATT services.

The names in the JSON are **Gadgetbridge classifications**. An `unknown` name
in that client is retained as null even when a native callback is identified;
matching an ID does not justify inventing a feature name.

## Native registration coverage

Registrar `0x7036c636` consumes 76-byte descriptors:

| Offset | Observed role |
| --- | --- |
| `+0` | module ID byte |
| `+1` | require authorization byte |
| `+2` | require encryption byte |
| `+3` | reserved byte |
| `+4`, `+8` | allocator/free callbacks; defaults supplied if null |
| `+0x40`, `+0x44`, `+0x48` | alternative receive-complete callbacks |

An encryption requirement implies authorization. Registration copies the
descriptor into the registry. Runtime discovery exposes the encryption byte,
not every field or callback. Other callbacks remain classified only by offset
unless separately followed.

The investigation first found 46 callers in the old C corpus. A raw JAL and
adjacent AUIPC/JALR candidate scan found 14 additional caller candidates whose
registration paths were absent from the old truncated exports. Fresh
ABI/logger-corrected exports confirm their setups. The original source corpus
was therefore insufficient as a complete cross-reference index.

There is also a **dynamic** registrar, `0x7036c834`. World clocks module `0x08`
uses it from `0x703a8c3a`; it copies the same descriptor layout and then notifies
the service layer through `0x7036a7f2`. Searching only for calls to the static
registrar missed this module.

The final inventory has 61 initializer exports and 63 candidate descriptors.
Initializer `0x703a4aca` selects among three assistant descriptors. Selector 1
registers `0x11`, selector 2 registers `0x4a`, and selector 0 describes `0x10`.
The capture announces the first two, not `0x10`. The three branch variants are
explicitly reviewed metadata tied to the exact source hash, not an attempt to
execute arbitrary conditional C.

Three prefixes require original-instruction checks. Ghidra renders the scalar
constants as addresses of CSR symbols (`scause`, `scounteren`, `sip`) and infers
a pointer-array assignment. LLVM shows `LI a5,value; SH a5,4(sp)`, a two-byte
store after zeroing, at the following addresses:

| Initializer | Store sequence | Literal prefix | Module |
| --- | --- | --- | --- |
| `0x7035a3d2` | `0x7035a5be` | `0x0142` | `0x42` |
| `0x7038549e` | `0x70385704` | `0x0105` | `0x05` |
| `0x7038dc06` | `0x7038ddfa` | `0x0144` | `0x44` |

The inspector guards the exact eight instruction bytes before overriding only
that prefix's value and width. The upper two bytes stay zero, including the
encryption byte. These symbol names do not establish CSR access by these
registration paths. Unknown expressions elsewhere remain unknown bytes.

## Selected payload contracts

The following ownership is now connected to concrete dispatchers:

| Module | Client label | Initializer | Receive callback | Auth/encryption |
| --- | --- | --- | --- | --- |
| `0x00` | Services | `0x7036a772` | `0x7036a4b6` | no/no |
| `0x0b` | Phone | `0x7035f150` | `0x7035ed4a` | yes/yes |
| `0x1e` | Notification | `0x70388a9e` | `0x7038946a` | yes/yes |
| `0x46` | Maps | `0x7038d5ba` | `0x7038d1e2` | yes/yes |

### Notification opcode 3

The selected notification parser reads:

```text
03 id:u32le kind:u8 subtype:u8
string0:NUL string1:NUL string2:NUL string3:NUL
[string4:NUL if kind == 3]
boolean0:u8 [extra_byte:u8 [extra_boolean:u8 [extra_string:NUL]]]
```

Strings are preserved as bytes; the native helper `0x703d066c` uses NUL
termination and does not establish a character encoding. The later dump-helper
and controlled capture analysis now identifies app ID, title, message, app name,
phone number, reply and flag fields; see
[NOTIFICATION_ACTIONS_AND_ROADSTR.md](NOTIFICATION_ACTIONS_AND_ROADSTR.md).
Boolean bytes normalize by nonzero testing. Optional fields must
occur consecutively; remaining bytes after the last parsed optional string
are ignored by the observed branch and preserved by the host decoder.

This describes opcode 3 only. Later notification formats, actions, app filters,
file resources and UI delivery remain open. The callback includes additional
opcodes; its existence is not a complete notification implementation.

### Phone pairing and settings

The native log messages identify this module's operations:

| Request | Payload after opcode | Observed role |
| --- | --- | --- |
| `01` | none | query version; reply `02 01 00` |
| `03` | NUL-terminated identifier | query pair status; reply `04 status:u8` |
| `05` | NUL-terminated identifier | start pairing via a delegate |
| `06` | none | query settings; reply `07 01 01 value:u8` |
| `08` | count:u8, then `(type:u8,value:u8)` entries | update setting type 1 |

In an update, zero count and unknown types are rejected; repeated type-1 entries
overwrite the same boolean, so the last value wins. The model retains every
entry plus the effective boolean. Peer-identifier validation and pairing are
delegate operations outside this parser. No pairing command was sent.

These findings do not demonstrate dialing, answering, hanging up or an audio
channel. Call controls and audio profiles need separate tracing and testing.

### Map download opcode 5

The selected map command is:

```text
05 total_size:u32le count:u16le file_identifier:NUL[count] [mode:u8]
```

The native parser requires a nonzero size/count and nonempty identifiers.
Absent mode defaults to 1; explicit values 0/1 are accepted. The host inspector
adds a 256-file bound and a 1 MiB payload bound, neither claimed as firmware
limits. Download callbacks, file contents and other map commands are not modeled.
This download-task format does not establish Roadstr turn-by-turn navigation.

## Reproduction and limits

The 61 initializer addresses are the filename stems in
`application-services.json:registration_source_sha256`. Export them using
`DecompileWithAbi.java firmware/decompiled/runtime-app-services`, the
startup-aware main ELF and the ABI/logger corrections in
[NATIVE_REPAIR.md](NATIVE_REPAIR.md). The static registrar and selected
dispatchers belong in `runtime-service-dispatch`; helpers belong in
`runtime-service-payload`. Their address lists and hashes are recorded by
`application_payloads.py`. Private headless logs use
`firmware/ghidra-runtime-app-services*-stdout.log`,
`firmware/ghidra-runtime-service-dispatch-stdout.log`, and
`firmware/ghidra-runtime-service-payload-stdout.log`.

```sh
python3 analysis_scripts/application_services.py firmware/bip6-4.6.0.3.zip \
  --capture firmware/device-session-20261115/gadgetbridge-session-debug-complete.log \
  --registrations firmware/decompiled/runtime-app-services \
  > analysis/application-services.json
python3 analysis_scripts/application_payloads.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled > analysis/application-payloads.json
python3 -m unittest discover -s tests -p 'test_application_*.py' -v
```

[application-services.json](application-services.json) contains the complete
62-entry announcement, 63 candidate native descriptors, callback offsets and
review/byte guards. [application-payloads.json](application-payloads.json) records
selected dispatcher/helper ownership and a synthetic notification vector.
Both outputs regenerate exactly. Sixteen synthetic tests cover count/layout
errors, private-label rejection, native/log agreement, descriptor partial/array
updates, dynamic/unknown fields, guarded u16 stores, selected payload boundaries
and string/optional-field behavior. All 189 Python tests pass with the existing
signature dependencies.

The descriptor inspector is for the reviewed exports. It supports explicit
zeroing, numeric/known callback assignments and a narrow `CONCAT22` update;
it rejects unknown setup calls, indirect writes and unreviewed control flow.
It is not a general C evaluator or complete side-effect analysis. Descriptor
matching, host wire tests and app-supplied names are distinct from execution of
native callbacks on the watch. No new device traffic or private-data export
was performed in this follow-up.
