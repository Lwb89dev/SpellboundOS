# Application container and packaged JavaScript bytecode

Static investigation of Bip 6 OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
The independent inspector is `analysis_scripts/app_formats.py`. It does not
execute the packaged JavaScript. Complete extracted atom strings and metadata
from this pass remain under ignored `firmware/app-atoms/` and
`firmware/app-format-summary.json`.

## Application.bin: complete top-level physical walk

`META/resources/Application.bin` has SHA-256
`611f52629c71e1cc92d0175301f5022d921937e834b5ee9b1a7b10cd51650bb0` and
physical size 2,533,862 bytes. It starts with RIFF/GAPP, but its LIST lengths
behave differently from conventional RIFF: the four-byte LIST type is outside
the declared length. Accounting for it gives a top-level walk that reaches
physical EOF exactly:

| Offset | Section | Declared size | Next physical offset |
| --- | --- | ---: | --- |
| `0x00000c` | APP | 3,054 | `0x000c02` |
| `0x000c02` | LIST / LAYR | 1,815,002 | `0x1bbde8` |
| `0x1bbde8` | LIST / SCEN | 196,626 | `0x1ebe06` |
| `0x1ebe06` | LIST / ANIM | 12,916 | `0x1ef086` |
| `0x1ef086` | LIST / RATE | 200 | `0x1ef15a` |
| `0x1ef15a` | DAMR | 505,988 | `0x26a9e6` (EOF) |

For LIST, the observed next offset is current offset + 8 + 4 + declared size;
for APP and DAMR it is current offset + 8 + declared size. No extra alignment
padding is needed for this specimen. LEND markers occur around the ends of the
LIST contents. The earlier four-byte boundary discrepancy was therefore a
container-length interpretation issue, not unexplained padding between these
sections.

This recovers physical top-level boundaries only. Nested layer/action formats
and the meaning or instruction set of DAMR have not been decoded. The top-level
RIFF declared size is 2,520,716, giving a conventional RIFF end at `0x267694`,
which still differs from physical EOF by 13,138 bytes. Its precise accounting
rule remains unknown; the inspector does not silently treat that declaration
as a validated total length.

## Thirty packaged app binaries: atom tables recovered

All 30 `.bin` members below `META/js_apps/` parse with the following consistent
layout:

1. Version byte `0x01`.
2. ULEB128 atom count.
3. That many strings, each with a ULEB128 descriptor: bit 0 marks a wide string,
   and the remaining bits give character count. Narrow strings occupy one byte
   per character; wide strings occupy two little-endian bytes per character.
4. A serialized-object tag immediately after the atom table. In every member
   here the tag is `0x0e`.

This pass recovered 6,695 atom entries across the 30 members. Every member's
atom table ended within its original byte range and left bytes for the object
body. This is considerably stronger than an ASCII-string scan: the declared
atom counts and encoded lengths account exactly for the consumed ranges.
The follow-up parser described below reads initial function metadata; opcode
semantics and nested constant-pool objects remain undecoded.

The observed layout matches the binary-object reader in the official
[QuickJS 2020-01-19 source release](https://bellard.org/quickjs/quickjs-2020-01-19.tar.xz):
The downloaded reference archive SHA-256 is
`4ae4c20c4ed7c201d72c228d5e8768314950914ba60d759f3df23d59037f2b85`.
`JS_ReadObjectAtoms` reads the version, count and strings; `JS_ReadString`
uses the descriptor layout above. In that release the non-BIGNUM base version
is 1 and `BC_TAG_FUNCTION_BYTECODE` is 14. This supports a QuickJS-v1-family
interpretation. It does not prove that Zepp's bytecode layout, opcode numbering,
builtin atom IDs or runtime behavior match that exact upstream release.

## Upstream full-reader experiment and limit

A local C probe was built against that official source outside the repository,
with `DUMP_BYTECODE=1` and without `CONFIG_BIGNUM`. It creates a QuickJS context,
passes one member to `JS_ReadObject(..., JS_READ_OBJ_BYTECODE)`, and would dump
function objects recursively; it never calls `JS_EvalFunction` on the target.
The build command, from the extracted reference directory, was:

```sh
gcc -O2 -D_GNU_SOURCE '-DCONFIG_VERSION="2020-01-19"' \
  spellbound_reader.c libregexp.c libunicode.c cutils.c \
  -lm -ldl -lpthread -o /tmp/spellbound-quickjs-reference/reader
```

The invocation was:

```sh
timeout 20s /tmp/spellbound-quickjs-reference/reader firmware/app-bytecode/first.bin
```

`first.bin` is `META/js_apps/000FFD39/app.bin`. The reader received SIGSEGV,
so this experiment did not establish full upstream compatibility or produce
usable decompilation. The local coredump metadata and symbol table place the
recorded instruction inside `free_function_bytecode`; the underlying reason
was not established, and the probe was not retried unchanged. Memory was
available, and the recorded signal was SIGSEGV, not an OOM kill. The reference
source, independent harness and compiled probe remain outside the repository
under `/tmp/spellbound-quickjs-reference/`; no target JavaScript or device code
was executed. The robust Python parser deliberately stops at atom-table bounds.

## Reproduce and continue

```sh
python3 analysis_scripts/app_formats.py firmware/bip6-4.6.0.3.zip
python3 analysis_scripts/app_formats.py firmware/bip6-4.6.0.3.zip \
  --atoms-dir firmware/NEW_PRIVATE_ATOM_DIRECTORY
python3 -m unittest tests/test_app_formats.py -v
```

The atom-directory option requires a new directory and stores full recovered
strings locally. Standard JSON output contains only ranges, counts and hashes.
Four tests cover mixed narrow/wide atoms, truncated and overflowing length
encodings, initial function-field consistency and bytecode bounds, LIST
type-length handling, and a section extending past EOF.

A next bytecode pass should extend the bounded parser through constant-pool
objects and validate the exact shipped runtime's opcode definitions before
disassembling, while preserving unresolved vendor changes.
A separate GAPP pass should follow the main firmware's APP/LIST/DAMR readers
before assigning semantics to those sections. Both tasks remain open.

## Follow-up: initial function metadata and bytecode ranges

A bounded parser following the initial-function structure in the same official
QuickJS reader now succeeds across all 30 members. It consumes the function tag,
16-bit flags, mode byte, raw encoded name-atom reference and eight ULEB128
counts, then validates/skips local and closure records before identifying the
bytecode range. It also consumes optional debug metadata up to the first
constant-pool object, without interpreting that object or executing bytecode.

All 30 initial functions have the same observed metadata:

| Field | Value |
| --- | ---: |
| Flags word | `0x0600` |
| JS mode | 0 |
| Encoded function-name atom reference | 160 |
| Atom index derived from that encoding | 80 |
| Argument / variable / defined-argument counts | 0 / 2 / 0 |
| Stack size | 5 |
| Closure / constant-pool / local counts | 0 / 4 / 2 |
| Initial function bytecode length | 91 bytes |
| Debug line / line-table length | 1 / 0 |
| First constant-pool object tag | `0x0e` |

The numeric name reference is preserved without assigning a builtin name:
vendor builtin atom numbering has not been established. Each member's exact
metadata, bytecode and debug offsets are emitted by the tool under
`initial_function`. Every bytecode range fits inside its source member, every
local count matches argument plus variable count, and all 30 leave the expected
first constant-pool tag after the debug prefix. No specimen diverged from this
bounded initial-metadata layout.

Twenty-eight 91-byte initial bytecode ranges have SHA-256
`43c15b790cf0fd2233f0ae0be0e45218e4537282c2618809c100c30f2f8172bf`;
two have SHA-256
`4d5292abf718b40a8e05c3bd85c687d8bc76bff7a31815dd388c9d437b85c919`.
This similarity suggests a common outer wrapper; its instruction semantics
have not been reconstructed. Matching the initial metadata does not resolve
the upstream full-reader failure, establish complete bytecode compatibility,
or validate nested functions and constants.
