# RTL8763 package: bounded structural inspection

Date: 2026-11-15. Source: `META/extfw/pamir/rtl8763_pack.bin` in the official
Bip 6 4.6.0.3 OTA. The archive SHA-256 is
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`;
the member SHA-256 is
`47c41063ca2eaa1bac730d5ca1b7f5338c43152d83aa173ca5038956b36708c4`.
This is a static observation, not a validated package specification.

The member is 1,508,342 bytes. It begins with bytes `47 4d bc db` (`GM` plus
two non-ASCII bytes); the little-endian word at offset `0x04` is `0x16`.
The first 0x48 bytes are the same length as the first read requested by the
candidate loader at `0x703cd15a` in the main firmware. We have not proven that
this function parses every field in those bytes.

From file offset `0x48` through `0xfb` there are 15 consecutive 12-byte
records. In each, the first little-endian word is between `0x02000000` and
`0x02ffffff`, the second is positive and less than the member size, and the
third is zero. The run stops at `0xfc`, where the next 12 bytes fail this
pattern. The first/second values plausibly resemble target addresses and
lengths, but they have not been identified through the loader's actual parser.
They must not be used as a memory map or flashed to a device on this evidence.
The complete literal words and offsets are in
[radio-package.json](radio-package.json).

The package contains readable strings referring to `RTL8763EFL`, `RTL8773E`,
`secure_boot_image_id`, and other embedded code paths. These strings indicate
that the file has internal content beyond the prefix. They do not identify the
exact radio fitted to this watch or prove that all code in the package runs.

## Reproduce

```sh
python3 analysis_scripts/inspect_radio_package.py firmware/bip6-4.6.0.3.zip
```

The scanner intentionally reports generic `word_0`/`word_1`/`word_2` fields.
It only accepts this observed prefix and scans until the first nonmatching
record. It neither extracts segments nor validates an image format. The Python
test uses a synthetic prefix to check that record detection stops at the first
nonmatching tuple.

Next, locate the parser and transfer routine called after the loader's initial
`0x48`-byte read, resolve the transport callback targets, and compare those
operations with these observed words. The current Ghidra RISC-V decompilation
loses important control flow at custom instructions, so this requires a
second disassembly method or manual instruction decoding.

## Update: AndeStar profile and field accounting

A fresh AndeStar v5 import restores more of `0x703cd15a`. Its pseudocode
compares the first 16 bits with `0x4d47` (`GM`), checks a little-endian 32-bit
value starting at byte 2 against `0x1fffb8`, and counts set bits in the word
at offset `0x28`. The actual word is `0x01e643ee`, with 15 set bits, agreeing
with the observed number of records. The bytes formerly reported as a fixed
four-byte prefix actually combine the two-byte `GM` marker and the first two
bytes of this size field; the scanner has been corrected accordingly.

The size field is `0x16dbbc`. The 15 candidate payload lengths sum to
`0x16dac0`; adding the `0xfc` bytes occupied by the header and candidate record
table gives exactly `0x16dbbc`. A consecutive payload interpretation therefore
accounts for the declared span exactly, leaving `0x283a` trailing bytes.
The inventory now records these candidate byte ranges and SHA-256 digests.
The reader's bit count is code evidence; the record layout and consecutive
payload interpretation still need corroboration from its downstream caller.
The trailing bytes remain unclassified.

The updated scanner uses the bit count to bound the candidate table and rejects
payload ranges extending beyond the declared span. It does not extract or
execute the resulting segments.

## Update: downstream record reader and transfer loop

With the AndeStar profile, a direct call to the package opener was located at
`0x703cf2d4`, in candidate function `0x703cf284`. It calls `0x703cd370` with
the bit-count result and a table buffer. That helper reads exactly `count * 12`
bytes from the open stream, corroborating the 12-byte record layout.

The transfer loop uses word 0 of each record as an address and word 1 as its
length, requires length greater than `0x200`, and calls a relative-seek helper
to skip `0x200` bytes before reading that record's remaining data. It reads
up to `0x1000` data bytes at a time and constructs command-like buffers whose
first two bytes correspond to words `0x3087`, `0x3287` and `0x5087`. The
buffers contain the derived address and lengths and are sent through an
indirect transport callback. An additional helper processes the outgoing
bytes but currently decompiles as an empty loop; its algorithm remains
unresolved. Protocol framing, checksum semantics and radio-side behavior have
not been reconstructed completely.

This provides code evidence that the first two record fields represent
addresses and lengths and that each candidate payload includes a 512-byte
prefix. Static consecutive payload accounting matches the declared size;
no hardware execution was used to validate the process. The script's
`--extract NEW_DIRECTORY` option now carves the 15 complete candidate payloads
including their 512-byte prefixes. It refuses to reuse an existing output
directory. Local extracted copies are in ignored `firmware/radio-segments/`;
only ranges and hashes are committed.

## Update: checksum model

Applying an explicit scalar return type and three-argument signature to candidate
`0x703ceb56` restores its checksum computation. The earlier empty loop was an
incorrect function-signature inference; it was not evidence that the loop did
nothing. The restored code indexes a 256-entry 16-bit table at candidate address
`0x70a806a8` (file offset `0x9206a8`) with `(seed XOR byte) AND 255`, then XORs
the table value with `seed >> 8`.

All 256 table entries match a reflected polynomial `0xA001` recurrence. An
independent bitwise model in `analysis_scripts/radio_checksum.py` gives `0xbb3d`
for ASCII `123456789` with seed zero, and supports incremental processing.
Evidence is recorded in [radio-checksum.json](radio-checksum.json).
This identifies the arithmetic used at the observed call sites; complete packet
semantics and behavior on the actual radio remain unverified. The explicit
signature can be reproduced with `DecompileChecksum.java` in an AndeStar main
image project.
