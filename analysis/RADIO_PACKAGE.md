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
