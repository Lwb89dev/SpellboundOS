# Original main NAND probe, candidate matching and ID/reset packets

All **24 native cases** pass in **13,623 instruction/service steps** (maximum
**2,091**, final candidate on the third round). The actual main probe at
`0x702d685c`, matcher `0x702d641a`, ID builder `0x702d6290` and reset builder
`0x702d62f2` execute over the unchanged original eleven-candidate table.
[main-nand-probe.json](main-nand-probe.json) records **18 code/export and 35 data
hashes**, native observations and explicit limitations.

The bus initialization and transfer bodies, regulator services, requested-delay
service, feature helpers and workaround/UID/BBT bodies remain supplied. This is
offline execution of original instructions over authored peripheral responses;
it does not identify the physical flash or establish electrical operation.

## Original main-image candidate inventory

[main-nand-chips.json](main-nand-chips.json) is extracted from the startup-aware
main image, independently of the boot-image inventory. It records the original
table at `0x70a31798`, all eleven 184-byte descriptors, names, five ID bytes,
geometry, feature sequences, reset opcode/delay, UID flag and hashes.

| Index | Original descriptor | Name | ID bytes | Page size |
| --- | --- | --- | --- | --- |
| 0 | `0x70a3204c` | Winbond W25N01GWZEIB | `ef ba 21 00 00` | 2 KiB |
| 1 | `0x70a31974` | Winbond W25N01KWZEIG | `ef be 21 00 00` | 2 KiB |
| 2 | `0x70a31f8c` | Winbond W25N04KW | `ef ba 23 00 00` | 2 KiB |
| 3 | `0x70a318b0` | Winbond W25N04LWZEIG | `ef b2 23 00 00` | 4 KiB |
| 4 | `0x70a31ec8` | DOSILICON DS35M1GA | `e5 21 00 00 00` | 2 KiB |
| 5 | `0x70a31e04` | DOSILICON DS35M1GB | `e5 a1 00 00 00` | 2 KiB |
| 6 | `0x70a31d40` | DOSILICON DS35M2GA | `e5 22 00 00 00` | 2 KiB |
| 7 | `0x70a31c7c` | DOSILICON DS35M2GB | `e5 a2 00 00 00` | 2 KiB |
| 8 | `0x70a31af8` | DOSILICON DS35M4GB-IB | `e5 64 00 00 00` | 2 KiB |
| 9 | `0x70a31a34` | DOSILICON DS35M4GM-IB | `e5 a4 00 00 00` | 2 KiB |
| 10 | `0x70a31bbc` | ESMT F50D4G41XB | `2c 35 00 00 00` | 4 KiB |

All original candidates are selected in separate native cases. The main matcher
requires the first two bytes; expected zero bytes in the later positions act as
wildcards. Its export compares a nonzero fifth expected byte against the fourth
received byte. Every original fifth expected byte is zero: these cases do not
exercise that nonzero branch or supply a new counterexample for it.

## Detection, power and command packets

Probe requests the original regulator property into `0x70f8e6e8`. With an authored
handle, it calls disable, requests delay 20, calls enable and requests delay 20.
Selected negative supplied power statuses are ignored. With no handle it logs
the missing regulator and continues without those calls. Delay values are
observed arguments, without elapsed-time or hardware-unit validation.

The actual body clears selected pointer `0x70f8e6f8`, then tries all eleven
candidates for up to three rounds. Each attempt reaches the original bus-init
callback address `0x70296ab0` through unchanged binding `0x80c007c4`, followed by
the real ID builder and matcher. Authored ID bytes permit success in round two,
success on the final 33rd attempt and complete no-match exhaustion.

The builders reach original transfer callback `0x70296c24` through that binding.
Its supplied implementation validates the actual 32-byte stack packet:

| Packet field | ID | Reset |
| --- | --- | --- |
| 16-bit mode at +0 | 0 | 1 |
| Byte fields +2, +4, +28 | all 1 | all 1 |
| Command word +8 | `0x9f` | original descriptor +`0x78`, all `0xff` |
| Byte +12 | 1 | 0 |
| Word +16 | 0 | 0 |
| Data pointer +20 | bounded five-byte stack output | 0 |
| Length +24 | 5 | 0 |
| Callback context | zero before selection | original selected descriptor |

After a match, reset runs and probe requests delay
`descriptor.reset_delay_us / 1000 + 1` (11 for all original candidates). It calls
the supplied workaround and conditionally supplied UID body according to the
original flag, then executes the original feature write/read/compare loop.
The exact original feature order and values are observed for every candidate.

## Failures and retained state

| Authored input | Original result / stopped assertion |
| --- | --- |
| No ID matches in 33 attempts | `-4`, selected pointer zero, no reset/features/BBT |
| Bus-init callback `-9` | Assertion owner `0x70a31738`, line 99 |
| ID transfer callback `-9` | ID-builder assertion owner `0x70a30fa4`, line 383 |
| Reset transfer callback `-9` | Reset-builder assertion owner `0x70a30f94`, line 402; selected pointer retained |
| Feature write `-9` | `-5`, selected pointer retained, no BBT call |
| Feature read `-9` | `-6`, prior feature write and selected pointer retained |
| Readback value differs | `-7`, selected pointer retained |

Assertions are captured at the call site; their bodies and recovery do not run.
The real ID/reset helpers normally return zero and assert on callback failure.
The outer probe's exported `-50`/`-51` branches are not exercised by substituting
invented helper returns.

Workaround, UID and BBT return-register values set to `-9` do not prevent success
in the selected case. UID's status convention is not established; this does not
demonstrate a real UID acquisition error. An authored BBT return of 1 with magic
zero also permits success. The BBT body does not run in this scope.

After that call, actual probe publishes a one-MiB page guard at `0x70f8e6f0`
and its block count at `0x70f8e6ec`: 512 pages / 8 blocks for the 2-KiB candidates,
256 pages / 4 blocks for the 4-KiB candidates. Selected early failures leave
these initially zero guard counters unchanged; they do not roll back selection.
These software counts do not prove protection or media validity.

## Reproduction and continuation

```sh
python3 analysis_scripts/main_nand_probe.py firmware/bip6-4.6.0.3.zip \
  --inventory-output /tmp/main-nand-chips.json
cmp analysis/main-nand-chips.json /tmp/main-nand-chips.json
python3 analysis_scripts/main_nand_probe.py --scope probe \
  --vectors-output firmware/main-nand-probe-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandProbe.java \
  -postScript ValidateMainObjects.java \
  firmware/main-nand-probe-vectors.json firmware/main-nand-probe-validation.json

python3 analysis_scripts/main_nand_probe.py firmware/bip6-4.6.0.3.zip \
  --scope probe --decompiled firmware/decompiled/runtime-main-nand-probe \
  --vectors firmware/main-nand-probe-vectors.json \
  --validation firmware/main-nand-probe-validation.json
```

Use the existing startup-aware main-object project and earlier metadata seeds.
`SeedMainNandProbe.java` changes metadata only. Export with
`DecompileWithLogger.java`, logger `0x702b38a2`, and addresses from
`ranges('probe')` in `analysis_scripts.main_nand_probe`. Firmware and exports
remain local. Code/data hashes, original descriptor/feature/table/bus immutability,
return ABI and authored buffer guards are checked.

The [connected root scope](MAIN_NAND_PROBE_ROOT.md) replaces its previous supplied
probe with these actual bodies. Next native work is the main bus/platform/feature
transport, then actual main UID/workaround/BBT and broader media/storage callers.
Boot-image coverage does not independently establish those main-image bodies.
