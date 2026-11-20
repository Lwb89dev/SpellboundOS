# RTL8763 Bluetooth: vendor HCI command CRC16

The RTL8763 controller firmware is downloaded over a vendor HCI protocol whose
commands carry a CRC16 (logged as `cmd low:%x, cmd high:%x crc low:%x, crc
high:%x` with the `@RTL` tag). `0x703ceb56(crc, buffer, length)` is the
byte-at-a-time CRC16 update that produces it:

```
crc = table[(crc ^ byte) & 0xff] ^ (crc >> 8)
```

over the 256-entry table at `0x70a806a8`. The table is verified to be the
standard reflected **CRC16/MODBUS** table (polynomial `0xA001`); the protocol
seeds the update with `0xFFFF`, so the check value of `"123456789"` is `0x4B37`.
This routine executes natively; the evidence is in
[main-bt-hci-crc.json](main-bt-hci-crc.json). All **7 native cases pass** and a
two-chunk run reproduces the one-pass CRC, confirming a pure chained update.

## Reproduction

```sh
python3 -m analysis_scripts.main_bt_hci_crc --vectors-output firmware/main-bt-hci-crc-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-bt-hci-crc-vectors.json firmware/main-bt-hci-crc-validation.json
python3 -m analysis_scripts.main_bt_hci_crc firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-bt-hci-crc-vectors.json \
  --validation firmware/main-bt-hci-crc-validation.json > analysis/main-bt-hci-crc.json
python3 -m unittest tests.test_main_bt_hci_crc -q
```

## Remaining (BT module)

- The HCI command builder around this CRC16, `hci_send_any`, the H5 / three-wire
  UART transport on `uart2`, and the `rtl8763_pack.bin` patch-RAM loader /
  upgrade task. These are UART/DMA transport orchestration (hardware), decoded
  here down to the integrity CRC16; the transport itself is the remaining work.
