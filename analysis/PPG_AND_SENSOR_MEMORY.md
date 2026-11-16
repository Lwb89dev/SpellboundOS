# Optical front end and reconstructed sensor-hub initial RAM

Follow-up: [SPI and timing contracts](OPTICAL_SPI_AND_TIMING.md) follows the
board binding through the hardware adapter, recovers control/divider formulas
and polling/error semantics, and distinguishes active from scheduler delays.
Physical timing and complete standalone operation remain unverified.

[Native register execution](SPI_REGISTER_NATIVE_EXECUTION.md) now confirms
the read/write wrappers' integer results and output-copy behavior with
synthetic SPI responses. The response used there is not a measured chip ID.

The sensor-hub member contains a `dev_max8617x` driver with six named optical
operations, an identification check and a concrete SPI device configuration.
This resolves the previous optical-front-end search to the **MAX8617X driver
family**. It does not establish an exact fitted chip suffix or a physical pinout.

All findings are static, from `META/extfw/sensorhub@mhs003_sign.bin`, SHA-256
`06f07541e8bb22b6118f081e791c3a4e40cbff2decd8ee478a7e82df826e9d0f`, under
the existing candidate file mapping at `0x80f62000`.

## Startup copy and zero tables

Startup helper `0x80f6295a` walks two three-word copy records at `0x80f62280`,
then one two-word zero record at `0x80f62298`. The words reconstruct:

| Operation | Source in mapped image | Destination | Bytes |
| --- | --- | --- | ---: |
| Copy | `0x80ff0ae8` | `0x80f0d000` | `0x9e08` |
| Copy | `0x80ffaa60` | `0x80f5d7c0` | `0x53c` |
| Zero | — | `0x80f16f78` | `0x46840` |

This explains initialized state references below the original image mapping.
[`sensorhub_memory.py`](../analysis_scripts/sensorhub_memory.py) reads the
tables and reconstructs a bounded initial-memory view. It checks alignment,
source/destination bounds and overlapping regions; unknown addresses fail
instead of being silently treated as zero. No startup code is run.

This is initial state before runtime modifications, not a RAM dump. It does not
establish the complete address space, external memory, MMIO or ROM mapping.

## Optical board configuration and probe

Board-registration helper `0x80f6257c` registers the 24-byte initial structure
at `0x80f153dc` as `dev_max8617x`. The recovered fields are:

| Field | Initial value / interpretation |
| --- | --- |
| `+0x00` | `sens_spi0_dev0` bus-name pointer |
| `+0x04` | `PPG_1V8` named power resource |
| `+0x08` | `PPG_VLED` named power resource |
| `+0x0c` | Zero; meaning unclassified |
| `+0x10` | Logical interrupt GPIO 39 |
| `+0x12` | Reset GPIO raw value `0xffff`; probe skips optional reset setup |
| `+0x14` | IRQ configuration word 4; electrical meaning unverified |

The field interpretations are supported by the uses in probe `0x80f76ae6`:
bus lookup, power-resource lookup, optional reset configuration, interrupt
configuration and callback installation. That probe sets a bus field to
8,000,000 and a configuration word to `0x801`; exact SPI mode/flags and clock
units still require HAL confirmation.

It attempts a read of register `0xff`, accepts byte `0x46`, and has up to three
attempts with a delay-like call carrying 10. On success it configures the IRQ,
creates a mutex, and registers six optical operation records. This is the
driver's expected identity, not a watch measurement.

Register-read wrapper `0x80f7304c` builds three bytes: register, `0x80`, zero;
it requests a three-byte transfer through `0x80f898ae` and takes the third
returned byte on success. Register-write wrapper `0x80f73152` builds register,
zero, value and sends three bytes through `0x80f897bc`. Both pass 1000 as a
timeout-like argument. Their broad C exports have unreliable return types;
the protocol buffer construction is the observation, not a verified standalone
driver or complete error contract.

The reconstructed LSM6DSO board structure independently names
`sens_spi1_dev0`, distinguishing the motion bus from the optical bus.
Logical device and GPIO names do not establish PCB traces or package pins.

## Optical operation records

Six consecutive 48-byte records in initialized RAM begin at `0x80f15568`:

| State address | Name |
| --- | --- |
| `0x80f15568` | `MAX8617X SPO2 5PD 2LED` |
| `0x80f15598` | `MAX8617X PPG 5PD 2LED` |
| `0x80f155c8` | `MAX8617X BP` |
| `0x80f155f8` | `MAX8617X SPO2` |
| `0x80f15628` | `MAX8617X PPG` |
| `0x80f15658` | `MAX8617X WEAR` |

The JSON retains the 12 literal words per record and candidate callback roles.
All share read candidate `0x80f747c0`, control candidate `0x80f763be` and
flush candidate `0x80f75bf6`; start/stop callbacks differ. The last record also
has power callback `0x80f75c80`, which reads register `0x0d` and writes bit 1
set for its argument-3 hibernate path. The probe registers these records in
reverse address order through `0x80f63fac`.

The driver family and `5PD 2LED` labels are compiled software descriptions.
They do not independently prove how many LEDs/photodiodes are fitted or that
the `BP` operation implements a usable blood-pressure measurement.

## Reproduction and limitations

```sh
python3 analysis_scripts/sensorhub_memory.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/sensor > analysis/sensorhub-memory.json
python3 -m unittest discover -s tests -p 'test_sensorhub_memory.py' -v
```

The [JSON evidence](sensorhub-memory.json) is deterministic and records source
text hashes for the startup, board-registration, probe and register wrappers.
Without `--decompiled`, binary memory reconstruction and board/operation tables
still work; the extracted probe constants are omitted. Six synthetic tests
cover relocated data, zeroed memory, unknown reads, invalid/overlapping regions,
strings, callback bounds, partial-word copies and empty records. Table offsets and board addresses are explicit
assumptions for this OTA, not a general container parser.

The remaining work is to verify the HAL flag meanings, initialization register
sequences, FIFO format, sample timing, inter-processor delivery and health
algorithms. Exact silicon and functional behavior require external evidence
or observation. No device access or firmware installation was performed.
