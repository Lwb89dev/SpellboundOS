# Candidate hardware profile and health capability surface

Static string inventory on 2026-11-15 of `META/firmware_sign.bin` in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The
inspector is `analysis_scripts/hardware_profile.py`; its reproducible output is
[hardware-profile.json](hardware-profile.json). These are driver names and
algorithm log tokens compiled into the image, not a bill of materials or a
readout of fitted silicon.

## Candidate chips

The firmware names peripheral drivers as `dev_<part>`. The part-number-shaped
names resolve to candidate parts; four are corroborated by independent findings
elsewhere in this repo:

| Driver | Candidate part | Role | Corroboration |
| --- | --- | --- | --- |
| `dev_ztw622` | Zinitix ZTW622 | capacitive touch controller | 0xE622 touch identity ([TOUCH_AND_SERIAL.md](TOUCH_AND_SERIAL.md)) |
| `dev_icna3311` | Chipone ICNA3311 | AMOLED display driver IC | 0xda/0xdb/0xdc display read ([DISPLAY_AND_LIGHT.md](DISPLAY_AND_LIGHT.md)) |
| `dev_stk31e60` | Sensortek STK31e60 | ambient light / proximity | the `dev_stk31e60` probe ([DISPLAY_AND_LIGHT.md](DISPLAY_AND_LIGHT.md)) |
| `dev_ag3335` | Airoha AG3335 | GNSS receiver | AG3352B GNSS container ([GNSS_AND_TOUCH_BLOBS.md](GNSS_AND_TOUCH_BLOBS.md)) |
| `dev_aw32012` | Awinic AW32012 | charger / LED driver (candidate) | — |
| `dev_cw6305` | CellWise CW6305 | battery fuel gauge / charger (candidate) | — |

The motion sensor (LSM6DSO, identity 0x6C) is covered in
[DRIVER_INTERFACES.md](DRIVER_INTERFACES.md); the radio is the RTL8763 package in
[RADIO_PACKAGE.md](RADIO_PACKAGE.md). The optical PPG/heart-rate analog front end
was unresolved in this main-image inventory. A subsequent sensor-hub analysis
finds a `dev_max8617x` driver, identity-register check and SPI board
configuration; see [PPG_AND_SENSOR_MEMORY.md](PPG_AND_SENSOR_MEMORY.md).
This narrows the candidate to the MAX8617X family without establishing an
exact fitted chip suffix.

## SoC identifiers

The literal tokens `AX861`, `MHS002`, `MHS003`/`mhs003` appear in the image. The
sensor-hub member is `sensorhub@mhs003_sign.bin`, so `mhs00x` names the sensor-
hub processor; `AX861` is the main application-processor identifier. The main
image decodes as Andes RISC-V (AndeStar v5), consistent with these being an
in-house multi-core SoC rather than an off-the-shelf MCU. Exact silicon, die and
memory map still need corroboration.

## Health capability surface

Whole-word counts of a fixed metric vocabulary in the main image (occurrences,
not features proven enabled):

| Metric | Count | Metric | Count |
| --- | ---: | --- | ---: |
| sport | 355 | hrv | 32 |
| hr | 288 | spo2 | 29 |
| sleep | 198 | step | 27 |
| stress | 107 | workout | 21 |
| distance | 87 | ppg | 15 |
| pai | 53 | heart rate | 14 |
| activity | 50 | calorie | 10 |
| | | vo2max | 8 |
| | | afib | 6 |
| | | body temp | 3 |
| | | ecg | 2 |

This spans resting/continuous heart rate (PPG), SpO2 (blood oxygen), HRV, stress,
sleep staging, steps/distance/calories, PAI, VO2max and workout tracking, with
weaker signals for atrial-fibrillation screening (`PPG_AFIB`), body temperature
and ECG. A standalone OS for this watch would need to drive the PPG AFE and the
LSM6DSO and reproduce (or replace) these algorithms; the companion syncs the
resulting records.

## Reproduction

```sh
python3 analysis_scripts/hardware_profile.py firmware/bip6-4.6.0.3.zip \
  > analysis/hardware-profile.json
python3 -m unittest tests/test_hardware_profile.py -v
```

The inspector reads the archive member directly, collects part-number-shaped
driver names, maps the recognized ones to candidate vendors/roles, and counts
the health vocabulary. The tests use synthetic inputs. JSON regenerates
deterministically from the archive.

## Limitations

Driver names and log tokens are not a schematic: they do not prove a part is
fitted, give its bus/address, or confirm a feature works. Vendor attributions
for `aw32012` and `cw6305` are from the name prefix only. The exact PPG model and
SoC silicon remain unidentified, and metric counts reflect logging
verbosity, not measurement quality. No hardware was queried.
