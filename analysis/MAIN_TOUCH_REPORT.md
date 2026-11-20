# ZTW622 touch: I2C register layer and touch report handler

All **29 native cases** pass (6,358 steps) in the `main-runtime` project. They
execute the original ZTW622 (`dev_ztw622`, chip id `0xe622`) I2C register
layer, the report timer wrapper, the event dispatcher and the touch event
handler `0x701eb18a`. Supplied: the bus write/read/reset services, the mutex,
memset, the timer service, the tick source, the logger and the report callback.
The evidence is in [main-touch-report.json](main-touch-report.json). This
extends the static reading in [TOUCH_AND_SERIAL.md](TOUCH_AND_SERIAL.md).

## I2C register layer

- Bus address **`0x20`**. Register numbers are 16-bit little-endian.
- `write(buf, len)` `0x701ead14` and `read(buf, len)` `0x701eae7a` call the bus
  transfer with argument 10. On failure they reset the bus (`0x702b59ea`) and
  retry once. If the reset itself fails, that error is returned.
- Register select `0x701eadce` writes the 2-byte register number. A register
  write `0x701eae04` sends `reg, value` as 4 bytes. A register read
  `0x701eaf30`/`0x701eaf56` selects the register, then reads.
- Clear interrupt `0x701eade4` writes command `0x0003`, with up to three
  attempts.

## Report handler state machine

The state byte is at context `+0x2c` (context `0x70f92d10`). The jump table is
`0x709d2704`:

| State | Behaviour |
| --- | --- |
| 1 | report: start the 5000 ms report timer, read the point status, dispatch, clear the interrupt |
| 3 | wake gesture: read `0x0126`, write it back as 0, report if it matches the mask at `+0x2d` |
| 6, >7 | return −10 |
| 0, 2, 4, 5, 7 | clear the interrupt only |

The mutex at `+0x30` is held for the whole handler, and the counter at `+0x38`
is incremented for states 1 and 3.

## Point status (register `0x0080`, 16 bytes)

The layout is `u16 status, u8 count, u8 time stamp`, followed by 6-byte points
`{u16 x, u16 y, u8 width, u8 sub_status}`. Only two points fit in the read.

- Status bit `0x0010`, large object ("TP LO"): handled only when enabled at
  `+0x29`. Writes `0x0126 = 0` and reports kind 2.
- Status bits `0x080e`, point data: up to `min(count, max fingers +0x2b)`
  points. A slot is used when `sub_status & 0xf` is nonzero. `down` is the
  inverse of `sub_status` bit 3. Coordinates are rotated by the value at
  `+0x2e`:
  - 0: `(x, y)`;
  - 1: `(y, xres−x)`;
  - 2: `(xres−x, yres−y)`;
  - 3: `(yres−y, x)`.

  The 180° flip at `+0x2a` then applies `(xres−x, yres−y)`.
- Status bit `0x1000`, no change: an empty report.
- Any other status, or status 0: clear the interrupt only.

## Report event (0x38 bytes) and dispatch

| Offset | Content |
| --- | --- |
| `+0x00` | 1 |
| `+0x04` | tick |
| `+0x0c` | points, `0x10` bytes each: `u8 down`, `i32 x @+4`, `i32 y @+8`, `u8 id @+0xc`. For a non-point event this byte is the kind (0 none, 2 large object, 3 wake gesture) |
| `+0x2c` | count |
| `+0x30`, `+0x34` | x and y resolution |

When the caller passes no event buffer, a stack buffer is used. Dispatch calls
`dev->cb(+0x3c)(dev, event, dev->arg(+0x40))`. A missing callback returns −4.
The interrupt is cleared only when the callback returns 0.

## Reproduction

```sh
python3 -m analysis_scripts.main_touch_report --vectors-output firmware/main-touch-report-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-touch-report-vectors.json \
  firmware/main-touch-report-validation.json
python3 -m analysis_scripts.main_touch_report firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-touch-report-vectors.json \
  --validation firmware/main-touch-report-validation.json > analysis/main-touch-report.json
python3 -m unittest tests.test_main_touch_report -q
```

`ValidateNativeScope.java` is a generic copy of the IMU runner. It adds a
`bus` stub that records written bytes and fills read buffers. New scopes use
it, and the IMU runner stays frozen.

## Remaining

- The probe/attach `0x701eb88a`: power rails and reset, chip id and
  information block, resolution, firmware/upgrade, and interrupt registration.
- The callers that move the state byte, and the input-layer consumer of the
  report callback.
- The physical controller configuration and the panel coordinate space on the
  device.
