# Display identification and ambient-light probe

Static analysis of the main image under the candidate base `0x70160000`, using
Ghidra 12.1.2 AndeStar v5. No hardware was queried.

## Display

Candidate `0x702c8238` sends three one-byte values `0xda`, `0xdb`, and `0xdc`
through `0x702c81d8`, receiving one byte for each. A zero status lets the loop
continue; a nonzero status logs an error and returns zero. The three response
bytes are combined into a 24-bit value and returned. The transfer wrapper
appears to dispatch through a callback, so these bytes alone do not identify
its electrical bus, a panel model, or the watch's actual panel ID.

Candidate `0x702c839e` registers a `display0` driver. The HAL initialization
candidate `0x702a928c` obtains a display handle and configures synchronization
objects and callbacks. These are layers in the bundled display stack; no
standalone initialization sequence has been established.

## Ambient light

Candidate `0x701ea1e8` looks up `dev_stk31e60`, acquires board/bus and optional
power information, initializes the bus and invokes an identification helper.
Candidate helper `0x701ea148` reads candidate register `0x3e` and rejects a
successful read if its value is not `0xe0`. The probe has retry and power-control
paths whose exact hardware effects and timing still need external verification.
This is the bundled driver's expected identity, not a device measurement.

## A concrete limitation in bulk pseudocode

The broad main-image export marks calls to logger-like `0x702b38a2` as
non-returning at some sites. In its bulk output, `0x702c8238` therefore loses
its normal value-return path, and parts of the light probe are similarly
truncated. A targeted import without whole-image analysis recovers explicit
returns at those sites and the complete three-byte accumulation. Independent
instruction checking is still required before using either result as a driver.

This demonstrates why a decompiler's completed status is not proof of complete
control flow. It also shows that switching instruction profiles alone does not
resolve incorrectly inferred function signatures, call effects or boundaries.
The broad corpus is a search aid; the paths selected for implementation need
separate review. The earlier checksum empty-loop issue is another example.

To reproduce the targeted comparison, use the existing AndeStar main-image
import instructions with `-noanalysis` and `DecompileFunctions.java` arguments
`0x702c8238 0x701ea148 0x701ea1e8`. The local comparison log is
`firmware/ghidra-display-light.log`; broad outputs are in
`firmware/decompiled/main/`.
