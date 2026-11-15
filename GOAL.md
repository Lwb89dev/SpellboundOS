# SpellboundOS goal

SpellboundOS is a new standalone operating system for the Amazfit Bip 6, not a
stripped-down Zepp OS image. Its companion, SpellboundFit for Android, is part
of the same project. The long-term aim is a useful watch that bridges to the
phone for notifications and actions, Roadstr turn-by-turn navigation, calls and
other interactions. Which call functions are technically possible on this
hardware remains to be established.

## Approach

1. Study the stock OTA and device hardware to identify boot requirements,
   interfaces, peripheral firmware and candidate drivers. Reverse engineering
   yields evidence; it does not automatically produce reusable source code.
2. Build independently authored OS and hardware support. Reuse extracted vendor
   drivers or proprietary blobs only where technically feasible and their
   distribution and use are authorized. Keep original firmware and extracted
   binaries out of this repository until their redistribution rights are clear.
3. Establish a verified backup, recovery method and viable boot path before
   attempting any write to the watch. The current signed boot chain is a major
   unresolved obstacle; no working unlock or recovery procedure is known.
4. Develop and test independently of hardware first, then add board-specific
   support backed by evidence and device tests. The current QEMU example is a
   bare-metal starting point, not a Bip 6 image or a complete OS.
5. Design a secure phone/watch protocol, pairing and lifecycle, then implement
   notification handling and actions, navigation, and calling capabilities.
   BLE messaging and Bluetooth call audio may require separate paths. Integration
   with Roadstr requires an explicit interface or an appropriately permitted
   notification-based bridge; neither is implemented yet.

## Definition of success

An independently built system boots reliably on the target, supports the
necessary hardware with tested drivers and any permitted external firmware,
and communicates securely with SpellboundFit. Notifications, relevant actions,
Roadstr guidance and the supported calling functions work on real devices. A
repeatable installation and recovery process is documented and tested.
