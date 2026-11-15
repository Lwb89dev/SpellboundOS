# Notification reverse messages and a controlled device test

A synthetic notification sent through Gadgetbridge now matches the recovered
native opcode-3 layout on the real link. Its encrypted payload decodes to the
expected app ID, title, body and app name, with exact field consumption. The
watch then requests the app logo and the client completes its transfer.

The work also identifies the native serializers for watch-to-phone text replies,
call-UI actions and image requests. Those reverse actions were modeled/tested on
host only; no SMS, call action or Roadstr route was executed.

## Field names and native API ownership

Fresh ABI/logger-corrected export `0x70388088` is the notification dump helper.
Its literal labels and structure offsets identify the previously anonymous
opcode-3 fields:

```text
03 notification_id:u32le category_id:u8 event_id:u8
app_id:NUL title:NUL message:NUL app_name:NUL
[phone_number:NUL if category_id == 3]
reply_available:u8 [event_flags:u8 [message_image_present:u8 [extra_string:NUL]]]
```

The final optional string's full semantics remain open. The bytes are preserved
without imposing a character encoding. The raw legacy decoder stays compatible;
`named_notification` adds the field names. A raw load at `0x703881ea` passes
structure byte `+0x1d` to the `eventflags` log, corroborating that optional byte
even though the tail-call pseudocode omits its argument.

Getter `0x7038a0dc` returns the Android API table at `0x70f63e50`. Its eight
function pointers are reconstructed through the main startup copy mapping:

| Offset | Function | Observed role |
| --- | --- | --- |
| `+0x00` | `0x70388dce` | initialize notification listeners |
| `+0x04` | `0x70388a9e` | initialize with feature options |
| `+0x08` | `0x7038820c` | send control action |
| `+0x0c` | `0x7038866c` | send text reply |
| `+0x10` | `0x70388468` | request app logo |
| `+0x14` | `0x703888ac` | register settings callbacks |
| `+0x18` | `0x70388798` | register focus callbacks |
| `+0x1c` | `0x70388296` | request message image |

The Android table ends at `0x70f63e70`, where a separate iOS interface begins.
Adjacent code/table locations must not be assumed to share platform ownership.

On opcode-3 reception, dispatcher `0x7038946a` validates decoding, then calls
listener offset `+4` for each registered listener. Initialization records the
listener pointer/count and bounds the count to 16. The concrete full UI/storage
listener chain is not closed by this work. The dispatcher also has a separate,
richer opcode-31 format; it is not modeled here. The controlled client used
opcode 3 despite advertising notification version 5.

## Reverse wire formats

These messages use the same encrypted native module `0x1e` as notifications.
The sender uses `0x7036ccf0`, which obtains the current authorized connection/app
through a delegate before invoking the channel send manager.

| Direction | Payload | Evidence |
| --- | --- | --- |
| watch → phone | `04 id:u32le text:NUL` | `0x7038866c` text-reply serializer |
| phone → watch | `06 id:u32le result:u8` | opcode-6 branch, listener `+8` reply-result callback |
| watch → phone | `05 action:u8 [id:u32le only when action == 3]` | `0x7038820c` |
| watch → phone | `10 app_id:NUL format:u8 width:u16le height:u16le` | `0x70388468` app-logo request |
| phone → watch | `11 app_id:NUL status:u8` | opcode-17 branch, listener `+0x0c` |
| watch → phone | `19 app_id:NUL id:u32le format:u8 width:u16le height:u16le` | `0x70388296` message-image request |

Call UI `androidReminderHangupOP` at `0x70279fa8` invokes API `+8` with action
1; `androidReminderIgnoreOP` at `0x70279f1a` uses action 2. These are concrete
native call-UI intents, not evidence that answering/dialing/audio already works
with a new companion. Action 3 carries an ID; its detailed UI meaning is left
unassigned. Unknown actions remain raw bytes in the host model. Unlike action
3, actions 1/2 do **not** carry the passed ID on wire.

Text reply accepts an empty string and requires a terminator. Its native
allocation uses a signed 16-bit string length; the host constructor excludes
lengths above 32767 rather than emulating overflow. No compatibility claim is
made for unusually large replies. Image format numbers 1–10 are accepted;
app-logo requests require nonzero width/height, while the reviewed message-image
branch explicitly guards width but not height. The host model preserves that
difference and does not assign a pixel format from the numeric code alone.

## Controlled live diagnostic

The existing user-authorized phone/watch connection remained available.
Gadgetbridge's Debug → Notifications test was configured with title
`Spellbound_RE_test`; its body stayed the app's synthetic `Notification body`.
One `Send NotificationSpec` action was performed. It did not send an Android
SMS or initiate a call.

The bounded private Logcat window contains five native packets/transfers: three
encrypted module-`0x1e` messages and two module-`0x0d` file-service messages.
The active session key was reused **in memory** from the previous private capture;
AES/CRC validation confirms that it applies to this continuing connection.

| Message | Observed result |
| --- | --- |
| phone → watch opcode 3 | 158 plaintext bytes, category 250, event 0 |
| decoded fields | Expected diagnostic app ID, title, body and app name all match |
| optional fields | reply unavailable, event flags 0, image flag false, extra string length 60 |
| exact consumption | no trailing bytes |
| watch → phone opcode `0x10` | logo request: numeric format 5, 128 × 128 |
| phone → watch opcode `0x11` | logo result status byte 1 |

The client logs successful completion of its app-icon file transfer. Normal
Gadgetbridge notification handling therefore also transferred an icon resource
to the watch; this was not a read-only radio observation. The underlying file
data stream is outside this native-channel verifier. Neither a display image
nor the watch UI was observed, so this establishes protocol exchange and exact
payload agreement, not proof of notification rendering or interaction.

The prior authenticated-session capture independently supplies a notification
capability reply: opcode 2, version 5, maximum 100, capability byte 1, no feature
blob and four trailing flags `[1,1,1,1]`. The capability decoder preserves those
flags without guessing all their meanings.

Logging was initially off. It was temporarily enabled and restored off; the
changed diagnostic title was restored to `Title`. The temporary app log and
phone UI XML were removed. The created file log remained empty in this follow-up,
so verification uses the captured Logcat window. Private copies live only under
ignored `firmware/device-notification-20261115/`, mode 0700/0600. Public output
contains field-match booleans, dimensions, protocol metadata and complete-input
hashes, not keys/key hashes, counters, notification IDs or message contents.

## Roadstr source surface

The local Roadstr repository at commit
`1a354ae11c928c625826396e91e8b5c75342def5` has a native notification policy and
Android foreground-service adapter. The two selected files match that checkout;
their file hashes are recorded in the JSON. They map navigation **instruction
to title** and **distance to body**, use channel `roadstr_navigation` and ID 42,
and update the same ongoing notification. Changed instructions post immediately;
distance-only changes are throttled by 3000 ms and unchanged text is suppressed.

This gives a concrete candidate input for a notification bridge. A future
companion would need permitted notification-listener access, explicit per-app/
channel selection and stable mapping from Android notification identity to the
watch's u32 ID. It should not assume that Android ID 42 is globally unique
across apps. Ongoing-notification filtering and the active Roadstr build also
need checking; the inspected service documents an opt-in native canary path.

No Roadstr code or phone permissions were changed, no GPS/navigation session was
started, and no Roadstr-to-watch handoff was performed. This is notification
text integration evidence, not a dedicated maneuver/icon navigation protocol.

## Reproduction and validation

Use the startup-aware main project and `DecompileWithAbi.java`. The reviewed
addresses/groups are enumerated in `notification_protocol.py`; only the selected
exports are fingerprinted. The initial dump/getter group is private
`runtime-notification-actions`; the Android API/string/send group is
`runtime-android-notification`. Native incoming dispatch remains in
`runtime-service-dispatch/7038946a.c`.

```sh
python3 analysis_scripts/notification_protocol.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled \
  --capture firmware/device-notification-20261115/notification-traffic.logcat \
  --key-capture firmware/device-session-20261115/gadgetbridge-session-debug-complete.log \
  --roadstr-root /path/to/local/roadstr > analysis/notification-protocol.json
python3 -m unittest discover -s tests -p 'test_notification_protocol.py' -v
```

Without the optional capture/Roadstr arguments, the script emits static evidence
and synthetic reverse-message vectors only. [notification-protocol.json](notification-protocol.json)
records the combined result. Eight synthetic tests cover field names, action-ID
presence, truncation, reply strings/results, capabilities, image guards,
verified-transfer observation and diagnostic-summary privacy. All 197 Python
tests pass with the existing signature/cipher dependencies. The earlier native
capture report also regenerates unchanged after adding its local transfer
observer; the observer never adds plaintext to the public verification report.
