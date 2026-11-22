package dev.spellboundfit.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

/**
 * SpellboundFit v1 binary framed link protocol (Android companion side).
 * Wire-compatible byte-for-byte with kernel/proto.c and companion/protocol.py.
 */
public final class Protocol {
    public static final byte MAGIC_0 = 0x53; // 'S'
    public static final byte MAGIC_1 = 0x42; // 'B'
    public static final int VERSION = 1;
    public static final int HEADER_LEN = 8;
    public static final int CRC_LEN = 4;
    public static final int MAX_PAYLOAD = 256;

    public static final int MSG_PING = 0x01;
    public static final int MSG_PONG = 0x02;
    public static final int MSG_ACK = 0x03;
    public static final int MSG_NACK = 0x04;
    public static final int MSG_TIME_SYNC = 0x10;
    public static final int MSG_NOTIFY_POST = 0x20;
    public static final int MSG_NOTIFY_DISMISS = 0x21;
    public static final int MSG_NOTIFY_ACTION = 0x22;
    public static final int MSG_NAV_UPDATE = 0x30;
    public static final int MSG_NAV_CLEAR = 0x31;
    public static final int MSG_CALL_STATE = 0x40;
    public static final int MSG_TELEMETRY = 0x50;

    public static final int NAV_NONE = 0;
    public static final int NAV_STRAIGHT = 1;
    public static final int NAV_SLIGHT_LEFT = 2;
    public static final int NAV_LEFT = 3;
    public static final int NAV_SHARP_LEFT = 4;
    public static final int NAV_SLIGHT_RIGHT = 5;
    public static final int NAV_RIGHT = 6;
    public static final int NAV_SHARP_RIGHT = 7;
    public static final int NAV_UTURN = 8;
    public static final int NAV_ROUNDABOUT = 9;
    public static final int NAV_ARRIVE = 10;

    public static final int CALL_IDLE = 0;
    public static final int CALL_RINGING = 1;
    public static final int CALL_ACTIVE = 2;

    private Protocol() {}

    public static final class Frame {
        public final int version;
        public final int type;
        public final int seq;
        public final byte[] payload;

        public Frame(int version, int type, int seq, byte[] payload) {
            this.version = version;
            this.type = type;
            this.seq = seq;
            this.payload = payload;
        }
    }

    public static final class Telemetry {
        public final int batteryPct;
        public final boolean charging;
        public final long steps;
        public final int hrBpm;
        public final long uptimeSec;

        public Telemetry(int batteryPct, boolean charging, long steps, int hrBpm, long uptimeSec) {
            this.batteryPct = batteryPct;
            this.charging = charging;
            this.steps = steps;
            this.hrBpm = hrBpm;
            this.uptimeSec = uptimeSec;
        }
    }

    public static final class NotifyActionEvent {
        public final long notifId;
        public final int actionIndex;

        public NotifyActionEvent(long notifId, int actionIndex) {
            this.notifId = notifId;
            this.actionIndex = actionIndex;
        }
    }

    public static long crc32(byte[] data, int off, int len) {
        CRC32 c = new CRC32();
        c.update(data, off, len);
        return c.getValue() & 0xFFFFFFFFL;
    }

    public static byte[] encodeFrame(int type, int seq, byte[] payload) {
        int plen = payload == null ? 0 : payload.length;
        if (plen > MAX_PAYLOAD) {
            throw new IllegalArgumentException("Payload too large: " + plen);
        }
        ByteBuffer buf = ByteBuffer.allocate(HEADER_LEN + plen + CRC_LEN)
                .order(ByteOrder.LITTLE_ENDIAN);
        buf.put(MAGIC_0);
        buf.put(MAGIC_1);
        buf.put((byte) VERSION);
        buf.put((byte) (type & 0xFF));
        buf.putShort((short) (seq & 0xFFFF));
        buf.putShort((short) plen);
        if (plen > 0) {
            buf.put(payload);
        }
        byte[] raw = buf.array();
        long crc = crc32(raw, 0, HEADER_LEN + plen);
        buf.putInt((int) crc);
        return raw;
    }

    private static void writeLenStr(ByteArrayOutputStream out, String s, int maxBytes) {
        byte[] utf = (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
        int len = Math.min(utf.length, maxBytes);
        out.write(len & 0xFF);
        out.write(utf, 0, len);
    }

    public static byte[] encodePing(int seq) {
        return encodeFrame(MSG_PING, seq, null);
    }

    public static byte[] encodeTimeSync(int seq, long unixSec, int tzOffsetMin) {
        ByteBuffer p = ByteBuffer.allocate(10).order(ByteOrder.LITTLE_ENDIAN);
        p.putLong(unixSec);
        p.putShort((short) tzOffsetMin);
        return encodeFrame(MSG_TIME_SYNC, seq, p.array());
    }

    public static byte[] encodeNotifyPost(int seq, long notifId, long timestampSec,
                                          String app, String title, String body,
                                          List<String> actions) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuffer hdr = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int) (notifId & 0xFFFFFFFFL));
        hdr.putInt((int) (timestampSec & 0xFFFFFFFFL));
        out.write(hdr.array(), 0, 8);
        writeLenStr(out, app, 23);
        writeLenStr(out, title, 47);
        writeLenStr(out, body, 127);
        int actCount = actions == null ? 0 : Math.min(actions.size(), 4);
        out.write(actCount);
        for (int i = 0; i < actCount; i++) {
            writeLenStr(out, actions.get(i), 19);
        }
        return encodeFrame(MSG_NOTIFY_POST, seq, out.toByteArray());
    }

    public static byte[] encodeNotifyDismiss(int seq, long notifId) {
        ByteBuffer p = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        p.putInt((int) (notifId & 0xFFFFFFFFL));
        return encodeFrame(MSG_NOTIFY_DISMISS, seq, p.array());
    }

    public static byte[] encodeNavUpdate(int seq, int maneuver, int roundaboutExit,
                                         long distanceMeters, int etaMin,
                                         String street, String nextStreet) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuffer hdr = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        hdr.put((byte) (maneuver & 0xFF));
        hdr.put((byte) (roundaboutExit & 0xFF));
        hdr.putInt((int) (distanceMeters & 0xFFFFFFFFL));
        hdr.putShort((short) (etaMin & 0xFFFF));
        out.write(hdr.array(), 0, 8);
        writeLenStr(out, street, 63);
        writeLenStr(out, nextStreet, 47);
        return encodeFrame(MSG_NAV_UPDATE, seq, out.toByteArray());
    }

    public static byte[] encodeNavClear(int seq) {
        return encodeFrame(MSG_NAV_CLEAR, seq, null);
    }

    public static byte[] encodeCallState(int seq, int callState, String caller, String number) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(callState & 0xFF);
        writeLenStr(out, caller, 47);
        writeLenStr(out, number, 23);
        return encodeFrame(MSG_CALL_STATE, seq, out.toByteArray());
    }

    public static Telemetry decodeTelemetry(byte[] payload) {
        if (payload == null || payload.length < 12) {
            throw new IllegalArgumentException("Telemetry payload too short");
        }
        ByteBuffer b = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        int bat = b.get() & 0xFF;
        boolean chg = b.get() != 0;
        long steps = b.getInt() & 0xFFFFFFFFL;
        int hr = b.getShort() & 0xFFFF;
        long up = b.getInt() & 0xFFFFFFFFL;
        return new Telemetry(bat, chg, steps, hr, up);
    }

    public static NotifyActionEvent decodeNotifyAction(byte[] payload) {
        if (payload == null || payload.length < 5) {
            throw new IllegalArgumentException("NotifyAction payload too short");
        }
        ByteBuffer b = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        long id = b.getInt() & 0xFFFFFFFFL;
        int idx = b.get() & 0xFF;
        return new NotifyActionEvent(id, idx);
    }

    public static final class StreamDecoder {
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        public int crcErrors = 0;
        public int framingErrors = 0;

        public List<Frame> feed(byte[] data) {
            List<Frame> frames = new ArrayList<>();
            if (data != null && data.length > 0) {
                buf.write(data, 0, data.length);
            }
            byte[] arr = buf.toByteArray();
            int pos = 0;
            while (pos < arr.length) {
                int idx = findMagic(arr, pos);
                if (idx < 0) {
                    if (arr.length > 0 && arr[arr.length - 1] == MAGIC_0) {
                        pos = arr.length - 1;
                    } else {
                        pos = arr.length;
                    }
                    break;
                }
                pos = idx;
                if (arr.length - pos < HEADER_LEN) {
                    break;
                }
                int ver = arr[pos + 2] & 0xFF;
                int type = arr[pos + 3] & 0xFF;
                int seq = (arr[pos + 4] & 0xFF) | ((arr[pos + 5] & 0xFF) << 8);
                int plen = (arr[pos + 6] & 0xFF) | ((arr[pos + 7] & 0xFF) << 8);
                if (ver != VERSION || plen > MAX_PAYLOAD) {
                    framingErrors++;
                    pos += 2;
                    continue;
                }
                int total = HEADER_LEN + plen + CRC_LEN;
                if (arr.length - pos < total) {
                    break;
                }
                long calc = crc32(arr, pos, HEADER_LEN + plen);
                int cOff = pos + HEADER_LEN + plen;
                long expected = (arr[cOff] & 0xFFL)
                        | ((arr[cOff + 1] & 0xFFL) << 8)
                        | ((arr[cOff + 2] & 0xFFL) << 16)
                        | ((arr[cOff + 3] & 0xFFL) << 24);
                if (calc != expected) {
                    crcErrors++;
                    pos += 2;
                    continue;
                }
                byte[] payload = new byte[plen];
                System.arraycopy(arr, pos + HEADER_LEN, payload, 0, plen);
                frames.add(new Frame(ver, type, seq, payload));
                pos += total;
            }
            buf.reset();
            if (pos < arr.length) {
                buf.write(arr, pos, arr.length - pos);
            }
            return frames;
        }

        private static int findMagic(byte[] a, int from) {
            for (int i = from; i + 1 < a.length; i++) {
                if (a[i] == MAGIC_0 && a[i + 1] == MAGIC_1) {
                    return i;
                }
            }
            return -1;
        }
    }
}
