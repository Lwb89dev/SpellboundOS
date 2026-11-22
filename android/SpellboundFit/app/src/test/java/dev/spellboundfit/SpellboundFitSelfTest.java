package dev.spellboundfit;

import dev.spellboundfit.protocol.Protocol;
import dev.spellboundfit.protocol.SecureLink;
import dev.spellboundfit.roadstr.RoadstrParser;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Standalone JVM self-test and live Java <-> C kernel encrypted wire interop runner.
 */
public final class SpellboundFitSelfTest {
    private static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError("FAIL: " + msg);
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void runUnitChecks() {
        // 1. IEEE CRC-32 check value
        byte[] digits = "123456789".getBytes(StandardCharsets.US_ASCII);
        check(Protocol.crc32(digits, 0, digits.length) == 0xCBF43926L, "CRC32 check");

        // 2. RFC 8439 ChaCha20-Poly1305 AEAD vector
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) (0x80 + i);
        byte[] nonce = hex("070000004041424344454647");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = ("Ladies and Gentlemen of the class of '99: "
                + "If I could offer you only one tip for the future, sunscreen would be it.")
                .getBytes(StandardCharsets.US_ASCII);
        byte[] ct = SecureLink.chacha20Xor(key, 1, nonce, pt);
        byte[] tag = SecureLink.aeadTag(key, nonce, aad, ct);
        check(Arrays.equals(tag, hex("1ae10b594f09e26a7e902ecbd0600691")), "RFC 8439 tag");

        // 3. Roadstr English & Italian parsing
        RoadstrParser.NavInstruction en = RoadstrParser.parse(
                "Roadstr", "Turn right in 400 m onto Main Street • ETA 5 min");
        check(en != null && en.maneuver == Protocol.NAV_RIGHT && en.distanceMeters == 400
                && en.etaMin == 5 && "Main Street".equals(en.street), "Roadstr EN");

        RoadstrParser.NavInstruction it = RoadstrParser.parse(
                "Rotonda tra 1,5 km", "Prendi la 3a uscita su Via Emilia (Arrivo 11 min)");
        check(it != null && it.maneuver == Protocol.NAV_ROUNDABOUT && it.roundaboutExit == 3
                && it.distanceMeters == 1500 && it.etaMin == 11
                && "Via Emilia".equals(it.street), "Roadstr IT");

        // 4. Protocol encode/decode with corruption recovery
        byte[] good = Protocol.encodeNotifyDismiss(9, 777L);
        byte[] bad = Protocol.encodeNavClear(10);
        bad[bad.length - 1] ^= (byte) 0xFF;
        Protocol.StreamDecoder dec = new Protocol.StreamDecoder();
        byte[] combined = new byte[bad.length + good.length];
        System.arraycopy(bad, 0, combined, 0, bad.length);
        System.arraycopy(good, 0, combined, bad.length, good.length);
        List<Protocol.Frame> frames = dec.feed(combined);
        check(dec.crcErrors == 1 && frames.size() == 1 && frames.get(0).seq == 9, "StreamDecoder");
    }

    private static void sendPkt(DataOutputStream out, byte[] data) throws Exception {
        out.writeByte(data.length & 0xFF);
        out.writeByte((data.length >> 8) & 0xFF);
        out.write(data);
        out.flush();
    }

    private static byte[] recvPkt(DataInputStream in) throws Exception {
        int lo = in.readUnsignedByte();
        int hi = in.readUnsignedByte();
        int len = lo | (hi << 8);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    private static void runInteropMode() throws Exception {
        byte[] psk = new byte[32];
        for (int i = 0; i < 32; i++) psk[i] = (byte) (0x33 + i);
        byte[] phoneNonce = new byte[16];
        for (int i = 0; i < 16; i++) phoneNonce[i] = (byte) (0x10 + i);

        SecureLink link = new SecureLink(psk);
        DataInputStream in = new DataInputStream(System.in);
        DataOutputStream out = new DataOutputStream(System.out);

        // 1. Handshake with real C watch binary
        sendPkt(out, link.buildHello(phoneNonce));
        link.finishHandshake(recvPkt(in));
        check(link.isEstablished(), "Java<->C handshake");

        // 2. Send encrypted notification and verify ACK
        byte[] notif = Protocol.encodeNotifyPost(
                1, 88L, 1795255200L, "Android", "Secret", "Hello from Java",
                Arrays.asList("OK"));
        byte[] encNotif = link.encrypt(notif);
        sendPkt(out, encNotif);
        List<Protocol.Frame> r1 = new Protocol.StreamDecoder().feed(link.decrypt(recvPkt(in)));
        check(r1.size() == 1 && r1.get(0).type == Protocol.MSG_ACK, "Notif ACK");

        // 3. Replay encNotif (C watch must silently reject it)
        sendPkt(out, encNotif);

        // 4. Send encrypted Roadstr nav update and verify ACK
        RoadstrParser.NavInstruction nav = RoadstrParser.parse(
                "Roadstr", "Turn left in 300 m onto Via Po");
        check(nav != null, "Nav parse");
        sendPkt(out, link.encrypt(nav.toFrame(2)));
        List<Protocol.Frame> r2 = new Protocol.StreamDecoder().feed(link.decrypt(recvPkt(in)));
        check(r2.size() == 1 && r2.get(0).type == Protocol.MSG_ACK, "Nav ACK");
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--interop".equals(args[0])) {
            runInteropMode();
        } else {
            runUnitChecks();
            System.out.println("PASS: Android SpellboundFit Java Protocol, SecureLink and RoadstrParser");
        }
    }
}
