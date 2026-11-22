package dev.spellboundfit.protocol;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure-Java RFC 8439 ChaCha20-Poly1305 AEAD + HKDF-SHA256 encrypted session.
 * Wire-compatible byte-for-byte with kernel/crypto.c and kernel/secure_link.c.
 */
public final class SecureLink {
    public static final byte MSG_HELLO = 0x01;
    public static final byte MSG_HELLO_ACK = 0x02;
    public static final byte MSG_DATA = 0x03;

    private static final byte[] KDF_INFO = "SpellboundFit-v1-session".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PROOF_LABEL = "WATCH-OK".getBytes(StandardCharsets.UTF_8);
    private static final BigInteger POLY_P = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger MASK_128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    private final byte[] psk;
    private byte[] phoneNonce;
    private byte[] watchNonce;
    private byte[] txKey;
    private byte[] rxKey;
    private long txCounter;
    private long rxNextCounter;
    private boolean established;

    public SecureLink(byte[] psk) {
        if (psk == null || psk.length != 32) {
            throw new IllegalArgumentException("PSK must be 32 bytes");
        }
        this.psk = Arrays.copyOf(psk, 32);
    }

    public boolean isEstablished() {
        return established;
    }

    public byte[] buildHello(byte[] customNonce) {
        byte[] n = customNonce != null ? Arrays.copyOf(customNonce, 16) : new byte[16];
        if (customNonce == null) {
            new SecureRandom().nextBytes(n);
        } else if (customNonce.length != 16) {
            throw new IllegalArgumentException("Nonce must be 16 bytes");
        }
        this.phoneNonce = n;
        this.established = false;
        this.txCounter = 0;
        this.rxNextCounter = 0;
        byte[] out = new byte[17];
        out[0] = MSG_HELLO;
        System.arraycopy(n, 0, out, 1, 16);
        return out;
    }

    public void finishHandshake(byte[] helloAck) {
        if (helloAck == null || helloAck.length != 49 || helloAck[0] != MSG_HELLO_ACK) {
            throw new IllegalArgumentException("Invalid HELLO_ACK packet");
        }
        this.watchNonce = Arrays.copyOfRange(helloAck, 1, 17);
        byte[] proof = Arrays.copyOfRange(helloAck, 17, 49);

        byte[] salt = new byte[32];
        System.arraycopy(this.phoneNonce, 0, salt, 0, 16);
        System.arraycopy(this.watchNonce, 0, salt, 16, 16);

        byte[] okm = hkdfSha256(salt, this.psk, KDF_INFO, 64);
        byte[] p2w = Arrays.copyOfRange(okm, 0, 32);
        byte[] w2p = Arrays.copyOfRange(okm, 32, 64);

        byte[] msg = new byte[PROOF_LABEL.length + 32];
        System.arraycopy(PROOF_LABEL, 0, msg, 0, PROOF_LABEL.length);
        System.arraycopy(salt, 0, msg, PROOF_LABEL.length, 32);
        byte[] expected = hmacSha256(w2p, msg);
        if (!MessageDigest.isEqual(expected, proof)) {
            throw new SecurityException("Watch authentication proof mismatch");
        }
        this.txKey = p2w;
        this.rxKey = w2p;
        this.txCounter = 0;
        this.rxNextCounter = 0;
        this.established = true;
    }

    public byte[] encrypt(byte[] plaintext) {
        if (!established) {
            throw new IllegalStateException("Session not established");
        }
        long ctr = txCounter++;
        byte[] aad = ByteBuffer.allocate(9).order(ByteOrder.LITTLE_ENDIAN)
                .put(MSG_DATA).putLong(ctr).array();
        byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0).putLong(ctr).array();
        byte[] ct = chacha20Xor(txKey, 1, nonce, plaintext);
        byte[] tag = aeadTag(txKey, nonce, aad, ct);
        byte[] out = new byte[9 + ct.length + 16];
        System.arraycopy(aad, 0, out, 0, 9);
        System.arraycopy(ct, 0, out, 9, ct.length);
        System.arraycopy(tag, 0, out, 9 + ct.length, 16);
        return out;
    }

    public byte[] decrypt(byte[] packet) {
        if (!established) {
            throw new IllegalStateException("Session not established");
        }
        if (packet == null || packet.length < 25 || packet[0] != MSG_DATA) {
            throw new IllegalArgumentException("Invalid encrypted packet");
        }
        long ctr = ByteBuffer.wrap(packet, 1, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
        if (Long.compareUnsigned(ctr, rxNextCounter) < 0) {
            throw new SecurityException("Replayed packet counter: " + ctr);
        }
        byte[] aad = Arrays.copyOfRange(packet, 0, 9);
        int ctLen = packet.length - 25;
        byte[] ct = Arrays.copyOfRange(packet, 9, 9 + ctLen);
        byte[] tag = Arrays.copyOfRange(packet, 9 + ctLen, packet.length);
        byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0).putLong(ctr).array();
        byte[] expected = aeadTag(rxKey, nonce, aad, ct);
        if (!MessageDigest.isEqual(expected, tag)) {
            throw new SecurityException("Poly1305 authentication failed");
        }
        rxNextCounter = ctr + 1;
        return chacha20Xor(rxKey, 1, nonce, ct);
    }

    /* ---- Cryptographic primitives ---- */

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int len) {
        byte[] useSalt = (salt != null && salt.length > 0) ? salt : new byte[32];
        byte[] prk = hmacSha256(useSalt, ikm);
        byte[] okm = new byte[len];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < len) {
            byte[] in = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, in, 0, t.length);
            System.arraycopy(info, 0, in, t.length, info.length);
            in[in.length - 1] = (byte) counter++;
            t = hmacSha256(prk, in);
            int take = Math.min(t.length, len - pos);
            System.arraycopy(t, 0, okm, pos, take);
            pos += take;
        }
        return okm;
    }

    private static void qr(int[] s, int a, int b, int c, int d) {
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    private static byte[] chacha20Block(byte[] key, int counter, byte[] nonce) {
        int[] st = new int[16];
        st[0] = 0x61707865; st[1] = 0x3320646E; st[2] = 0x79622D32; st[3] = 0x6B206574;
        ByteBuffer kb = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 8; i++) st[4 + i] = kb.getInt();
        st[12] = counter;
        ByteBuffer nb = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 3; i++) st[13 + i] = nb.getInt();

        int[] w = Arrays.copyOf(st, 16);
        for (int i = 0; i < 10; i++) {
            qr(w, 0, 4, 8, 12);  qr(w, 1, 5, 9, 13);
            qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
            qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12);
            qr(w, 2, 7, 8, 13);  qr(w, 3, 4, 9, 14);
        }
        ByteBuffer out = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 16; i++) out.putInt(w[i] + st[i]);
        return out.array();
    }

    public static byte[] chacha20Xor(byte[] key, int counter, byte[] nonce, byte[] data) {
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += 64) {
            byte[] ks = chacha20Block(key, counter++, nonce);
            int n = Math.min(64, data.length - off);
            for (int i = 0; i < n; i++) out[off + i] = (byte) (data[off + i] ^ ks[i]);
        }
        return out;
    }

    private static BigInteger fromLittleEndianUnsigned(byte[] b, int off, int len) {
        byte[] be = new byte[len + 1];
        for (int i = 0; i < len; i++) {
            be[len - i] = b[off + i];
        }
        return new BigInteger(be);
    }

    private static byte[] poly1305Mac(byte[] key, byte[] msg) {
        byte[] rBytes = Arrays.copyOfRange(key, 0, 16);
        rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
        rBytes[4] &= (byte) 252; rBytes[8] &= (byte) 252; rBytes[12] &= (byte) 252;
        BigInteger r = fromLittleEndianUnsigned(rBytes, 0, 16);
        BigInteger s = fromLittleEndianUnsigned(key, 16, 16);
        BigInteger acc = BigInteger.ZERO;

        for (int off = 0; off < msg.length; off += 16) {
            int n = Math.min(16, msg.length - off);
            byte[] blk = new byte[n + 1];
            System.arraycopy(msg, off, blk, 0, n);
            blk[n] = 1;
            BigInteger bi = fromLittleEndianUnsigned(blk, 0, blk.length);
            acc = acc.add(bi).multiply(r).mod(POLY_P);
        }
        BigInteger sum = acc.add(s).and(MASK_128);
        byte[] tag = new byte[16];
        byte[] be = sum.toByteArray();
        for (int i = 0; i < 16; i++) {
            int idx = be.length - 1 - i;
            tag[i] = idx >= 0 ? be[idx] : 0;
        }
        return tag;
    }

    public static byte[] aeadTag(byte[] key, byte[] nonce, byte[] aad, byte[] ct) {
        byte[] polyKey = Arrays.copyOfRange(chacha20Block(key, 0, nonce), 0, 32);
        int aadPad = (16 - (aad.length & 15)) & 15;
        int ctPad = (16 - (ct.length & 15)) & 15;
        ByteBuffer macBuf = ByteBuffer.allocate(aad.length + aadPad + ct.length + ctPad + 16)
                .order(ByteOrder.LITTLE_ENDIAN);
        macBuf.put(aad);
        macBuf.put(new byte[aadPad]);
        macBuf.put(ct);
        macBuf.put(new byte[ctPad]);
        macBuf.putLong(aad.length);
        macBuf.putLong(ct.length);
        return poly1305Mac(polyKey, macBuf.array());
    }
}
