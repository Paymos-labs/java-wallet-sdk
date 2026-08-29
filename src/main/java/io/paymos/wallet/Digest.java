package io.paymos.wallet;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The exact 32 bytes the vault's signature is computed over — a byte-for-byte port of the Python
 * SDK's digest, which is itself pinned to the server by a cross-language golden vector.
 *
 * <p>The SDK uses this to VERIFY, before a single FROST commitment leaves the process, that the
 * server disclosed the true message it is asking the vault to sign. Never blind-sign.
 *
 * <p>digest = sha256 of:
 *   u32   tag                 fixed domain separation; must byte-match the server
 *   string message            u32-LE length prefix + utf-8
 *   bytes32 nonce             raw, exactly 32
 *   string recipient          u32-LE length prefix + utf-8
 *   option&lt;string&gt; callback   0x00 = none, else 0x01 + string
 */
public final class Digest {
    /** Part of the wire contract. Change it and the client and server stop agreeing forever.
     *  (Over Integer.MAX_VALUE — held as a long, written as its u32-LE bytes.) */
    private static final long MSG_TAG = 2147484061L;

    private Digest() {}

    /** The 32-byte sha256 digest the vault's ed25519 signature is over. nonce must be exactly 32. */
    public static byte[] payloadDigest(String message, byte[] nonce, String recipient, String callbackUrl) {
        if (nonce.length != 32)
            throw new PaymosException("nonce must be 32 bytes, got " + nonce.length);
        try {
            ByteArrayOutputStream w = new ByteArrayOutputStream();
            w.write(le32(MSG_TAG));
            w.write(lenPrefixedUtf8(message));
            w.write(nonce);
            w.write(lenPrefixedUtf8(recipient));
            if (callbackUrl == null || callbackUrl.isEmpty()) {
                w.write(0x00);
            } else {
                w.write(0x01);
                w.write(lenPrefixedUtf8(callbackUrl));
            }
            return MessageDigest.getInstance("SHA-256").digest(w.toByteArray());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 missing from this JVM", e);
        } catch (java.io.IOException e) {
            // ByteArrayOutputStream never throws on write; the signature just says it can.
            throw new IllegalStateException(e);
        }
    }

    /** The digest as lowercase hex — the form the FROST signing package carries, so the two compare. */
    public static String payloadDigestHex(String message, byte[] nonce, String recipient, String callbackUrl) {
        byte[] digest = payloadDigest(message, nonce, recipient, callbackUrl);
        StringBuilder sb = new StringBuilder(64);
        for (byte b : digest) sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        return sb.toString();
    }

    private static byte[] le32(long v) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) v).array();
    }

    private static byte[] lenPrefixedUtf8(String s) {
        byte[] body = s.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(4 + body.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(body.length);
        buf.put(body);
        return buf.array();
    }
}
