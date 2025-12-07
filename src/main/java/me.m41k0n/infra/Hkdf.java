package me.m41k0n.infra;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF com SHA-256 (RFC 5869) — utilitário mínimo para derivação de chaves.
 */
public final class Hkdf {

    private Hkdf() {}

    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (ikm == null) throw new IllegalArgumentException("ikm null");
        if (length <= 0 || length > 255 * 32) throw new IllegalArgumentException("length inválido");
        try {
            // Extract
            byte[] prk = hmacSha256(salt != null ? salt : new byte[32], ikm);
            // Expand
            int n = (int) Math.ceil((double) length / 32.0);
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            for (int i = 1; i <= n; i++) {
                byte[] data;
                if (info != null && info.length > 0) {
                    data = concat(t, info, new byte[]{(byte) i});
                } else {
                    data = concat(t, new byte[]{(byte) i});
                }
                t = hmacSha256(prk, data);
                int toCopy = Math.min(32, length - pos);
                System.arraycopy(t, 0, okm, pos, toCopy);
                pos += toCopy;
            }
            return okm;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] concat(byte[]... arrs) {
        int len = 0;
        for (byte[] a : arrs) len += a.length;
        byte[] out = new byte[len];
        int p = 0;
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, p, a.length);
            p += a.length;
        }
        return out;
    }
}
