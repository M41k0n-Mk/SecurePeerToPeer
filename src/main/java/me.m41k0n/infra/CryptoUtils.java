package me.m41k0n.infra;

import me.m41k0n.domain.PeerIdentity;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

    public static PeerIdentity generateEd25519KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();
            byte[] pub = kp.getPublic().getEncoded();
            byte[] priv = kp.getPrivate().getEncoded();
            return new PeerIdentity(pub, priv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String sign(byte[] privateKeyEncoded, String data) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = sig.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(byte[] publicKeyEncoded, String data, String signatureBase64) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}