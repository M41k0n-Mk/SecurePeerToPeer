package me.m41k0n.infra;

import me.m41k0n.domain.PeerIdentity;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class CryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PeerIdentity generateEd25519KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();
            byte[] pub = kp.getPublic().getEncoded();
            byte[] priv = kp.getPrivate().getEncoded();
            return new PeerIdentity(pub, priv);
        } catch (Exception e) {
            // Fallback to BouncyCastle
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
                KeyPair kp = kpg.generateKeyPair();
                byte[] pub = kp.getPublic().getEncoded();
                byte[] priv = kp.getPrivate().getEncoded();
                return new PeerIdentity(pub, priv);
            } catch (Exception ex) {
                throw new RuntimeException("Ed25519 not available", ex);
            }
        }
    }

    public static String sign(byte[] privateKeyEncoded, String data) {
        try {
            if (privateKeyEncoded == null) {
                throw new IllegalArgumentException("privateKeyEncoded não pode ser null");
            }
            if (data == null) {
                throw new IllegalArgumentException("data não pode ser null");
            }
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = sig.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            // Fallback to BouncyCastle
            try {
                KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
                PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
                Signature sig = Signature.getInstance("Ed25519", "BC");
                sig.initSign(privateKey);
                assert data != null;
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                byte[] signatureBytes = sig.sign();
                return Base64.getEncoder().encodeToString(signatureBytes);
            } catch (Exception ex) {
                // chaves inválidas ou formato incorreto devem ser tratadas como entrada inválida
                throw new IllegalArgumentException("chave privada inválida para Ed25519", ex);
            }
        }
    }

    public static boolean verify(byte[] publicKeyEncoded, String data, String signatureBase64) {
        if (publicKeyEncoded == null || publicKeyEncoded.length == 0) return false;
        if (data == null) return false;
        if (signatureBase64 == null || signatureBase64.isEmpty()) return false;
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes;
            try {
                signatureBytes = Base64.getDecoder().decode(signatureBase64);
            } catch (IllegalArgumentException badB64) {
                return false;
            }
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            // Fallback to BouncyCastle
            try {
                KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
                PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
                Signature sig = Signature.getInstance("Ed25519", "BC");
                sig.initVerify(publicKey);
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                byte[] signatureBytes;
                try {
                    signatureBytes = Base64.getDecoder().decode(signatureBase64);
                } catch (IllegalArgumentException badB64) {
                    return false;
                }
                return sig.verify(signatureBytes);
            } catch (Exception ex) {
                return false;
            }
        }
    }
}