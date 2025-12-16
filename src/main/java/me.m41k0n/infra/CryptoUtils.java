package me.m41k0n.infra;

import me.m41k0n.domain.PeerIdentity;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utilidades criptográficas de alto nível para Ed25519.
 *
 * Regras de exceção:
 * - Entradas inválidas: IllegalArgumentException
 * - Provedor/algoritmo indisponível: CryptoProviderUnavailableException
 * - Falhas inesperadas de operação: CryptoOperationException
 */

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
                throw new CryptoProviderUnavailableException("Ed25519 provider/algorithm not available (JDK and BC)", ex);
            }
        }
    }

    public static String sign(byte[] privateKeyEncoded, String data) {
        if (privateKeyEncoded == null) {
            throw new IllegalArgumentException("privateKeyEncoded não pode ser null");
        }
        if (data == null) {
            throw new IllegalArgumentException("data não pode ser null");
        }

        // Tenta provider padrão do JDK (quando disponível)
        try {
            return doSign("Ed25519", null, privateKeyEncoded, data);
        } catch (NoSuchAlgorithmException e) {
            // Fallback para BouncyCastle quando o algoritmo não estiver disponível no JDK (ex.: Java 11)
            try {
                return doSign("Ed25519", "BC", privateKeyEncoded, data);
            } catch (NoSuchAlgorithmException e2) {
                throw new CryptoProviderUnavailableException("Ed25519 indisponível em todos os providers (JDK e BC)", e2);
            } catch (InvalidKeySpecException | InvalidKeyException badKey) {
                throw new IllegalArgumentException("invalid Ed25519 private key", badKey);
            } catch (GeneralSecurityException gse) {
                throw new CryptoOperationException("Falha inesperada ao assinar com Ed25519 (BC)", gse);
            }
        } catch (InvalidKeySpecException | InvalidKeyException badKey) {
            throw new IllegalArgumentException("invalid Ed25519 private key", badKey);
        } catch (GeneralSecurityException gse) {
            throw new CryptoOperationException("Falha inesperada ao assinar com Ed25519", gse);
        }
    }

    private static String doSign(String algorithm, String provider, byte[] privateKeyEncoded, String data)
            throws GeneralSecurityException {
        KeyFactory kf = (provider == null)
                ? KeyFactory.getInstance(algorithm)
                : KeyFactory.getInstance(algorithm, provider);
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
        Signature sig = (provider == null)
                ? Signature.getInstance(algorithm)
                : Signature.getInstance(algorithm, provider);
        sig.initSign(privateKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
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