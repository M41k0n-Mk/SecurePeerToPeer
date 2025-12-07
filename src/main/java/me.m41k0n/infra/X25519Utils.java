package me.m41k0n.infra;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import javax.crypto.KeyAgreement;

/**
 * Utilitário mínimo para X25519 (ECDH) usando JDK 11.
 */
public final class X25519Utils {

    private static final NamedParameterSpec X25519 = new NamedParameterSpec("X25519");

    private X25519Utils() {}

    public static KeyPair generate() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            kpg.initialize(X25519);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Falha ao gerar X25519", e);
        }
    }

    public static byte[] agree(PrivateKey privateKey, PublicKey peerPublic) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(privateKey);
            ka.doPhase(peerPublic, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("Falha no acordo X25519", e);
        }
    }
}
