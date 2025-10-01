package me.m41k0n.domain;

import me.m41k0n.infra.CryptoUtils;

import java.util.Base64;

public class PeerIdentity {

    private final byte[] publicKey;
    private final byte[] privateKey;

    public PeerIdentity(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static PeerIdentity generate() {
        return CryptoUtils.generateEd25519KeyPair();
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey);
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}