package me.m41k0n.domain;

import me.m41k0n.infra.CryptoUtils;

import java.util.Arrays;
import java.util.Base64;

public class PeerIdentity {

    private byte[] publicKey;
    private byte[] privateKey;

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

    /**
     * Apaga de forma segura o conteúdo da chave privada na memória.
     * Após a chamada, o array é sobrescrito com zeros e referenciado como null.
     * Retorna true se havia conteúdo para limpar.
     */
    public boolean wipePrivateKey() {
        if (privateKey == null) return false;
        Arrays.fill(privateKey, (byte) 0);
        privateKey = null;
        return true;
    }

    /**
     * Apaga de forma segura o conteúdo da chave pública na memória.
     * Útil em cenários onde deseja-se minimizar a exposição de material chave codificado.
     */
    public boolean wipePublicKey() {
        if (publicKey == null) return false;
        Arrays.fill(publicKey, (byte) 0);
        publicKey = null;
        return true;
    }

    /**
     * Limpa ambas as chaves (pública e privada).
     */
    public void wipeAll() {
        wipePrivateKey();
        wipePublicKey();
    }
}