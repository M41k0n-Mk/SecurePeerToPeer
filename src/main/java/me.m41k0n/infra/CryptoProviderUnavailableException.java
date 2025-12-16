package me.m41k0n.infra;

/**
 * Lançada quando o algoritmo/provedor criptográfico necessário não está disponível
 * no ambiente (nem no JDK, nem no BouncyCastle).
 */
public class CryptoProviderUnavailableException extends RuntimeException {
    public CryptoProviderUnavailableException(String message) {
        super(message);
    }

    public CryptoProviderUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
