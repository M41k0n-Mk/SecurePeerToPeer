package me.m41k0n.infra;

/**
 * Exceção unchecked para falhas inesperadas em operações criptográficas.
 * Não expõe detalhes sensíveis por padrão; use a causa para investigação.
 */
public class CryptoOperationException extends RuntimeException {
    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
