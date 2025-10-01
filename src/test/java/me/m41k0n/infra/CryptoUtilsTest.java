package me.m41k0n.infra;

import me.m41k0n.domain.PeerIdentity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoUtilsTest {

    @Test
    void testKeyPairGenerationAndSignVerify() {
        PeerIdentity identity = CryptoUtils.generateEd25519KeyPair();
        String message = "mensagem de teste";
        String signature = CryptoUtils.sign(identity.getPrivateKey(), message);

        boolean isValid = CryptoUtils.verify(identity.getPublicKey(), message, signature);
        assertTrue(isValid);

        boolean isInvalid = CryptoUtils.verify(identity.getPublicKey(), "outra mensagem", signature);
        assertFalse(isInvalid);
    }
}