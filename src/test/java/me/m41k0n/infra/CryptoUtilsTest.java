package me.m41k0n.infra;

import me.m41k0n.domain.Message;
import me.m41k0n.domain.PeerIdentity;
import org.junit.jupiter.api.Test;

import java.util.Base64;

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

    @Test
    void testMessageWithTimestamp() {
        PeerIdentity identity = CryptoUtils.generateEd25519KeyPair();
        String payload = "test message";
        String signature = CryptoUtils.sign(identity.getPrivateKey(), payload);
        Message msg = new Message("chat", identity.getPublicKeyBase64(), "recipient", payload, signature);

        assertTrue(msg.getTimestamp() > 0);
        assertEquals("chat", msg.getType());
        assertEquals(payload, msg.getPayload());

        // Test JSON serialization
        String json = msg.toJson();
        assertTrue(json.contains("\"timestamp\":"));

        // Test deserialization
        Message deserialized = Message.fromJson(json);
        assertEquals(msg.getType(), deserialized.getType());
        assertEquals(msg.getPayload(), deserialized.getPayload());
        assertEquals(msg.getTimestamp(), deserialized.getTimestamp());

        // Test signature verification
        boolean verified = CryptoUtils.verify(
                Base64.getDecoder().decode(deserialized.getFrom()),
                deserialized.getPayload(),
                deserialized.getSignature()
        );
        assertTrue(verified);
    }

    @Test
    void testVerifyWithInvalidInputs() {
        PeerIdentity identity = CryptoUtils.generateEd25519KeyPair();
        String msg = "abc";
        String sig = CryptoUtils.sign(identity.getPrivateKey(), msg);

        // nulls e vazios
        assertFalse(CryptoUtils.verify(null, msg, sig));
        assertFalse(CryptoUtils.verify(new byte[0], msg, sig));
        assertFalse(CryptoUtils.verify(identity.getPublicKey(), null, sig));
        assertFalse(CryptoUtils.verify(identity.getPublicKey(), msg, null));
        assertFalse(CryptoUtils.verify(identity.getPublicKey(), msg, ""));

        // assinatura base64 inválida
        assertFalse(CryptoUtils.verify(identity.getPublicKey(), msg, "###invalido###"));

        // chave pública inválida (bytes aleatórios)
        byte[] badPub = new byte[16];
        assertFalse(CryptoUtils.verify(badPub, msg, sig));
    }

    @Test
    void testSignWithInvalidInputs() {
        PeerIdentity identity = CryptoUtils.generateEd25519KeyPair();

        // nulls
        assertThrows(IllegalArgumentException.class, () -> CryptoUtils.sign(null, "data"));
        assertThrows(IllegalArgumentException.class, () -> CryptoUtils.sign(identity.getPrivateKey(), null));

        // chave privada inválida (bytes aleatórios)
        byte[] badPriv = new byte[16];
        assertThrows(RuntimeException.class, () -> CryptoUtils.sign(badPriv, "data"));
    }
}
