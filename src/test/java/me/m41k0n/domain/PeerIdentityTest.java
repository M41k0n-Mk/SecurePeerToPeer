package me.m41k0n.domain;

import me.m41k0n.infra.CryptoUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PeerIdentityTest {

    @Test
    void testWipePrivateKey() {
        PeerIdentity id = CryptoUtils.generateEd25519KeyPair();
        byte[] privRef = id.getPrivateKey();
        assertNotNull(privRef);
        assertTrue(privRef.length > 0);

        boolean wiped = id.wipePrivateKey();
        assertTrue(wiped);
        assertNull(id.getPrivateKey());

        // o array previamente referenciado deve ter sido zerado
        int sum = 0;
        for (byte b : privRef) sum |= b;
        assertEquals(0, sum, "private key buffer deve estar zerado");
    }

    @Test
    void testWipePublicKey() {
        PeerIdentity id = CryptoUtils.generateEd25519KeyPair();
        byte[] pubRef = id.getPublicKey();
        assertNotNull(pubRef);
        assertTrue(pubRef.length > 0);

        boolean wiped = id.wipePublicKey();
        assertTrue(wiped);
        assertNull(id.getPublicKey());

        int sum = 0;
        for (byte b : pubRef) sum |= b;
        assertEquals(0, sum, "public key buffer deve estar zerado");
    }

    @Test
    void testWipeAllIdempotent() {
        PeerIdentity id = CryptoUtils.generateEd25519KeyPair();
        id.wipeAll();
        // chamadas subsequentes não devem lançar exceção e retornam false nos wipes específicos
        assertFalse(id.wipePrivateKey());
        assertFalse(id.wipePublicKey());
        assertNull(id.getPrivateKey());
        assertNull(id.getPublicKey());
    }
}
