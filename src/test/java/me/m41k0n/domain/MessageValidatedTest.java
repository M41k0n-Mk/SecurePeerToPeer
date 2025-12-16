package me.m41k0n.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MessageValidatedTest {

    @Test
    void fromJsonValidated_rejectsNullOrEmpty() {
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(null));
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(""));
    }

    @Test
    void fromJsonValidated_rejectsBadJson() {
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated("{not-json"));
    }

    @Test
    void fromJsonValidated_rejectsMissingMandatoryFields() {
        // missing type
        String noType = "{\"from\":\"QmFzZTY0\",\"payload\":\"x\",\"signature\":\"U0lH\"}";
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(noType));

        // missing from
        String noFrom = "{\"type\":\"chat\",\"payload\":\"x\",\"signature\":\"U0lH\"}";
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(noFrom));

        // missing payload
        String noPayload = "{\"type\":\"chat\",\"from\":\"QUJD\",\"signature\":\"U0lH\"}";
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(noPayload));

        // missing signature
        String noSig = "{\"type\":\"chat\",\"from\":\"QUJD\",\"payload\":\"x\"}";
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(noSig));
    }

    @Test
    void fromJsonValidated_rejectsNonBase64() {
        String badFrom = "{\"type\":\"chat\",\"from\":\"###\",\"payload\":\"x\",\"signature\":\"U0lH\"}";
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(badFrom));

        String badSig = "{\"type\":\"chat\",\"from\":\"QUJD\",\"payload\":\"x\",\"signature\":\"###\"}";
        assertThrows(IllegalArgumentException.class, () -> Message.fromJsonValidated(badSig));
    }

    @Test
    void fromJsonValidated_acceptsValid() {
        String ok = "{\"type\":\"chat\",\"from\":\"QUJD\",\"to\":\"REVG\",\"payload\":\"cGF5bG9hZA==\",\"signature\":\"U0lHTkFU\",\"timestamp\":123456}";
        Message m = Message.fromJsonValidated(ok);
        assertEquals("chat", m.getType());
        assertEquals("QUJD", m.getFrom());
        assertEquals("cGF5bG9hZA==", m.getPayload());
        assertEquals("U0lHTkFU", m.getSignature());
        assertEquals(123456L, m.getTimestamp());
    }
}
