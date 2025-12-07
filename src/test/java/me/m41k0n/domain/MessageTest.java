package me.m41k0n.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MessageTest {

    @Test
    void testSerializeDeserializeRoundtrip() {
        Message m = new Message("chat", "fromX", "toY", "hello", "sig123");
        String json = m.toJson();
        assertNotNull(json);
        assertTrue(json.contains("\"type\":\"chat\""));
        Message d = Message.fromJson(json);
        assertEquals(m.getType(), d.getType());
        assertEquals(m.getFrom(), d.getFrom());
        assertEquals(m.getTo(), d.getTo());
        assertEquals(m.getPayload(), d.getPayload());
        assertEquals(m.getSignature(), d.getSignature());
        assertEquals(m.getTimestamp(), d.getTimestamp());
    }

    @Test
    void testDeserializeMissingFields() {
        // signature e to ausentes
        String json = "{\"type\":\"chat\",\"from\":\"A\",\"payload\":\"P\",\"timestamp\":123}";
        Message d = Message.fromJson(json);
        assertEquals("chat", d.getType());
        assertEquals("A", d.getFrom());
        assertNull(d.getTo());
        assertEquals("P", d.getPayload());
        assertNull(d.getSignature());
        assertEquals(123, d.getTimestamp());
    }

    @Test
    void testDeserializeInvalidJson() {
        String bad = "{not-json";
        assertThrows(com.google.gson.JsonSyntaxException.class, () -> Message.fromJson(bad));
    }
}
