package me.m41k0n.domain;

import com.google.gson.Gson;

public class Message {

    private final String type;
    private final String from;
    private final String to;
    private final String payload;
    private final String signature;
    private final long timestamp;

    public Message(String type, String from, String to, String payload, String signature) {
        this.type = type;
        this.from = from;
        this.to = to;
        this.payload = payload;
        this.signature = signature;
        this.timestamp = System.currentTimeMillis();
    }

    public String getType() {
        return type;
    }

    public String getFrom() {
        return from;
    }

    public String getTo() {
        return to;
    }

    public String getPayload() {
        return payload;
    }

    public String getSignature() {
        return signature;
    }

    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Serializa usando Gson para evitar erros de escape e manter consistência
     * com {@link #fromJson(String)}. Mantemos os nomes dos campos tal como
     * definidos para compatibilidade com testes e outros componentes.
     */
    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }

    public static Message fromJson(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, Message.class);
    }
}
