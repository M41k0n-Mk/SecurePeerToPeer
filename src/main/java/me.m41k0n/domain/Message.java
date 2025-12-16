package me.m41k0n.domain;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import java.util.Base64;

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

    /**
     * Variante segura para entradas externas: valida JSON e campos esperados.
     * Não lança stack traces detalhadas por padrão; usa mensagens curtas.
     *
     * Regras de validação mínimas:
     * - JSON deve ser válido
     * - type, from, payload, signature não podem ser nulos/vazios
     * - from e signature devem ser Base64 válidos (assinatura é base64 de bytes)
     */
    public static Message fromJsonValidated(String json) {
        if (json == null || json.isEmpty()) {
            throw new IllegalArgumentException("json vazio");
        }
        final Message m;
        try {
            m = fromJson(json);
        } catch (JsonSyntaxException jse) {
            throw new IllegalArgumentException("json inválido");
        }
        if (isBlank(m.type)) throw new IllegalArgumentException("campo 'type' ausente");
        if (isBlank(m.from)) throw new IllegalArgumentException("campo 'from' ausente");
        if (isBlank(m.payload)) throw new IllegalArgumentException("campo 'payload' ausente");
        if (isBlank(m.signature)) throw new IllegalArgumentException("campo 'signature' ausente");

        // validação Base64 básica
        try {
            Base64.getDecoder().decode(m.from);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("from não é Base64 válido");
        }
        try {
            Base64.getDecoder().decode(m.signature);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("signature não é Base64 válido");
        }
        return m;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
