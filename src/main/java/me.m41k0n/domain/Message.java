package me.m41k0n.domain;

public class Message {

    private final String type;
    private final String from;
    private final String to;
    private final String payload;
    private final String signature;

    public Message(String type, String from, String to, String payload, String signature) {
        this.type = type;
        this.from = from;
        this.to = to;
        this.payload = payload;
        this.signature = signature;
    }

    public String getType() { return type; }
    public String getFrom() { return from; }
    public String getTo() { return to; }
    public String getPayload() { return payload; }
    public String getSignature() { return signature; }

    public String toJson() {
        return String.format(
                "{\"type\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
                type, from, to, payload, signature
        );
    }

    public static Message fromJson(String json) {
        String[] parts = json.replace("{", "").replace("}", "").replace("\"", "").split(",");
        String type = "", from = "", to = "", payload = "", signature = "";
        for (String p : parts) {
            String[] kv = p.split(":");
            switch (kv[0]) {
                case "type": type = kv[1]; break;
                case "from": from = kv[1]; break;
                case "to": to = kv[1]; break;
                case "payload": payload = kv[1]; break;
                case "signature": signature = kv[1]; break;
            }
        }
        return new Message(type, from, to, payload, signature);
    }
}