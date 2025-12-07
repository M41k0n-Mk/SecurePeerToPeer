package me.m41k0n.infra;

import me.m41k0n.domain.Message;
import me.m41k0n.domain.PeerIdentity;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.net.SocketException;

/**
 * Camada de sessão segura P2P: handshake autenticado (Ed25519) + X25519 (PFS) + AEAD.
 * Após o handshake, os dados trafegam cifrados (linhas base64 via AES-GCM em {@link AeadUtils}).
 */
public class SecureSession implements Closeable {

    private final SocketLike socket;
    private final PeerIdentity me;
    private final String peerStaticPubB64;
    private final boolean initiator;

    private BufferedReader reader;
    private BufferedWriter writer;

    private byte[] aeadKey;
    private long sendSeq = 0;
    private long recvSeq = -1; // último seq aceito

    // Flag de encerramento para coordenação com o CLI
    private volatile boolean closed = false;

    // Limite defensivo para cada linha/fragmento recebido (base64 + metadados)
    // Evita consumo excessivo de memória em caso de peers maliciosos.
    private static final int MAX_LINE_LEN = 16 * 1024; // 16 KiB

    public interface MessageHandler {
        void onPlaintext(String text);
        void onError(Exception e);
    }

    public interface SocketLike extends Closeable {
        InputStream getInputStream() throws IOException;
        OutputStream getOutputStream() throws IOException;
    }

    public SecureSession(SocketLike socket, PeerIdentity me, String peerStaticPubB64, boolean initiator) {
        this.socket = Objects.requireNonNull(socket);
        this.me = Objects.requireNonNull(me);
        this.peerStaticPubB64 = Objects.requireNonNull(peerStaticPubB64);
        this.initiator = initiator;
    }

    public void startHandshake() throws Exception {
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

        // Gera par efêmero X25519
        KeyPair eph = X25519Utils.generate();
        String ephPubB64 = Base64.getEncoder().encodeToString(eph.getPublic().getEncoded());

        // payload assinado inclui nossa eph key e o peer esperado, para evitar mitm com mudança de destino
        String payload = "epk:" + ephPubB64 + "|peer:" + peerStaticPubB64;
        String sig = CryptoUtils.sign(me.getPrivateKey(), payload);
        Message m = new Message("hs1", me.getPublicKeyBase64(), peerStaticPubB64, payload, sig);

        if (initiator) {
            sendLine(m.toJson());
            Message other = Message.fromJson(expectLineNonNullLimited());
            validateHandshakeMessage(other);

            PublicKey otherEph = decodeX25519FromPayload(other.getPayload());
            byte[] secret = X25519Utils.agree(eph.getPrivate(), otherEph);
            // HKDF: info amarra identidades estáticas
            byte[] info = (sortPair(me.getPublicKeyBase64(), other.getFrom()) + ":chat").getBytes(StandardCharsets.UTF_8);
            this.aeadKey = Hkdf.hkdfSha256(secret, null, info, 32);
        } else {
            Message first = Message.fromJson(expectLineNonNullLimited());
            validateHandshakeMessage(first);
            PublicKey otherEph = decodeX25519FromPayload(first.getPayload());

            // responde com nosso hs1
            sendLine(m.toJson());

            byte[] secret = X25519Utils.agree(eph.getPrivate(), otherEph);
            byte[] info = (sortPair(first.getFrom(), me.getPublicKeyBase64()) + ":chat").getBytes(StandardCharsets.UTF_8);
            this.aeadKey = Hkdf.hkdfSha256(secret, null, info, 32);
        }
    }

    public void runReceiver(MessageHandler handler) {
        Thread t = new Thread(() -> {
            try {
                for (String line = readLineLimited(); line != null; line = readLineLimited()) {
                    // Cada linha é: base64(ciphertext); AAD = seq(8 bytes) || ids
                    String[] parts = line.split("\\|", 2);
                    if (parts.length != 2) continue;
                    long seq;
                    try {
                        seq = Long.parseLong(parts[0]);
                    } catch (NumberFormatException nfe) {
                        // linha malformada: ignora
                        continue;
                    }
                    if (seq <= recvSeq) continue; // proteção simples contra replay/out-of-order
                    byte[] aad = aadFor(seq);
                    byte[] plain = AeadUtils.decryptFromBase64(aeadKey, parts[1], aad);
                    recvSeq = seq;
                    handler.onPlaintext(new String(plain, StandardCharsets.UTF_8));
                }
                // EOF alcançado: fechar sessão silenciosamente e notificar término normal
                try { SecureSession.this.close(); } catch (IOException ignore) {}
                handler.onError(null);
            } catch (Exception e) {
                try { SecureSession.this.close(); } catch (IOException ignore) {}
                if (e instanceof EOFException || e instanceof SocketException) {
                    // Encerramentos comuns: tratar como término normal (sem erro ruidoso)
                    handler.onError(null);
                } else {
                    handler.onError(e);
                }
            }
        }, "secure-recv");
        t.setDaemon(true);
        t.start();
    }

    // Lê uma linha impondo limite de tamanho para evitar OOM em entrada maliciosa
    private String expectLineNonNullLimited() throws IOException {
        String line = readLineLimited();
        if (line == null) throw new EOFException("Conexão encerrada durante o handshake: a outra ponta fechou antes de concluir a negociação.");
        return line;
    }

    private String readLineLimited() throws IOException {
        StringBuilder sb = new StringBuilder(256);
        int ch;
        while ((ch = reader.read()) != -1) {
            if (ch == '\n') break;
            sb.append((char) ch);
            if (sb.length() > MAX_LINE_LEN) {
                // descarta essa linha longa demais
                // consome até o fim da linha
                while (ch != -1 && ch != '\n') {
                    ch = reader.read();
                }
                return ""; // retorna vazia para ser ignorada
            }
        }
        if (ch == -1 && sb.length() == 0) return null;
        return sb.toString();
    }

    public synchronized void send(String plaintext) throws IOException {
        long seq = sendSeq++;
        byte[] aad = aadFor(seq);
        String enc = AeadUtils.encryptToBase64(aeadKey, plaintext.getBytes(StandardCharsets.UTF_8), aad);
        sendLine(seq + "|" + enc);
    }

    private void validateHandshakeMessage(Message other) {
        if (!"hs1".equals(other.getType())) {
            throw new IllegalStateException("Mensagem de handshake inválida: tipo inesperado '" + other.getType() + "' (esperado 'hs1').");
        }
        if (!peerStaticPubB64.equals(other.getFrom())) {
            throw new IllegalStateException("Autenticação falhou: chave pública recebida não é a esperada para o peer.");
        }
        boolean ok = CryptoUtils.verify(Base64.getDecoder().decode(other.getFrom()), other.getPayload(), other.getSignature());
        if (!ok) {
            throw new IllegalStateException("Assinatura do handshake é inválida (Ed25519 verificação falhou).");
        }
        if (!other.getPayload().contains("epk:")) {
            throw new IllegalStateException("Payload do handshake malformado: chave efêmera (epk) ausente.");
        }
    }

    private PublicKey decodeX25519FromPayload(String payload) throws Exception {
        String[] kv = payload.split("\\|");
        String epk = null;
        for (String s : kv) {
            if (s.startsWith("epk:")) {
                epk = s.substring(4);
            }
        }
        if (epk == null) throw new IllegalStateException("Handshake inválido: campo 'epk' ausente no payload.");
        byte[] der = Base64.getDecoder().decode(epk);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePublic(new X509EncodedKeySpec(der));
    }

    private String sortPair(String a, String b) {
        return a.compareTo(b) <= 0 ? a + ":" + b : b + ":" + a;
    }

    private byte[] aadFor(long seq) {
        ByteBuffer bb = ByteBuffer.allocate(8 + 1);
        bb.putLong(seq);
        bb.put((byte) 1); // versão do canal
        return bb.array();
    }

    private void sendLine(String s) throws IOException {
        writer.write(s);
        writer.write('\n');
        writer.flush();
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        try { if (writer != null) writer.close(); } finally {
            try { if (reader != null) reader.close(); } finally {
                // limpar chave de sessão da memória
                if (aeadKey != null) {
                    Arrays.fill(aeadKey, (byte) 0);
                    aeadKey = null;
                }
                socket.close();
            }
        }
    }

    /**
     * Indica se a sessão já foi encerrada.
     */
    public boolean isClosed() {
        return closed;
    }
}
