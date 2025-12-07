package me.m41k0n.integration;

import me.m41k0n.domain.Message;
import me.m41k0n.domain.PeerIdentity;
import me.m41k0n.infra.AeadUtils;
import me.m41k0n.infra.CryptoUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class PeerToPeerAeadIntegrationTest {

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testHandshakeAndAeadExchange() throws Exception {
        PeerIdentity serverIdentity = CryptoUtils.generateEd25519KeyPair();
        PeerIdentity clientIdentity = CryptoUtils.generateEd25519KeyPair();
        int port = 10081;

        CompletableFuture<Void> server = CompletableFuture.runAsync(() -> {
            try (ServerSocket ss = new ServerSocket(port);
                 Socket s = ss.accept();
                 BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));
                 BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()))) {

                String helloJson = r.readLine();
                Message hello = Message.fromJson(helloJson);
                assertEquals("hello", hello.getType());

                boolean ok = CryptoUtils.verify(Base64.getDecoder().decode(hello.getFrom()), hello.getPayload(), hello.getSignature());
                assertTrue(ok);

                // responder e derivar chave compartilhada
                String respPayload = "OK";
                String respSig = CryptoUtils.sign(serverIdentity.getPrivateKey(), respPayload);
                Message resp = new Message("hello", serverIdentity.getPublicKeyBase64(), hello.getFrom(), respPayload, respSig);
                w.write(resp.toJson() + "\n");
                w.flush();

                byte[] key = AeadUtils.deriveSharedKey(serverIdentity.getPublicKey(), Base64.getDecoder().decode(hello.getFrom()));
                byte[] aad = "chat-aad".getBytes(StandardCharsets.UTF_8);

                // receber mensagem cifrada
                String encB64 = r.readLine();
                byte[] plain = AeadUtils.decryptFromBase64(key, encB64, aad);
                assertEquals("secret from client", new String(plain, StandardCharsets.UTF_8));

                // responder cifrado
                String echo = "echo: secret from client";
                String out = AeadUtils.encryptToBase64(key, echo.getBytes(StandardCharsets.UTF_8), aad);
                w.write(out + "\n");
                w.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        Thread.sleep(300);

        CompletableFuture<Void> client = CompletableFuture.runAsync(() -> {
            try (Socket s = new Socket("127.0.0.1", port);
                 BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));
                 BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()))) {
                String payload = "client-hello";
                String sig = CryptoUtils.sign(clientIdentity.getPrivateKey(), payload);
                Message hello = new Message("hello", clientIdentity.getPublicKeyBase64(), serverIdentity.getPublicKeyBase64(), payload, sig);
                w.write(hello.toJson() + "\n");
                w.flush();

                Message resp = Message.fromJson(r.readLine());
                assertEquals("hello", resp.getType());

                byte[] key = AeadUtils.deriveSharedKey(clientIdentity.getPublicKey(), Base64.getDecoder().decode(resp.getFrom()));
                byte[] aad = "chat-aad".getBytes(StandardCharsets.UTF_8);

                String enc = AeadUtils.encryptToBase64(key, "secret from client".getBytes(StandardCharsets.UTF_8), aad);
                w.write(enc + "\n");
                w.flush();

                String echoB64 = r.readLine();
                byte[] echo = AeadUtils.decryptFromBase64(key, echoB64, aad);
                assertEquals("echo: secret from client", new String(echo, StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        server.get(15, TimeUnit.SECONDS);
        client.get(15, TimeUnit.SECONDS);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testPartialReadsAndDrop() throws Exception {
        PeerIdentity serverIdentity = CryptoUtils.generateEd25519KeyPair();
        PeerIdentity clientIdentity = CryptoUtils.generateEd25519KeyPair();
        int port = 10082;

        CompletableFuture<String> server = CompletableFuture.supplyAsync(() -> {
            try (ServerSocket ss = new ServerSocket(port);
                 Socket s = ss.accept()) {
                InputStream in = s.getInputStream();
                BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));

                // ler hello linha por linha mesmo com chunks
                String helloJson = readLineChunked(in);
                Message hello = Message.fromJson(helloJson);

                // responde normal
                String respPayload = "OK";
                String respSig = CryptoUtils.sign(serverIdentity.getPrivateKey(), respPayload);
                Message resp = new Message("hello", serverIdentity.getPublicKeyBase64(), hello.getFrom(), respPayload, respSig);
                w.write(resp.toJson() + "\n");
                w.flush();

                // agora conexão será dropada pelo cliente antes da próxima mensagem
                // tentar ler retornará -1 eventualmente
                try {
                    String next = readLineChunked(in);
                    return next == null ? "dropped" : "still-open";
                } catch (IOException ioe) {
                    return "exception";
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        Thread.sleep(200);

        CompletableFuture<Void> client = CompletableFuture.runAsync(() -> {
            try (Socket s = new Socket("127.0.0.1", port)) {
                OutputStream out = s.getOutputStream();
                BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));

                // enviar hello em pedaços (partial writes)
                String payload = "client-hello";
                String sig = CryptoUtils.sign(clientIdentity.getPrivateKey(), payload);
                Message hello = new Message("hello", clientIdentity.getPublicKeyBase64(), serverIdentity.getPublicKeyBase64(), payload, sig);
                byte[] bytes = (hello.toJson() + "\n").getBytes(StandardCharsets.UTF_8);
                Random rnd = new Random();
                int i = 0;
                while (i < bytes.length) {
                    int chunk = 1 + rnd.nextInt(5);
                    int end = Math.min(bytes.length, i + chunk);
                    out.write(bytes, i, end - i);
                    out.flush();
                    i = end;
                    Thread.yield();
                }

                // ler a resposta e em seguida dropar a conexão sem enviar a próxima mensagem
                String resp = r.readLine();
                assertNotNull(resp);
                // fecha sem enviar nada
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        client.get(10, TimeUnit.SECONDS);
        String result = server.get(10, TimeUnit.SECONDS);
        assertTrue(result.equals("dropped") || result.equals("exception"));
    }

    private static String readLineChunked(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int b;
        boolean sawLF = false;
        while ((b = in.read()) != -1) {
            if (b == '\n') { sawLF = true; break; }
            buffer.write(b);
        }
        if (b == -1 && buffer.size() == 0) return null;
        String s = buffer.toString(StandardCharsets.UTF_8);
        return sawLF ? s : s; // pode não ter LF se conexão fechar
    }

    @Test
    @Timeout(value = 40, unit = TimeUnit.SECONDS)
    void testLightLoadLatency() throws Exception {
        PeerIdentity serverIdentity = CryptoUtils.generateEd25519KeyPair();
        PeerIdentity clientIdentity = CryptoUtils.generateEd25519KeyPair();
        int port = 10083;

        CompletableFuture<Void> server = CompletableFuture.runAsync(() -> {
            try (ServerSocket ss = new ServerSocket(port);
                 Socket s = ss.accept();
                 BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));
                 BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()))) {

                // handshake
                Message hello = Message.fromJson(r.readLine());
                String respPayload = "OK";
                String respSig = CryptoUtils.sign(serverIdentity.getPrivateKey(), respPayload);
                Message resp = new Message("hello", serverIdentity.getPublicKeyBase64(), hello.getFrom(), respPayload, respSig);
                w.write(resp.toJson() + "\n");
                w.flush();

                byte[] key = AeadUtils.deriveSharedKey(serverIdentity.getPublicKey(), Base64.getDecoder().decode(hello.getFrom()));

                // echo loop de N mensagens
                String line;
                while ((line = r.readLine()) != null) {
                    String echoB64 = AeadUtils.encryptToBase64(key, ("echo:" + new String(AeadUtils.decryptFromBase64(key, line, null), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8), null);
                    w.write(echoB64 + "\n");
                    w.flush();
                }
            } catch (Exception e) {
                // termina
            }
        });

        Thread.sleep(200);

        CompletableFuture<Long> client = CompletableFuture.supplyAsync(() -> {
            try (Socket s = new Socket("127.0.0.1", port);
                 BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));
                 BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()))) {
                Message hello = new Message("hello", clientIdentity.getPublicKeyBase64(), serverIdentity.getPublicKeyBase64(), "hi", CryptoUtils.sign(clientIdentity.getPrivateKey(), "hi"));
                w.write(hello.toJson() + "\n");
                w.flush();
                r.readLine(); // ignore conteudo

                byte[] key = AeadUtils.deriveSharedKey(clientIdentity.getPublicKey(), serverIdentity.getPublicKey());

                int N = 200;
                long start = System.nanoTime();
                for (int i = 0; i < N; i++) {
                    String enc = AeadUtils.encryptToBase64(key, ("m" + i).getBytes(StandardCharsets.UTF_8), null);
                    w.write(enc + "\n");
                    w.flush();
                    String echo = r.readLine();
                    byte[] dec = AeadUtils.decryptFromBase64(key, echo, null);
                    assertEquals("echo:m" + i, new String(dec, StandardCharsets.UTF_8));
                }
                long end = System.nanoTime();
                return (end - start) / N; // latency média por mensagem (ns)
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        long avgNs = client.get(30, TimeUnit.SECONDS);
        server.cancel(true);
        // Apenas uma asserção fraca de que funcionou e atrasos não explodiram absurdamente
        assertTrue(avgNs > 0);
    }
}
