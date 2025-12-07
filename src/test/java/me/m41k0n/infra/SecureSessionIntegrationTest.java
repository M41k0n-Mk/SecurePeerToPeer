package me.m41k0n.infra;

import me.m41k0n.domain.PeerIdentity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Teste de integração direto da camada SecureSession (sem CLI).
 * Exercita: handshake autenticado, troca de mensagens em ambos sentidos,
 * estabilidade por um curto período e encerramento limpo.
 */
public class SecureSessionIntegrationTest {

    private static class SocketAdapter implements SecureSession.SocketLike {
        private final Socket sock;
        SocketAdapter(Socket s) { this.sock = s; }
        @Override public InputStream getInputStream() throws IOException { return sock.getInputStream(); }
        @Override public OutputStream getOutputStream() throws IOException { return sock.getOutputStream(); }
        @Override public void close() throws IOException { sock.close(); }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void testSecureSessionHandshakeAndChatStability() throws Exception {
        PeerIdentity a = CryptoUtils.generateEd25519KeyPair();
        PeerIdentity b = CryptoUtils.generateEd25519KeyPair();

        int port = 12001;

        AtomicReference<String> recvOnServer = new AtomicReference<>();
        AtomicReference<String> recvOnClient = new AtomicReference<>();
        AtomicBoolean serverClosed = new AtomicBoolean(false);
        AtomicBoolean clientClosed = new AtomicBoolean(false);
        AtomicBoolean okToClientClose = new AtomicBoolean(false);

        // Servidor (aceita e atua como responder/initiator=false)
        CompletableFuture<Void> server = CompletableFuture.runAsync(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                Socket s = ss.accept();
                try (SecureSession session = new SecureSession(new SocketAdapter(s), a, b.getPublicKeyBase64(), false)) {
                    // Handshake responder
                    session.startHandshake();
                    session.runReceiver(new SecureSession.MessageHandler() {
                        @Override public void onPlaintext(String text) { recvOnServer.set(text); }
                        @Override public void onError(Exception e) { serverClosed.set(true); }
                    });

                    // Envia mensagem do servidor para o cliente
                    session.send("srv:hello");

                    // Aguarda por trocas e depois espera um pouco sem encerrar
                    Thread.sleep(300);

                    // Garante que sessão ainda está aberta neste ponto
                    assertFalse(session.isClosed(), "sessão do servidor não deve fechar imediatamente");
                    // Autoriza o cliente a encerrar quando terminar seus asserts
                    okToClientClose.set(true);

                    // Espera o cliente encerrar ao final do teste
                    while (!session.isClosed()) {
                        Thread.sleep(50);
                        // tempo máximo de espera será controlado pelo timeout do teste
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        // Pequeno atraso para o servidor subir
        Thread.sleep(150);

        // Cliente (conecta e atua como initiator=true)
        CompletableFuture<Void> client = CompletableFuture.runAsync(() -> {
            try (Socket sock = new Socket()) {
                sock.connect(new InetSocketAddress("127.0.0.1", port), 2000);
                try (SecureSession session = new SecureSession(new SocketAdapter(sock), b, a.getPublicKeyBase64(), true)) {
                    session.startHandshake();
                    session.runReceiver(new SecureSession.MessageHandler() {
                        @Override public void onPlaintext(String text) { recvOnClient.set(text); }
                        @Override public void onError(Exception e) { clientClosed.set(true); }
                    });

                    // Envia mensagem do cliente para o servidor
                    session.send("cli:hello");

                    // Aguarda recebimento em ambos os lados
                    long start = System.currentTimeMillis();
                    while ((recvOnServer.get() == null || recvOnClient.get() == null) && System.currentTimeMillis() - start < 2000) {
                        Thread.sleep(20);
                    }

                    assertEquals("cli:hello", recvOnServer.get(), "servidor deve receber mensagem do cliente");
                    assertEquals("srv:hello", recvOnClient.get(), "cliente deve receber mensagem do servidor");

                    // Verifica estabilidade por um curto período
                    Thread.sleep(200);
                    assertFalse(session.isClosed(), "sessão do cliente não deve fechar sozinha");

                    // Aguarda autorização do servidor para encerrar (evita corrida com o assert do servidor)
                    long spinStart = System.currentTimeMillis();
                    while (!okToClientClose.get() && System.currentTimeMillis() - spinStart < 2000) {
                        Thread.sleep(20);
                    }
                    // Encerra o cliente de forma limpa
                    session.close();
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        // Espera completarem
        client.get(10, TimeUnit.SECONDS);
        server.get(10, TimeUnit.SECONDS);

        // Após fechamento do cliente, o servidor deve ter fechado também (via EOF/Socket closed normal)
        assertTrue(serverClosed.get(), "servidor deve notificar fechamento");
        assertTrue(clientClosed.get(), "cliente deve notificar fechamento");
    }
}
