package me.m41k0n.app;

import me.m41k0n.domain.PeerIdentity;
import me.m41k0n.infra.SecureSession;
import me.m41k0n.infra.TcpSocketAdapter;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Orquestra a conexão P2P: listener sempre ativo + discagem opcional.
 * O primeiro caminho que completar o handshake autenticado vence localmente.
 */
public class P2PConnector {

    /**
     * Orquestra o fluxo P2P em etapas bem definidas:
     * 1) listenForConnections: inicia o listener (thread de accept) que tenta handshake para cada conexão entrante.
     * 2) dialPeer: opcionalmente inicia o dialer (thread) com tentativas e backoff, se IP/porta do peer forem informados.
     * 3) awaitWinner: aguarda a primeira sessão segura (handshake concluído) e fecha o listener.
     * 4) establishSecureSession: inicia o receptor da sessão, envia ping de prontidão e inicia o laço de envio do CLI.
     * 5) sendReadinessPing: envia um frame simples para sinalizar que o canal está pronto.
     */
    public void startPeerRace(int listenPort,
                              String peerIpOrNull,
                              Integer peerPort,
                              PeerIdentity myIdentity,
                              String peerStaticPubB64,
                              Scanner scanner) throws IOException {

        final AtomicBoolean done = new AtomicBoolean(false);
        final CompletableFuture<SecureSession> winner = new CompletableFuture<>();

        ServerSocket serverSocket = listenForConnections(listenPort, myIdentity, peerStaticPubB64, done, winner);
        dialPeer(peerIpOrNull, peerPort, myIdentity, peerStaticPubB64, done, winner);

        try (SecureSession session = awaitWinner(serverSocket, done, winner)) {
            establishSecureSession(session, scanner);
        }
    }

    /**
     * listenForConnections: abre um ServerSocket e inicia um thread "p2p-accept" que aceita conexões entrantes.
     * Para cada conexão aceita, tenta realizar o handshake autenticado (como responder). Se o handshake
     * concluir e ninguém tiver vencido ainda, completa o CompletableFuture winner com a sessão.
     * A thread encerra quando o sinal de 'done' for verdadeiro.
     */
    private ServerSocket listenForConnections(int listenPort,
                                              PeerIdentity myIdentity,
                                              String peerStaticPubB64,
                                              AtomicBoolean done,
                                              CompletableFuture<SecureSession> winner) throws IOException {
        final ServerSocket serverSocket = new ServerSocket(listenPort);
        Thread acceptThread = new Thread(() -> {
            System.out.println("[P2P] Ouvindo em 0.0.0.0:" + listenPort + ". Aguardando conexão do peer...");
            while (!done.get()) {
                try {
                    Socket s = serverSocket.accept();
                    if (done.get()) { try { s.close(); } catch (IOException ignored) {} break; }
                    SecureSession session = new SecureSession(new TcpSocketAdapter(s), myIdentity, peerStaticPubB64, false);
                    try {
                        session.startHandshake();
                        if (done.compareAndSet(false, true)) {
                            winner.complete(session);
                            break;
                        } else {
                            session.close();
                        }
                    } catch (Exception ex) {
                        System.err.println("[P2P] Handshake falhou no caminho de aceitação: " + ex.getMessage());
                        try { session.close(); } catch (IOException ignored) {}
                    }
                } catch (IOException ioe) {
                    if (!done.get()) System.err.println("[P2P] Erro ao aceitar conexão: " + ioe.getMessage());
                    break;
                }
            }
        }, "p2p-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        return serverSocket;
    }

    /**
     * dialPeer: se IP e porta do peer forem fornecidos, inicia um thread "p2p-dial" que tenta
     * conexões ativas com retry e backoff exponencial (com jitter). Ao conectar, realiza o handshake
     * como iniciador; se vencer a corrida, completa o winner com a sessão resultante.
     */
    private void dialPeer(String peerIpOrNull,
                          Integer peerPort,
                          PeerIdentity myIdentity,
                          String peerStaticPubB64,
                          AtomicBoolean done,
                          CompletableFuture<SecureSession> winner) {
        if (peerIpOrNull == null || peerPort == null) {
            System.out.println("[P2P] Modo somente ouvir (sem IP do peer informado).");
            return;
        }
        final String peerIpFinal = peerIpOrNull;
        Thread dialThread = new Thread(() -> {
            long backoffMs = 1000;
            System.out.println("[P2P] Tentando conectar ativamente ao peer em " + peerIpFinal + ":" + peerPort + " ...");
            while (!done.get()) {
                Socket socket = null;
                SecureSession session = null;
                try {
                    socket = new Socket();
                    socket.connect(new InetSocketAddress(peerIpFinal, peerPort), 2000);
                    if (done.get()) {
                        // se outro caminho já venceu, garante fechar o socket que criamos e sair
                        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
                        break;
                    }

                    session = new SecureSession(new TcpSocketAdapter(socket), myIdentity, peerStaticPubB64, true);
                    try {
                        session.startHandshake();
                        if (done.compareAndSet(false, true)) {
                            // vencemos a corrida: não fechamos o socket aqui — a sessão é entregue ao caller
                            winner.complete(session);
                            break; // sai do loop mantendo a sessão ativa
                        } else {
                            // perdemos a corrida: fechar a sessão que criamos
                            try { session.close(); } catch (IOException ignored) {}
                            break;
                        }
                    } catch (Exception ex) {
                        System.err.println("[P2P] Handshake falhou no caminho de discagem: " + ex.getMessage());
                        // continuar com retry
                    }
                } catch (IOException ce) {
                    // conexão não estabelecida — fechar socket e retry com backoff
                    try { if (socket != null) socket.close(); } catch (IOException ignored) {}
                }
                try {
                    long jitter = (long) (Math.random() * 250);
                    Thread.sleep(backoffMs + jitter);
                } catch (InterruptedException ie) {
                    break;
                }
                backoffMs = Math.min(backoffMs * 2, 5000);
            }
        }, "p2p-dial");
        dialThread.setDaemon(true);
        dialThread.start();
    }
    /**
     * awaitWinner: bloqueia até que uma sessão segura seja definida no CompletableFuture winner
     * (proveniente do listener ou do dialer). Ao sair, sinaliza 'done=true' e fecha o ServerSocket
     * para liberar a porta e parar a thread de accept.
     */
    private SecureSession awaitWinner(ServerSocket serverSocket,
                                      AtomicBoolean done,
                                      CompletableFuture<SecureSession> winner) {
        SecureSession established;
        try {
            established = winner.join();
        } finally {
            done.set(true);
            try { serverSocket.close(); } catch (IOException ignored) {}
        }
        return established;
    }

    /**
     * establishSecureSession: com a sessão já criada, inicia o receptor (imprime mensagens do peer),
     * envia um ping de prontidão (para sinalizar que o canal está operacional) e então entra no laço
     * de envio que lê do Scanner e envia ao peer. Ao encerrar, retorna ao caller.
     */
    private void establishSecureSession(SecureSession session, Scanner scanner) throws IOException {
        System.out.println("Sessão segura estabelecida. Digite /exit para sair.");
        session.runReceiver(new SecureSession.MessageHandler() {
            @Override public void onPlaintext(String text) {
                System.out.println("Peer: " + text);
            }
            @Override public void onError(Exception e) {
                if (e == null) {
                    System.out.println("[P2P] Sessão encerrada pelo peer.");
                    return;
                }
                if (e instanceof SocketException || e instanceof EOFException) {
                    String m = e.getMessage();
                    if (m == null || m.contains("Socket closed") || m.contains("Connection reset")) {
                        System.out.println("[P2P] Sessão encerrada pela rede.");
                        return;
                    }
                }
                System.err.println("[P2P] Erro no receptor: " + (e.getMessage() == null ? e.toString() : e.getMessage()));
            }
        });
        sendReadinessPing(session);
        sendingLoop(session, scanner);
    }

    /**
     * sendReadinessPing: envia uma pequena mensagem de controle ("[/ready]") logo após o handshake
     * para confirmar caminho de envio/recepção e facilitar diagnóstico de conectividade no início da sessão.
     * Qualquer erro é ignorado para não interromper o fluxo do chat.
     */
    private void sendReadinessPing(SecureSession session) {
        try {
            session.send("[/ready]");
        } catch (IOException ignored) {
            // ping é best-effort
        }
    }

    private void sendingLoop(SecureSession session, Scanner scanner) {
        try {
            while (!session.isClosed()) {
                try {
                    if (!scanner.hasNextLine()) {
                        try { Thread.sleep(200); } catch (InterruptedException ignored) {}
                        continue;
                    }
                    String input = scanner.nextLine();
                    if ("/exit".equalsIgnoreCase(input) || "exit".equalsIgnoreCase(input)) break;
                    if (input.trim().isEmpty()) continue;
                    session.send(input);
                } catch (java.util.NoSuchElementException | IllegalStateException e) {
                    System.out.println("[CLI] Entrada indisponível. Sessão continuará somente recebendo.");
                    while (!session.isClosed()) {
                        try { Thread.sleep(250); } catch (InterruptedException ignored) {}
                    }
                    break;
                }
            }
        } catch (IOException e) {
            String m = e.getMessage();
            if (m != null && (m.contains("Socket closed") || m.contains("Connection reset"))) {
                System.out.println("[P2P] Envio encerrado: conexão fechada.");
            } else {
                System.err.println("[P2P] Erro ao enviar mensagem: " + e.getMessage());
            }
        }
    }
}
