package me.m41k0n;

import me.m41k0n.app.P2PConnector;
import me.m41k0n.cli.CliUtils;
import me.m41k0n.domain.PeerIdentity;

import java.util.Scanner;

public class PeerToPeerApp {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Gerando identidade...");
        PeerIdentity myIdentity = PeerIdentity.generate();
        System.out.println("Sua chave pública (sua identidade): " + myIdentity.getPublicKeyBase64());
        System.out.println();
        System.out.println("Seus endereços IP (v4) locais:");
        CliUtils.printLocalIPv4();
        System.out.println();

        // Loop principal: qualquer erro volta ao início, evitando reiniciar a aplicação
        while (true) {
            try {
                int listenPort = CliUtils.askPort(scanner, "Porta local para ouvir conexões");

                String peerPubB64 = CliUtils.askBase64Key(scanner, "Chave pública (Base64) do peer com quem deseja falar");

                String peerIp = CliUtils.askPeerIp(scanner);
                Integer peerPort = null;
                if (!peerIp.isEmpty()) {
                    peerPort = CliUtils.askPort(scanner, "Porta do peer");
                }

                // Inicia sempre o listener e, se IP do peer for informado, também um dialer com retry.
                new P2PConnector().startPeerRace(listenPort, peerIp.isEmpty() ? null : peerIp, peerPort, myIdentity, peerPubB64, scanner);
                System.out.println("Sessão encerrada. Voltando ao início...\n");
            } catch (Exception e) {
                System.err.println("Erro inesperado na aplicação: " + (e.getMessage() == null ? e.toString() : e.getMessage()));
                System.err.println("Reiniciando o fluxo...\n");
            }
        }
    }
}
