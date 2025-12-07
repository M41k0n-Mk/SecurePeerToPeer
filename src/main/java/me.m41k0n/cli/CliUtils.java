package me.m41k0n.cli;

import java.net.*;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

/**
 * Utilidades de CLI para leitura/validação de entradas e exibição de IPs locais.
 * Mantém laços por campo: ao errar a porta, volta só na porta; ao errar a chave, volta só na chave.
 */
public final class CliUtils {

    private CliUtils() {}

    public static int askPort(Scanner sc, String label) {
        while (true) {
            System.out.print(label + ": ");
            String s = sc.nextLine().trim();
            try {
                int p = Integer.parseInt(s);
                if (p < 1 || p > 65535) throw new NumberFormatException("faixa inválida (válida: 1..65535)");
                return p;
            } catch (NumberFormatException nfe) {
                System.err.println("Porta inválida: " + nfe.getMessage() + ". Tente novamente.");
            }
        }
    }

    public static String askBase64Key(Scanner sc, String label) {
        while (true) {
            System.out.print(label + ": ");
            String b64 = sc.nextLine().trim();
            if (b64.isEmpty()) {
                System.err.println("Chave pública obrigatória. Cole a string Base64 exibida pelo seu peer.");
                continue;
            }
            try {
                Base64.getDecoder().decode(b64);
                return b64;
            } catch (IllegalArgumentException e) {
                System.err.println("Chave pública inválida: não é Base64 válido. Tente novamente.");
            }
        }
    }

    /**
     * Pergunta o IP do peer. Retorna string vazia para modo somente ouvir.
     * Valida formato de IPv4 simples quando informado.
     */
    public static String askPeerIp(Scanner sc) {
        while (true) {
            System.out.print("IP do peer (vazio para apenas aguardar conexões): ");
            String ip = sc.nextLine().trim();
            if (ip.isEmpty()) return ip; // somente ouvir
            if (isLikelyIPv4(ip)) return ip;
            System.err.println("IP inválido. Informe um IPv4 (ex.: 127.0.0.1 ou 192.168.0.10) ou deixe vazio para somente ouvir.");
        }
    }

    private static boolean isLikelyIPv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            for (String p : parts) {
                if (p.isEmpty()) return false;
                int n = Integer.parseInt(p);
                if (n < 0 || n > 255) return false;
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static void printLocalIPv4() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) continue;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                        System.out.println(" - " + a.getHostAddress() + " (" + ni.getDisplayName() + ")");
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("(Falha ao listar IPs locais: " + e.getMessage() + ")");
        }
    }
}
