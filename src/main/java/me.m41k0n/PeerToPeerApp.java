package me.m41k0n;

import me.m41k0n.domain.Message;
import me.m41k0n.domain.PeerIdentity;
import me.m41k0n.infra.CryptoUtils;

import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Scanner;

public class PeerToPeerApp {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Generating identity...");
        PeerIdentity myIdentity = PeerIdentity.generate();
        System.out.println("Your public key (your identity): " + myIdentity.getPublicKeyBase64());

        System.out.println("Enter 's' for server, 'c' for client:");
        String mode = scanner.nextLine().trim();

        if (mode.equalsIgnoreCase("s")) {
            System.out.print("Port to listen on: ");
            int port = Integer.parseInt(scanner.nextLine().trim());
            new Thread(() -> startServer(port, myIdentity)).start();
        } else if (mode.equalsIgnoreCase("c")) {
            System.out.print("IP to connect to: ");
            String ip = scanner.nextLine().trim();
            System.out.print("Port to connect to: ");
            int port = Integer.parseInt(scanner.nextLine().trim());
            System.out.print("Recipient's public key: ");
            String toPub = scanner.nextLine().trim();
            startClient(ip, port, myIdentity, toPub, scanner);
        } else {
            System.out.println("Invalid option.");
        }
    }

    public static void startServer(int port, PeerIdentity myIdentity) {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Listening on port " + port + "...");
            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))) {

                    String jsonMsg = reader.readLine();
                    System.out.println("Received: " + jsonMsg);
                    Message msg = Message.fromJson(jsonMsg);

                    System.out.println("Public key: " + msg.getFrom());
                    System.out.println("Payload: [" + msg.getPayload() + "]");
                    System.out.println("Signature: " + msg.getSignature());

                    boolean verified = CryptoUtils.verify(
                            Base64.getDecoder().decode(msg.getFrom()),
                            msg.getPayload(),
                            msg.getSignature()
                    );

                    if (verified && msg.getType().equals("hello") && msg.getPayload().equalsIgnoreCase("Hi!")) {
                        String responsePayload = "Hi, I am here!";
                        String responseSignature = CryptoUtils.sign(myIdentity.getPrivateKey(), responsePayload);
                        Message response = new Message("hello", myIdentity.getPublicKeyBase64(), msg.getFrom(), responsePayload, responseSignature);
                        writer.write(response.toJson() + "\n");
                        writer.flush();
                        System.out.println("Responded: " + response.toJson());

                        // Enter chat loop
                        chatLoop(clientSocket, myIdentity, msg.getFrom());
                    } else {
                        writer.write("Invalid message or incorrect signature\n");
                        writer.flush();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }

    public static void startClient(String ip, int port, PeerIdentity myIdentity, String toPub, Scanner scanner) {
        try (Socket socket = new Socket(ip, port);
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {

            String payload = "Hi!";
            String signature = CryptoUtils.sign(myIdentity.getPrivateKey(), payload);
            Message msg = new Message("hello", myIdentity.getPublicKeyBase64(), toPub, payload, signature);

            System.out.println("Payload signed: [" + payload + "]");
            System.out.println("Signature sent: " + signature);

            writer.write(msg.toJson() + "\n");
            writer.flush();
            System.out.println("Sent: " + msg.toJson());

            String responseJson = reader.readLine();
            System.out.println("Response received: " + responseJson);

            if (responseJson != null && responseJson.startsWith("{")) {
                Message response = Message.fromJson(responseJson);
                boolean verified = CryptoUtils.verify(
                        Base64.getDecoder().decode(response.getFrom()),
                        response.getPayload(),
                        response.getSignature()
                );
                System.out.println("Is the response signature valid? " + verified);

                if (verified && response.getType().equals("hello")) {
                    // Enter chat loop
                    chatLoop(socket, myIdentity, toPub, scanner);
                }
            }
        } catch (IOException e) {
            System.err.println("Client error: " + e.getMessage());
        }
    }

    private static void chatLoop(Socket socket, PeerIdentity myIdentity, String toPub, Scanner scanner) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {

            // Thread for receiving messages
            Thread receiver = new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Message msg = Message.fromJson(line);
                        boolean verified = CryptoUtils.verify(
                                Base64.getDecoder().decode(msg.getFrom()),
                                msg.getPayload(),
                                msg.getSignature()
                        );
                        if (verified) {
                            System.out.println("[" + msg.getTimestamp() + "] " + msg.getFrom() + ": " + msg.getPayload());
                        } else {
                            System.out.println("Invalid signature from " + msg.getFrom());
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Receive error: " + e.getMessage());
                }
            });
            receiver.start();

            // Send messages
            while (true) {
                System.out.print("You: ");
                String input = scanner.nextLine();
                if ("exit".equalsIgnoreCase(input)) break;
                String signature = CryptoUtils.sign(myIdentity.getPrivateKey(), input);
                Message chatMsg = new Message("chat", myIdentity.getPublicKeyBase64(), toPub, input, signature);
                writer.write(chatMsg.toJson() + "\n");
                writer.flush();
            }
        } catch (IOException e) {
            System.err.println("Chat error: " + e.getMessage());
        }
    }

    private static void chatLoop(Socket socket, PeerIdentity myIdentity, String fromPub) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {

            String line;
            while ((line = reader.readLine()) != null) {
                Message msg = Message.fromJson(line);
                boolean verified = CryptoUtils.verify(
                        Base64.getDecoder().decode(msg.getFrom()),
                        msg.getPayload(),
                        msg.getSignature()
                );
                if (verified && msg.getType().equals("chat")) {
                    System.out.println("[" + msg.getTimestamp() + "] " + msg.getFrom() + ": " + msg.getPayload());
                    // Echo back
                    String echo = "Echo: " + msg.getPayload();
                    String signature = CryptoUtils.sign(myIdentity.getPrivateKey(), echo);
                    Message response = new Message("chat", myIdentity.getPublicKeyBase64(), fromPub, echo, signature);
                    writer.write(response.toJson() + "\n");
                    writer.flush();
                }
            }
        } catch (IOException e) {
            System.err.println("Chat error: " + e.getMessage());
        }
    }
}
