package me.m41k0n.integration;

import me.m41k0n.domain.Message;
import me.m41k0n.domain.PeerIdentity;
import me.m41k0n.infra.CryptoUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class PeerToPeerIntegrationTest {

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    public void testFullPeerToPeerChat() throws Exception {
        // Generate identities for both peers
        PeerIdentity serverIdentity = CryptoUtils.generateEd25519KeyPair();
        PeerIdentity clientIdentity = CryptoUtils.generateEd25519KeyPair();

        int port = 9999;

        // Start server in a separate thread
        CompletableFuture<String> serverResult = CompletableFuture.supplyAsync(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                System.out.println("Test Server: Listening on port " + port);

                try (Socket clientSocket = serverSocket.accept();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))) {

                    // Receive hello message from client
                    String jsonMsg = reader.readLine();
                    System.out.println("Test Server: Received: " + jsonMsg);

                    Message msg = Message.fromJson(jsonMsg);
                    assertEquals("hello", msg.getType());
                    assertEquals("Hi!", msg.getPayload());

                    // Verify signature
                    boolean verified = CryptoUtils.verify(
                            Base64.getDecoder().decode(msg.getFrom()),
                            msg.getPayload(),
                            msg.getSignature()
                    );
                    assertTrue(verified, "Client signature should be valid");

                    // Send response
                    String responsePayload = "Hi, I am here!";
                    String responseSignature = CryptoUtils.sign(serverIdentity.getPrivateKey(), responsePayload);
                    Message response = new Message("hello", serverIdentity.getPublicKeyBase64(), msg.getFrom(), responsePayload, responseSignature);
                    writer.write(response.toJson() + "\n");
                    writer.flush();
                    System.out.println("Test Server: Responded: " + response.toJson());

                    // Now test chat messages
                    // Receive chat message
                    String chatJson = reader.readLine();
                    System.out.println("Test Server: Received chat: " + chatJson);

                    Message chatMsg = Message.fromJson(chatJson);
                    assertEquals("chat", chatMsg.getType());
                    assertEquals("Hello from client", chatMsg.getPayload());

                    verified = CryptoUtils.verify(
                            Base64.getDecoder().decode(chatMsg.getFrom()),
                            chatMsg.getPayload(),
                            chatMsg.getSignature()
                    );
                    assertTrue(verified, "Chat signature should be valid");

                    // Send echo response
                    String echo = "Echo: " + chatMsg.getPayload();
                    String echoSignature = CryptoUtils.sign(serverIdentity.getPrivateKey(), echo);
                    Message echoResponse = new Message("chat", serverIdentity.getPublicKeyBase64(), chatMsg.getFrom(), echo, echoSignature);
                    writer.write(echoResponse.toJson() + "\n");
                    writer.flush();
                    System.out.println("Test Server: Echoed: " + echoResponse.toJson());

                    return "Server completed successfully";
                }
            } catch (Exception e) {
                throw new RuntimeException("Server error: " + e.getMessage(), e);
            }
        });

        // Wait a bit for server to start
        Thread.sleep(500);

        // Start client in another thread
        CompletableFuture<String> clientResult = CompletableFuture.supplyAsync(() -> {
            try (Socket socket = new Socket("localhost", port);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {

                // Send hello message
                String payload = "Hi!";
                String signature = CryptoUtils.sign(clientIdentity.getPrivateKey(), payload);
                Message msg = new Message("hello", clientIdentity.getPublicKeyBase64(), serverIdentity.getPublicKeyBase64(), payload, signature);

                System.out.println("Test Client: Sending hello");
                writer.write(msg.toJson() + "\n");
                writer.flush();

                // Receive response
                String responseJson = reader.readLine();
                System.out.println("Test Client: Response received: " + responseJson);

                Message response = Message.fromJson(responseJson);
                assertEquals("hello", response.getType());
                assertEquals("Hi, I am here!", response.getPayload());

                boolean verified = CryptoUtils.verify(
                        Base64.getDecoder().decode(response.getFrom()),
                        response.getPayload(),
                        response.getSignature()
                );
                assertTrue(verified, "Server response signature should be valid");

                // Send chat message
                String chatPayload = "Hello from client";
                String chatSignature = CryptoUtils.sign(clientIdentity.getPrivateKey(), chatPayload);
                Message chatMsg = new Message("chat", clientIdentity.getPublicKeyBase64(), serverIdentity.getPublicKeyBase64(), chatPayload, chatSignature);

                System.out.println("Test Client: Sending chat message");
                writer.write(chatMsg.toJson() + "\n");
                writer.flush();

                // Receive echo
                String echoJson = reader.readLine();
                System.out.println("Test Client: Echo received: " + echoJson);

                Message echoMsg = Message.fromJson(echoJson);
                assertEquals("chat", echoMsg.getType());
                assertEquals("Echo: Hello from client", echoMsg.getPayload());

                verified = CryptoUtils.verify(
                        Base64.getDecoder().decode(echoMsg.getFrom()),
                        echoMsg.getPayload(),
                        echoMsg.getSignature()
                );
                assertTrue(verified, "Echo signature should be valid");

                return "Client completed successfully";
            } catch (Exception e) {
                throw new RuntimeException("Client error: " + e.getMessage(), e);
            }
        });

        // Wait for both to complete and check results
        String serverOutput = serverResult.get(20, TimeUnit.SECONDS);
        String clientOutput = clientResult.get(20, TimeUnit.SECONDS);

        assertEquals("Server completed successfully", serverOutput);
        assertEquals("Client completed successfully", clientOutput);

        System.out.println("Integration test passed!");
    }
}