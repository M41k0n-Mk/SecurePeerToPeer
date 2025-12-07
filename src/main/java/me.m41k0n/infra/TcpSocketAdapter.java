package me.m41k0n.infra;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Adaptador de Socket TCP para a interface {@link SecureSession.SocketLike}.
 */
public class TcpSocketAdapter implements SecureSession.SocketLike {
    private final Socket socket;

    public TcpSocketAdapter(Socket socket) {
        this.socket = socket;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return socket.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return socket.getOutputStream();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
