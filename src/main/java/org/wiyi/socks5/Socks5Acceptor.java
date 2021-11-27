package org.wiyi.socks5;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;

public class Socks5Acceptor implements Runnable{
    private final int port;
    private final BlockingQueue<Socket> queue;

    public Socks5Acceptor(int port,BlockingQueue<Socket> queue) {
        this.port = port;
        this.queue = queue;
    }

    @Override
    public void run() {
        accept();
    }

    private void accept() {
        try {
            ServerSocket socket = new ServerSocket(port);
            System.out.println("socks5 server listen on port: " + port);
            while (true) {
                try {
                    Socket client = socket.accept();
                    System.out.printf("accept client { %s }\n",client);
                    queue.put(client);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
