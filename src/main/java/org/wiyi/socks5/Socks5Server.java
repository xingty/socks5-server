package org.wiyi.socks5;

import java.net.Socket;
import java.util.concurrent.LinkedBlockingQueue;

public class Socks5Server {
    public static void main(String[] args) throws Exception{
        LinkedBlockingQueue<Socket> queue = new LinkedBlockingQueue<>();

        Socks5Acceptor acceptor = new Socks5Acceptor(7582,queue);
        Socks5Processor processor = new Socks5Processor(queue);

        new Thread(acceptor).start();
        new Thread(processor).start();

        Thread.currentThread().join();
    }
}
