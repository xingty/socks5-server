package org.wiyi.socks5;

import java.net.Socket;
import java.util.concurrent.BlockingQueue;

public class Socks5Processor implements Runnable{

    private final BlockingQueue<Socket> queue;
    private final Socks5Handler handler = new Socks5Handler();

    public Socks5Processor(BlockingQueue<Socket> queue) {
        this.queue = queue;
    }

    @Override
    public void run() {
        while (true) {
            try {
                Socket client = queue.take();
                handler.handle(client,true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
