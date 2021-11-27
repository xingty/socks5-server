package org.wiyi.socks5;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Socks5RelayHandler {

    public void doRelay(Socket client, String addr, int port) {
        Socket relay = null;
        try {
            relay = new Socket(addr,port);
            relay.setSoTimeout(30 * 1000);
            Socks5Pipe p1 = new Socks5Pipe(client,relay,"client");
            Socks5Pipe p2 = new Socks5Pipe(relay,client,"server");

            p1.relay();
            p2.relay();
        } catch (IOException e) {
            try {
                if (relay != null && !relay.isClosed()) {
                    System.out.printf("address: %s, reason: %s",relay.getInetAddress(),e.getMessage());
                    relay.close();
                }

                if (!client.isClosed()) {
                    client.close();
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        }
    }

    static class Socks5Pipe implements Runnable{
        private String id;
        private final Socket source;
        private final Socket target;

        Socks5Pipe(Socket source, Socket target,String id) {
            this.source = source;
            this.target = target;
            this.id = id;
        }

        public void relay() {
            Thread t = new Thread(this);
            t.setName("Socks5-Thread-" + target.getInetAddress().toString());
            t.start();
        }

        @Override
        public void run() {
            try {
                InputStream sis = source.getInputStream();
                OutputStream tos = target.getOutputStream();

                byte[] buffer = new byte[1024];
                int len;
                while ((len = sis.read(buffer)) > 0) {
                    tos.write(buffer,0,len);
                }

                close();
            } catch (IOException e) {
                System.out.printf("address: %s, reason: %s\n",source.getInetAddress(),e.getMessage());
                close();
                e.printStackTrace();
            }
        }

        public void close() {
            try {
                System.out.println(id + " close");

                if (!source.isClosed()) {
                    source.close();
                }

                if (!target.isClosed()) {
                    target.shutdownInput();
                }
            } catch (IOException e) {
                System.out.println("close socket error");
                e.printStackTrace();
            }
        }
    }
}
