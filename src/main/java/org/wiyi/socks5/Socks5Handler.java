package org.wiyi.socks5;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class Socks5Handler {
    final ExecutorService es = new ThreadPoolExecutor(
            5,10,1, TimeUnit.MINUTES,new ArrayBlockingQueue<>(30));
    private final Socks5RelayHandler relayHandler = new Socks5RelayHandler();

    public void handle(Socket socket,boolean allowAnon) {
        es.execute(() -> {
            try {
                connect(socket,allowAnon);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * The client connects to the server, and sends a version
     * identifier/method selection message:
     *
     *  +----+----------+----------+
     *  |VER | NMETHODS | METHODS  |
     *  +----+----------+----------+
     *  | 1  |    1     | 1 to 255 |
     *  +----+----------+----------+
     *
     *   The VER field is set to X'05' for this version of the protocol.  The
     *   NMETHODS field contains the number of method identifier octets that
     *   appear in the METHODS field.
     *
     *   The server selects from one of the methods given in METHODS, and
     *   sends a METHOD selection message:
     *
     *   +----+--------+
     *   |VER | METHOD |
     *   +----+--------+
     *   | 1  |   1    |
     *   +----+--------+
     *
     *   If the selected METHOD is X'FF', none of the methods listed by the
     *    client are acceptable, and the client MUST close the connection.
     *
     *   The values currently defined for METHOD are:
     *      o  X'00' NO AUTHENTICATION REQUIRED
     *      o  X'01' GSSAPI
     *      o  X'02' USERNAME/PASSWORD
     *      o  X'03' to X'7F' IANA ASSIGNED
     *      o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
     *      o  X'FF' NO ACCEPTABLE METHODS
     *
     */
    private void connect(Socket client, boolean allowAnon) throws IOException {
        InputStream is = client.getInputStream();
        OutputStream os = client.getOutputStream();

        /*
         *  +----+----------+----------+
         *  |VER | NMETHODS | METHODS  |
         *  +----+----------+----------+
         *  | 1  |    1     | 1 to 255 |
         *  +----+----------+----------+
         */
        byte[] buffer = new byte[257];
        int len = is.read(buffer);
        if (len <= 0) {
            os.close();
            return;
        }

        //VER
        int version = buffer[0];
        if (version != 0x05) {
            os.write(new byte[]{5,-1});
            return;
        }

        //NO AUTHENTICATION REQUIRED
        if (allowAnon) {
            os.write(new byte[]{5,0});
            waitingRequest(client);
            return;
        }

        if (len <= 1) {
            os.write(new byte[]{5,-1}); //-1 = 0xFF
            return;
        }

        //NMETHODS
        int methods = buffer[1];
        for (int i=0;i<methods;i++) {
            //username password authentication
            if (buffer[i+2] == 0x02) {
                os.write(new byte[]{5,2});
                if (doAuthentication(client)) {
                    waitingRequest(client);
                }

                return;
            }
        }

        os.write(new byte[]{5,-1});
    }

    /**
     *  Once the method-dependent subnegotiation has completed, the client
     *  sends the request details.  If the negotiated method includes
     *  encapsulation for purposes of integrity checking and/or
     *  confidentiality, these requests MUST be encapsulated in the method-
     *  dependent encapsulation.
     *
     *  The SOCKS request is formed as follows:
     *
     *   +----+-----+-------+------+----------+----------+
     *   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
     *   +----+-----+-------+------+----------+----------+
     *   | 1  |  1  | X'00' |  1   | Variable |    2     |
     *   +----+-----+-------+------+----------+----------+
     *
     *   Where:
     *
     *     o  VER    protocol version: X'05'
     *     o  CMD
     *         o  CONNECT X'01'
     *         o  BIND X'02'
     *         o  UDP ASSOCIATE X'03'
     *     o  RSV    RESERVED
     *     o  ATYP   address type of following address
     *         o  IP V4 address: X'01'
     *         o  DOMAINNAME: X'03'
     *         o  IP V6 address: X'04'
     *     o  DST.ADDR       desired destination address
     *     o  DST.PORT desired destination port in network octet order
     *
     *    The SOCKS server will typically evaluate the request based on source
     *    and destination addresses, and return one or more reply messages, as
     *    appropriate for the request type.
     */
    private void waitingRequest(Socket socket) throws IOException{
        InputStream is = socket.getInputStream();
        OutputStream os = socket.getOutputStream();

        /*
         *   +----+-----+-------+------+----------+----------+
         *   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
         *   +----+-----+-------+------+----------+----------+
         *   | 1  |  1  | X'00' |  1   | Variable |    2     |
         *   +----+-----+-------+------+----------+----------+
         */
        byte[] buffer = new byte[256];
        int len = is.read(buffer);
        if (len <= 0) {
            socket.close();
            return;
        }

        int ver = buffer[0];
        if (ver != 0x05) {
            os.write(new byte[]{5,1,0,1,0,0,0,0,0});
            return;
        }

        int cmd = buffer[1];
        //ONLY ACCEPT CONNECT
        if (cmd != 0x01) {
            os.write(new byte[]{5,1,0,1,0,0,0,0,0});
            return;
        }

        RemoteAddr addr = getRemoteAddrInfo(buffer,len);
        socket.getOutputStream().write(new byte[]{5,0,0,1,0,0,0,0,0,0});

        relayHandler.doRelay(socket, addr.addr,addr.port);
    }

    /**
     * Once the SOCKS V5 server has started, and the client has selected the
     * Username/Password Authentication protocol, the Username/Password
     * subnegotiation begins.  This begins with the client producing a
     * Username/Password request:
     *  +----+------+----------+------+----------+
     *  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     *  +----+------+----------+------+----------+
     *  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     *  +----+------+----------+------+----------+
     *
     *  The server verifies the supplied UNAME and PASSWD, and sends the
     *  following response:
     *
     *  +----+--------+
     *  |VER | STATUS |
     *  +----+--------+
     *  | 1  |   1    |
     *  +----+--------+
     *
     *  A STATUS field of X'00' indicates success. If the server returns a
     *  `failure' (STATUS value other than X'00') status, it MUST close the
     *  connection.
     *
     *  https://datatracker.ietf.org/doc/html/rfc1929
     */
    private static boolean doAuthentication(Socket client) throws IOException{
        InputStream is = client.getInputStream();
        OutputStream os = client.getOutputStream();
        byte[] buffer = new byte[512];
        int len = is.read(buffer);
        if (len <= 0) {
            //TODO throw exception
            client.close();
            return false;
        }

        int ver = buffer[0];
        if (ver != 0x01) {
            os.write(new byte[]{5,1});
            return false;
        }

        if (len <= 1) {
            os.write(new byte[]{5,1});
            return false;
        }

        UserInfo info = UserInfo.parse(buffer);
        if (info.match("bigbyto","123456")) {
            //SUCCESSFUL
            os.write(new byte[]{1,0});
            return true;
        }

        //AUTHENTICATION FAILURE
        os.write(new byte[]{1,1});
        return false;
    }

    private RemoteAddr getRemoteAddrInfo(byte[] bytes,int len) {
        byte[] data = new byte[len -6];
        System.arraycopy(bytes,4,data,0,data.length);
        String addr = new String(data);

        RemoteAddr info = new RemoteAddr();
        info.addr = addr.trim();

        ByteBuffer buffer = ByteBuffer.wrap(new byte[]{bytes[len-2],bytes[len-1]});
        info.port = buffer.asCharBuffer().get();

        return info;
    }

    private static class UserInfo {
        String username;
        String password;

        public static UserInfo parse(byte[] data) {
            int uLen = data[1];
            byte[] uBytes = new byte[uLen];
            System.arraycopy(data,2,uBytes,0,uBytes.length);;

            UserInfo info = new UserInfo();
            info.username = new String(uBytes);

            int pLen = data[uLen + 2];
            byte[] pBytes = new byte[pLen];
            System.arraycopy(data,uLen + 3,pBytes,0,pBytes.length);
            info.password = new String(pBytes);

            return info;
        }

        public boolean match(String username,String password) {
            return username.equals(this.username) && password.equals(this.password);
        }
    }

    private static class RemoteAddr {
        public String addr;
        public int port;

        @Override
        public String toString() {
            return "RemoteAddr{" +
                    "addr='" + addr + '\'' +
                    ", port=" + port +
                    '}';
        }
    }
}
