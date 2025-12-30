import javax.net.ssl.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.time.LocalDateTime;

public class IsoTcpDebugClient {

    // ===== ATM ENDPOINT =====
    private static final String HOST = "10.0.54.36";
    private static final int PORT = 8524;

    // ===== SSL CONFIG =====
    private static final String KEYSTORE_PATH = "/path/to/client_keystore.jks";
    private static final String TRUSTSTORE_PATH = "/path/to/truststore.jks";
    private static final String STORE_PASSWORD = "changeit";

    public static void main(String[] args) {
        try {
            System.out.println("===== ISO SSL DEBUG CLIENT =====");

            // -------- LOAD CLIENT KEYSTORE (CLIENT CERT) --------
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE_PATH),
                    STORE_PASSWORD.toCharArray());

            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, STORE_PASSWORD.toCharArray());

            // -------- LOAD TRUSTSTORE (ATM SERVER CERT / CA) --------
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH),
                    STORE_PASSWORD.toCharArray());

            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // -------- SSL CONTEXT --------
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(
                    kmf.getKeyManagers(),
                    tmf.getTrustManagers(),
                    null
            );

            SSLSocketFactory socketFactory = sslContext.getSocketFactory();

            // -------- CREATE SSL SOCKET --------
            System.out.println("Connecting to " + HOST + ":" + PORT);
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(HOST, PORT);
            socket.setSoTimeout(15000);

            // IMPORTANT: Force handshake
            socket.startHandshake();
            System.out.println("✅ SSL HANDSHAKE SUCCESS");

            // -------- STREAMS --------
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // -------- ISO LOGON MESSAGE --------
            String isoLogon =
                    "ISO0060000400800822000000000000004000000000000001230194741194741301";

            byte[] isoBytes = isoLogon.getBytes("ASCII");

            // 2-byte big-endian length header
            byte[] lengthHeader = ByteBuffer.allocate(2)
                    .putShort((short) isoBytes.length)
                    .array();

            byte[] finalMsg = new byte[lengthHeader.length + isoBytes.length];
            System.arraycopy(lengthHeader, 0, finalMsg, 0, 2);
            System.arraycopy(isoBytes, 0, finalMsg, 2, isoBytes.length);

            System.out.println("Sending ISO LOGON @ " + LocalDateTime.now());
            System.out.println("TX HEX: " + toHex(finalMsg));

            out.write(finalMsg);
            out.flush();

            // -------- READ RESPONSE LENGTH --------
            byte[] respLenBytes = new byte[2];
            int read = in.read(respLenBytes);

            if (read != 2) {
                System.err.println("❌ Failed to read response length");
                socket.close();
                return;
            }

            int respLen = ByteBuffer.wrap(respLenBytes).getShort() & 0xFFFF;
            byte[] resp = new byte[respLen];

            int totalRead = 0;
            while (totalRead < respLen) {
                int r = in.read(resp, totalRead, respLen - totalRead);
                if (r == -1) break;
                totalRead += r;
            }

            System.out.println("RX LENGTH: " + respLen);
            System.out.println("RX HEX: " + toHex(resp));
            System.out.println("RX ASCII: " + new String(resp, "ASCII"));

            socket.close();
            System.out.println("Connection closed");

        } catch (Exception e) {
            System.err.println("❌ ERROR OCCURRED");
            e.printStackTrace();
        }
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}



/opt/IBM/ace/common/jdk/bin/java \
-Djavax.net.debug=ssl,handshake \
-cp . IsoTcpDebugClient

