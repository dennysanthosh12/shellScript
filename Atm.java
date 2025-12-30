import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;

public class IsoTcpDebugClient {

    static final String HOST = "10.0.54.36";
    static final int PORT = 8524;

    public static void main(String[] args) {
        try {
            System.out.println("Connecting to " + HOST + ":" + PORT);

            Socket socket = new Socket(HOST, PORT);
            socket.setSoTimeout(10000);

            System.out.println("TCP CONNECTED ✅");

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Your ISO logon message (WITHOUT length)
            String isoLogon =
                    "ISO0060000400800822000000000000004000000000000001230194741194741301";

            byte[] isoBytes = isoLogon.getBytes();

            // 2-byte binary length header
            byte[] lengthHeader = ByteBuffer.allocate(2)
                    .putShort((short) isoBytes.length)
                    .array();

            // Final message
            byte[] finalMsg = new byte[lengthHeader.length + isoBytes.length];
            System.arraycopy(lengthHeader, 0, finalMsg, 0, 2);
            System.arraycopy(isoBytes, 0, finalMsg, 2, isoBytes.length);

            System.out.println("Sending ISO LOGON @ " + LocalDateTime.now());
            System.out.println("TX HEX: " + toHex(finalMsg));

            out.write(finalMsg);
            out.flush();

            // ---- READ RESPONSE ----
            byte[] respLenBytes = new byte[2];
            int read = in.read(respLenBytes);

            if (read != 2) {
                System.out.println("❌ No length header received");
                socket.close();
                return;
            }

            int respLen = ByteBuffer.wrap(respLenBytes).getShort();
            byte[] resp = new byte[respLen];

            int total = 0;
            while (total < respLen) {
                int r = in.read(resp, total, respLen - total);
                if (r == -1) break;
                total += r;
            }

            System.out.println("RX LENGTH: " + respLen);
            System.out.println("RX HEX: " + toHex(resp));
            System.out.println("RX ASCII: " + new String(resp));

            socket.close();
            System.out.println("Socket closed");

        } catch (Exception e) {
            System.err.println("❌ ERROR:");
            e.printStackTrace();
        }
    }

    static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
