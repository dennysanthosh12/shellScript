/* Decompiler 556ms, total 1631ms, lines 578 */
package com.tcs.sbi;

import com.ibm.mq.MQException;
import com.ibm.mq.MQMessage;
import com.ibm.mq.MQPutMessageOptions;
import com.ibm.mq.MQQueue;
import com.ibm.mq.MQQueueManager;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.jpos.iso.ISOException;
import org.jpos.iso.ISOMsg;
import org.json.JSONException;
import org.json.JSONObject;

public class ATMSocketFactory {
   public static String tripleDesKey = null;
   public static String app = null;
   public static String properyFilePath = null;
   public static boolean readerOn = true;
   static int openOptions;
   static MQQueueManager QMgr = null;
   static MQQueue queuelogger = null;
   static String responseQueue = null;
   static String loggerQueue = null;
   static String qmgrName = null;
   static String encFlag = "Y";
   private static final Lock writeLock = new ReentrantLock(true);
   public static Socket socket = null;
   public static String IP = null;
   public static int PORT;
   public static int GCCTIMEOUT;
   public static int BUFFER;
   public static int WRITETIMEOUT;
   public static int msgExpiryTime;
   static InputStream inputStream = null;
   static OutputStream outputsteam = null;
   static JSONObject json = null;
   static JSONObject writelogger = null;

   public static String getATMSocket(String logon) {
      String logonReq = null;
      String response = null;
      String propertyLoader = getProperty(properyFilePath);

      try {
         if (propertyLoader.substring(0, 5).equalsIgnoreCase("ERROR")) {
            response = propertyLoader;
         } else {
            logonReq = "000000" + logon;
            System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
            char[] passphrase = "password".toCharArray();
            SSLContext ctx = SSLContext.getInstance("TLSv1.2");
            SSLContext.setDefault(ctx);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("IbmX509");
            KeyStore ks = KeyStore.getInstance("JKS");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("IbmX509");
            KeyStore tm = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("/opt/IBM/Keystore/keyStore.jks"), passphrase);
            tm.load(new FileInputStream("/opt/IBM/Keystore/N2ks.jks"), passphrase);
            kmf.init(ks, passphrase);
            tmf.init(tm);
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), (SecureRandom)null);
            SSLSocketFactory factory = ctx.getSocketFactory();
            socket = (SSLSocket)factory.createSocket(IP, PORT);
            String[] cipherSuites = new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"};
            ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
            socket.setKeepAlive(true);
            socket.setKeepAlive(true);
            socket.setSoTimeout(GCCTIMEOUT);
            socket.setReceiveBufferSize(BUFFER * 1024);
            outputsteam = socket.getOutputStream();
            inputStream = socket.getInputStream();
            outputsteam.write(getHeaderBytes(logonReq.getBytes()));
            byte[] lengthBytes = new byte[2];
            inputStream.read(lengthBytes, 0, 2);
            int length = (new BigInteger(lengthBytes)).intValue();
            byte[] cbuf = new byte[length];
            inputStream.read(cbuf, 0, length);
            response = (new String(cbuf)).trim();
            if (length != 0 && length >= 69) {
               if (length >= 75) {
                  if (response.substring(18, 22).equalsIgnoreCase("0810") && response.substring(72, 75).equalsIgnoreCase("001")) {
                     response = "ENC" + response;
                  } else {
                     response = "ERROR:Response string is not logon string " + response;
                  }
               } else if (response.substring(12, 16).equalsIgnoreCase("0810") && response.substring(66, 69).equalsIgnoreCase("001")) {
                  response = "DEC" + response;
               } else {
                  response = "ERROR:Response string is not logon string " + response;
               }
            } else {
               response = "ERROR:logon response null " + response;
            }
         }
      } catch (UnknownHostException var15) {
         response = "ERROR:" + var15.toString();
      } catch (IOException var16) {
         response = "ERROR:" + var16.toString();
      } catch (Exception var17) {
         response = "ERROR:" + var17.toString();
      }

      return response;
   }

   public static String writesocket(String request, String encFlag1) {
      System.out.println(request);
      writelogger = new JSONObject();

      JSONException reqheader;
      try {
         System.out.println("Inside write socket try");
         writelogger.put("ATM_SOCKET", socket);
         writelogger.put("PLAIN_REQUEST", request);
         if (!writeLock.tryLock((long)WRITETIMEOUT, TimeUnit.NANOSECONDS)) {
            writelogger.put("LOCKER ", "Failed to acquire lock to write request on socket");
            writelogger.put("REQUEST_TIMESTAMP ", getTimeStamp());
            writelogger.put("REQUEST ", request);
         } else {
            String var9;
            try {
               writelogger.put("LOCK IS", "Applied");
               writelogger.put("DESTINATION_ADDRESS", IP + " " + PORT);
               String reqheader;
               if (encFlag.equalsIgnoreCase("Y")) {
                  System.out.println("Inside write socket try encflag if");
                  reqheader = requestbyte(request);
                  System.out.println("inside ENCFLAG Y:" + reqheader);
                  if (reqheader.substring(0, 5).equalsIgnoreCase("ERROR")) {
                     writelogger.put("Exception", reqheader.substring(5));
                     System.out.println("Inside write socket try encflag if error");
                  }
               } else {
                  System.out.println("Inside write socket try encflag else:" + request.substring(12, 16));
                  reqheader = null;
                  String IsoToencrypt = null;
                  if (request.substring(12, 16).equalsIgnoreCase("0800")) {
                     System.out.println("REQ MTI:" + request.substring(12, 16));
                     request = "000000" + request;
                     reqheader = request.substring(0, 22);
                     IsoToencrypt = request.substring(22);
                     System.out.println("inside 800");
                  } else {
                     reqheader = request.substring(0, 16);
                     IsoToencrypt = request.substring(20);
                     System.out.println("else:" + request);
                  }

                  byte[] byteIso = ISOPackager.IsoFormation("req", IsoToencrypt.getBytes());
                  String msg = new String(byteIso);
                  System.out.println("msg" + msg);
                  if (msg.substring(0, 5).equalsIgnoreCase("ERROR")) {
                     var9 = msg;
                     return var9;
                  }

                  byte[] headerByte = reqheader.getBytes();
                  byteIso = ISOPackager.byteAppend(headerByte, byteIso);
                  byte[] requestwithHeader = getHeaderBytes(byteIso);
                  writelogger.put("REQUEST_TO_ATM", Base64.getEncoder().encodeToString(requestwithHeader));
                  socket.getOutputStream().write(requestwithHeader);
                  socket.getOutputStream().flush();
                  writelogger.put("REQUEST_TIMESTAMP", getTimeStamp());
               }

               System.out.println("readerOn:" + readerOn);
               if (readerOn) {
                  System.out.println("inside if readerOn");
                  writelogger.put("ASYNCHRONOUS_CALL_TO", "SOCKET_READER");
                  (new Thread(new Runnable() {
                     public void run() {
                        ATMSocketFactory.readsocket();
                     }
                  })).start();
               } else {
                  (new Thread(new Runnable() {
                     public void run() {
                        ATMSocketFactory.readsocket();
                     }
                  })).start();
               }

               return writelogger.toString();
            } catch (Exception var15) {
               writelogger.put("INSIDE_LOCKER_TRY_CATCH", "WRITE_SOCKET");
               writelogger.put("Exception", var15.toString());
               var9 = writelogger.toString();
            } finally {
               writeLock.unlock();
               writelogger.put("LOCKER", "Unlocked");
            }

            return var9;
         }
      } catch (InterruptedException | JSONException var17) {
         reqheader = var17;

         try {
            writelogger.put("INSIDE_TRY_CATCH", "WRITE_SOCKET");
            writelogger.put("Exception ", reqheader.toString());
         } catch (JSONException var14) {
            var14.printStackTrace();
         }
      }

      return writelogger.toString();
   }

   public static String requestbyte(String req) {
      String encReq = TripleDesCrypto.encrypt(req, tripleDesKey);

      try {
         if (encReq.substring(0, 5).equalsIgnoreCase("ERROR")) {
            writelogger.put("Exception while Encryption", encReq);
         } else {
            byte[] requestwithHeader = getHeaderBytes(encReq.getBytes());
            writelogger.put("ENCRYPTED_REQUEST_TO_ATM", encReq);
            socket.getOutputStream().write(requestwithHeader);
            socket.getOutputStream().flush();
            writelogger.put("REQUEST_TIMESTAMP", getTimeStamp());
         }

         return "success";
      } catch (JSONException | IOException var3) {
         return "ERROR " + var3.toString();
      }
   }

   public static char getHexHeader(String request) {
      int len = request.length();
      char asciitoChar = (char)len;
      return asciitoChar;
   }

   public static void readsocket() {
      String decResp = null;
      String isoresponse = null;
      readerOn = false;
      System.out.println("Inside read socket");
      String correllId = null;
      MQQueue queue = null;
      String lastReadMsg = getTimeStamp();

      while(true) {
         json = new JSONObject();

         try {
            System.out.println("Inside Try!");
            json.put("ATM_SOCKET", socket);
            json.put("DESTINATION_ADDRESS", IP + " " + PORT);
            byte[] lengthBytes = new byte[2];
            inputStream.read(lengthBytes, 0, 2);
            int length = (new BigInteger(lengthBytes)).intValue();
            json.put("MESSAGE_LENGTH_FROM_ATM", length);
            byte[] cbuf = new byte[length];
            int count = false;
            int count = inputStream.read(cbuf);
            System.out.println("Response of input stream: " + count);
            if (count < length) {
               boolean end = false;
               int byteToRead = length - count;

               while(!end) {
                  int byteRead = inputStream.read(cbuf, count, byteToRead);
                  count += byteRead;
                  if (count == length) {
                     end = true;
                  } else {
                     byteToRead = length - count;
                  }
               }
            }

            json.put("LENGTH_READ", count);
            isoresponse = (new String(cbuf)).trim();
            System.out.println("isoresponse" + isoresponse);
            correllId = "000000000000" + isoresponse.substring(22, 34);
            System.out.println("ResponseCorrellID: " + correllId);
            System.out.println("responseQueue" + responseQueue);
            if (encFlag.equalsIgnoreCase("N")) {
               json.put("RESPONSE_FROM_ATM", Base64.getEncoder().encodeToString(cbuf));
               json.put("RESPONSE_TIMESTAMP", getTimeStamp());
               String reqheader = isoresponse.substring(0, 16);
               byte[] isoResp = Arrays.copyOfRange(cbuf, 16, cbuf.length);
               isoResp = ISOPackager.IsoFormation("resp", isoResp);
               String msg = new String(isoResp);
               if (msg.substring(0, 5).equalsIgnoreCase("ERROR")) {
                  decResp = msg;
               } else {
                  decResp = reqheader + msg;
               }
            } else if (isoresponse.substring(0, 6).equalsIgnoreCase(ISOPackager.messageHeader)) {
               json.put("RESPONSE_FROM_ATM", isoresponse);
               json.put("RESPONSE_TIMESTAMP", getTimeStamp());
               decResp = TripleDesCrypto.decrypt(isoresponse, tripleDesKey);
            } else {
               json.put("RESPONSE_FROM_ATM", isoresponse);
               json.put("RESPONSE_TIMESTAMP", getTimeStamp());
               decResp = isoresponse.substring(6);
            }

            MQMessage theMessage;
            if (decResp.substring(0, 5).equalsIgnoreCase("ERROR")) {
               json.put("Exception while Decryption", decResp);
            } else {
               json.put("DECRYPTED_RESPONSE", isoresponse);
               if (QMgr == null) {
                  System.out.println("UNDER QMGR == NULL");
                  Mqwriter(decResp);
               } else {
                  String MTI = isoresponse.substring(46, 50);
                  System.out.println("MTI: " + MTI);
                  json.put("RESPONSE_STAN", correllId);
                  System.out.println("before if");
                  if (MTI.equalsIgnoreCase("0210")) {
                     System.out.println("if equal to true");
                     queue = QMgr.accessQueue(responseQueue, openOptions);
                     theMessage = new MQMessage();
                     theMessage.writeString(isoresponse);
                     theMessage.correlationId = correllId.getBytes();
                     queue.put(theMessage);
                     lastReadMsg = getTimeStamp();
                     queue.close();
                  } else {
                     System.out.println("else");
                  }
               }
            }

            queuelogger = QMgr.accessQueue(loggerQueue, openOptions);
            theMessage = new MQMessage();
            theMessage.writeString(json.toString());
            queuelogger.put(theMessage);
            queuelogger.close();
            continue;
         } catch (SocketException var15) {
            isoresponse = var15.toString();

            try {
               readerOn = true;
               socket.close();
            } catch (Exception var14) {
               isoresponse = isoresponse + " " + var14.toString();
            }

            System.out.println("catch soc" + isoresponse);
            ErrorWriter(isoresponse);
         } catch (SocketTimeoutException var16) {
            isoresponse = var16.toString();
            if (respTimeDiff(lastReadMsg) < 35L) {
               ErrorWriter(isoresponse);
               System.out.println("catch stout" + isoresponse);
               continue;
            }

            try {
               socket.close();
            } catch (Exception var13) {
               isoresponse = isoresponse + " " + var13.toString();
            }

            readerOn = true;
         } catch (Exception var17) {
            isoresponse = var17.toString();
            if (respTimeDiff(lastReadMsg) < 35L) {
               ErrorWriter(isoresponse);
               System.out.println("catch e" + isoresponse);
               continue;
            }

            try {
               socket.close();
            } catch (Exception var12) {
               isoresponse = isoresponse + " " + var12.toString();
            }

            readerOn = true;
         }

         return;
      }
   }

   public static void Mqwriter(String msg) {
      String correllId = null;
      MQQueue queue = null;

      String error;
      try {
         QMgr = new MQQueueManager(qmgrName);
         openOptions = 8208;
         queue = QMgr.accessQueue(responseQueue, openOptions);
         MQMessage theMessage = new MQMessage();
         MQPutMessageOptions pmo = new MQPutMessageOptions();
         ISOMsg responseObject = ISOPackager.buildISOObject(msg.substring(12));
         String BranchNum = responseObject.getString(41);
         String ResponseSTAN = responseObject.getString(11);
         String MTI = responseObject.getMTI();
         System.out.println("0MTI: " + MTI);
         if (MTI.equalsIgnoreCase("0810")) {
            ResponseSTAN = responseObject.getString(11);
            correllId = "000000000000000000000000".substring(0, 24 - ResponseSTAN.length()) + ResponseSTAN;
         } else {
            BranchNum = responseObject.getString(41);
            ResponseSTAN = responseObject.getString(11);
            String stanNumber = BranchNum.concat(ResponseSTAN);
            correllId = "000000000000000000000000".substring(0, 24 - stanNumber.length()) + stanNumber;
         }

         json.put("RESPONSE_STAN", correllId);
         System.out.println("CORRELATION_ID" + correllId);
         theMessage.writeString(msg);
         theMessage.correlationId = correllId.getBytes();
         theMessage.expiry = msgExpiryTime;
         queue.put(theMessage, pmo);
         queue.close();
      } catch (IOException | MQException | ISOException | JSONException var13) {
         error = var13.getMessage();
         System.out.println("Entered in catch failure qmgrmqwriter" + error);

         try {
            System.out.println("Entered in catch failure qmgrmqwritertry");
            json.put("INSIDE_CATCH_BLOCK_OF", "MQ_WRITER");
            json.put("Exception", error);
            queue.close();
         } catch (Exception var12) {
            System.out.println("Entered in catch failure qmgrmqwritercatch");
            var12.printStackTrace();
         }
      } catch (Exception var14) {
         System.out.println("Entered in catch failure qmgrmqwriter9");
         error = var14.getMessage();

         try {
            System.out.println("Entered in catch failure qmgrmqwriter10");
            json.put("INSIDE_CATCH_BLOCK_OF", "MQ_WRITER");
            json.put("Exception", error);
            queue.close();
         } catch (Exception var11) {
            System.out.println("Entered in catch failure qmgrmqwriter11");
            var11.printStackTrace();
         }
      }

   }

   public static byte[] getHeaderBytes(byte[] message) {
      int length = message.length;
      byte[] messageWithHeader = new byte[2 + length];
      String header = Integer.toHexString(length);
      String strHexHeader = String.format("%0" + (4 - header.length()) + "d%s", 0, header);
      messageWithHeader[0] = (byte)Integer.parseInt(strHexHeader.substring(0, 2), 16);
      messageWithHeader[1] = (byte)Integer.parseInt(strHexHeader.substring(2), 16);
      int i = 2;
      byte[] var9 = message;
      int var8 = message.length;

      for(int var7 = 0; var7 < var8; ++var7) {
         byte res = var9[var7];
         messageWithHeader[i++] = res;
      }

      return messageWithHeader;
   }

   public static String getTimeStamp() {
      SimpleDateFormat formattedDate = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss.SSSS");
      Date date1 = new Date();
      String timestamp = formattedDate.format(date1);
      return timestamp;
   }

   public static void ErrorWriter(String error) {
      try {
         QMgr = new MQQueueManager(qmgrName);
         openOptions = 8208;
         json.put("RESPONSE_TIMESTAMP", getTimeStamp());
         json.put("INSIDE_TRY_BLOCK", "ERROR_WRITER");
         json.put("Exception", error);
         queuelogger = QMgr.accessQueue(loggerQueue, openOptions);
         MQMessage theMessage = new MQMessage();
         theMessage.writeString(json.toString());
         queuelogger.put(theMessage);
         queuelogger.close();
      } catch (JSONException | MQException | IOException var5) {
         var5.printStackTrace();

         try {
            queuelogger.close();
         } catch (MQException var4) {
            var4.printStackTrace();
         }
      } catch (Exception var6) {
         var6.printStackTrace();

         try {
            queuelogger.close();
         } catch (MQException var3) {
            var3.printStackTrace();
         }
      }

   }

   public static long respTimeDiff(String lastmsg) {
      Date d1 = null;
      Date d2 = null;
      long diffSeconds = 0L;
      String currentTime = getTimeStamp();
      SimpleDateFormat format = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss.SSSS");

      try {
         d1 = format.parse(lastmsg);
         d2 = format.parse(currentTime);
         long diff = d2.getTime() - d1.getTime();
         diffSeconds = diff / 1000L;
      } catch (Exception var9) {
         ErrorWriter(var9.toString());
      }

      return diffSeconds;
   }

   public static String getProperty(String propertiesPath) {
      try {
         BufferedReader reader = new BufferedReader(new FileReader(propertiesPath));
         Properties p = new Properties();
         p.load(reader);
         qmgrName = p.getProperty("QMGR" + app);
         System.out.println("QMGR_NAME:" + qmgrName);
         responseQueue = p.getProperty("responseQueue" + app);
         System.out.println("RESPONSE_QUEUE_NAME: " + responseQueue);
         loggerQueue = p.getProperty("loggerQueue" + app);
         System.out.println("LOGGER_QUEUE_NAME: " + loggerQueue);
         IP = p.getProperty("IP" + app);
         PORT = Integer.parseInt(p.getProperty("port" + app));
         GCCTIMEOUT = Integer.parseInt(p.getProperty("SocketTimeOut" + app));
         WRITETIMEOUT = Integer.parseInt(p.getProperty("WriteTimeOut" + app));
         msgExpiryTime = Integer.parseInt(p.getProperty("MsgExpiryTime" + app));
         BUFFER = Integer.parseInt(p.getProperty("BufferSize" + app));
         tripleDesKey = p.getProperty("TripleDesKey" + app);
         encFlag = p.getProperty("EncryptionFlag" + app);
         String msgHeader = p.getProperty("MessageHeader" + app);
         ISOPackager.messageHeader = msgHeader + "      ".substring(msgHeader.length());
         return "success";
      } catch (IOException var4) {
         return "ERROR " + var4.toString();
      } catch (Exception var5) {
         return "ERROR " + var5.toString();
      }
   }
}
