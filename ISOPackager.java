/* Decompiler 126ms, total 745ms, lines 190 */
package com.tcs.sbi;

import java.io.InputStream;
import java.util.Arrays;
import org.jpos.iso.ISOException;
import org.jpos.iso.ISOMsg;
import org.jpos.iso.packager.GenericPackager;

public class ISOPackager {
   public static String messageHeader = null;
   private static final GenericPackager packager = initPackager();

   public static byte[] IsoFormation(String isoReqResFlag, byte[] isomsg) {
      String BitMap = null;
      String D55 = Character.toString((char)isomsg[13]);

      byte[] iso;
      try {
         if (!"2367ABEFabef".contains(D55)) {
            return isomsg;
         }

         String SecondaryBitflag = Character.toString((char)isomsg[0]);
         String isoReq = new String(isomsg);
         String isoBeforeD55;
         byte[] d55;
         String LLLD55;
         byte[] isoAfterD55;
         if ("89ABCDEFabcdef".contains(SecondaryBitflag)) {
            BitMap = isoReq.substring(0, 32);
            isoBeforeD55 = "0200" + BitMap.substring(0, 13) + D55Isolator(D55) + "000000000000000000" + isoReq.substring(32);
            isoBeforeD55 = buildISO(isoBeforeD55);
            isoBeforeD55 = BitMap + isoBeforeD55.substring(16);
            if (isoReqResFlag.equalsIgnoreCase("req")) {
               d55 = isoD55tag(isoBeforeD55, isomsg, isoReqResFlag);
               LLLD55 = D55LLL(d55.length);
               isoBeforeD55 = isoBeforeD55 + LLLD55;
               isoAfterD55 = isoAfterD55(isoBeforeD55.length(), d55.length * 2, isomsg);
               iso = byteAppend(isoBeforeD55.getBytes(), d55);
               iso = byteAppend(iso, isoAfterD55);
            } else {
               d55 = isoD55tag(isoBeforeD55, isomsg, isoReqResFlag);
               LLLD55 = D55LLL(d55.length);
               isoBeforeD55 = isoBeforeD55 + LLLD55;
               isoAfterD55 = isoAfterD55(isoBeforeD55.length(), d55.length / 2, isomsg);
               iso = byteAppend(isoBeforeD55.getBytes(), d55);
               iso = byteAppend(iso, isoAfterD55);
            }
         } else {
            BitMap = isoReq.substring(0, 16);
            isoBeforeD55 = "0200" + BitMap.substring(0, 13) + D55Isolator(D55) + "00" + isoReq.substring(16);
            isoBeforeD55 = buildISO(isoBeforeD55);
            isoBeforeD55 = BitMap + isoBeforeD55.substring(16);
            if (isoReqResFlag.equalsIgnoreCase("req")) {
               d55 = isoD55tag(isoBeforeD55, isomsg, isoReqResFlag);
               LLLD55 = D55LLL(d55.length);
               isoBeforeD55 = isoBeforeD55 + LLLD55;
               isoAfterD55 = isoAfterD55(isoBeforeD55.length(), d55.length * 2, isomsg);
               iso = byteAppend(isoBeforeD55.getBytes(), d55);
               iso = byteAppend(iso, isoAfterD55);
            } else {
               d55 = isoD55tag(isoBeforeD55, isomsg, isoReqResFlag);
               LLLD55 = D55LLL(d55.length);
               isoBeforeD55 = isoBeforeD55 + LLLD55;
               isoAfterD55 = isoAfterD55(isoBeforeD55.length(), d55.length / 2, isomsg);
               iso = byteAppend(isoBeforeD55.getBytes(), d55);
               iso = byteAppend(iso, isoAfterD55);
            }
         }
      } catch (ISOException var11) {
         iso = ("ERROR FROM IsoFormation METHOD " + var11.toString()).getBytes();
      }

      return iso;
   }

   public static ISOMsg buildISOObject(String isoMessage) throws ISOException {
      ISOMsg isoObject = new ISOMsg();
      isoObject.setPackager(packager);
      byte[] bIsoMessage = new byte[isoMessage.length()];

      for(int i = 0; i < bIsoMessage.length; ++i) {
         bIsoMessage[i] = (byte)isoMessage.charAt(i);
      }

      isoObject.unpack(bIsoMessage);
      return isoObject;
   }

   private static GenericPackager initPackager() {
      GenericPackager packager = null;

      try {
         InputStream in = ISOPackager.class.getResourceAsStream("basic.xml");
         packager = new GenericPackager(in);
      } catch (ISOException var2) {
         var2.printStackTrace();
      }

      return packager;
   }

   public static String buildISO(String iso) throws ISOException {
      new ISOMsg();
      ISOMsg isoMsg = buildISOObject(iso);
      ISOMsg msg = new ISOMsg();

      for(int i = 1; i <= isoMsg.getMaxField(); ++i) {
         if (isoMsg.hasField(i)) {
            msg.set(i, isoMsg.getString(i));
         }
      }

      msg.setPackager(packager);
      String isoString = new String(msg.pack());
      return isoString;
   }

   public static byte[] isoD55tag(String iso1, byte[] iso, String isoReqResFlag) {
      int iso1length = iso1.length();
      byte[] c = Arrays.copyOfRange(iso, iso1length, iso1length + 3);
      int d55length = Integer.parseInt(new String(c));
      byte[] tagD55 = Arrays.copyOfRange(iso, iso1length + 3, iso1length + d55length + 3);
      if (isoReqResFlag.equalsIgnoreCase("req")) {
         tagD55 = hex2Byte(new String(tagD55));
      } else {
         tagD55 = decimaltohex(tagD55);
      }

      return tagD55;
   }

   public static String D55Isolator(String bit) {
      String binaString = Integer.toBinaryString(Integer.parseInt(bit, 16));
      binaString = "0000".substring(0, 4 - binaString.length()) + binaString;
      binaString = binaString.substring(0, 2) + "0" + binaString.substring(3);
      binaString = Integer.toHexString(Integer.parseInt(binaString, 2));
      return binaString;
   }

   public static byte[] isoAfterD55(int isoBeforeD55, int d55tag, byte[] iso) {
      byte[] iso2 = Arrays.copyOfRange(iso, isoBeforeD55 + d55tag, iso.length);
      return iso2;
   }

   public static byte[] byteAppend(byte[] Source1, byte[] Source2) {
      byte[] byResult = new byte[Source1.length + Source2.length];
      int size = 0;

      int inDest;
      for(inDest = 0; inDest < Source1.length; ++inDest) {
         byResult[size++] = Source1[inDest];
      }

      for(inDest = 0; inDest < Source2.length; ++inDest) {
         byResult[size++] = Source2[inDest];
      }

      return byResult;
   }

   public static byte[] hex2Byte(String str) {
      byte[] bytes = new byte[str.length() / 2];

      for(int i = 0; i < bytes.length; ++i) {
         bytes[i] = (byte)Integer.parseInt(str.substring(2 * i, 2 * i + 2), 16);
      }

      return bytes;
   }

   public static String D55LLL(int d55length) {
      String d55len = Integer.toString(d55length);
      return "000".substring(0, 3 - d55len.length()) + d55len;
   }

   public static byte[] decimaltohex(byte[] tagD55) {
      StringBuffer str = new StringBuffer();
      byte[] D55 = new byte[tagD55.length * 2];

      for(int i = 0; i < tagD55.length; ++i) {
         String hex = Integer.toHexString(tagD55[i] & 255);
         str.append("00".substring(0, 2 - hex.length()) + hex);
      }

      D55 = (new String(str)).getBytes();
      return D55;
   }
}
