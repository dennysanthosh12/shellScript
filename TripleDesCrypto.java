/* Decompiler 28ms, total 566ms, lines 58 */
package com.tcs.sbi;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class TripleDesCrypto {
   public static String encrypt(String toencrypt, String key) {
      try {
         if (toencrypt.substring(12, 16).equalsIgnoreCase("0800")) {
            return "000000" + toencrypt;
         } else {
            String reqheader = toencrypt.substring(0, 20);
            String IsoToencrypt = toencrypt.substring(20);
            StringBuilder sbenc = (new StringBuilder()).append(reqheader).append(IsoToencrypt);
            return sbenc.toString();
         }
      } catch (Exception var5) {
         return "ERROR " + var5.toString();
      }
   }

   public static String decrypt(String encrypted, String key) {
      try {
         String reqheader = encrypted.substring(0, 22);
         String isoTodecrypt = encrypted.substring(22);
         byte[] keybyte = DatatypeConverter.parseHexBinary(key);
         SecretKey keya = new SecretKeySpec(keybyte, "DESede");
         Cipher decipher = Cipher.getInstance("DESede/ECB/NoPadding");
         decipher.init(2, keya);
         byte[] decdata = DatatypeConverter.parseHexBinary(isoTodecrypt);
         byte[] plaintext = decipher.doFinal(decdata);
         plaintext = ISOPackager.IsoFormation("resp", plaintext);
         String decString = new String(plaintext);
         if (decString.substring(0, 5).equalsIgnoreCase("ERROR")) {
            return decString;
         } else {
            StringBuilder sbdec = (new StringBuilder(reqheader.substring(6))).append(decString);
            return sbdec.toString();
         }
      } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException var11) {
         return "ERROR " + var11.toString();
      } catch (Exception var12) {
         return "ERROR " + var12.toString();
      }
   }

   public static void main(String[] args) {
      System.out.println(decrypt("DC15 ISO0160000500200BB3DEBAB9ED75D1DC5561064482DB6F7760A759F62FE2867A943802A478A7A13C88C3AACBAC01706578A3C1704B895C558D78DAD01ACED7593FFC10EBE81021B27C824A03B6B8A769C60F415AE2B2BF81AE4FB1C8FD8AEF4F981D9CAA674147E29F892E6476DD39191FA904256528B25578A3C1704B895C54F8CB76AE653D16602E0876131A7C1554BC40ACA714FE268BBFBB8BF056C3A43BA07DA1523D7BDFF33458D9A65DE767D311F8DB19B743B4137747E009895D3D679887B90604E40C71A585F5FB5C2973CF081B414C91462C1A39B34848AFF4E76397914249625159AB53171C6677D669BB34DD26B26FE62C0024C8D3915168046", "C15DD34979F7D0FB7FFB379EF8971FBFC15DD34979F7D0FB"));
   }
}
