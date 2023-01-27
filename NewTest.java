[12:58 PM] Muhammad Hammad
package com.systemsltd.common.util;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*; import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec; import com.ibm.broker.config.common.Base64; public class Test {     public static void main(String[] args) {
        String rawPassword = "dcprtl123";
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMMfIOEAZORp44fubLgnKabv0Dx2K/bG3reJ7F1UETaZNYUkEth68Zdlres33+Nn/++0B6qHBSjCRgXunKSzBTfb5dbx0GlkHw4sZW14UFG+Kib6EDsP/pn+FE0cXr3cXPie/sOVHwE+qstaoWWwt8jNThLTQyMVjRcDU7Zw0MUwIDAQAB";
        encryptTest_UBL(rawPassword,publicKey,"275t-2rt-4u32415bt-22-1201212");     }
    public static byte[] generateSymmetricKey(Long keySize, String keyAlgo) {
        byte[] generatedKey = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);
            keyGen.init(keySize.intValue());    
            generatedKey = keyGen.generateKey().getEncoded();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return generatedKey;
    }
    public static byte[] encrypt(byte[] data, String algorithm, byte[] key, byte[] iv) {
        byte[] encryptedBytes = null;
        try {
            String[] algo = algorithm.split("/");
            SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
            Cipher cipher = Cipher.getInstance(algorithm);
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            encryptedBytes = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedBytes;
    }
    public static byte[] encryptAsymmetric(byte[] data, String algorithm, byte[] key) {
        byte[] encryptedBytes = null;
        try {
            String[] algo = algorithm.split("/");
            KeyFactory kf = KeyFactory.getInstance(algo[0]);
            PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(key));
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            encryptedBytes = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedBytes;
    } 
    private static void encryptTest_UBL(String rawPassword, String publicKey,String RefNo) {
        long keySize = 128;
        String algorithm = "AES";         System.out.println("************Start*********************************************");         
        String password = rawPassword+":"+RefNo;         byte[] key = generateSymmetricKey(keySize, algorithm);         
        byte[] encryptedPassword = encrypt(password.getBytes(), "AES/ECB/PKCS5Padding", key, null);
        System.out.println("password: " + Base64.encode(encryptedPassword));
        byte[] encryptedKey = encryptAsymmetric(key, "RSA/ECB/PKCS1Padding", Base64.decode(publicKey));
        System.out.println("authKey: " + Base64.encode(encryptedKey));
        System.out.println("************end*********************************************");     }
}

