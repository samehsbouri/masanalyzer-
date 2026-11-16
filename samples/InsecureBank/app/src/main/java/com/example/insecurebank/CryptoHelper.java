package com.example.insecurebank;

import java.security.MessageDigest;

public class CryptoHelper {
    // OWASP M10: MD5 digest + default cipher instance
    static byte[] digest(String value) throws Exception {
        return MessageDigest.getInstance("MD5").digest(value.getBytes());
    }

    static byte[] weakCipher(byte[] plain) throws Exception {
        javax.crypto.spec.SecretKeySpec key =
            new javax.crypto.spec.SecretKeySpec(new byte[16], "DES");
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES");
        return c.doFinal(plain);
    }
}
