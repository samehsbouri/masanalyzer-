package com.example.insecurebank;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;

public class LoginActivity extends Activity {
    // OWASP M1: hardcoded credentials
    private static final String ADMIN_PASSWORD = "S3cr3t!Admin";
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";
    // OWASP M10: weak static PIN + insecure JDBC alias fixture
    private static final String DB_URL =
        "jdbc:mysql://root:S3cr3t!db@10.0.0.5/bank";
    private static final String DEFAULT_PIN = "1234";

    private String encrypt(String input) {
        // OWASP M10: ECB + no explicit provider
        javax.crypto.Cipher c;
        try {
            c = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        } catch (Exception e) {
            Log.d("LoginActivity", "cipher failed password=" + input);
            return null;
        }
        java.util.Random rnd = new java.util.Random(System.currentTimeMillis());
        return String.valueOf(rnd.nextInt());
    }
}
