package com.example.insecurebank;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class PinActivity extends Activity {
    public void onCreate(Bundle state) {
        super.onCreate(state);
        // OWASP M6: personal data written to logs
        Log.i("PinActivity", "user entered email="
            + (getIntent().getStringExtra("email") != null));
        Log.e("PinActivity", "token verification failed token="
            + getIntent().getStringExtra("token"));
    }
}
