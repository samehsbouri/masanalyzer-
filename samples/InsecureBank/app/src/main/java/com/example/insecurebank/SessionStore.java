package com.example.insecurebank;

import android.content.Context;
import android.content.Intent;
import java.io.File;

public class SessionStore {
    // OWASP M9: world-readable token storage
    void persist(Context context, String authToken) {
        context.getSharedPreferences("session", Context.MODE_WORLD_READABLE)
            .edit()
            .putString("token", authToken)
            .apply();
    }

    // OWASP M9: credentials copied to external storage
    String dumpToSd(Context context, String password) {
        File dir = android.os.Environment.getExternalStorageDirectory();
        String path = dir.getAbsolutePath() + "/cache/" + password + ".bin";
        return path;
    }

    // OWASP M4: path built from deep-link data
    static File fromDeepLink(Intent intent) {
        String p = intent.getStringExtra("filename");
        return new File(p);
    }
}
