package com.example.insecurebank;

import android.app.Activity;
import android.os.Bundle;

public class TransferActivity extends Activity {
    android.database.sqlite.SQLiteDatabase db;

    void transfer(String account, String amountCents) {
        // OWASP M4: SQL built by concatenation
        db.execSQL("SELECT * FROM account WHERE owner = '" + account + "'");
        db.rawQuery("UPDATE balance SET cents = " + amountCents
            + " WHERE owner = '" + account + "'", null);
    }
}
