package io.xconn.androidexample.util;

import android.app.Application;
import android.content.Context;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;

import androidx.appcompat.app.AlertDialog;

import com.google.android.material.textfield.TextInputLayout;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.xconn.androidexample.R;

public class Helpers extends Application {

    private static AlertDialog passwordDialog;

    public interface PasswordDialogListener {
        boolean onPasswordSubmit(String password);
        void onPasswordCancel();
        void onDismissed(boolean dismissedAfterSubmit);
    }

    public static void showPasswordDialog(Context context, PasswordDialogListener listener,
                                          boolean isCancelButtonVisible) {
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        LayoutInflater inflater = LayoutInflater.from(context);
        View dialogView = inflater.inflate(R.layout.custom_dialog_box, null);
        TextInputLayout textInputLayoutPassword = dialogView.findViewById(R.id.enterPassword);
        EditText editTextPassword = textInputLayoutPassword.getEditText();

        builder.setView(dialogView)
                .setTitle("Enter Password")
                .setPositiveButton("Submit", null)
                .setCancelable(true);

        if (isCancelButtonVisible) {
            builder.setNegativeButton("Cancel", (dialog, which) -> {
                if (listener != null) {
                    listener.onPasswordCancel();
                }
            });
        }

        passwordDialog = builder.create();
        passwordDialog.show();

        boolean[] dismissedAfterSubmit = {false};

        passwordDialog.setOnDismissListener(dialog -> {
            if (listener != null) {
                listener.onDismissed(dismissedAfterSubmit[0]);
            }
        });

        if (editTextPassword != null) {
            editTextPassword.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                    // No action needed
                }

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    passwordDialog.getButton(AlertDialog.BUTTON_POSITIVE)
                            .setEnabled(!TextUtils.isEmpty(s));
                }

                @Override
                public void afterTextChanged(Editable s) {
                    // No action needed
                }
            });
        }

        passwordDialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String password = editTextPassword != null ?
                    editTextPassword.getText().toString().trim() : null;
            if (password != null && !password.isEmpty()) {
                if (listener != null) {
                    if (listener.onPasswordSubmit(password)) {
                        dismissedAfterSubmit[0] = true;
                        passwordDialog.dismiss();
                    } else {
                        // Show error message
                        textInputLayoutPassword.setError("Incorrect password");
                        editTextPassword.requestFocus();
                    }
                }
            }
        });

        if (passwordDialog.getButton(AlertDialog.BUTTON_POSITIVE) != null) {
            passwordDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
        }
    }

    public static byte[] hexToBytes(String hexString) {int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static byte[] convertTo32Bytes(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());

            // If the hash is less than 32 bytes, we pad it with zeros
            byte[] result = new byte[32];
            System.arraycopy(hash, 0, result, 0, Math.min(hash.length, 32));

            return result;
        } catch (NoSuchAlgorithmException e) {
            Log.e("Helpers", "Error generating hash", e);
            return null;
        }
    }
}