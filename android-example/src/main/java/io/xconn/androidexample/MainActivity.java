package io.xconn.androidexample;

import static io.xconn.androidexample.util.Helpers.bytesToHex;
import static io.xconn.androidexample.util.Helpers.convertTo32Bytes;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputLayout;

import java.util.Objects;

import io.xconn.cryptology.KeyPair;
import io.xconn.cryptology.SealedBox;
import io.xconn.cryptology.SecretBox;
import io.xconn.androidexample.fragment.CameraFragment;
import io.xconn.androidexample.fragment.GalleryFragment;
import io.xconn.androidexample.util.App;
import io.xconn.androidexample.util.Helpers;


public class MainActivity extends AppCompatActivity implements Helpers.PasswordDialogListener {

    private androidx.appcompat.app.AlertDialog passwordDialog;
    private FragmentManager fragmentManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        fragmentManager = getSupportFragmentManager();
        BottomNavigationView bottomNavigationView = findViewById(R.id.bottom_navigation);

        Fragment cameraFragment = new CameraFragment();
        fragmentManager.beginTransaction().replace(R.id.frameLayout, cameraFragment).commit();

        bottomNavigationView.setOnItemSelectedListener(item -> {
            Fragment fragment = null;
            if (item.getItemId() == R.id.menu_camera) {
                fragment = new CameraFragment();
            } else if (item.getItemId() == R.id.menu_gallery) {
                fragment = new GalleryFragment();
            }

            if (fragment != null) {
                fragmentManager.beginTransaction().replace(R.id.frameLayout, fragment).commit();
                return true;
            }
            return false;
        });

        if (!App.getBoolean("isDialogShown")) {
            showPasswordDialog();
        }
    }

    private void showPasswordDialog() {
        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(this);
        LayoutInflater inflater = getLayoutInflater();
        View dialogView = inflater.inflate(R.layout.custom_dialog_box, null);
        TextInputLayout textInputLayoutPassword = dialogView.findViewById(R.id.enterPassword);
        EditText editTextPassword = textInputLayoutPassword.getEditText();

        builder.setView(dialogView)
                .setTitle("Enter Password")
                .setPositiveButton("Submit", null)
                .setCancelable(false);

        passwordDialog = builder.create();
        passwordDialog.show();

        passwordDialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(v -> {
                    String enteredPassword = editTextPassword != null ?
                            editTextPassword.getText().toString().trim() : "";

                    if (enteredPassword.isEmpty()) {
                        textInputLayoutPassword.setError("Please enter a password");
                        textInputLayoutPassword.requestFocus();
                    } else {
                        // Generate key pair
                        KeyPair keyPair = SealedBox.generateKeyPair();

                        // Convert public key to hexadecimal string and save it
                        String publicKey = bytesToHex(keyPair.getPublicKey());
                        App.saveString(App.PREF_PUBLIC_KEY, publicKey);

                        // Generate nonce and save it
                        byte[] nonce = SecretBox.generateNonce();
                        App.saveString("nonce", bytesToHex(nonce));

                        // Encrypt private key with entered password and save it
                        byte[] encryptedPrivateKey = SecretBox.box(nonce, keyPair.getPrivateKey(),
                                Objects.requireNonNull(convertTo32Bytes(enteredPassword)));
                        App.saveString(App.PREF_PRIVATE_KEY, bytesToHex(encryptedPrivateKey));


                        App.saveBoolean("isDialogShown", true);
                        passwordDialog.dismiss();

                    }
                });

        assert editTextPassword != null;
        editTextPassword.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // No action needed
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                passwordDialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE)
                        .setEnabled(!TextUtils.isEmpty(s));
            }

            @Override
            public void afterTextChanged(Editable s) {
                // No action needed
            }
        });

        passwordDialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE)
                .setEnabled(false);
    }

    @Override
    public boolean onPasswordSubmit(String password) {
        savePassword(password);
        passwordDialog.dismiss();
        return true;
    }

    private void savePassword(String ignoredPassword) {

    }

    @Override
    public void onPasswordCancel() {

    }

    @Override
    public void onDismissed(boolean dismissedAfterSubmit) {

    }


}