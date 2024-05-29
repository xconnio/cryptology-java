package io.xconn.androidexample;

import static io.xconn.androidexample.util.Helpers.bytesToHex;
import static io.xconn.androidexample.util.Helpers.convertTo32Bytes;

import android.os.Bundle;


import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;

import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.util.Objects;

import io.xconn.cryptology.KeyPair;
import io.xconn.cryptology.SealedBox;
import io.xconn.cryptology.SecretBox;
import io.xconn.androidexample.fragment.CameraFragment;
import io.xconn.androidexample.fragment.GalleryFragment;
import io.xconn.androidexample.util.App;
import io.xconn.androidexample.util.Helpers;

public class MainActivity extends AppCompatActivity implements Helpers.PasswordDialogListener {

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
                Fragment currentFragment = fragmentManager.findFragmentById(R.id.frameLayout);

                // Do nothing if already on the selected fragment
                if (currentFragment != null && currentFragment.getClass().equals(fragment.getClass())) {
                    return true;
                }

                // Clear the backstack
                fragmentManager.popBackStackImmediate(null, FragmentManager.POP_BACK_STACK_INCLUSIVE);

                FragmentTransaction transaction = fragmentManager.beginTransaction()
                        .replace(R.id.frameLayout, fragment);

                // Add to backstack if it's GalleryFragment
                if (fragment instanceof GalleryFragment) {
                    transaction.addToBackStack(null);
                }

                transaction.commit();
                return true;
            }
            return false;
        });

        fragmentManager.addOnBackStackChangedListener(() -> {
            Fragment currentFragment = fragmentManager.findFragmentById(R.id.frameLayout);

            if (currentFragment instanceof CameraFragment) {
                bottomNavigationView.setSelectedItemId(R.id.menu_camera);
            } else if (currentFragment instanceof GalleryFragment) {
                bottomNavigationView.setSelectedItemId(R.id.menu_gallery);
            }
        });

        if (!App.getBoolean(App.PREF_IS_DIALOG_SHOWN)) {
            Helpers.showPasswordDialog(this, this, false);
        }
    }


    @Override
    public boolean onPasswordSubmit(String password) {
        if (password.isEmpty()) {
            return false;
        }

        // Generate key pair
        KeyPair keyPair = SealedBox.generateKeyPair();

        // Convert public key to hexadecimal string and save it
        String publicKey = bytesToHex(keyPair.getPublicKey());
        App.saveString(App.PREF_PUBLIC_KEY, publicKey);

        // Generate nonce and save it
        byte[] nonce = SecretBox.generateNonce();
        App.saveString(App.PREF_NONCE, bytesToHex(nonce));

        // Encrypt private key with entered password and save it
        byte[] encryptedPrivateKey = SecretBox.box(nonce, keyPair.getPrivateKey(),
                Objects.requireNonNull(convertTo32Bytes(password)));
        App.saveString(App.PREF_PRIVATE_KEY, bytesToHex(encryptedPrivateKey));

        App.saveBoolean(App.PREF_IS_DIALOG_SHOWN, true);
        return true;
    }

    @Override
    public void onPasswordCancel() {

    }

    @Override
    public void onDismissed(boolean dismissedAfterSubmit) {

    }
}
