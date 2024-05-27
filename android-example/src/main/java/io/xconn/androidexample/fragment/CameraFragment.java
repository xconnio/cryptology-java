package io.xconn.androidexample.fragment;

import static android.app.Activity.RESULT_OK;
import static io.xconn.androidexample.util.Helpers.bytesToHex;
import static io.xconn.androidexample.util.Helpers.hexToBytes;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.provider.MediaStore;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Objects;

import io.xconn.cryptology.SealedBox;
import io.xconn.androidexample.R;
import io.xconn.androidexample.util.App;


public class CameraFragment extends Fragment {


    private ActivityResultLauncher<String> cameraPermissionLauncher;
    private ActivityResultLauncher<Intent> cameraLauncher;
    private ActivityResultLauncher<Intent> galleryLauncher;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_camera, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        view.findViewById(R.id.button_capture).setOnClickListener(v -> dispatchTakePictureIntent());
        view.findViewById(R.id.button_select_photo).setOnClickListener(v -> openGallery());

        // Initialize ActivityResultLaunchers
        cameraLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK) {
                        handleCameraResult(result.getData());
                    }
                }
        );

        galleryLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK) {
                        handleGalleryResult(result.getData());
                    }
                }
        );

        // Initialize camera permission launcher
        cameraPermissionLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestPermission(),
                isGranted -> {
                    if (isGranted) {
                        startCamera();
                    } else {
                        Toast.makeText(requireContext(), "Camera permission denied",
                                Toast.LENGTH_SHORT).show();
                    }
                }
        );
    }

    private void dispatchTakePictureIntent() {
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            requestCameraPermission();
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA);
        }
    }

    private void requestCameraPermission() {
        cameraPermissionLauncher.launch(Manifest.permission.CAMERA);
    }

    @SuppressLint("QueryPermissionsNeeded")
    private void startCamera() {
        Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (takePictureIntent.resolveActivity(requireActivity().getPackageManager()) != null) {
            cameraLauncher.launch(takePictureIntent);
        } else {
            Toast.makeText(requireContext(), "No camera app found", Toast.LENGTH_SHORT).show();
        }
    }

    private void openGallery() {
        Intent intent = new Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
        galleryLauncher.launch(intent);
    }

    private void handleCameraResult(@Nullable Intent data) {
        assert data != null;
        Bitmap bitmap = (Bitmap) Objects.requireNonNull(data.getExtras()).get("data");
        assert bitmap != null;
        byte[] imageData = bitmapToByteArray(bitmap);

        byte[] publicKey = hexToBytes(App.getString(App.PREF_PUBLIC_KEY));
        Log.d("PublicKey", "Public Key: " + bytesToHex(publicKey));

        byte[] encryptedImageData = SealedBox.seal(imageData, publicKey);
        saveImageToFile(encryptedImageData);
    }

    private void handleGalleryResult(@Nullable Intent data) {
        try {
            if (data != null && data.getData() != null) {
                Bitmap bitmap = MediaStore.Images.Media.getBitmap(
                        requireActivity().getContentResolver(), data.getData());
                byte[] imageData = bitmapToByteArray(bitmap);

                byte[] publicKey = hexToBytes(App.getString(App.PREF_PUBLIC_KEY));

                byte[] encryptedImageData = SealedBox.seal(imageData, publicKey);
                saveImageToFile(encryptedImageData);
            }
        } catch (IOException e) {
            Log.w("IOException", e.getMessage(), e);
        }
    }

    private byte[] bitmapToByteArray(Bitmap bitmap) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, baos);
        return baos.toByteArray();
    }

    private void saveImageToFile(byte[] data) {
        File directory = new File(requireContext().getFilesDir(), "cryptology");
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                Toast.makeText(requireContext(), "Failed to create directory",
                        Toast.LENGTH_SHORT).show();
                return;
            }
        }

        String fileName = "image_" + System.currentTimeMillis() + ".dat";
        File file = new File(directory, fileName);

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(data);
            Toast.makeText(requireContext(), "Image saved: " + file.getAbsolutePath(),
                    Toast.LENGTH_SHORT).show();
            Log.d("ImagePath", "Image saved: " + file.getAbsolutePath());
        } catch (IOException e) {
            Log.w("IOException", e.getMessage(), e);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    Log.w("IOException", e.getMessage(), e);
                }
            }
        }
    }
}
