package io.xconn.androidexample.fragment;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import io.xconn.androidexample.R;
import io.xconn.androidexample.util.App;
import io.xconn.androidexample.util.Helpers;
import io.xconn.cryptology.SealedBox;
import io.xconn.cryptology.SecretBox;

public class GalleryFragment extends Fragment implements Helpers.PasswordDialogListener {

    private GridView gridView;
    private static byte[] privateKey;

    private final ExecutorService executorService = Executors.newFixedThreadPool(4);
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_gallery, container, false);
        gridView = view.findViewById(R.id.gridView);
        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        requireActivity().findViewById(R.id.frameLayout).setFocusableInTouchMode(true);
        requireActivity().findViewById(R.id.frameLayout).requestFocus();
        Helpers.showPasswordDialog(requireContext(), this,
                true);
    }

    @Override
    public boolean onPasswordSubmit(String password) {
        boolean isPrivateKeyDecrypted = decryptPrivateKey(password);
        if (isPrivateKeyDecrypted) {
            loadImages();
            return true;
        } else {
            Toast.makeText(requireContext(), "Incorrect password", Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    @Override
    public void onPasswordCancel() {
        if (isCameraFragmentFocused()) {
            focusOnCameraFragment();
        }
        navigateToCameraFragment();
    }


    @Override
    public void onDismissed(boolean dismissedAfterSubmit) {
        if (!dismissedAfterSubmit) {
            if (isCameraFragmentFocused()) {
                focusOnCameraFragment();
            }
            navigateToCameraFragment();
        }
    }


    private boolean decryptPrivateKey(String password) {
        String encryptedPrivateKeyHex = App.getString(App.PREF_PRIVATE_KEY);
        String nonceHex = App.getString(App.PREF_NONCE);

        if (!TextUtils.isEmpty(encryptedPrivateKeyHex) && !TextUtils.isEmpty(nonceHex)) {
            byte[] encryptedPrivateKey = Helpers.hexToBytes(encryptedPrivateKeyHex);
            byte[] nonce = Helpers.hexToBytes(nonceHex);

            try {
                privateKey = SecretBox.boxOpen(nonce, encryptedPrivateKey,
                        Objects.requireNonNull(Helpers.convertTo32Bytes(password)));
                return true;
            } catch (Exception e) {
                Log.e("IOException", "Error reading or decrypting image data", e);
                return false;
            }
        } else {
            Toast.makeText(requireContext(), "Private key or nonce not found",
                    Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    private boolean isCameraFragmentFocused() {
        if (isAdded()) {
            return !requireActivity().findViewById(R.id.menu_camera).isSelected();
        }
        return false;
    }


    private void focusOnCameraFragment() {
        requireActivity().findViewById(R.id.menu_camera).performClick();
    }

    private void navigateToCameraFragment() {
        if (isAdded()) {
            FragmentManager fragmentManager = requireActivity().getSupportFragmentManager();
            FragmentTransaction transaction = fragmentManager.beginTransaction();
            transaction.replace(R.id.frameLayout, new CameraFragment());
            transaction.addToBackStack(null);
            transaction.commit();
        }
    }


    private void loadImages() {
        File directory = new File(requireContext().getFilesDir(), "cryptology");
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                Toast.makeText(requireContext(), "Failed to create directory",
                        Toast.LENGTH_SHORT).show();
                return;
            }
        }

        List<File> imageFiles = new ArrayList<>();
        File[] files = directory.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    imageFiles.add(file);
                }
            }
        }

        ImageAdapter adapter = new ImageAdapter(
                requireContext(),
                imageFiles,
                executorService,
                mainHandler);
        gridView.setAdapter(adapter);
    }

    private static class ImageAdapter extends BaseAdapter {

        private final List<File> imageFiles;
        private final LayoutInflater inflater;
        private final ExecutorService executorService;
        private final Handler mainHandler;

        ImageAdapter(
                Context context,
                List<File> imageFiles,
                ExecutorService executorService,
                Handler mainHandler) {
            this.imageFiles = imageFiles;
            this.inflater = LayoutInflater.from(context);
            this.executorService = executorService;
            this.mainHandler = mainHandler;
        }

        @Override
        public int getCount() {
            return imageFiles.size();
        }

        @Override
        public Object getItem(int position) {
            return imageFiles.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            if (convertView == null) {
                convertView = inflater.inflate(R.layout.gallery_item, parent, false);
                holder = new ViewHolder();
                holder.imageView = convertView.findViewById(R.id.imageView);
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }

            holder.imageView.setImageResource(R.drawable.image_icon);

            File imageFile = imageFiles.get(position);
            decodeAndDecryptImageDataAsync(imageFile, holder.imageView);

            return convertView;
        }

        private static class ViewHolder {
            ImageView imageView;
        }

        private void decodeAndDecryptImageDataAsync(final File imageFile, final ImageView imageView) {
            executorService.execute(() -> {
                Bitmap bitmap = decryptImageData(imageFile);
                mainHandler.post(() -> {
                    if (bitmap != null) {
                        imageView.setImageBitmap(bitmap);
                    } else {
                        imageView.setImageResource(R.drawable.broken_image);
                    }
                });
            });
        }

        private Bitmap decryptImageData(File imageFile) {
            try (FileInputStream fis = new FileInputStream(imageFile)) {
                byte[] encryptedData = new byte[(int) imageFile.length()];
                int bytesRead = fis.read(encryptedData);
                if (bytesRead == -1) {
                    Log.e("FileInputStream", "No bytes were read from the file");
                    return null;
                }

                byte[] decryptedData = SealedBox.sealOpen(encryptedData, privateKey);
                return BitmapFactory.decodeByteArray(decryptedData, 0, decryptedData.length);
            } catch (IOException e) {
                Log.e("IOException", "Error reading or decrypting image data", e);
                return null;
            }
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executorService.shutdown();
    }
}

