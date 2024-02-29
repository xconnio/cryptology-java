package io.xconn.cryptology;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class SecretBox {

    public static final int NONCE_SIZE = 24;
    public static final int SECRET_KEY_LEN = 32;
    public static final int MAC_SIZE = 16;

    public static byte[] box(byte[] message, byte[] privateKey) {
        checkLength(privateKey, SECRET_KEY_LEN);

        byte[] nonce = generateNonce();
        byte[] output = new byte[message.length + MAC_SIZE + NONCE_SIZE];
        box(output, nonce, message, privateKey);

        return output;
    }

    public static void box(byte[] output, byte[] message, byte[] privateKey) {
        checkLength(privateKey, SECRET_KEY_LEN);

        byte[] nonce = generateNonce();
        box(output, nonce, message, privateKey);
    }

    static void box(byte[] output, byte[] nonce, byte[] plaintext, byte[] privateKey) {
        checkLength(nonce, NONCE_SIZE);

        XSalsa20Engine cipher = new XSalsa20Engine();
        Poly1305 mac = new Poly1305();

        cipher.init(true, new ParametersWithIV(new KeyParameter(privateKey), nonce));
        byte[] subKey = new byte[SECRET_KEY_LEN];
        cipher.processBytes(subKey, 0, SECRET_KEY_LEN, subKey, 0);
        byte[] cipherWithoutNonce = new byte[plaintext.length + mac.getMacSize()];
        cipher.processBytes(plaintext, 0, plaintext.length, cipherWithoutNonce, mac.getMacSize());

        // hash the ciphertext
        mac.init(new KeyParameter(subKey));
        mac.update(cipherWithoutNonce, mac.getMacSize(), plaintext.length);
        mac.doFinal(cipherWithoutNonce, 0);

        System.arraycopy(nonce, 0, output, 0, nonce.length);
        System.arraycopy(cipherWithoutNonce, 0, output, nonce.length, cipherWithoutNonce.length);
    }


    public static byte[] boxOpen(byte[] ciphertext, byte[] privateKey) {
        checkLength(privateKey, SECRET_KEY_LEN);

        byte[] nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
        byte[] message = Arrays.copyOfRange(ciphertext, NONCE_SIZE,
                ciphertext.length);
        byte[] plainText = new byte[message.length - MAC_SIZE];
        boxOpen(plainText, nonce, message, privateKey);

        return plainText;
    }

    public static void boxOpen(byte[] output, byte[] ciphertext, byte[] privateKey) {
        checkLength(privateKey, SECRET_KEY_LEN);

        byte[] nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
        byte[] message = Arrays.copyOfRange(ciphertext, NONCE_SIZE,
                ciphertext.length);

        boxOpen(output, nonce, message, privateKey);
    }

    static void boxOpen(byte[] output, byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        checkLength(nonce, NONCE_SIZE);

        XSalsa20Engine cipher = new XSalsa20Engine();
        Poly1305 mac = new Poly1305();

        cipher.init(false, new ParametersWithIV(new KeyParameter(privateKey), nonce));
        byte[] sk = new byte[SECRET_KEY_LEN];
        cipher.processBytes(sk, 0, sk.length, sk, 0);

        // hash ciphertext
        mac.init(new KeyParameter(sk));
        int len = Math.max(ciphertext.length - mac.getMacSize(), 0);
        mac.update(ciphertext, mac.getMacSize(), len);
        byte[] calculatedMAC = new byte[mac.getMacSize()];
        mac.doFinal(calculatedMAC, 0);

        // extract mac
        final byte[] presentedMAC = new byte[mac.getMacSize()];
        System.arraycopy(
                ciphertext, 0, presentedMAC, 0, Math.min(ciphertext.length, mac.getMacSize()));

        if (!MessageDigest.isEqual(calculatedMAC, presentedMAC)) {
            throw new IllegalArgumentException("Invalid MAC");
        }


        cipher.processBytes(ciphertext, mac.getMacSize(), output.length, output, 0);
    }

    public static byte[] generateSecret() {
        return generateRandomBytesArray(SECRET_KEY_LEN);
    }

    static byte[] generateNonce() {
        return generateRandomBytesArray(NONCE_SIZE);
    }

    static byte[] generateRandomBytesArray(int size) {
        byte[] randomBytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    static void checkLength(byte[] data, int size) {
        if (data == null)
            throw new NullPointerException("Input array is null.");
        else if (data.length != size) {
            throw new IllegalArgumentException("Invalid array length: " + data.length +
                    ". Length should be " + size);
        }
    }
}
