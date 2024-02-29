package io.xconn.cryptology;

import java.security.SecureRandom;
import java.util.Arrays;

import static io.xconn.cryptology.Util.MAC_SIZE;
import static io.xconn.cryptology.Util.NONCE_SIZE;
import static io.xconn.cryptology.Util.SECRET_KEY_LEN;

public class SecretBox {

    public static byte[] box(byte[] message, byte[] privateKey) {
        byte[] output = new byte[message.length + MAC_SIZE + NONCE_SIZE];
        box(output, message, privateKey);

        return output;
    }

    public static void box(byte[] output, byte[] message, byte[] privateKey) {
        byte[] nonce = generateNonce();
        byte[] cipherWithoutNonce = Util.encrypt(nonce, message, privateKey);

        System.arraycopy(nonce, 0, output, 0, nonce.length);
        System.arraycopy(cipherWithoutNonce, 0, output, nonce.length, cipherWithoutNonce.length);
    }


    public static byte[] boxOpen(byte[] ciphertext, byte[] privateKey) {
        byte[] plainText = new byte[ciphertext.length - MAC_SIZE - NONCE_SIZE];
        boxOpen(plainText, ciphertext, privateKey);

        return plainText;
    }

    public static void boxOpen(byte[] output, byte[] ciphertext, byte[] privateKey) {
        byte[] nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
        byte[] message = Arrays.copyOfRange(ciphertext, NONCE_SIZE, ciphertext.length);

        Util.decrypt(output, nonce, message, privateKey);
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
}
