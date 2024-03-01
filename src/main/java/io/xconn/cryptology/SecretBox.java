package io.xconn.cryptology;

import java.security.SecureRandom;

import static io.xconn.cryptology.Util.MAC_SIZE;
import static io.xconn.cryptology.Util.NONCE_SIZE;
import static io.xconn.cryptology.Util.SECRET_KEY_LEN;

public class SecretBox {

    public static byte[] box(byte[] nonce, byte[] message, byte[] privateKey) {
        byte[] output = new byte[message.length + MAC_SIZE];
        box(output, nonce, message, privateKey);

        return output;
    }

    public static void box(byte[] output, byte[] nonce, byte[] message, byte[] privateKey) {
        Util.encrypt(output, nonce, message, privateKey);
    }


    public static byte[] boxOpen(byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        byte[] plainText = new byte[ciphertext.length - MAC_SIZE];
        boxOpen(plainText, nonce, ciphertext, privateKey);

        return plainText;
    }

    public static void boxOpen(byte[] output, byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        Util.decrypt(output, nonce, ciphertext, privateKey);
    }

    public static void prependNonce(byte[] output, byte[] nonce, byte[] cipherWithoutNonce) {
        System.arraycopy(nonce, 0, output, 0, nonce.length);
        System.arraycopy(cipherWithoutNonce, 0, output, nonce.length, cipherWithoutNonce.length);
    }

    public static void extractNonce(byte[] nonce, byte[] cipher, byte[] cipherWithNonce) {
        System.arraycopy(cipherWithNonce, 0, nonce, 0, nonce.length);
        System.arraycopy(cipherWithNonce, nonce.length, cipher, 0, cipherWithNonce.length - nonce.length);
    }

    public static byte[] generateSecret() {
        return Util.generateRandomBytesArray(SECRET_KEY_LEN);
    }

    public static byte[] generateNonce() {
        return Util.generateRandomBytesArray(NONCE_SIZE);
    }
}
