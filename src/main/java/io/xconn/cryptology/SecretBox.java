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

    public static byte[] generateSecret() {
        return generateRandomBytesArray(SECRET_KEY_LEN);
    }

    public static byte[] generateNonce() {
        return generateRandomBytesArray(NONCE_SIZE);
    }

    static byte[] generateRandomBytesArray(int size) {
        byte[] randomBytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);
        return randomBytes;
    }
}
