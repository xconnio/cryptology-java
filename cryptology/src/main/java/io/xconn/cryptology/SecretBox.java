package io.xconn.cryptology;

import static io.xconn.cryptology.Util.MAC_SIZE;
import static io.xconn.cryptology.Util.NONCE_SIZE;
import static io.xconn.cryptology.Util.SECRET_KEY_LEN;

public class SecretBox {

    /**
     * Encrypts a message using a nonce and privateKey.
     *
     * @param nonce      nonce for encryption.
     * @param message    message to encrypt.
     * @param privateKey privateKey for encryption.
     * @return encrypted message.
     */
    public static byte[] box(byte[] nonce, byte[] message, byte[] privateKey) {
        byte[] output = new byte[message.length + MAC_SIZE];
        box(output, nonce, message, privateKey);

        return output;
    }

    /**
     * Encrypts a message using nonce, privateKey and writes the result to the given output array.
     *
     * @param output     output array to write the encrypted message.
     * @param nonce      nonce for encryption.
     * @param message    message to encrypt.
     * @param privateKey privateKey for encryption.
     */
    public static void box(byte[] output, byte[] nonce, byte[] message, byte[] privateKey) {
        Util.encrypt(output, nonce, message, privateKey);
    }


    /**
     * Decrypts a ciphertext using nonce and privateKey.
     *
     * @param nonce      nonce for decryption.
     * @param ciphertext ciphertext to decrypt.
     * @param privateKey privateKey for decryption.
     * @return decrypted message.
     */
    public static byte[] boxOpen(byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        byte[] plainText = new byte[ciphertext.length - MAC_SIZE];
        boxOpen(plainText, nonce, ciphertext, privateKey);

        return plainText;
    }

    /**
     * Decrypts a ciphertext using nonce, private key, and writes the result to the given output array.
     *
     * @param output     output array to write the decrypted message.
     * @param nonce      nonce for decryption.
     * @param ciphertext ciphertext to decrypt.
     * @param privateKey privateKey for decryption.
     */
    public static void boxOpen(byte[] output, byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        Util.decrypt(output, nonce, ciphertext, privateKey);
    }

    /**
     * Generates a new secret key.
     *
     * @return generated secret key.
     */
    public static byte[] generateSecret() {
        return Util.generateRandomBytesArray(SECRET_KEY_LEN);
    }

    /**
     * Generates a new nonce.
     *
     * @return generated nonce.
     */
    public static byte[] generateNonce() {
        return Util.generateRandomBytesArray(NONCE_SIZE);
    }
}
