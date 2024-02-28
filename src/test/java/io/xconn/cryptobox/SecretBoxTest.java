package io.xconn.cryptobox;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

public class SecretBoxTest {

    @Test
    public void testConstructor() {
        // test with valid key
        new SecretBox(new byte[32]);

        // test with invalid key
        assertThrows(IllegalArgumentException.class, () -> new SecretBox(new byte[16]));

        // test with null key
        assertThrows(NullPointerException.class, () -> new SecretBox(null));
    }

    @Test
    public void testEncryptAndDecrypt() {
        SecretBox secretBox = new SecretBox(new byte[32]);
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = secretBox.encrypt(message);
        byte[] decrypted = secretBox.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithNonce() {
        SecretBox secretBox = new SecretBox(new byte[32]);
        byte[] nonce = Util.generateRandomBytesArray(Util.NONCE_SIZE);
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = secretBox.encrypt(nonce, message);
        byte[] decrypted = secretBox.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithInvalidMAC() {
        SecretBox secretBox = new SecretBox(new byte[32]);
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = secretBox.encrypt(message);
        encrypted[encrypted.length - 1] ^= 0xFF; // Modify last byte
        assertThrows(IllegalArgumentException.class, () -> secretBox.decrypt(encrypted));
    }

    @Test
    public void testEncryptAndDecryptWithInvalidNonce() {
        SecretBox secretBox = new SecretBox(new byte[32]);
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = secretBox.encrypt(message);
        encrypted[0] ^= 0xFF; // Modify first byte
        assertThrows(IllegalArgumentException.class, () -> secretBox.decrypt(encrypted));
    }

    @Test
    public void testEncryptAndDecryptWithModifiedCiphertext() {
        byte[] key = new byte[32];
        SecretBox secretBox = new SecretBox(key);
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = secretBox.encrypt(message);
        encrypted[Util.NONCE_SIZE + 1] ^= 0xFF; // Modify the byte next to nonce
        assertThrows(IllegalArgumentException.class, () -> secretBox.decrypt(encrypted));
    }

}
