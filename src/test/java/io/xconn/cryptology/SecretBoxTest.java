package io.xconn.cryptology;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static io.xconn.cryptology.SecretBox.box;
import static io.xconn.cryptology.SecretBox.boxOpen;
import static io.xconn.cryptology.SecretBox.checkLength;
import static io.xconn.cryptology.SecretBox.generateSecret;

public class SecretBoxTest {

    private static byte[] secretKey;

    @BeforeAll
    public static void setUp() {
        secretKey = generateSecret();
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, secretKey);
        byte[] decrypted = boxOpen(encrypted, secretKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptOutput() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = new byte[SecretBox.NONCE_SIZE + SecretBox.MAC_SIZE + message.length];
        box(encrypted, message, secretKey);
        byte[] decrypted = new byte[message.length];
        boxOpen(decrypted, encrypted, secretKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithNonce() {
        byte[] nonce = SecretBox.generateNonce();
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = new byte[message.length + SecretBox.NONCE_SIZE + SecretBox.MAC_SIZE];
        box(encrypted, nonce, message, secretKey);
        byte[] decrypted = boxOpen(encrypted, secretKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithInvalidMAC() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, secretKey);
        encrypted[encrypted.length - 1] ^= 0xFF; // Modify last byte
        assertThrows(IllegalArgumentException.class, () -> boxOpen(encrypted, secretKey));
    }

    @Test
    public void testEncryptAndDecryptWithInvalidNonce() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, secretKey);
        encrypted[0] ^= 0xFF; // Modify first byte
        assertThrows(IllegalArgumentException.class, () -> boxOpen(encrypted, secretKey));
    }

    @Test
    public void testEncryptAndDecryptWithModifiedCiphertext() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, secretKey);
        encrypted[SecretBox.NONCE_SIZE + 1] ^= 0xFF; // Modify the byte next to nonce
        assertThrows(IllegalArgumentException.class, () -> boxOpen(encrypted, secretKey));
    }

    @Test
    public void testGenerateRandomBytesArray() {
        int size = 32;
        byte[] randomBytes = SecretBox.generateRandomBytesArray(size);

        assertNotNull(randomBytes);
        assertEquals(size, randomBytes.length);
    }

    @Test
    void testCheckLength() {
        assertThrows(NullPointerException.class, () -> checkLength(null, 16));

        byte[] data = new byte[16];
        checkLength(data, 16);

        assertThrows(IllegalArgumentException.class, () -> checkLength(data, 32));
    }
}
