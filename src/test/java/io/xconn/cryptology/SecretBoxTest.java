package io.xconn.cryptology;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static io.xconn.cryptology.SecretBox.box;
import static io.xconn.cryptology.SecretBox.boxOpen;
import static io.xconn.cryptology.SecretBox.extractNonce;
import static io.xconn.cryptology.SecretBox.generateSecret;
import static io.xconn.cryptology.SecretBox.prependNonce;

public class SecretBoxTest {

    private static byte[] secretKey;

    @BeforeAll
    public static void setUp() {
        secretKey = generateSecret();
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] message = "Hello, World!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        byte[] encrypted = box(nonce, message, secretKey);
        byte[] decrypted = boxOpen(nonce, encrypted, secretKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptOutput() {
        byte[] message = "Hello, World!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        byte[] encrypted = new byte[Util.MAC_SIZE + message.length];
        box(encrypted, nonce, message, secretKey);

        byte[] decrypted = new byte[message.length];
        boxOpen(decrypted, nonce, encrypted, secretKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithInvalidMAC() {
        byte[] message = "Hello, World!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        byte[] encrypted = box(nonce, message, secretKey);
        encrypted[encrypted.length - 1] ^= 0xFF; // Modify last byte
        assertThrows(IllegalArgumentException.class, () -> boxOpen(nonce, encrypted, secretKey));
    }

    @Test
    public void testEncryptAndDecryptWithInvalidNonce() {
        byte[] message = "Hello, World!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        byte[] encrypted = box(nonce, message, secretKey);
        nonce[0] ^= 0xFF; // Modify first byte
        assertThrows(IllegalArgumentException.class, () -> boxOpen(nonce, encrypted, secretKey));
    }

    @Test
    public void testEncryptAndDecryptWithModifiedCiphertext() {
        byte[] message = "Hello, World!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        byte[] encrypted = box(nonce, message, secretKey);
        encrypted[Util.NONCE_SIZE + 1] ^= 0xFF; // Modify the byte next to nonce
        assertThrows(IllegalArgumentException.class, () -> boxOpen(nonce, encrypted, secretKey));
    }


    @Test
    public void testPrependNonceAndExtractNonce() {
        byte[] nonce = new byte[]{1, 2, 3, 4, 5};
        byte[] cipherWithoutNonce = new byte[]{6, 7, 8, 9};
        byte[] cipherWithNonce = new byte[nonce.length + cipherWithoutNonce.length];
        prependNonce(cipherWithNonce, nonce, cipherWithoutNonce);

        assertArrayEquals(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9}, cipherWithNonce);

        byte[] extractedNonce = new byte[nonce.length];
        byte[] extractedCipher = new byte[cipherWithoutNonce.length];
        extractNonce(extractedNonce, extractedCipher, cipherWithNonce);

        assertArrayEquals(nonce, extractedNonce);
        assertArrayEquals(cipherWithoutNonce, extractedCipher);
    }


    @Test
    public void testGenerateRandomBytesArray() {
        int size = 32;
        byte[] randomBytes = SecretBox.generateRandomBytesArray(size);

        assertNotNull(randomBytes);
        assertEquals(size, randomBytes.length);
    }
}
