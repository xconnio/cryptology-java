package io.xconn.cryptobox;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static io.xconn.cryptobox.Util.MAC_SIZE;
import static io.xconn.cryptobox.SecretBox.box;
import static io.xconn.cryptobox.SecretBox.boxOpen;
import static io.xconn.cryptobox.SecretBox.checkLength;

public class SecretBoxTest {

    private static byte[] privateKey;

    @BeforeAll
    public static void setUp() {
        privateKey = Hex.decode("cd281cb85a967c5fc249b31c1c6503a181841526182d4f6e63c81e4213a45fb7");
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, privateKey);
        byte[] decrypted = boxOpen(encrypted, privateKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptOutput() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = new byte[Util.NONCE_SIZE + MAC_SIZE + message.length];
        box(encrypted, message, privateKey);
        byte[] decrypted = new byte[message.length];
        boxOpen(decrypted, encrypted, privateKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithNonce() {
        byte[] nonce = Util.generateRandomBytesArray(Util.NONCE_SIZE);
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = new byte[message.length + Util.NONCE_SIZE + MAC_SIZE];
        box(encrypted, nonce, message, privateKey);
        byte[] decrypted = boxOpen(encrypted, privateKey);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithInvalidMAC() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, privateKey);
        encrypted[encrypted.length - 1] ^= 0xFF; // Modify last byte
        assertThrows(IllegalArgumentException.class, () -> boxOpen(encrypted, privateKey));
    }

    @Test
    public void testEncryptAndDecryptWithInvalidNonce() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, privateKey);
        encrypted[0] ^= 0xFF; // Modify first byte
        assertThrows(IllegalArgumentException.class, () -> boxOpen(encrypted, privateKey));
    }

    @Test
    public void testEncryptAndDecryptWithModifiedCiphertext() {
        byte[] message = "Hello, World!".getBytes();
        byte[] encrypted = box(message, privateKey);
        encrypted[Util.NONCE_SIZE + 1] ^= 0xFF; // Modify the byte next to nonce
        assertThrows(IllegalArgumentException.class, () -> boxOpen(encrypted, privateKey));
    }

    @Test
    void testCheckLength() {
        assertThrows(NullPointerException.class, () -> checkLength(null, 16));

        byte[] data = new byte[16];
        checkLength(data, 16);

        assertThrows(IllegalArgumentException.class, () -> checkLength(data, 32));
    }
}
