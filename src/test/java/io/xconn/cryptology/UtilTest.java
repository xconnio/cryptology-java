package io.xconn.cryptology;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static io.xconn.cryptology.Util.checkLength;
import static io.xconn.cryptology.Util.decrypt;
import static io.xconn.cryptology.Util.encrypt;

public class UtilTest {
    private static final byte[] secretKey = Hex.decode("70954bdc59afe040fcabf3b19b0ec34a4684653cc03bd376d24284944c5e1f7b");

    @Test
    void testCheckLength() {
        assertThrows(NullPointerException.class, () -> checkLength(null, 16));

        byte[] data = new byte[16];
        checkLength(data, 16);

        assertThrows(IllegalArgumentException.class, () -> checkLength(data, 32));
    }

    @Test
    void testEncryptDecrypt() {
        byte[] message = "Hello, world!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        byte[] encryptedText = encrypt(nonce, message, secretKey);

        byte[] decryptedText = new byte[message.length];
        decrypt(decryptedText, nonce, encryptedText, secretKey);

        assertArrayEquals(message, decryptedText);
    }
}
