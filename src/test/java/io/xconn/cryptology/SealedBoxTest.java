package io.xconn.cryptology;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static io.xconn.cryptology.SealedBox.computeSharedSecret;
import static io.xconn.cryptology.SealedBox.createNonce;
import static io.xconn.cryptology.SealedBox.sealOpen;
import static io.xconn.cryptology.SealedBox.seal;
import static io.xconn.cryptology.Util.MAC_SIZE;
import static io.xconn.cryptology.Util.PUBLIC_KEY_BYTES;

public class SealedBoxTest {

    private static byte[] publicKey;
    private static byte[] privateKey;

    @BeforeAll
    public static void setUp() {
        publicKey = Hex.decode("e146721761cf7378cb2e007adc1a51b70fa40abfb87652c645d8e86be19c2b1e");
        privateKey = Hex.decode("3817e2630237d569188a02a06354d9e9f61ee9cdd0cc8b5388c56013b7b5654a");
    }

    @Test
    public void testEncryptAndDecrypt() {
        String message = "Hello, world!";
        byte[] encrypted = SealedBox.seal(message.getBytes(), publicKey);
        byte[] decrypted = SealedBox.sealOpen(encrypted, privateKey);

        assertArrayEquals(message.getBytes(), decrypted);
    }

    @Test
    public void testEncryptAndDecryptOutput() {
        String message = "Hello, world!";

        byte[] encrypted = new byte[message.getBytes().length + PUBLIC_KEY_BYTES + MAC_SIZE];
        seal(encrypted, message.getBytes(), publicKey);
        byte[] decrypted = new byte[message.length()];
        sealOpen(decrypted, encrypted, privateKey);

        assertArrayEquals(message.getBytes(), decrypted);
    }

    @Test
    void testCreateNonce() {
        byte[] nonce = createNonce(new byte[32], new byte[32]);
        assertNotNull(nonce);
        assertEquals(Util.NONCE_SIZE, nonce.length);
    }

    @Test
    public void testComputeSharedSecret() {
        byte[] sharedSecret = computeSharedSecret(publicKey, privateKey);

        byte[] expectedSharedSecret = Hex.decode("544b3aea8fcebe9e986a1628e517927526407c100d09e17c5dc7dd81149325e1");
        assertArrayEquals(expectedSharedSecret, sharedSecret);
    }


    @Test
    public void testInvalidDecrypt() {
        byte[] encrypted = SealedBox.seal("Hello, world!".getBytes(), publicKey);

        // Using a different private key for decryption
        byte[] wrongPrivateKey = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000");

        assertThrows(IllegalArgumentException.class, () -> SealedBox.sealOpen(encrypted, wrongPrivateKey));
    }

}
