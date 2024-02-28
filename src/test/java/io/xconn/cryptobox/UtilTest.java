package io.xconn.cryptobox;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import static io.xconn.cryptobox.Util.PUBLIC_KEY_BYTES;
import static io.xconn.cryptobox.Util.generateX25519KeyPair;
import static io.xconn.cryptobox.Util.getX25519PublicKey;


public class UtilTest {

    @Test
    public void testGenerateRandomBytesArray() {
        int size = 32;
        byte[] randomBytes = Util.generateRandomBytesArray(size);

        assertNotNull(randomBytes);
        assertEquals(size, randomBytes.length);
    }

    @Test
    void testGetX25519PublicKey() {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyRaw = new byte[32];
        random.nextBytes(privateKeyRaw);

        byte[] publicKey = getX25519PublicKey(privateKeyRaw);

        assertNotNull(publicKey);
        assertEquals(PUBLIC_KEY_BYTES, publicKey.length);
    }

    @Test
    void testGenerateX25519KeyPair() {
        KeyPair keyPair = generateX25519KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());
        assertEquals(Util.PUBLIC_KEY_BYTES, keyPair.getPublicKey().length);
        assertEquals(Util.SECRET_KEY_LEN, keyPair.getPrivateKey().length);
    }
}
