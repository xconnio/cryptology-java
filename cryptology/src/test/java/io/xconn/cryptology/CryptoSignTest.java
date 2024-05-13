package io.xconn.cryptology;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import static io.xconn.cryptology.CryptoSign.generateKeyPair;
import static io.xconn.cryptology.CryptoSign.getPublicKey;
import static io.xconn.cryptology.CryptoSign.sign;
import static io.xconn.cryptology.CryptoSign.verify;

public class CryptoSignTest {
    private static final String privateKey = "6b19991b461d1073918a25525652c4c913fb28b07142faf1146f6bde228653c5";
    private static final String publicKey = "568850ef3a95c4fc3720f534004f1837ed4e32049271b2e1a8c3d979b571e3e4";

    @Test
    public void testGenerateKeyPair() {
        KeyPair keyPair = generateKeyPair();

        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());
        assertEquals(32, keyPair.getPublicKey().length);
        assertEquals(32, keyPair.getPrivateKey().length);
    }

    @Test
    public void testGetPublicKey() {
        byte[] publicKey = getPublicKey(Hex.decode(privateKey));

        assertArrayEquals(Hex.decode(CryptoSignTest.publicKey), publicKey);
    }

    String challengeString = "f9d17535fb925e9f674d648cbfc41399";
    String signatureString = "054932bce44c62d749723f808c2f7ba8b3eb6fe27a2886644317" + "cc95022da5b6211866f36572da9ee783fb229e63d0c76ab050e8aa840a48d8285537ed57f70f";

    @Test
    public void testSign() {
        byte[] signedChallenge = sign(Hex.decode(privateKey), Hex.decode(challengeString));

        assertArrayEquals(Hex.decode(signatureString), signedChallenge);
    }

    @Test
    public void testVerify() {
        byte[] challenge = Hex.decode(challengeString);
        byte[] signature = Hex.decode(signatureString);
        byte[] publicKeyBytes = Hex.decode(publicKey);

        boolean verified = verify(publicKeyBytes, challenge, signature);

        assertTrue(verified);
    }
}
