package io.xconn.cryptology;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import com.iwebpp.crypto.TweetNaclFast;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class InteroperabilityTest {

    private static final byte[] publicKey = Hex.decode("e54e7c4f75ea1cba7b276711ad2e88e7ac963502906724b86794d115df85114b");
    private static final byte[] privateKey = Hex.decode("28cf2aaeca5db014927f3956ac3c32141b9a08164367326b549b36bc81c3ac48");

    @Test
    public void secretBoxTest() {
        // tweetnacl is broken on java 8, lets skip the test if Java version is not 9 at least.
        assumeTrue(isJava9OrLater());

        byte[] message = "Hello, World!".getBytes();
        byte[] nonce = SecretBox.generateNonce();

        // encrypt using TweetNaCl
        TweetNaclFast.SecretBox box = new TweetNaclFast.SecretBox(privateKey);
        byte[] ct = box.box(message, nonce);

        //  decrypt using SecretBox
        byte[] plainText = SecretBox.boxOpen(nonce, ct, privateKey);

        assertArrayEquals(message, plainText);

        // encrypt using SecretBox
        byte[] cipherText = SecretBox.box(nonce, message, privateKey);

        // decrypt using TweetNaCl
        byte[] decryptedMessage = box.open(cipherText, nonce);

        assertArrayEquals(message, decryptedMessage);
    }

    @Test
    public void sealedBoxTest() throws GeneralSecurityException {
        // tweetnacl is broken on java 8, lets skip the test if Java version is not 9 at least.
        assumeTrue(isJava9OrLater());

        byte[] message = "Hello, World!".getBytes();

        // encrypt using TweetNaCl
        byte[] ct = SealedBoxNaCl.crypto_box_seal(message, publicKey);

        // decrypt using SealedBox
        byte[] plainText = SealedBox.sealOpen(ct, privateKey);

        assertArrayEquals(message, plainText);

        // encrypt using SealedBox
        byte[] cipherText = SealedBox.seal(message, publicKey);

        // decrypt using TweetNaCl
        byte[] plaintext = SealedBoxNaCl.crypto_box_seal_open(cipherText, publicKey, privateKey);

        assertArrayEquals(message, plaintext);
    }

    private boolean isJava9OrLater() {
        String version = System.getProperty("java.version");
        int majorVersion = Integer.parseInt(version.split("\\.")[0]);
        return majorVersion >= 9;
    }

    /**
     * An implementation SealedBox using TweetNaCl.
     * Taken from https://stackoverflow.com/a/42456750
     */
    static class SealedBoxNaCl {
        static byte[] crypto_box_seal(byte[] clearText, byte[] receiverPubKey) throws GeneralSecurityException {
            // create ephemeral keypair for sender
            TweetNaclFast.Box.KeyPair ephkeypair = TweetNaclFast.Box.keyPair();
            // create nonce
            byte[] nonce = SealedBox.createNonce(ephkeypair.getPublicKey(), receiverPubKey);
            TweetNaclFast.Box box = new TweetNaclFast.Box(receiverPubKey, ephkeypair.getSecretKey());
            byte[] ciphertext = box.box(clearText, nonce);
            if (ciphertext == null) throw new GeneralSecurityException("could not create box");

            byte[] sealedbox = new byte[ciphertext.length + SealedBox.PUBLIC_KEY_BYTES];
            byte[] ephpubkey = ephkeypair.getPublicKey();

            System.arraycopy(ephpubkey, 0, sealedbox, 0, SealedBox.PUBLIC_KEY_BYTES);
            System.arraycopy(ciphertext, 0, sealedbox, 32, ciphertext.length);

            return sealedbox;
        }

        public static byte[] crypto_box_seal_open(byte[] c, byte[] pk, byte[] sk) throws GeneralSecurityException {
            if (c.length < SealedBox.PUBLIC_KEY_BYTES + Util.MAC_SIZE)
                throw new IllegalArgumentException("Ciphertext too short");

            byte[] pksender = Arrays.copyOfRange(c, 0, SealedBox.PUBLIC_KEY_BYTES);
            byte[] ciphertextwithmac = Arrays.copyOfRange(c, SealedBox.PUBLIC_KEY_BYTES, c.length);
            byte[] nonce = SealedBox.createNonce(pksender, pk);

            TweetNaclFast.Box box = new TweetNaclFast.Box(pksender, sk);
            byte[] cleartext = box.open(ciphertextwithmac, nonce);
            if (cleartext == null) throw new GeneralSecurityException("could not open box");
            return cleartext;
        }
    }
}
