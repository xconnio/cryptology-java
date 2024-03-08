package io.xconn.cryptology;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

import static io.xconn.cryptology.Util.MAC_SIZE;
import static io.xconn.cryptology.Util.NONCE_SIZE;

public class SealedBox {
    private static final byte[] HSALSA20_SEED = new byte[16];
    public static final int PUBLIC_KEY_BYTES = 32;

    /**
     * Seals a message using recipient's publicKey.
     *
     * @param message            message to seal.
     * @param recipientPublicKey recipient's publicKey.
     * @return sealed message.
     */
    public static byte[] seal(byte[] message, byte[] recipientPublicKey) {
        byte[] cipherText = new byte[message.length + PUBLIC_KEY_BYTES + MAC_SIZE];
        seal(cipherText, message, recipientPublicKey);
        return cipherText;
    }

    /**
     * Seals a message using recipient's publicKey and writes the result to the given output array.
     *
     * @param output             output array to write the sealed message.
     * @param message            message to seal.
     * @param recipientPublicKey recipient's publicKey.
     */
    public static void seal(byte[] output, byte[] message, byte[] recipientPublicKey) {
        KeyPair keyPair = generateKeyPair();
        byte[] nonce = createNonce(keyPair.getPublicKey(), recipientPublicKey);
        byte[] sharedSecret = computeSharedSecret(recipientPublicKey, keyPair.getPrivateKey());

        byte[] ciphertext = new byte[message.length + MAC_SIZE];
        Util.encrypt(ciphertext, nonce, message, sharedSecret);

        System.arraycopy(keyPair.getPublicKey(), 0, output, 0, keyPair.getPublicKey().length);
        System.arraycopy(ciphertext, 0, output, keyPair.getPublicKey().length, ciphertext.length);
    }

    /**
     * Generates a new X25519 keypair.
     *
     * @return KeyPair object containing the public and private key bytes.
     */
    public static KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        X25519KeyGenerationParameters params = new X25519KeyGenerationParameters(random);
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(params);

        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        X25519PrivateKeyParameters privateKeyParams = (X25519PrivateKeyParameters) keyPair.getPrivate();
        X25519PublicKeyParameters publicKeyParams = (X25519PublicKeyParameters) keyPair.getPublic();

        return new KeyPair(publicKeyParams.getEncoded(), privateKeyParams.getEncoded());
    }

    /**
     * Derives the publicKey from the given privateKey.
     *
     * @param privateKeyRaw privateKey bytes.
     * @return publicKey bytes.
     */
    public static byte[] getPublicKey(byte[] privateKeyRaw) {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(privateKeyRaw, 0);

        return privateKey.generatePublicKey().getEncoded();
    }

    static byte[] createNonce(byte[] ephemeralPublicKey, byte[] recipientPublicKey) {
        Blake2bDigest blake2b = new Blake2bDigest(NONCE_SIZE * 8);
        byte[] nonce = new byte[blake2b.getDigestSize()];

        blake2b.update(ephemeralPublicKey, 0, ephemeralPublicKey.length);
        blake2b.update(recipientPublicKey, 0, recipientPublicKey.length);

        blake2b.doFinal(nonce, 0);

        return nonce;
    }

    static byte[] computeSharedSecret(byte[] publicKey, byte[] privateKey) {
        byte[] sharedSecret = new byte[32];
        // compute the raw shared secret
        X25519.scalarMult(privateKey, 0, publicKey, 0, sharedSecret, 0);
        // encrypt the shared secret
        byte[] key = new byte[32];
        HSalsa20.hsalsa20(key, HSALSA20_SEED, sharedSecret);
        return key;
    }

    /**
     * Opens a sealed message using the recipient's privateKey.
     *
     * @param message    sealed message to open.
     * @param privateKey recipient's privateKey.
     * @return opened message.
     */
    public static byte[] sealOpen(byte[] message, byte[] privateKey) {
        byte[] plainText = new byte[message.length - PUBLIC_KEY_BYTES - MAC_SIZE];
        sealOpen(plainText, message, privateKey);
        return plainText;
    }

    /**
     * Opens a sealed message using the recipient's privateKey, and writes the result to the given output array.
     *
     * @param output     output array to write the opened message.
     * @param message    sealed message to open.
     * @param privateKey recipient's privateKey.
     */
    public static void sealOpen(byte[] output, byte[] message, byte[] privateKey) {
        byte[] ephemeralPublicKey = Arrays.copyOf(message, PUBLIC_KEY_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(message, PUBLIC_KEY_BYTES, message.length);
        byte[] nonce = createNonce(ephemeralPublicKey, getPublicKey(privateKey));
        byte[] sharedSecret = computeSharedSecret(ephemeralPublicKey, privateKey);

        Util.decrypt(output, nonce, ciphertext, sharedSecret);
    }
}
