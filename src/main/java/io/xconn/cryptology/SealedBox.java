package io.xconn.cryptology;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

public class SealedBox {
    private static final byte[] HSALSA20_SEED = new byte[16];
    public static final int NONCE_SIZE = 24;
    public static final int PUBLIC_KEY_BYTES = 32;
    public static final int PRIVATE_KEY_BYTES = 32;
    public static final int MAC_SIZE = 16;

    public static byte[] seal(byte[] message, byte[] recipientPublicKey) {
        byte[] cipherText = new byte[message.length + PUBLIC_KEY_BYTES + MAC_SIZE];
        seal(cipherText, message, recipientPublicKey);
        return cipherText;
    }

    public static void seal(byte[] output, byte[] message, byte[] recipientPublicKey) {
        KeyPair keyPair = generateKeyPair();
        byte[] nonce = createNonce(keyPair.getPublicKey(), recipientPublicKey);
        byte[] sharedSecret = computeSharedSecret(recipientPublicKey, keyPair.getPrivateKey());

        XSalsa20Engine cipher = new XSalsa20Engine();
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(sharedSecret), nonce);
        cipher.init(true, params);

        byte[] sk = new byte[PRIVATE_KEY_BYTES];
        cipher.processBytes(sk, 0, sk.length, sk, 0);

        // encrypt the message
        byte[] ciphertext = new byte[message.length];
        cipher.processBytes(message, 0, message.length, ciphertext, 0);

        // create the MAC
        Poly1305 mac = new Poly1305();
        byte[] macBuf = new byte[mac.getMacSize()];
        mac.init(new KeyParameter(sk));
        mac.update(ciphertext, 0, ciphertext.length);
        mac.doFinal(macBuf, 0);

        System.arraycopy(keyPair.getPublicKey(), 0, output, 0, keyPair.getPublicKey().length);
        System.arraycopy(macBuf, 0, output, keyPair.getPublicKey().length, macBuf.length);
        System.arraycopy(ciphertext, 0, output, keyPair.getPublicKey().length + macBuf.length, ciphertext.length);
    }

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

    public static byte[] sealOpen(byte[] message, byte[] privateKey) {
        byte[] plainText = new byte[message.length - PUBLIC_KEY_BYTES - MAC_SIZE];
        sealOpen(plainText, message, privateKey);
        return plainText;
    }

    public static void sealOpen(byte[] output, byte[] message, byte[] privateKey) {
        byte[] ephemeralPublicKey = Arrays.copyOf(message, PUBLIC_KEY_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(message, PUBLIC_KEY_BYTES, message.length);
        byte[] nonce = createNonce(ephemeralPublicKey, getPublicKey(privateKey));
        byte[] sharedSecret = computeSharedSecret(ephemeralPublicKey, privateKey);

        SecretBox.boxOpen(output, nonce, ciphertext, sharedSecret);
    }
}
