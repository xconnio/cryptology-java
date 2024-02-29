package io.xconn.cryptology;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class Util {
    public static final int NONCE_SIZE = 24;
    public static final int SECRET_KEY_LEN = 32;
    public static final int PUBLIC_KEY_BYTES = 32;
    public static int MAC_SIZE = 16;

    static byte[] generateRandomBytesArray(int size) {
        byte[] randomBytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    public static byte[] getX25519PublicKey(byte[] privateKeyRaw) {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(privateKeyRaw, 0);

        return privateKey.generatePublicKey().getEncoded();
    }

    public static KeyPair generateX25519KeyPair() {
        SecureRandom random = new SecureRandom();
        X25519KeyGenerationParameters params = new X25519KeyGenerationParameters(random);
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(params);

        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        X25519PrivateKeyParameters privateKeyParams = (X25519PrivateKeyParameters) keyPair.getPrivate();
        X25519PublicKeyParameters publicKeyParams = (X25519PublicKeyParameters) keyPair.getPublic();

        return new KeyPair(publicKeyParams.getEncoded(), privateKeyParams.getEncoded());
    }
}
