package io.xconn.cryptology;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public class CryptoSign {
    public static KeyPair generateKeyPair() {
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));

        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

        return new KeyPair(publicKey.getEncoded(), privateKey.getEncoded());
    }

    public static byte[] getPublicKey(byte[] privateKey) {
        Ed25519PrivateKeyParameters privateKeyParam = new Ed25519PrivateKeyParameters(privateKey, 0);

        return privateKeyParam.generatePublicKey().getEncoded();
    }


    public static byte[] sign(byte[] privateKey, byte[] challenge) {
        Ed25519PrivateKeyParameters privateKeyParam = new Ed25519PrivateKeyParameters(privateKey, 0);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKeyParam);
        signer.update(challenge, 0, challenge.length);

        return signer.generateSignature();
    }
}
