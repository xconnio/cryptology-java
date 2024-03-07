package io.xconn.cryptology.example;

import java.util.Arrays;

import io.xconn.cryptology.CryptoSign;
import io.xconn.cryptology.KeyPair;
import io.xconn.cryptology.SealedBox;
import io.xconn.cryptology.SecretBox;

public class Main {
    public static void main(String[] args) {
        // Generate Ed25519 key pair for signing
        KeyPair signingKeyPair = CryptoSign.generateKeyPair();

        // Generate a message to sign and encrypt
        String message = "Hello, world!";
        byte[] messageBytes = message.getBytes();

        // Sign the message
        byte[] signature = CryptoSign.sign(signingKeyPair.getPrivateKey(), messageBytes);

        System.out.println("Original message: " + message);
        System.out.println("Signature: " + Arrays.toString(signature));

        // Generate X25519 key pair for encryption
        KeyPair encryptionKeyPair = SealedBox.generateKeyPair();

        // Seal the message
        byte[] sealedMessage = SealedBox.seal(messageBytes, encryptionKeyPair.getPublicKey());

        // Open the sealed message
        byte[] openedMessage = SealedBox.sealOpen(sealedMessage, encryptionKeyPair.getPrivateKey());

        System.out.println("Sealed message: " + Arrays.toString(sealedMessage));
        System.out.println("Opened message: " + new String(openedMessage));

        // Encrypt the message using SecretBox
        byte[] nonce = SecretBox.generateNonce();
        byte[] encryptedMessage = SecretBox.box(nonce, messageBytes, encryptionKeyPair.getPrivateKey());

        // Decrypt the message using SecretBox
        byte[] decryptedMessage = SecretBox.boxOpen(nonce, encryptedMessage, encryptionKeyPair.getPrivateKey());

        System.out.println("Encrypted message: " + Arrays.toString(encryptedMessage));
        System.out.println("Decrypted message: " + new String(decryptedMessage));
    }
}
