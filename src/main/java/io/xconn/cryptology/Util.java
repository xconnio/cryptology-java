package io.xconn.cryptology;

import java.security.MessageDigest;

import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Util {
    public static final int SECRET_KEY_LEN = 32;
    public static final int NONCE_SIZE = 24;
    public static final int MAC_SIZE = 16;

    public static byte[] encrypt(byte[] nonce, byte[] message, byte[] secret) {
        checkLength(secret, SECRET_KEY_LEN);
        checkLength(nonce, NONCE_SIZE);

        XSalsa20Engine cipher = new XSalsa20Engine();
        Poly1305 mac = new Poly1305();

        cipher.init(true, new ParametersWithIV(new KeyParameter(secret), nonce));
        byte[] subKey = new byte[SECRET_KEY_LEN];
        cipher.processBytes(subKey, 0, SECRET_KEY_LEN, subKey, 0);
        byte[] cipherText = new byte[message.length + mac.getMacSize()];
        cipher.processBytes(message, 0, message.length, cipherText, mac.getMacSize());

        // hash the ciphertext
        mac.init(new KeyParameter(subKey));
        mac.update(cipherText, mac.getMacSize(), message.length);
        mac.doFinal(cipherText, 0);

        return cipherText;
    }

    static void decrypt(byte[] output, byte[] nonce, byte[] ciphertext, byte[] secret) {
        checkLength(secret, SECRET_KEY_LEN);
        checkLength(nonce, NONCE_SIZE);

        XSalsa20Engine cipher = new XSalsa20Engine();
        Poly1305 mac = new Poly1305();

        cipher.init(false, new ParametersWithIV(new KeyParameter(secret), nonce));
        byte[] sk = new byte[SECRET_KEY_LEN];
        cipher.processBytes(sk, 0, sk.length, sk, 0);

        // hash ciphertext
        mac.init(new KeyParameter(sk));
        int len = Math.max(ciphertext.length - mac.getMacSize(), 0);
        mac.update(ciphertext, mac.getMacSize(), len);
        byte[] calculatedMAC = new byte[mac.getMacSize()];
        mac.doFinal(calculatedMAC, 0);

        // extract mac
        final byte[] presentedMAC = new byte[mac.getMacSize()];
        System.arraycopy(
                ciphertext, 0, presentedMAC, 0, Math.min(ciphertext.length, mac.getMacSize()));

        if (!MessageDigest.isEqual(calculatedMAC, presentedMAC)) {
            throw new IllegalArgumentException("Invalid MAC");
        }


        cipher.processBytes(ciphertext, mac.getMacSize(), output.length, output, 0);
    }

    static void checkLength(byte[] data, int size) {
        if (data == null)
            throw new NullPointerException("Input array is null.");
        else if (data.length != size) {
            throw new IllegalArgumentException("Invalid array length: " + data.length +
                    ". Length should be " + size);
        }
    }
}
