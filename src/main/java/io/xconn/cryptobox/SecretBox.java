package io.xconn.cryptobox;

import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.MessageDigest;
import java.util.Arrays;

public class SecretBox {

    static int MAC_SIZE = 16;

    public static byte[] box(byte[] message, byte[] key) {
        checkLength(key, Util.SECRET_KEY_LEN);

        byte[] nonce = Util.generateRandomBytesArray(Util.NONCE_SIZE);
        byte[] output = new byte[message.length + MAC_SIZE + Util.NONCE_SIZE];
        box(output, nonce, message, key);

        return output;
    }

    public static void box(byte[] output, byte[] message, byte[] key) {
        checkLength(key, Util.SECRET_KEY_LEN);

        byte[] nonce = Util.generateRandomBytesArray(Util.NONCE_SIZE);
        box(output, nonce, message, key);
    }

    static void box(byte[] output, byte[] nonce, byte[] plaintext, byte[] key) {
        checkLength(nonce, Util.NONCE_SIZE);

        XSalsa20Engine cipher = new XSalsa20Engine();
        Poly1305 mac = new Poly1305();

        cipher.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] subKey = new byte[Util.SECRET_KEY_LEN];
        cipher.processBytes(subKey, 0, Util.SECRET_KEY_LEN, subKey, 0);
        byte[] cipherWithoutNonce = new byte[plaintext.length + mac.getMacSize()];
        cipher.processBytes(plaintext, 0, plaintext.length, cipherWithoutNonce, mac.getMacSize());

        // hash the ciphertext
        mac.init(new KeyParameter(subKey));
        mac.update(cipherWithoutNonce, mac.getMacSize(), plaintext.length);
        mac.doFinal(cipherWithoutNonce, 0);

        System.arraycopy(nonce, 0, output, 0, nonce.length);
        System.arraycopy(cipherWithoutNonce, 0, output, nonce.length, cipherWithoutNonce.length);
    }


    public static byte[] boxOpen(byte[] ciphertext, byte[] key) {
        checkLength(key, Util.SECRET_KEY_LEN);

        byte[] nonce = Arrays.copyOfRange(ciphertext, 0, Util.NONCE_SIZE);
        byte[] message = Arrays.copyOfRange(ciphertext, Util.NONCE_SIZE,
                ciphertext.length);
        byte[] plainText = new byte[message.length - MAC_SIZE];
        boxOpen(plainText, nonce, message, key);

        return plainText;
    }

    public static void boxOpen(byte[] output, byte[] ciphertext, byte[] key) {
        checkLength(key, Util.SECRET_KEY_LEN);

        byte[] nonce = Arrays.copyOfRange(ciphertext, 0, Util.NONCE_SIZE);
        byte[] message = Arrays.copyOfRange(ciphertext, Util.NONCE_SIZE,
                ciphertext.length);

        boxOpen(output, nonce, message, key);
    }

    static void boxOpen(byte[] output, byte[] nonce, byte[] ciphertext, byte[] key) {
        checkLength(nonce, Util.NONCE_SIZE);

        XSalsa20Engine xsalsa20 = new XSalsa20Engine();
        Poly1305 poly1305 = new Poly1305();

        xsalsa20.init(false, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] sk = new byte[Util.SECRET_KEY_LEN];
        xsalsa20.processBytes(sk, 0, sk.length, sk, 0);

        // hash ciphertext
        poly1305.init(new KeyParameter(sk));
        int len = Math.max(ciphertext.length - poly1305.getMacSize(), 0);
        poly1305.update(ciphertext, poly1305.getMacSize(), len);
        byte[] calculatedMAC = new byte[poly1305.getMacSize()];
        poly1305.doFinal(calculatedMAC, 0);

        // extract mac
        final byte[] presentedMAC = new byte[poly1305.getMacSize()];
        System.arraycopy(
                ciphertext, 0, presentedMAC, 0, Math.min(ciphertext.length, poly1305.getMacSize()));

        if (!MessageDigest.isEqual(calculatedMAC, presentedMAC)) {
            throw new IllegalArgumentException("Invalid MAC");
        }


        xsalsa20.processBytes(ciphertext, poly1305.getMacSize(), output.length, output, 0);
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
