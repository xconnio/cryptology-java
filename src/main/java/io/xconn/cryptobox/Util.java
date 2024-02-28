package io.xconn.cryptobox;

import java.security.SecureRandom;

public class Util {
    public static final int NONCE_SIZE = 24;
    public static final int SECRET_KEY_LEN = 32;

    static byte[] generateRandomBytesArray(int size) {
        byte[] randomBytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);
        return randomBytes;
    }
}
