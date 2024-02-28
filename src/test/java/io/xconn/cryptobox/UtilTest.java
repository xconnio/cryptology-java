package io.xconn.cryptobox;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class UtilTest {

    @Test
    public void testGenerateRandomBytesArray() {
        int size = 32;
        byte[] randomBytes = Util.generateRandomBytesArray(size);

        assertNotNull(randomBytes);
        assertEquals(size, randomBytes.length);
    }

}
