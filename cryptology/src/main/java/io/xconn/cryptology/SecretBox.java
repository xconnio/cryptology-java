/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 * Copyright © 2024 XConnIO
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.xconn.cryptology;

import static io.xconn.cryptology.Util.MAC_SIZE;
import static io.xconn.cryptology.Util.NONCE_SIZE;
import static io.xconn.cryptology.Util.SECRET_KEY_LEN;

public class SecretBox {

    /**
     * Encrypts a message using a nonce and privateKey.
     *
     * @param nonce      nonce for encryption.
     * @param message    message to encrypt.
     * @param privateKey privateKey for encryption.
     * @return encrypted message.
     */
    public static byte[] box(byte[] nonce, byte[] message, byte[] privateKey) {
        byte[] output = new byte[message.length + MAC_SIZE];
        box(output, nonce, message, privateKey);

        return output;
    }

    /**
     * Encrypts a message using nonce, privateKey and writes the result to the given output array.
     *
     * @param output     output array to write the encrypted message.
     * @param nonce      nonce for encryption.
     * @param message    message to encrypt.
     * @param privateKey privateKey for encryption.
     */
    public static void box(byte[] output, byte[] nonce, byte[] message, byte[] privateKey) {
        Util.encrypt(output, nonce, message, privateKey);
    }


    /**
     * Decrypts a ciphertext using nonce and privateKey.
     *
     * @param nonce      nonce for decryption.
     * @param ciphertext ciphertext to decrypt.
     * @param privateKey privateKey for decryption.
     * @return decrypted message.
     */
    public static byte[] boxOpen(byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        byte[] plainText = new byte[ciphertext.length - MAC_SIZE];
        boxOpen(plainText, nonce, ciphertext, privateKey);

        return plainText;
    }

    /**
     * Decrypts a ciphertext using nonce, private key, and writes the result to the given output array.
     *
     * @param output     output array to write the decrypted message.
     * @param nonce      nonce for decryption.
     * @param ciphertext ciphertext to decrypt.
     * @param privateKey privateKey for decryption.
     */
    public static void boxOpen(byte[] output, byte[] nonce, byte[] ciphertext, byte[] privateKey) {
        Util.decrypt(output, nonce, ciphertext, privateKey);
    }

    /**
     * Generates a new secret key.
     *
     * @return generated secret key.
     */
    public static byte[] generateSecret() {
        return Util.generateRandomBytesArray(SECRET_KEY_LEN);
    }

    /**
     * Generates a new nonce.
     *
     * @return generated nonce.
     */
    public static byte[] generateNonce() {
        return Util.generateRandomBytesArray(NONCE_SIZE);
    }
}
