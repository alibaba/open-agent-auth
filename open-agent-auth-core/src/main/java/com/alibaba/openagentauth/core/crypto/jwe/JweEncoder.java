/*
 * Copyright 2026 Alibaba Group Holding Ltd.
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
package com.alibaba.openagentauth.core.crypto.jwe;

import com.nimbusds.jose.JOSEException;

/**
 * Interface for JWE (JSON Web Encryption) encoding operations.
 * <p>
 * This interface provides the ability to encrypt plaintext data into JWE format
 * as specified in RFC 7516. Implementations support various encryption algorithms
 * including RSA-OAEP, ECDH-ES, and direct key encryption.
 * </p>
 * <p>
 * <b>Supported Algorithms:</b></p>
 * <ul>
 *   <li><b>Key Encryption Algorithms:</b> RSA-OAEP, RSA-OAEP-256, ECDH-ES, dir</li>
 *   <li><b>Content Encryption Algorithms:</b> A128GCM, A192GCM, A256GCM, A128CBC-HS256, A256CBC-HS512</li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * JweEncoder encoder = new NimbusJweEncoder(encryptionJwk, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
 * 
 * // Encrypt string
 * String encrypted = encoder.encrypt("sensitive data");
 * 
 * // Encrypt bytes
 * byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);
 * String encrypted = encoder.encrypt(plaintext);
 * }</pre>
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations of this interface should be thread-safe and can be used
 * concurrently from multiple threads.
 * </p>
 *
 * @see JweDecoder
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7516">RFC 7516 - JSON Web Encryption (JWE)</a>
 * @since 1.0
 */
public interface JweEncoder {

    /**
     * Encrypts a string into JWE format.
     * <p>
     * This method converts the plaintext string to UTF-8 bytes and encrypts it
     * using the configured encryption algorithm and key.
     * </p>
     *
     * @param plaintext the plaintext string to encrypt
     * @return the JWE-encrypted string in compact serialization format
     * @throws JOSEException if encryption fails
     * @throws IllegalArgumentException if plaintext is null
     */
    String encrypt(String plaintext) throws JOSEException;

    /**
     * Encrypts a byte array into JWE format.
     * <p>
     * This method encrypts the provided plaintext bytes using the configured
     * encryption algorithm and key.
     * </p>
     *
     * @param plaintext the plaintext bytes to encrypt
     * @return the JWE-encrypted string in compact serialization format
     * @throws JOSEException if encryption fails
     * @throws IllegalArgumentException if plaintext is null
     */
    String encrypt(byte[] plaintext) throws JOSEException;
}
