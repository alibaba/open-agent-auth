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
 * Interface for JWE (JSON Web Encryption) decoding operations.
 * <p>
 * This interface provides the ability to decrypt JWE-formatted data back to
 * plaintext as specified in RFC 7516. Implementations support the same set
 * of encryption algorithms as the corresponding encoder.
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
 * JweDecoder decoder = new NimbusJweDecoder(decryptionKey, jwkSource);
 * 
 * // Decrypt to string
 * String decrypted = decoder.decryptToString(encryptedJwe);
 * 
 * // Decrypt to bytes
 * byte[] decrypted = decoder.decryptToBytes(encryptedJwe);
 * }</pre>
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations of this interface should be thread-safe and can be used
 * concurrently from multiple threads.
 * </p>
 *
 * @see JweEncoder
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7516">RFC 7516 - JSON Web Encryption (JWE)</a>
 * @since 1.0
 */
public interface JweDecoder {

    /**
     * Decrypts a JWE string to a plaintext string.
     * <p>
     * This method decrypts the JWE-formatted string and converts the resulting
     * bytes to a UTF-8 string.
     * </p>
     *
     * @param jweString the JWE-encrypted string in compact serialization format
     * @return the decrypted plaintext string
     * @throws JOSEException if decryption fails
     * @throws IllegalArgumentException if jweString is null or invalid
     */
    String decryptToString(String jweString) throws JOSEException;

    /**
     * Decrypts a JWE string to a byte array.
     * <p>
     * This method decrypts the JWE-formatted string and returns the raw
     * plaintext bytes.
     * </p>
     *
     * @param jweString the JWE-encrypted string in compact serialization format
     * @return the decrypted plaintext bytes
     * @throws JOSEException if decryption fails
     * @throws IllegalArgumentException if jweString is null or invalid
     */
    byte[] decryptToBytes(String jweString) throws JOSEException;
}
