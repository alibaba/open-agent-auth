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
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

/**
 * JWE decoder implementation based on Nimbus JOSE+JWT library.
 * <p>
 * This implementation provides decryption capabilities for JWE tokens encrypted
 * with various algorithms including RSA-OAEP, ECDH-ES, and direct key encryption.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This class is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7516">RFC 7516 - JSON Web Encryption (JWE)</a>
 * @since 1.0
 */
public class NimbusJweDecoder implements JweDecoder {

    private final PrivateKey decryptionKey;

    /**
     * Constructs a new NimbusJweDecoder.
     *
     * @param decryptionKey the private key used for decryption
     * @throws NullPointerException if decryptionKey is null
     */
    public NimbusJweDecoder(PrivateKey decryptionKey) {
        this.decryptionKey = Objects.requireNonNull(decryptionKey, "decryptionKey must not be null");
    }

    @Override
    public String decryptToString(String jweString) throws JOSEException {
        Objects.requireNonNull(jweString, "jweString must not be null");
        byte[] decrypted = decryptToBytes(jweString);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decryptToBytes(String jweString) throws JOSEException {
        Objects.requireNonNull(jweString, "jweString must not be null");

        try {
            // Parse JWE string
            JWEObject jweObject = JWEObject.parse(jweString);

            // Get the JWE header to determine the algorithm
            JWEHeader header = jweObject.getHeader();

            // Create decrypter based on algorithm
            JWEDecrypter decrypter = createDecrypter(header);

            // Decrypt
            jweObject.decrypt(decrypter);

            return jweObject.getPayload().toBytes();
        } catch (java.text.ParseException e) {
            throw new JOSEException("Failed to parse JWE string", e);
        }
    }

    /**
     * Creates the appropriate JWE decrypter based on the algorithm in the JWE header.
     *
     * @param header the JWE header
     * @return the JWE decrypter
     * @throws JOSEException if the algorithm is not supported or key type mismatch
     */
    private JWEDecrypter createDecrypter(JWEHeader header) throws JOSEException {
        JWEAlgorithm algorithm = header.getAlgorithm();

        if (algorithm.equals(JWEAlgorithm.RSA_OAEP) || algorithm.equals(JWEAlgorithm.RSA_OAEP_256)) {
            // RSA key unwrapping
            if (!(decryptionKey instanceof RSAPrivateKey)) {
                throw new JOSEException("RSA private key required for RSA-OAEP algorithms");
            }
            return new RSADecrypter((RSAPrivateKey) decryptionKey);
        } else if (algorithm.equals(JWEAlgorithm.DIR)) {
            // Direct key encryption
            return new DirectDecrypter(decryptionKey.getEncoded());
        } else {
            throw new JOSEException("Unsupported JWE algorithm: " + algorithm);
        }
    }
}
