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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * JWE encoder implementation based on Nimbus JOSE+JWT library.
 * <p>
 * This implementation provides encryption capabilities using various algorithms:
 * <ul>
 *   <li><b>RSA-OAEP / RSA-OAEP-256:</b> Asymmetric key wrapping using RSA</li>
 *   <li><b>ECDH-ES:</b> Key agreement using Elliptic Curve Diffie-Hellman</li>
 *   <li><b>dir:</b> Direct use of shared symmetric key</li>
 * </ul>
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This class is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7516">RFC 7516 - JSON Web Encryption (JWE)</a>
 * @since 1.0
 */
public class NimbusJweEncoder implements JweEncoder {

    private final JWK encryptionJwk;
    private final JWEAlgorithm jweAlgorithm;
    private final EncryptionMethod encryptionMethod;

    /**
     * Constructs a new NimbusJweEncoder.
     *
     * @param encryptionJwk the JWK used for encryption (public key for RSA/EC, shared key for dir)
     * @param jweAlgorithm the JWE key encryption algorithm
     * @param encryptionMethod the content encryption algorithm
     * @throws NullPointerException if any parameter is null
     */
    public NimbusJweEncoder(JWK encryptionJwk, JWEAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
        this.encryptionJwk = Objects.requireNonNull(encryptionJwk, "encryptionJwk must not be null");
        this.jweAlgorithm = Objects.requireNonNull(jweAlgorithm, "jweAlgorithm must not be null");
        this.encryptionMethod = Objects.requireNonNull(encryptionMethod, "encryptionMethod must not be null");
    }

    @Override
    public String encrypt(String plaintext) throws JOSEException {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        return encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String encrypt(byte[] plaintext) throws JOSEException {
        Objects.requireNonNull(plaintext, "plaintext must not be null");

        // Create JWE header with algorithm and key ID
        JWEHeader header = new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
                .keyID(encryptionJwk.getKeyID())
                .build();

        // Create JWE object with payload
        JWEObject jweObject = new JWEObject(header, new Payload(plaintext));

        // Encrypt using appropriate encrypter based on key type
        JWEEncrypter encrypter = createEncrypter();
        jweObject.encrypt(encrypter);

        return jweObject.serialize();
    }

    /**
     * Creates the appropriate JWE encrypter based on the key type and algorithm.
     *
     * @return the JWE encrypter
     * @throws JOSEException if the key type or algorithm is not supported
     */
    private JWEEncrypter createEncrypter() throws JOSEException {
        if (encryptionJwk instanceof RSAKey) {
            // RSA key wrapping
            return new RSAEncrypter((RSAKey) encryptionJwk);
        } else if (encryptionJwk instanceof ECKey) {
            // ECDH key agreement
            return new ECDHEncrypter((ECKey) encryptionJwk);
        } else if (encryptionJwk instanceof OctetSequenceKey) {
            // Direct key encryption
            if (jweAlgorithm.equals(JWEAlgorithm.DIR)) {
                return new DirectEncrypter((OctetSequenceKey) encryptionJwk);
            } else {
                throw new JOSEException("OctetSequenceKey can only be used with DIR algorithm");
            }
        } else {
            throw new JOSEException("Unsupported key type: " + encryptionJwk.getKeyType());
        }
    }
}
