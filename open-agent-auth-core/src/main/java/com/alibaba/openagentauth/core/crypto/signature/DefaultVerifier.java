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
package com.alibaba.openagentauth.core.crypto.signature;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.exception.crypto.SignatureException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.Signature;

/**
 * Default implementation of Verifier.
 * <p>
 * This implementation supports both RSA and ECDSA signature verification using the NimbusDS library.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see Verifier
 * @since 1.0
 */
public class DefaultVerifier implements Verifier {

    /**
     * The logger for verifier.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultVerifier.class);

    /**
     * The public key for verification.
     */
    private final PublicKey publicKey;

    /**
     * The signature algorithm.
     */
    private final KeyAlgorithm algorithm;

    /**
     * Creates a new DefaultVerifier.
     *
     * @param publicKey the public key for verification
     * @param algorithm the signature algorithm
     * @throws IllegalArgumentException if publicKey or algorithm is null
     */
    public DefaultVerifier(PublicKey publicKey, KeyAlgorithm algorithm) {

        // Check arguments
        ValidationUtils.validateNotNull(publicKey, "Public key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Initialize
        this.publicKey = publicKey;
        this.algorithm = algorithm;
        
        logger.info("DefaultVerifier initialized with algorithm: {}", algorithm);
    }

    /**
     * Verifies the signature.
     *
     * @param data the data
     * @param signature the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if the signature cannot be verified
     */
    @Override
    public boolean verify(byte[] data, byte[] signature) throws SignatureException {

        // Check arguments
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        
        try {
            // Use Java Signature API for raw data verification
            String signatureAlgorithm = getJavaSignatureAlgorithm(algorithm);
            Signature sig = java.security.Signature.getInstance(signatureAlgorithm);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new SignatureException("Failed to verify signature: " + e.getMessage(), e);
        }
    }
    
    /**
     * Maps KeyAlgorithm to Java Signature algorithm name.
     *
     * @param algorithm the key algorithm
     * @return the Java Signature algorithm name
     */
    private String getJavaSignatureAlgorithm(KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case RS256 -> "SHA256withRSA";
            case RS384 -> "SHA384withRSA";
            case RS512 -> "SHA512withRSA";
            case ES256 -> "SHA256withECDSA";
            case ES384 -> "SHA384withECDSA";
            case ES512 -> "SHA512withECDSA";
        };
    }

    /**
     * Returns the public key for verification.
     *
     * @return the public key
     */
    @Override
    public PublicKey getVerificationKey() {
        return publicKey;
    }

    /**
     * Returns the signature algorithm.
     *
     * @return the signature algorithm
     */
    @Override
    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }
}