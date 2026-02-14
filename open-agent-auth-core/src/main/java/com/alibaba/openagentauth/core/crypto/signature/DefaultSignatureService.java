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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Default implementation of SignatureService.
 * <p>
 * This implementation provides factory methods for creating signers and verifiers.
 * It also provides convenience methods for one-time signing and verification.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see SignatureService
 * @since 1.0
 */
public class DefaultSignatureService implements SignatureService {

    /**
     * The logger for signature service.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultSignatureService.class);
    
    /**
     * Creates a new DefaultSignatureService.
     */
    public DefaultSignatureService() {
        logger.info("DefaultSignatureService initialized");
    }

    /**
     * Creates a signer for the given private key and algorithm.
     *
     * @param privateKey the private key
     * @param algorithm the algorithm
     * @return a signer
     */
    @Override
    public Signer createSigner(PrivateKey privateKey, KeyAlgorithm algorithm) {

        // Check arguments
        ValidationUtils.validateNotNull(privateKey, "Private key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Create signer
        return new DefaultSigner(privateKey, algorithm);
    }

    /**
     * Creates a verifier for the given public key and algorithm.
     *
     * @param publicKey the public key
     * @param algorithm the algorithm
     * @return a verifier
     */
    @Override
    public Verifier createVerifier(PublicKey publicKey, KeyAlgorithm algorithm) {

        // Check arguments
        ValidationUtils.validateNotNull(publicKey, "Public key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Create verifier
        return new DefaultVerifier(publicKey, algorithm);
    }

    /**
     * Signs the given data with the given private key and algorithm.
     *
     * @param data the data
     * @param privateKey the private key
     * @param algorithm the algorithm
     * @return the signature
     */
    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey, KeyAlgorithm algorithm) throws SignatureException {

        // Check arguments
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        ValidationUtils.validateNotNull(privateKey, "Private key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Create signer
        Signer signer = createSigner(privateKey, algorithm);
        return signer.sign(data);
    }

    /**
     * Verifies the given data with the given signature, public key and algorithm.
     *
     * @param data the data
     * @param signature the signature
     * @param publicKey the public key
     * @param algorithm the algorithm
     * @return true if the signature is valid, false otherwise
     */
    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey, KeyAlgorithm algorithm) throws SignatureException {

        // Check arguments
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        ValidationUtils.validateNotNull(publicKey, "Public key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Create verifier
        Verifier verifier = createVerifier(publicKey, algorithm);
        return verifier.verify(data, signature);
    }
}