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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.ECPrivateKey;

/**
 * Default implementation of Signer.
 * <p>
 * This implementation supports both RSA and ECDSA signatures using the NimbusDS library.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see Signer
 * @since 1.0
 */
public class DefaultSigner implements Signer {

    /**
     * The logger for signer.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultSigner.class);

    /**
     * The private key for signing.
     */
    private final PrivateKey privateKey;

    /**
     * The signature algorithm.
     */
    private final KeyAlgorithm algorithm;

    /**
     * The JWS signer.
     */
    private final JWSSigner jwsSigner;
    
    /**
     * Creates a new DefaultSigner.
     *
     * @param privateKey the private key for signing
     * @param algorithm the signature algorithm
     * @throws IllegalArgumentException if privateKey or algorithm is null
     */
    public DefaultSigner(PrivateKey privateKey, KeyAlgorithm algorithm) {

        // Check arguments
        ValidationUtils.validateNotNull(privateKey, "Private key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Initialize
        this.privateKey = privateKey;
        this.algorithm = algorithm;
        try {
            this.jwsSigner = createSigner(privateKey, algorithm);
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed to create signer: " + e.getMessage(), e);
        }
        
        logger.info("DefaultSigner initialized with algorithm: {}", algorithm);
    }

    /**
     * Signs the data.
     *
     * @param data the data to sign
     * @return the signature
     * @throws SignatureException if the signature cannot be created
     */
    @Override
    public byte[] sign(byte[] data) throws SignatureException {

        // Check arguments
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        
        try {
            // Use Java Signature API for raw data signing
            String signatureAlgorithm = getJavaSignatureAlgorithm(algorithm);
            Signature signature = java.security.Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();

        } catch (Exception e) {
            throw new SignatureException("Failed to sign data: " + e.getMessage(), e);
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
     * Returns the signing key.
     *
     * @return the signing key
     */
    @Override
    public PrivateKey getSigningKey() {
        return privateKey;
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
    
    /**
     * Creates a JWS signer based on the key type.
     *
     * @param privateKey the private key
     * @param algorithm the algorithm
     * @return the JWS signer
     * @throws JOSEException if the signer cannot be created
     */
    private JWSSigner createSigner(PrivateKey privateKey, KeyAlgorithm algorithm) throws JOSEException {

        // Create signer
        if (algorithm.isRsa()) {
            if (privateKey instanceof RSAPrivateKey) {
                return new RSASSASigner(privateKey);
            } else {
                throw new JOSEException("Private key is not an RSA key");
            }
        }

        // Create signer
        if (algorithm.isEc()) {
            if (privateKey instanceof ECPrivateKey) {
                return new ECDSASigner((ECPrivateKey) privateKey);
            } else {
                throw new JOSEException("Private key is not an EC key");
            }
        }

        // Unsupported algorithm
        throw new JOSEException("Unsupported algorithm: " + algorithm);
    }
}