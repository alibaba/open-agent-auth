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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Service for creating signers and verifiers.
 * <p>
 * This factory interface provides a unified way to create signers and verifiers
 * for different algorithms and use cases.
 * </p>
 * <p>
 * <b>Supported Algorithms:</b></p>
 * <ul>
 *   <li><b>RS256/RS384/RS512:</b> RSA signatures</li>
 *   <li><b>ES256/ES384/ES512:</b> ECDSA signatures</li>
 * </ul>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations of this interface should be thread-safe and can be used
 * concurrently from multiple threads.
 * </p>
 *
 * @see Signer
 * @see Verifier
 * @see KeyAlgorithm
 * @since 1.0
 */
public interface SignatureService {
    
    /**
     * Creates a signer with the specified private key and algorithm.
     *
     * @param privateKey the private key for signing
     * @param algorithm the signature algorithm
     * @return the signer
     * @throws IllegalArgumentException if privateKey or algorithm is null
     */
    Signer createSigner(PrivateKey privateKey, KeyAlgorithm algorithm);
    
    /**
     * Creates a verifier with the specified public key and algorithm.
     *
     * @param publicKey the public key for verification
     * @param algorithm the signature algorithm
     * @return the verifier
     * @throws IllegalArgumentException if publicKey or algorithm is null
     */
    Verifier createVerifier(PublicKey publicKey, KeyAlgorithm algorithm);
    
    /**
     * Signs the specified data using the specified private key and algorithm.
     *
     * @param data the data to sign
     * @param privateKey the private key for signing
     * @param algorithm the signature algorithm
     * @return the signature
     * @throws SignatureException if signing fails
     * @throws IllegalArgumentException if parameters are invalid
     */
    byte[] sign(byte[] data, PrivateKey privateKey, KeyAlgorithm algorithm) throws SignatureException;
    
    /**
     * Verifies the signature of the specified data using the specified public key and algorithm.
     *
     * @param data the data that was signed
     * @param signature the signature to verify
     * @param publicKey the public key for verification
     * @param algorithm the signature algorithm
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if verification fails due to an error
     * @throws IllegalArgumentException if parameters are invalid
     */
    boolean verify(byte[] data, byte[] signature, PublicKey publicKey, KeyAlgorithm algorithm) throws SignatureException;
}
