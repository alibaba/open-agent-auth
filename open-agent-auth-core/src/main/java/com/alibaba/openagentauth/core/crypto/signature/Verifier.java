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

import java.security.PublicKey;

/**
 * Interface for verifying signatures using cryptographic keys.
 * <p>
 * This interface provides a unified abstraction for signature verification operations
 * across different signature types (JWT, HTTP Message Signatures, etc.) and algorithms.
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
 * @see KeyAlgorithm
 * @since 1.0
 */
public interface Verifier {
    
    /**
     * Verifies the signature of the specified data.
     *
     * @param data the data that was signed
     * @param signature the signature to verify
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if verification fails due to an error
     * @throws IllegalArgumentException if data or signature is null or empty
     */
    boolean verify(byte[] data, byte[] signature) throws SignatureException;
    
    /**
     * Gets the verification key.
     *
     * @return the public key
     */
    PublicKey getVerificationKey();
    
    /**
     * Gets the signature algorithm.
     *
     * @return the algorithm
     */
    KeyAlgorithm getAlgorithm();
}
