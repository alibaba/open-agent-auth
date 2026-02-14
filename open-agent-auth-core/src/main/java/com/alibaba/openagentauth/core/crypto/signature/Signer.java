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

/**
 * Interface for signing data using cryptographic keys.
 * <p>
 * This interface provides a unified abstraction for signing operations across
 * different signature types (JWT, HTTP Message Signatures, etc.) and algorithms.
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
 * @see Verifier
 * @see KeyAlgorithm
 * @since 1.0
 */
public interface Signer {
    
    /**
     * Signs the specified data using the configured private key.
     *
     * @param data the data to sign
     * @return the signature
     * @throws SignatureException if signing fails
     * @throws IllegalArgumentException if data is null or empty
     */
    byte[] sign(byte[] data) throws SignatureException;
    
    /**
     * Gets the signing key.
     *
     * @return the private key
     */
    PrivateKey getSigningKey();
    
    /**
     * Gets the signature algorithm.
     *
     * @return the algorithm
     */
    KeyAlgorithm getAlgorithm();
}
