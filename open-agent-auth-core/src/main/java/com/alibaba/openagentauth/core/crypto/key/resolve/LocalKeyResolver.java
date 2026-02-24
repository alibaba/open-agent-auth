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
package com.alibaba.openagentauth.core.crypto.key.resolve;

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link KeyResolver} implementation that resolves keys from the local {@link KeyManager}.
 * <p>
 * This resolver handles key definitions where the key is stored locally (i.e., the
 * {@code jwksConsumer} property is not set). It delegates to the {@link KeyManager}
 * to retrieve or generate the key from the underlying {@code KeyStore}.
 * </p>
 *
 * <p><b>Resolution Strategy:</b></p>
 * <ol>
 *   <li>Check if the key already exists in the {@code KeyManager}</li>
 *   <li>If it exists, return the existing JWK</li>
 *   <li>If it does not exist and an algorithm is specified, generate a new key pair</li>
 *   <li>Return the generated JWK</li>
 * </ol>
 *
 * <p><b>Priority:</b> 0 (highest — local keys are checked first)</p>
 *
 * @see KeyResolver
 * @see KeyManager
 * @since 1.0
 */
public class LocalKeyResolver implements KeyResolver {

    private static final Logger logger = LoggerFactory.getLogger(LocalKeyResolver.class);

    private final KeyManager keyManager;

    /**
     * Creates a new {@code LocalKeyResolver} with the specified key manager.
     *
     * @param keyManager the key manager to resolve keys from
     * @throws IllegalArgumentException if keyManager is null
     */
    public LocalKeyResolver(KeyManager keyManager) {
        if (keyManager == null) {
            throw new IllegalArgumentException("KeyManager cannot be null");
        }
        this.keyManager = keyManager;
    }

    /**
     * Supports key definitions that are local (i.e., {@code jwksConsumer} is not set).
     *
     * @param keyDefinition the key definition to check
     * @return {@code true} if the key definition is a local key
     */
    @Override
    public boolean supports(KeyDefinition keyDefinition) {
        return keyDefinition != null && keyDefinition.isLocalKey();
    }

    /**
     * Resolves a JWK from the local {@link KeyManager}.
     * <p>
     * If the key does not exist and an algorithm is provided in the key definition,
     * a new key pair is generated automatically.
     * </p>
     *
     * @param keyDefinition the key definition describing which key to resolve
     * @return the resolved JWK
     * @throws KeyResolutionException if the key cannot be resolved
     */
    @Override
    public JWK resolve(KeyDefinition keyDefinition) throws KeyResolutionException {
        String keyId = keyDefinition.getKeyId();
        logger.debug("Resolving local key: keyId={}", keyId);

        try {
            Object jwk;
            if (keyDefinition.getAlgorithm() != null) {
                jwk = keyManager.getOrGenerateKey(keyId, keyDefinition.getAlgorithm());
            } else {
                jwk = keyManager.getSigningJWK(keyId);
            }

            if (!(jwk instanceof JWK)) {
                throw new KeyResolutionException(
                        "Resolved object is not a JWK instance for key: " + keyId);
            }

            logger.debug("Successfully resolved local key: keyId={}", keyId);
            return (JWK) jwk;
        } catch (KeyResolutionException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyResolutionException(
                    "Failed to resolve local key '" + keyId + "': " + e.getMessage(), e);
        }
    }

    /**
     * Returns the priority order of this resolver.
     *
     * @return 0 (highest priority — local keys are checked first)
     */
    @Override
    public int getOrder() {
        return 0;
    }
}
