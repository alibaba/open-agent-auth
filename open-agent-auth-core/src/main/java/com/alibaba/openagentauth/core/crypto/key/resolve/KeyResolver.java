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

import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.jwk.JWK;

/**
 * Service Provider Interface (SPI) for resolving cryptographic keys from various sources.
 * <p>
 * This interface enables a pluggable key resolution strategy, allowing the framework
 * to resolve keys from different backends without coupling to any specific implementation.
 * Each {@code KeyResolver} implementation handles a specific type of key source
 * (e.g., local key store, remote JWKS endpoint, file system, external KMS).
 * </p>
 *
 * <p><b>Design Pattern:</b> Strategy Pattern + Chain of Responsibility</p>
 * <p>
 * Multiple {@code KeyResolver} implementations can be registered in the application context.
 * The framework iterates through them in order, using the first resolver that
 * {@linkplain #supports(KeyDefinition) supports} the given key definition.
 * </p>
 *
 * <p><b>Built-in Implementations:</b></p>
 * <ul>
 *   <li>{@link LocalKeyResolver} — resolves keys from the local {@code KeyStore}</li>
 *   <li>{@link JwksConsumerKeyResolver} — resolves keys from remote JWKS endpoints</li>
 * </ul>
 *
 * <p><b>Custom Extension Example:</b></p>
 * <pre>{@code
 * @Component
 * public class VaultKeyResolver implements KeyResolver {
 *
 *     @Override
 *     public boolean supports(KeyDefinition keyDefinition) {
 *         return "vault".equals(keyDefinition.getProvider());
 *     }
 *
 *     @Override
 *     public JWK resolve(KeyDefinition keyDefinition) throws KeyResolutionException {
 *         // Fetch key from HashiCorp Vault
 *     }
 *
 *     @Override
 *     public int getOrder() {
 *         return 100; // Lower priority than built-in resolvers
 *     }
 * }
 * }</pre>
 *
 * @see KeyDefinition
 * @see LocalKeyResolver
 * @see JwksConsumerKeyResolver
 * @since 1.0
 */
public interface KeyResolver {

    /**
     * Determines whether this resolver can handle the given key definition.
     * <p>
     * The framework calls this method before {@link #resolve(KeyDefinition)} to check
     * if this resolver is appropriate for the key's configuration. Implementations
     * should inspect the key definition's properties (e.g., provider, jwksConsumer)
     * to make this determination.
     * </p>
     *
     * @param keyDefinition the key definition to check
     * @return {@code true} if this resolver can resolve the key, {@code false} otherwise
     */
    boolean supports(KeyDefinition keyDefinition);

    /**
     * Resolves a JWK from the configured source based on the key definition.
     * <p>
     * This method is called only when {@link #supports(KeyDefinition)} returns {@code true}.
     * Implementations should fetch or construct the JWK from their respective backend
     * and return it. The returned JWK may be either a public key (for verification/encryption)
     * or a key pair (for signing/decryption), depending on the source.
     * </p>
     *
     * @param keyDefinition the key definition describing which key to resolve
     * @return the resolved JWK (never {@code null})
     * @throws KeyResolutionException if the key cannot be resolved
     */
    JWK resolve(KeyDefinition keyDefinition) throws KeyResolutionException;

    /**
     * Returns the priority order of this resolver.
     * <p>
     * Lower values indicate higher priority. When multiple resolvers support the same
     * key definition, the one with the lowest order value is used first.
     * </p>
     * <p>
     * Built-in resolvers use the following order values:
     * <ul>
     *   <li>{@link LocalKeyResolver}: 0 (highest priority)</li>
     *   <li>{@link JwksConsumerKeyResolver}: 10</li>
     * </ul>
     * Custom resolvers should use values of 100 or higher to avoid conflicts.
     * </p>
     *
     * @return the order value (lower = higher priority)
     */
    default int getOrder() {
        return 100;
    }
}
