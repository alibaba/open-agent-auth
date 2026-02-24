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
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link KeyResolver} implementation that resolves keys from remote JWKS endpoints.
 * <p>
 * This resolver handles key definitions where the {@code jwksConsumer} property is set,
 * indicating that the key should be fetched from a remote JWKS endpoint. The consumer
 * name maps to a configured JWKS endpoint URL.
 * </p>
 *
 * <p><b>Caching:</b></p>
 * <p>
 * Resolved JWK sets are cached per consumer name to avoid redundant network calls.
 * The cache can be refreshed by calling {@link #clearCache()} or
 * {@link #clearCache(String)}.
 * </p>
 *
 * <p><b>Priority:</b> 10 (lower than {@link LocalKeyResolver})</p>
 *
 * @see KeyResolver
 * @since 1.0
 */
public class JwksConsumerKeyResolver implements KeyResolver {

    private static final Logger logger = LoggerFactory.getLogger(JwksConsumerKeyResolver.class);

    /**
     * Mapping from JWKS consumer name to its endpoint URL.
     */
    private final Map<String, String> consumerEndpoints;

    /**
     * Cache of resolved JWK sets, keyed by consumer name.
     */
    private final ConcurrentHashMap<String, JWKSet> jwkSetCache = new ConcurrentHashMap<>();

    /**
     * Creates a new {@code JwksConsumerKeyResolver} with the specified consumer endpoint mappings.
     *
     * @param consumerEndpoints mapping from consumer name to JWKS endpoint URL
     * @throws IllegalArgumentException if consumerEndpoints is null
     */
    public JwksConsumerKeyResolver(Map<String, String> consumerEndpoints) {
        if (consumerEndpoints == null) {
            throw new IllegalArgumentException("Consumer endpoints map cannot be null");
        }
        this.consumerEndpoints = consumerEndpoints;
        logger.info("JwksConsumerKeyResolver initialized with {} consumer(s): {}",
                consumerEndpoints.size(), consumerEndpoints.keySet());
    }

    /**
     * Supports key definitions that have a {@code jwksConsumer} set and the consumer
     * is registered in this resolver.
     *
     * @param keyDefinition the key definition to check
     * @return {@code true} if the key definition requires remote JWKS resolution
     *         and the consumer is known
     */
    @Override
    public boolean supports(KeyDefinition keyDefinition) {
        if (keyDefinition == null || !keyDefinition.isRemoteKey()) {
            return false;
        }
        return consumerEndpoints.containsKey(keyDefinition.getJwksConsumer());
    }

    /**
     * Resolves a JWK from a remote JWKS endpoint.
     * <p>
     * The method fetches the JWK set from the endpoint associated with the consumer name
     * in the key definition, then searches for the key by its key ID.
     * </p>
     *
     * @param keyDefinition the key definition describing which key to resolve
     * @return the resolved JWK
     * @throws KeyResolutionException if the key cannot be resolved
     */
    @Override
    public JWK resolve(KeyDefinition keyDefinition) throws KeyResolutionException {
        String consumerName = keyDefinition.getJwksConsumer();
        String keyId = keyDefinition.getKeyId();

        String jwksEndpoint = consumerEndpoints.get(consumerName);
        if (jwksEndpoint == null || jwksEndpoint.isBlank()) {
            throw new KeyResolutionException(
                    "No JWKS endpoint configured for consumer '" + consumerName + "'");
        }

        logger.debug("Resolving remote key: keyId={}, consumer={}, endpoint={}",
                keyId, consumerName, jwksEndpoint);

        try {
            JWKSet jwkSet = jwkSetCache.computeIfAbsent(consumerName, name -> {
                try {
                    logger.info("Fetching JWKS from consumer '{}': {}", name, jwksEndpoint);
                    return JWKSet.load(new URL(jwksEndpoint));
                } catch (Exception e) {
                    throw new RuntimeException(
                            "Failed to fetch JWKS from '" + name + "' at " + jwksEndpoint, e);
                }
            });

            JWK resolvedKey = jwkSet.getKeyByKeyId(keyId);
            if (resolvedKey == null) {
                // Cache might be stale — retry with a fresh fetch
                logger.info("Key '{}' not found in cached JWKS for consumer '{}', refreshing...",
                        keyId, consumerName);
                jwkSetCache.remove(consumerName);

                jwkSet = JWKSet.load(new URL(jwksEndpoint));
                jwkSetCache.put(consumerName, jwkSet);

                resolvedKey = jwkSet.getKeyByKeyId(keyId);
                if (resolvedKey == null) {
                    throw new KeyResolutionException(
                            "Key '" + keyId + "' not found in JWKS from consumer '" +
                                    consumerName + "' at " + jwksEndpoint);
                }
            }

            logger.debug("Successfully resolved remote key: keyId={}, consumer={}, keyType={}",
                    keyId, consumerName, resolvedKey.getKeyType());
            return resolvedKey;
        } catch (KeyResolutionException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyResolutionException(
                    "Failed to resolve key '" + keyId + "' from consumer '" +
                            consumerName + "': " + e.getMessage(), e);
        }
    }

    /**
     * Returns the priority order of this resolver.
     *
     * @return 10 (lower priority than {@link LocalKeyResolver})
     */
    @Override
    public int getOrder() {
        return 10;
    }

    /**
     * Clears the entire JWK set cache, forcing fresh fetches on next resolution.
     */
    public void clearCache() {
        jwkSetCache.clear();
        logger.info("Cleared all JWKS consumer caches");
    }

    /**
     * Clears the JWK set cache for a specific consumer.
     *
     * @param consumerName the consumer name whose cache should be cleared
     */
    public void clearCache(String consumerName) {
        jwkSetCache.remove(consumerName);
        logger.info("Cleared JWKS cache for consumer: {}", consumerName);
    }
}
