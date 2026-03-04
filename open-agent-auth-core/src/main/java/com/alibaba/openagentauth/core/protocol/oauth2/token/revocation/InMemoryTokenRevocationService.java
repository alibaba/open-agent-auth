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
package com.alibaba.openagentauth.core.protocol.oauth2.token.revocation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link TokenRevocationService}.
 * <p>
 * This implementation stores revoked tokens in a thread-safe in-memory set backed by
 * {@link ConcurrentHashMap}. It is suitable for single-instance deployments and
 * development/testing scenarios.
 * </p>
 * <p>
 * <b>Limitations:</b>
 * <ul>
 *   <li>Revoked tokens are lost on application restart</li>
 *   <li>Not suitable for distributed or clustered deployments</li>
 *   <li>Memory usage grows with the number of revoked tokens</li>
 * </ul>
 * </p>
 * <p>
 * For production environments with multiple instances or persistence requirements,
 * consider implementing a {@code TokenRevocationService} that stores revoked tokens
 * in a distributed cache or database.
 * </p>
 *
 * @since 1.0
 */
public class InMemoryTokenRevocationService implements TokenRevocationService {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryTokenRevocationService.class);

    /**
     * Thread-safe set storing revoked token strings.
     */
    private final Set<String> revokedTokens;

    /**
     * Creates a new in-memory token revocation service.
     */
    public InMemoryTokenRevocationService() {
        this.revokedTokens = ConcurrentHashMap.newKeySet();
        logger.info("InMemoryTokenRevocationService initialized");
    }

    /**
     * Revokes the specified token by adding it to the revoked token set.
     * <p>
     * This operation is idempotent - adding an already revoked token has no effect.
     * </p>
     *
     * @param token the token string to revoke
     * @throws NullPointerException if {@code token} is null
     */
    @Override
    public void revoke(String token) {
        if (token == null) {
            throw new NullPointerException("Token cannot be null");
        }
        boolean added = revokedTokens.add(token);
        logger.debug("Token revocation attempted, added: {}", added);
    }

    /**
     * Checks whether the specified token has been revoked.
     *
     * @param token the token string to check
     * @return {@code true} if the token is in the revoked set, {@code false} otherwise
     */
    @Override
    public boolean isRevoked(String token) {
        if (token == null) {
            return false;
        }
        return revokedTokens.contains(token);
    }
}
