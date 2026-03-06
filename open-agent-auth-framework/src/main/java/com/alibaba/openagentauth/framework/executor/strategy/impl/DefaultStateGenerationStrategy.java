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
package com.alibaba.openagentauth.framework.executor.strategy.impl;

import com.alibaba.openagentauth.framework.executor.strategy.StateGenerationStrategy;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default implementation of {@link StateGenerationStrategy}.
 * <p>
 * Generates cryptographically secure, opaque state parameters using {@link SecureRandom}.
 * The generated values are URL-safe Base64-encoded strings with 32 bytes (256 bits) of entropy,
 * exceeding the RFC 6749 Section 10.12 recommendation for sufficient randomness.
 * </p>
 *
 * <h3>Design Change (1.1)</h3>
 * <p>
 * In version 1.0, this class generated state values in the format {@code agent:UUID:sessionId},
 * encoding flow type and session information directly into the state parameter. Starting from
 * version 1.1, the state is a pure opaque value with no business semantics. Flow routing
 * metadata is stored server-side in an {@code OAuth2AuthorizationRequestStorage}.
 * </p>
 *
 * @since 1.0
 */
public class DefaultStateGenerationStrategy implements StateGenerationStrategy {

    private static final int STATE_BYTE_LENGTH = 32;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    public String generate() {
        byte[] randomBytes = new byte[STATE_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
