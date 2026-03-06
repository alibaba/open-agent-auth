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
package com.alibaba.openagentauth.framework.executor.strategy;

/**
 * Strategy for generating OAuth 2.0 state parameters.
 * <p>
 * This interface defines the contract for generating opaque state values used
 * in OAuth 2.0 authorization requests. Per RFC 6749 Section 10.12, the state
 * parameter should be an unguessable value bound to the user-agent's authenticated
 * state, used primarily for CSRF protection.
 * </p>
 *
 * <h3>Design Change (1.1)</h3>
 * <p>
 * In version 1.0, the state parameter encoded business semantics (flow type prefix
 * and session ID). Starting from version 1.1, the state is a pure opaque value.
 * Flow type and session metadata are stored server-side in an
 * {@code OAuth2AuthorizationRequestStorage}, following the approach used by
 * Spring Security OAuth2 and other industry-standard implementations.
 * </p>
 *
 * @since 1.0
 */
@FunctionalInterface
public interface StateGenerationStrategy {
    
    /**
     * Generates an opaque, cryptographically secure state parameter.
     * <p>
     * The generated value must be:
     * </p>
     * <ul>
     *   <li>Unguessable — sufficient entropy to prevent brute-force attacks</li>
     *   <li>Unique — no collisions across concurrent authorization requests</li>
     *   <li>Opaque — no business semantics encoded in the value</li>
     * </ul>
     *
     * @return the opaque state parameter value
     */
    String generate();
}
