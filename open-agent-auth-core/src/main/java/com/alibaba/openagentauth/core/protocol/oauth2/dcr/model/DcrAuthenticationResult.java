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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.model;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.authenticator.OAuth2DcrAuthenticator;

/**
 * Represents the result of a DCR client authentication attempt.
 * <p>
 * This record encapsulates both the authenticated subject identifier and whether
 * the authenticator provides a stable client identity that should be used as the
 * OAuth {@code client_id}.
 * </p>
 * <p>
 * <b>Design Rationale:</b> By pairing the subject with the identity-binding flag,
 * the DCR server can make the {@code client_id} decision without any hardcoded
 * knowledge of specific authentication protocols. The decision is delegated to
 * each {@link OAuth2DcrAuthenticator} via its {@code providesClientIdentity()} method.
 * </p>
 *
 * @param subject               the authenticated subject identifier
 * @param providesClientIdentity whether the subject should be used as the {@code client_id}
 * @since 2.1
 * @see OAuth2DcrAuthenticator#providesClientIdentity()
 */
public record DcrAuthenticationResult(String subject, boolean providesClientIdentity) {

    /**
     * Default subject for unauthenticated requests.
     */
    private static final String UNAUTHENTICATED_SUBJECT = "anonymous";

    /**
     * Creates an unauthenticated result.
     * <p>
     * Used when no authenticator can handle the request. The subject is set to
     * a default value and {@code providesClientIdentity} is {@code false},
     * causing the DCR server to generate a random {@code client_id}.
     * </p>
     *
     * @return an unauthenticated result
     */
    public static DcrAuthenticationResult unauthenticated() {
        return new DcrAuthenticationResult(UNAUTHENTICATED_SUBJECT, false);
    }

}
