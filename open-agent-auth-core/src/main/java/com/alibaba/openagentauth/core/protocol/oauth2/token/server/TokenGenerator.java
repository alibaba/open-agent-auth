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
package com.alibaba.openagentauth.core.protocol.oauth2.token.server;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;

/**
 * Interface for generating access tokens.
 * <p>
 * This interface abstracts the token generation logic, allowing different
 * token types to be generated (e.g., standard OAuth tokens, AOAT tokens).
 * </p>
 * <p>
 * Implementations can choose to generate standard OAuth 2.0 access tokens,
 * JWT tokens, or Agent Operation Authorization Tokens (AOAT) depending on
 * the use case.
 * </p>
 *
 * @since 1.0
 */
public interface TokenGenerator {

    /**
     * Generates an access token based on the authorization code and token request.
     *
     * @param authCode the authorization code
     * @param request the token request
     * @return the generated access token string
     * @throws OAuth2TokenException if token generation fails
     */
    String generateToken(AuthorizationCode authCode, TokenRequest request);

    /**
     * Gets the default token expiration time in seconds.
     *
     * @return the expiration time in seconds
     */
    long getExpirationSeconds();

}
