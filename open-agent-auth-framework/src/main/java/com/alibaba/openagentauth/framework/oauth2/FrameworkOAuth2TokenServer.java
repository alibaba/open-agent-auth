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
package com.alibaba.openagentauth.framework.oauth2;

import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;

/**
 * Framework-level interface for OAuth 2.0 Token Server operations.
 * 
 * @since 1.0
 */
public interface FrameworkOAuth2TokenServer {

    /**
     * Processes a token request and issues an access token.
     *
     * @param request the token request
     * @param clientId the authenticated client identifier
     * @return the token response
     * @throws FrameworkOAuth2TokenException if token issuance fails
     */
    TokenResponse issueToken(TokenRequest request, String clientId) throws FrameworkOAuth2TokenException;

}
