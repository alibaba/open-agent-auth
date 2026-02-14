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
package com.alibaba.openagentauth.framework.actor;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenServer;
import com.alibaba.openagentauth.framework.role.ApplicationRole;

/**
 * User Identity Provider actor interface.
 * <p>
 * This interface defines the contract for User IDP actor implementations,
 * which are responsible for user authentication and ID Token issuance.
 * Both Agent User IDP and AS User IDP implement this interface as independent
 * actors with their specific authentication strategies.
 * </p>
 * 
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>User Authentication:</b> Verify user identity through various authentication methods</li>
 *   <li><b>Token Issuance:</b> Generate ID Tokens containing user identity claims</li>
 * </ul>
 * 
 * <h3>Design Philosophy:</h3>
 * <p>
 * This interface serves as a <b>role-oriented aggregation layer</b> for User IDP actors,
 * enabling efficient positioning and integration for Agent User IDP and AS User IDP.
 * It provides a unified entry point that aggregates authentication capabilities,
 * making it easier for developers to implement and extend User IDP functionality.
 * </p>
 * <p>
 * <b>Framework Agnostic:</b> This interface is framework-agnostic. While Spring Boot
 * applications can use pre-built controllers for OIDC Discovery and JWKS endpoints,
 * non-Spring Boot applications should implement these endpoints themselves by
 * calling this interface and the underlying core module services.
 * </p>
 * 
 * <h3>Usage:</h3>
 * <p>
 * Implementations should delegate to core module's {@code AuthenticationProvider}
 * for authentication logic and {@code IdTokenGenerator} for token generation.
 * This interface provides a role-oriented abstraction for User IDP actors.
 * </p>
 * 
 * <h3>Authentication Flow:</h3>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                   User IDP Authentication Flow                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌───────────────────┐      ┌──────────────────┐         ┌────────────────┐
 *    │ Client (Agent/AS) │      │ User IDP Service │         │   Core Module  │
 *    └──────┬────────────┘      └──────┬───────────┘         └───────┬────────┘
 *           │                          │                             │
 *           │ 1. authenticate(request) │                             │
 *           │─────────────────────────>│                             │
 *           │                          │                             │
 *           │                          │ 2. Delegate Authentication  │
 *           │                          │────────────────────────────>│
 *           │                          │                             │
 *           │                          │ 3. Validate Credentials     │
 *           │                          │   - Username/Password       │
 *           │                          │   - OAuth 2.0               │
 *           │                          │   - SAML                    │
 *           │                          │   - MFA                     │
 *           │                          │                             │
 *           │                          │ 4. Return IdToken           │
 *           │                          │<────────────────────────────│
 *           │                          │                             │
 *           │ 5. Format Response       │                             │
 *           │                          │   - Extract JWT string      │
 *           │                          │   - Calculate expires_in    │
 *           │                          │                             │
 *           │ 6. Return AuthResponse   │                             │
 *           │<─────────────────────────│                             │
 * </pre>
 * 
 * <h4>Flow Description:</h4>
 * <ul>
 *   <li><b>1:</b> Client (Agent or AS) calls authenticate() with authentication request</li>
 *   <li><b>2:</b> User IDP delegates authentication to core module's AuthenticationProvider</li>
 *   <li><b>3:</b> AuthenticationProvider validates credentials using configured strategy</li>
 *   <li><b>4:</b> AuthenticationProvider returns IdToken with OIDC claims</li>
 *   <li><b>5:</b> User IDP formats authentication response for client consumption</li>
 *   <li><b>6:</b> Client receives authentication response with ID Token</li>
 * </ul>
 * 
 * @see ApplicationRole#AGENT_USER_IDP
 * @see ApplicationRole#AS_USER_IDP
 * @see FrameworkOAuth2TokenServer
 * @since 1.0
 */
public interface UserIdentityProvider extends FrameworkOAuth2TokenServer {
    
    /**
     * Processes an authentication request and returns the authentication response.
     * <p>
     * This method authenticates the user and generates an ID Token containing
     * standard OIDC claims (iss, sub, aud, exp, iat, jti, etc.).
     * </p>
     * 
     * <p>
     * <b>Implementation Note:</b> Implementations should delegate to
     * {@link AuthenticationProvider} for
     * authentication and {@link IdTokenGenerator}
     * for token generation.
     * </p>
     *
     * @param request the authentication request
     * @return the authentication response containing the ID Token
     * @throws AuthenticationException if authentication fails
     * @throws IllegalArgumentException if request is null
     */
    AuthenticationResponse authenticate(AuthenticationRequest request) throws AuthenticationException;
    
}