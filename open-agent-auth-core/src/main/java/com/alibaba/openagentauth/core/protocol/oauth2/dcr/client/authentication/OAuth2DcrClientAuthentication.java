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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;

import java.net.http.HttpRequest;

/**
 * Strategy interface for DCR client authentication.
 * <p>
 * This interface defines the contract for applying authentication to DCR requests
 * using different protocols. Implementations can support various authentication methods
 * such as WIMSE, Bearer token, or no authentication.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern</p>
 * <p>
 * This interface allows the DCR client to support pluggable authentication mechanisms
 * without modifying the core HTTP request building logic. Each implementation handles
 * the specific authentication requirements of its protocol.
 * </p>
 * <p>
 * <b>Implementation Examples:</b></p>
 * <ul>
 *   <li>{@code WimseDcrClientAuthentication} - WIMSE protocol with Workload Identity Token</li>
 *   <li>{@code NoAuthDcrClientAuthentication} - No authentication for initial registration</li>
 *   <li>{@code BearerTokenDcrClientAuthentication} - Bearer token authentication</li>
 * </ul>
 *
 * @see WimseOAuth2DcrClientAuthentication
 * @see NoAuthOAuth2DcrClientAuthentication
 * @since 1.0
 */
public interface OAuth2DcrClientAuthentication {

    /**
     * Applies authentication headers to the HTTP request.
     * <p>
     * This method adds the appropriate authentication headers to the HTTP request
     * based on the authentication method being used. It extracts credentials from
     * the DCR request and applies them to the request builder.
     * </p>
     *
     * @param requestBuilder the HTTP request builder to modify
     * @param request the DCR request containing authentication credentials
     * @return the modified HTTP request builder
     */
    HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, DcrRequest request);

    /**
     * Gets the authentication method name for this authenticator.
     * <p>
     * This method returns a string identifier for the authentication method,
     * useful for logging and debugging purposes.
     * </p>
     *
     * @return the authentication method name
     */
    String getAuthenticationMethod();
}
