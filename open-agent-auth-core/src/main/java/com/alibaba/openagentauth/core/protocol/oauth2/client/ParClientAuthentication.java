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
package com.alibaba.openagentauth.core.protocol.oauth2.client;

import java.net.http.HttpRequest;
import java.util.Map;

/**
 * Strategy interface for PAR client authentication.
 * <p>
 * This interface defines the contract for different OAuth 2.0 client authentication
 * methods used in Pushed Authorization Requests (PAR). Implementations support various
 * authentication mechanisms such as Basic Auth, Client Assertion, etc.
 * </p>
 * <p>
 * <b>Supported Authentication Methods:</b></p>
 * <ul>
 *   <li><b>client_secret_basic</b>: HTTP Basic Authentication with client_id and client_secret</li>
 *   <li><b>private_key_jwt</b>: JWT assertion signed with client's private key (RFC 7523)</li>
 *   <li><b>client_secret_jwt</b>: JWT assertion signed with client_secret (RFC 7523)</li>
 * </ul>
 * <p>
 * <b>WIMSE Integration:</b></p>
 * <p>
 * When using WIMSE-based authentication, the client assertion is generated using
 * a Workload Identity Token (WIT) that authenticates the workload. This provides
 * stronger security guarantees compared to traditional client secrets.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public interface ParClientAuthentication {

    /**
     * Applies authentication headers to the HTTP request.
     * <p>
     * This method adds the appropriate authentication headers to the HTTP request
     * based on the authentication method being used.
     * </p>
     *
     * @param requestBuilder the HTTP request builder to modify
     * @param requestBody the request body (for methods that need to include assertion in body)
     * @return the modified HTTP request builder
     */
    HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, Map<String, String> requestBody);

    /**
     * Gets the authentication method identifier.
     *
     * @return the authentication method (e.g., "client_secret_basic", "private_key_jwt")
     */
    String getAuthenticationMethod();

    /**
     * Gets the client identifier for this authentication.
     * <p>
     * This method returns the client ID used for authentication. For some authentication
     * methods like client_assertion, the client ID may be embedded in the assertion itself.
     * </p>
     *
     * @return the client identifier, or null if not applicable
     */
    String getClientId();

}
