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
 * Unified strategy interface for OAuth 2.0 client authentication.
 * <p>
 * This interface defines the contract for different OAuth 2.0 client authentication
 * methods used across all OAuth 2.0 endpoints, including Token, PAR, Revocation,
 * and Introspection endpoints. This follows RFC 6749 Section 2.3 and RFC 7523
 * for JWT-based client authentication.
 * </p>
 * <p>
 * <b>Design Rationale:</b></p>
 * <p>
 * Per RFC 9126 Section 2.1, the PAR endpoint uses the same client authentication
 * methods as the Token endpoint. This interface provides a unified abstraction
 * that can be shared across all endpoints, following the Strategy pattern.
 * </p>
 * <p>
 * <b>Supported Authentication Methods:</b></p>
 * <ul>
 *   <li><b>client_secret_basic</b>: HTTP Basic Authentication with client_id and client_secret
 *       (RFC 6749 Section 2.3.1)</li>
 *   <li><b>client_secret_post</b>: client_id and client_secret in request body
 *       (RFC 6749 Section 2.3.1)</li>
 *   <li><b>private_key_jwt</b>: JWT assertion signed with client's private key
 *       (RFC 7523 Section 2.2)</li>
 *   <li><b>client_secret_jwt</b>: JWT assertion signed with client_secret
 *       (RFC 7523 Section 2.2)</li>
 *   <li><b>none</b>: No client authentication (public clients)</li>
 * </ul>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * // Basic Authentication
 * OAuth2ClientAuthentication basicAuth = new BasicAuthAuthentication(clientId, clientSecret);
 *
 * // WIMSE WIT-based Client Assertion Authentication
 * // The WIT is passed per-request through additionalParameters in ParRequest/TokenRequest,
 * // propagated into the request body map, and extracted by ClientAssertionAuthentication.
 * OAuth2ClientAuthentication witAuth = new ClientAssertionAuthentication();
 *
 * // Use with any OAuth 2.0 client
 * OAuth2TokenClient tokenClient = new DefaultOAuth2TokenClient(resolver, serviceName, witAuth);
 * OAuth2ParClient parClient = new DefaultOAuth2ParClient(resolver, witAuth);
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126#section-2.1">RFC 9126 - PAR Client Authentication</a>
 * @since 1.1
 */
public interface OAuth2ClientAuthentication {

    /**
     * Applies client authentication to an HTTP request.
     * <p>
     * Depending on the authentication method, this may:
     * </p>
     * <ul>
     *   <li>Add an {@code Authorization} header (for {@code client_secret_basic})</li>
     *   <li>Add {@code client_id}, {@code client_assertion}, and {@code client_assertion_type}
     *       parameters to the request body (for {@code private_key_jwt})</li>
     *   <li>Add {@code client_id} and {@code client_secret} to the request body
     *       (for {@code client_secret_post})</li>
     * </ul>
     *
     * @param requestBuilder the HTTP request builder to modify
     * @param requestBody the mutable request body parameters map; implementations may
     *                    add authentication parameters to this map
     * @return the modified HTTP request builder
     */
    HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, Map<String, String> requestBody);

    /**
     * Returns the OAuth 2.0 client authentication method identifier.
     * <p>
     * Standard values defined in IANA OAuth Parameters registry:
     * </p>
     * <ul>
     *   <li>{@code client_secret_basic}</li>
     *   <li>{@code client_secret_post}</li>
     *   <li>{@code private_key_jwt}</li>
     *   <li>{@code client_secret_jwt}</li>
     *   <li>{@code none}</li>
     * </ul>
     *
     * @return the authentication method identifier string
     */
    String getAuthenticationMethod();

    /**
     * Returns the client identifier associated with this authentication.
     * <p>
     * For most authentication methods, this returns the OAuth 2.0 {@code client_id}.
     * For some methods like {@code private_key_jwt}, the client ID may also be
     * embedded in the JWT assertion's {@code iss} and {@code sub} claims.
     * </p>
     *
     * @return the client identifier, or null if not applicable
     */
    String getClientId();

}
