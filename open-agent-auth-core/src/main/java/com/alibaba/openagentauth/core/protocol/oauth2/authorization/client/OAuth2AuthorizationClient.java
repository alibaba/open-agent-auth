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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.client;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;

/**
 * Client-side interface for OAuth 2.0 Authorization Code flow.
 * <p>
 * This interface defines the contract for clients to initiate authorization requests
 * and handle authorization responses according to RFC 6749. Implementations are
 * responsible for redirecting users to the Authorization Server and processing
 * the authorization response.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 6749 Section 4.1):</b></p>
 * <pre>
 * Client                                        Authorization Server
 *  |                                                    |
 *  |-- GET /authorize?request_uri=... ------------------>|
 *  |                                                    |
 *  |                   User authenticates & consents     |
 *  |                                                    |
 *  |<-- 302 Found (redirect to client) ----------------|
 *  | Location: https://client.example.com/callback?   |
 *  |           code=...&state=...                      |
 *  |                                                    |
 *  |-- Extract code and state from callback            |
 *  |                                                    |
 *  |<-- Return authorization code to caller           |
 * </pre>
 * <p>
 * <b>Client Responsibilities:</b></p>
 * <ul>
 *   <li><b>Request Construction:</b> Build the authorization endpoint URL with request_uri</li>
 *   <li><b>User Redirection:</b> Redirect the user to the Authorization Server</li>
 *   <li><b>Response Handling:</b> Parse the authorization response from the callback</li>
 *   <li><b>State Validation:</b> Validate the state parameter to prevent CSRF attacks</li>
 *   <li><b>Error Handling:</b> Handle authorization errors gracefully</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST use HTTPS for all authorization requests</li>
 *   <li>MUST validate the state parameter</li>
 *   <li>MUST handle error responses securely</li>
 *   <li>MUST protect the authorization code during exchange</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Grant</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public interface OAuth2AuthorizationClient {

    /**
     * Builds the authorization endpoint URL.
     * <p>
     * This method constructs the full URL for the authorization endpoint with the
     * request_uri parameter obtained from the PAR flow. The URL is used to redirect
     * the user to the Authorization Server for authentication and consent.
     * </p>
     * <p>
     * <b>URL Format:</b></p>
     * <pre>
     * https://as.example.com/authorize?request_uri=urn:ietf:params:oauth:request_uri:...
     * </pre>
     *
     * @param requestUri the request URI returned from PAR
     * @return the full authorization endpoint URL
     * @throws OAuth2AuthorizationException if URL construction fails
     * @throws IllegalArgumentException if requestUri is null or empty
     */
    String buildAuthorizationUrl(String requestUri);

    /**
     * Handles the authorization response callback.
     * <p>
     * This method processes the authorization response returned by the Authorization Server
     * after user authentication and consent. The response contains either an authorization
     * code or an error.
     * </p>
     * <p>
     * <b>Success Response:</b></p>
     * <pre>
     * https://client.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
     * </pre>
     * <p>
     * <b>Error Response:</b></p>
     * <pre>
     * https://client.example.com/callback?error=access_denied&state=xyz
     * </pre>
     *
     * @param callbackUrl the full callback URL containing the authorization response
     * @return the authorization code if successful
     * @throws OAuth2AuthorizationException if the response contains an error or parsing fails
     * @throws IllegalArgumentException if callbackUrl is null or empty
     */
    String handleCallback(String callbackUrl);

    /**
     * Validates the state parameter from the authorization response.
     * <p>
     * This method validates that the state parameter returned in the callback matches
     * the state parameter sent in the original authorization request. This prevents
     * CSRF attacks as required by RFC 6749 Section 10.12.
     * </p>
     *
     * @param state the state parameter from the callback
     * @param expectedState the expected state value from the original request
     * @return true if the state is valid, false otherwise
     * @throws IllegalArgumentException if parameters are null
     */
    boolean validateState(String state, String expectedState);

    /**
     * Extracts the authorization code from the callback URL.
     * <p>
     * This method parses the callback URL and extracts the authorization code parameter.
     * It does not perform validation; use {@link #handleCallback(String)} for full processing.
     * </p>
     *
     * @param callbackUrl the callback URL
     * @return the authorization code, or null if not present
     * @throws IllegalArgumentException if callbackUrl is null
     */
    String extractCode(String callbackUrl);

    /**
     * Extracts the error information from the callback URL.
     * <p>
     * This method parses the callback URL and extracts the error code and description.
     * </p>
     *
     * @param callbackUrl the callback URL
     * @return an array containing [error_code, error_description], or null if no error
     * @throws IllegalArgumentException if callbackUrl is null
     */
    String[] extractError(String callbackUrl);

}
