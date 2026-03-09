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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.Map;

/**
 * Basic Authentication implementation for OAuth 2.0 client authentication.
 * <p>
 * This implementation uses HTTP Basic Authentication with client_id and client_secret
 * as credentials, following OAuth 2.0 specification (RFC 6749 Section 2.3.1).
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1">RFC 6749 - Client Authentication</a>
 * @since 1.0
 */
public class BasicAuthAuthentication implements OAuth2ClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(BasicAuthAuthentication.class);

    /**
     * The client identifier.
     */
    private final String clientId;

    /**
     * The client secret.
     */
    private final String clientSecret;

    /**
     * Creates a new BasicAuthAuthentication.
     *
     * @param clientId the client identifier
     * @param clientSecret the client secret
     * @throws IllegalArgumentException if any parameter is null or blank
     */
    public BasicAuthAuthentication(String clientId, String clientSecret) {
        this.clientId = requireNotBlank(clientId, "Client ID cannot be null or blank");
        this.clientSecret = requireNotBlank(clientSecret, "Client secret cannot be null or blank");
        
        logger.debug("BasicAuthAuthentication initialized for client: {}", clientId);
    }

    @Override
    public HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, Map<String, String> requestBody) {
        String authHeader = buildBasicAuthHeader();
        return requestBuilder.header("Authorization", authHeader);
    }

    @Override
    public String getAuthenticationMethod() {
        return "client_secret_basic";
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    /**
     * Builds the Basic Authentication header.
     *
     * @return the Basic Auth header value
     */
    private String buildBasicAuthHeader() {
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder()
                .encodeToString(credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return "Basic " + encodedCredentials;
    }

    /**
     * Validates that a string is not null or blank.
     *
     * @param value the string to validate
     * @param fieldName the name of the field for error messages
     * @return the validated string
     * @throws IllegalArgumentException if the value is null or blank
     */
    private static String requireNotBlank(String value, String fieldName) {
        if (ValidationUtils.isNullOrEmpty(value)) {
            throw new IllegalArgumentException(fieldName);
        }
        return value.trim();
    }
}