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
package com.alibaba.openagentauth.framework.web.authorization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for building OAuth 2.0 authorization redirect URIs.
 * <p>
 * This class provides a centralized method to construct redirect URIs with
 * authorization codes and state parameters, following RFC 6749 specification.
 * It eliminates code duplication across different authorization flow strategies.
 * </p>
 *
 * @since 1.0
 */
public final class AuthorizationUriBuilder {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationUriBuilder.class);

    private AuthorizationUriBuilder() {
        // Utility class - prevent instantiation
    }

    /**
     * Builds a redirect URI with authorization code and optional state parameter.
     * <p>
     * This method constructs the final redirect URI according to OAuth 2.0 specification
     * (RFC 6749 Section 4.1.2). The URI includes the authorization code and optionally
     * the state parameter for CSRF protection.
     * </p>
     *
     * @param result the authorization code result containing code and redirect information
     * @return the complete redirect URI with authorization code
     */
    public static String buildRedirectUri(AuthorizationCodeResult result) {
        StringBuilder uri = new StringBuilder(result.getRedirectUri());
        uri.append("?code=").append(URLEncoder.encode(result.getCode(), StandardCharsets.UTF_8));

        if (result.getState() != null && !result.getState().isBlank()) {
            uri.append("&state=").append(URLEncoder.encode(result.getState(), StandardCharsets.UTF_8));
        }

        String redirectUri = uri.toString();
        logger.debug("Built redirect URI: {}", redirectUri);
        return redirectUri;
    }

    /**
     * Builds an error redirect URI according to OAuth 2.0 specification.
     * <p>
     * This method constructs the redirect URI with error parameters when authorization fails,
     * following RFC 6749 Section 4.1.2.1. The URI includes the error code, optional error
     * description, and optional state parameter.
     * </p>
     * <p>
     * According to RFC 6749, authorization errors should be returned via redirect to the
     * client's redirect_uri rather than as HTTP error responses. This allows the client
     * to handle the error appropriately.
     * </p>
     *
     * @param redirectUri the client's redirect URI (must not be null or blank)
     * @param errorCode the OAuth 2.0 error code (e.g., "access_denied", "invalid_request")
     * @param errorDescription the optional error description (can be null)
     * @param state the optional state parameter for CSRF protection (can be null)
     * @return the complete redirect URI with error parameters
     */
    public static String buildErrorRedirectUri(String redirectUri, String errorCode, String errorDescription, String state) {
        StringBuilder uri = new StringBuilder(redirectUri);
        uri.append("?error=").append(URLEncoder.encode(errorCode, StandardCharsets.UTF_8));

        if (errorDescription != null && !errorDescription.isBlank()) {
            uri.append("&error_description=").append(URLEncoder.encode(errorDescription, StandardCharsets.UTF_8));
        }

        if (state != null && !state.isBlank()) {
            uri.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }

        String errorRedirectUri = uri.toString();
        logger.debug("Built error redirect URI: {}", errorRedirectUri);
        return errorRedirectUri;
    }
}
