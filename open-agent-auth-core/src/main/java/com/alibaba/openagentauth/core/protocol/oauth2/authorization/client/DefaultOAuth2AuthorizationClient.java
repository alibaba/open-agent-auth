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
import com.alibaba.openagentauth.core.util.UriQueryBuilder;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OAuth2AuthorizationClient}.
 * <p>
 * This implementation provides a complete authorization client following RFC 6749
 * specification with PAR integration for the Agent Operation Authorization framework.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Authorization URL construction with request_uri</li>
 *   <li>Callback response parsing</li>
 *   <li>State parameter validation for CSRF protection</li>
 *   <li>Error handling and extraction</li>
 *   <li>Configurable authorization endpoint</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Grant</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class DefaultOAuth2AuthorizationClient implements OAuth2AuthorizationClient {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2AuthorizationClient.class);

    /**
     * The service endpoint resolver for resolving endpoint URLs.
     */
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * Creates a new DefaultAuthorizationClient.
     *
     * @param serviceEndpointResolver the service endpoint resolver
     */
    public DefaultOAuth2AuthorizationClient(ServiceEndpointResolver serviceEndpointResolver) {
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        logger.info("DefaultAuthorizationClient initialized with service endpoint resolver");
    }

    @Override
    public String buildAuthorizationUrl(String requestUri) {

        // Validate parameters
        ValidationUtils.validateNotNull(requestUri, "Request URI");
        logger.debug("Building authorization URL with request_uri: {}", requestUri);

        try {
            String authorizationEndpoint = serviceEndpointResolver.resolveProvider("oauth2.authorize");
            URI baseUri = new URI(authorizationEndpoint);
            String encodedRequestUri = URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
            String queryString = buildQueryString(baseUri.getQuery(), encodedRequestUri);

            // Build the URL using string concatenation to avoid double encoding by URI constructor
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(baseUri.getScheme()).append("://");
            urlBuilder.append(baseUri.getAuthority());
            if (!ValidationUtils.isNullOrEmpty(baseUri.getPath())) {
                urlBuilder.append(baseUri.getPath());
            }
            if (!ValidationUtils.isNullOrEmpty(queryString)) {
                urlBuilder.append("?").append(queryString);
            }
            if (!ValidationUtils.isNullOrEmpty(baseUri.getFragment())) {
                urlBuilder.append("#").append(baseUri.getFragment());
            }

            String authorizationUrl = urlBuilder.toString();
            logger.debug("Authorization URL built: {}", authorizationUrl);
            return authorizationUrl;

        } catch (Exception e) {
            logger.error("Error building authorization URL", e);
            throw OAuth2AuthorizationException.invalidRequest("Failed to build authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Builds the query string by appending request_uri parameter to existing query.
     *
     * @param existingQuery the existing query string from the endpoint (may be null)
     * @param encodedRequestUri the URL-encoded request_uri value
     * @return the complete query string
     */
    private String buildQueryString(String existingQuery, String encodedRequestUri) {
        UriQueryBuilder builder = new UriQueryBuilder();

        if (!ValidationUtils.isNullOrEmpty(existingQuery)) {
            builder.appendRaw(existingQuery);
        }
        builder.add("request_uri", encodedRequestUri);

        return builder.build();
    }

    @Override
    public String handleCallback(String callbackUrl) {

        ValidationUtils.validateNotNull(callbackUrl, "Callback URL");
        logger.info("Handling callback: {}", callbackUrl);

        try {
            Map<String, String> params = parseCallbackParameters(callbackUrl);
            
            // Check for error response
            if (params.containsKey("error")) {
                String error = params.get("error");
                String errorDescription = params.getOrDefault("error_description", "");
                
                logger.error("Authorization error received: {} - {}", error, errorDescription);
                throw OAuth2AuthorizationException.oauthError(error, errorDescription);
            }
            
            // Extract authorization code
            String code = params.get("code");
            if (ValidationUtils.isNullOrEmpty(code)) {
                logger.error("No authorization code found in callback");
                throw OAuth2AuthorizationException.invalidRequest("No authorization code found in callback");
            }
            
            logger.info("Authorization code extracted successfully");
            return code;
            
        } catch (OAuth2AuthorizationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error handling callback", e);
            throw OAuth2AuthorizationException.invalidRequest(
                    "Failed to handle callback: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean validateState(String state, String expectedState) {

        ValidationUtils.validateNotNull(state, "State");
        ValidationUtils.validateNotNull(expectedState, "Expected state");

        boolean isValid = state.equals(expectedState);
        
        if (isValid) {
            logger.debug("State parameter validated successfully");
        } else {
            logger.warn("State parameter validation failed: expected={}, received={}", 
                    expectedState, state);
        }
        
        return isValid;
    }

    @Override
    public String extractCode(String callbackUrl) {

        ValidationUtils.validateNotNull(callbackUrl, "Callback URL");

        try {
            Map<String, String> params = parseCallbackParameters(callbackUrl);
            String code = params.get("code");
            
            if (!ValidationUtils.isNullOrEmpty(code)) {
                logger.debug("Authorization code extracted from callback");
            } else {
                logger.debug("No authorization code found in callback");
            }
            
            return code;
            
        } catch (Exception e) {
            logger.error("Error extracting code from callback", e);
            return null;
        }
    }

    @Override
    public String[] extractError(String callbackUrl) {

        ValidationUtils.validateNotNull(callbackUrl, "Callback URL");

        try {
            Map<String, String> params = parseCallbackParameters(callbackUrl);
            
            if (!params.containsKey("error")) {
                logger.debug("No error found in callback");
                return null;
            }
            
            String error = params.get("error");
            String errorDescription = params.getOrDefault("error_description", "");
            
            logger.debug("Error extracted from callback: {} - {}", error, errorDescription);
            
            return new String[]{error, errorDescription};
            
        } catch (Exception e) {
            logger.error("Error extracting error from callback", e);
            return null;
        }
    }

    /**
     * Parses query parameters from a callback URL.
     * <p>
     * This method extracts all query parameters from the URL and returns them
     * as a map of parameter names to values.
     * </p>
     *
     * @param callbackUrl the callback URL
     * @return a map of query parameters
     * @throws Exception if URL parsing fails
     */
    private Map<String, String> parseCallbackParameters(String callbackUrl) throws Exception {

        Map<String, String> params = new HashMap<>();
        
        URI uri = new URI(callbackUrl);
        String query = uri.getQuery();
        
        if (ValidationUtils.isNullOrEmpty(query)) {
            return params;
        }
        
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = pair.substring(0, idx);
                String value = pair.substring(idx + 1);
                
                // URL decode the value
                params.put(key, URLDecoder.decode(value, StandardCharsets.UTF_8));
            }
        }
        
        return params;
    }

}