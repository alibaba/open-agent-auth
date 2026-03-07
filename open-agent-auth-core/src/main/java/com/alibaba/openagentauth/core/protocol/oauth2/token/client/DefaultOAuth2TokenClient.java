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
package com.alibaba.openagentauth.core.protocol.oauth2.token.client;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.OAuth2ClientAuthentication;
import com.alibaba.openagentauth.core.util.UriQueryBuilder;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OAuth2TokenClient}.
 * <p>
 * This implementation provides a complete token client following RFC 6749
 * specification with support for the Agent Operation Authorization framework.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Authorization code exchange for access tokens</li>
 *   <li>Refresh token support</li>
 *   <li>Token revocation support (RFC 7009)</li>
 *   <li>Pluggable client authentication via {@link OAuth2ClientAuthentication} strategy</li>
 *   <li>Supports client_secret_basic, private_key_jwt, and custom authentication methods</li>
 *   <li>Configurable timeout and connection settings</li>
 *   <li>Comprehensive error handling</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7009">RFC 7009 - OAuth 2.0 Token Revocation</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
public class DefaultOAuth2TokenClient implements OAuth2TokenClient {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2TokenClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * The service endpoint resolver for resolving endpoint URLs.
     */
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * The HTTP client for making requests.
     */
    private final HttpClient httpClient;

    /**
     * The service name for resolving consumer endpoints (e.g., "agent-user-idp", "authorization-server").
     */
    private final String serviceName;

    /**
     * The pluggable client authentication strategy.
     * <p>
     * This follows the Strategy pattern to support multiple OAuth 2.0 client authentication
     * methods (client_secret_basic, private_key_jwt, etc.) as defined in RFC 6749 Section 2.3
     * and RFC 7523.
     * </p>
     */
    private final OAuth2ClientAuthentication authentication;

    /**
     * Creates a new DefaultTokenClient with pluggable authentication strategy.
     * <p>
     * This is the preferred constructor that supports any OAuth 2.0 client authentication
     * method through the {@link OAuth2ClientAuthentication} strategy interface. Per RFC 6749
     * Section 2.3, clients MUST authenticate to the token endpoint using one of the
     * supported methods.
     * </p>
     * <p>
     * <b>Usage Example:</b></p>
     * <pre>{@code
     * // Basic Authentication
     * OAuth2ClientAuthentication auth = new BasicAuthAuthentication(clientId, clientSecret);
     * OAuth2TokenClient client = new DefaultOAuth2TokenClient(resolver, "authorization-server", auth);
     *
     * // Private Key JWT Authentication
     * ClientAssertionGenerator generator = new ClientAssertionGenerator(clientId, signingKey, JWSAlgorithm.RS256);
     * OAuth2ClientAuthentication auth = new ClientAssertionAuthentication(clientId, generator, tokenEndpoint);
     * OAuth2TokenClient client = new DefaultOAuth2TokenClient(resolver, "authorization-server", auth);
     * }</pre>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param serviceName the service name for resolving consumer endpoints
     * @param authentication the client authentication strategy
     */
    public DefaultOAuth2TokenClient(
            ServiceEndpointResolver serviceEndpointResolver,
            String serviceName,
            OAuth2ClientAuthentication authentication) {

        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.serviceName = ValidationUtils.validateNotEmpty(serviceName, "Service name");
        this.authentication = ValidationUtils.validateNotNull(authentication, "Client authentication");
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

        logger.info("DefaultTokenClient initialized with {} authentication, service_name: {}, client_id: {}",
                authentication.getAuthenticationMethod(), serviceName, authentication.getClientId());
    }

    @Override
    public TokenResponse exchangeCodeForToken(TokenRequest request) {

        // Validate parameters
        ValidationUtils.validateNotNull(request, "Token request");
        logger.info("Exchanging authorization code for access token");

        try {
            // Build request body
            String requestBody = buildTokenRequestBody(request);
            logger.debug("Token request body built");

            // Build HTTP request
            HttpRequest.Builder httpRequestBuilder = buildHttpRequestBuilder(requestBody);

            HttpRequest httpRequest = httpRequestBuilder.build();

            // Send request
            logger.debug("Sending token request to: {}", serviceEndpointResolver.resolveConsumer(serviceName, "oauth2.token"));
            HttpResponse<String> response = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );

            // Process response
            return processTokenResponse(response);

        } catch (OAuth2TokenException e) {
            throw e;
        } catch (Exception e) {
            throw handleTokenException("Error exchanging authorization code for token",
                    "Failed to exchange authorization code", e);
        }
    }

    @Override
    public TokenResponse refreshToken(String refreshToken) {

        // Validate parameters
        ValidationUtils.validateNotNull(refreshToken, "Refresh token cannot be null or empty");
        logger.info("Refreshing access token");

        try {
            // Build request body using UriQueryBuilder
            String requestBody = new UriQueryBuilder()
                    .addEncoded("grant_type", "refresh_token")
                    .addEncoded("refresh_token", refreshToken)
                    .build();

            // Build HTTP request
            HttpRequest.Builder httpRequestBuilder = buildHttpRequestBuilder(requestBody);

            HttpRequest httpRequest = httpRequestBuilder.build();

            // Send request
            logger.debug("Sending refresh token request to: {}", serviceEndpointResolver.resolveConsumer(serviceName, "oauth2.token"));
            HttpResponse<String> response = httpClient.send(httpRequest,
                    HttpResponse.BodyHandlers.ofString());

            // Process response
            return processTokenResponse(response);

        } catch (OAuth2TokenException e) {
            throw e;
        } catch (Exception e) {
            throw handleTokenException("Error refreshing access token",
                    "Failed to refresh access token", e);
        }
    }

    @Override
    public void revokeToken(String token, String tokenType) {

        // Validate parameters
        ValidationUtils.validateNotNull(token, "Token cannot be null or empty");
        ValidationUtils.validateNotNull(tokenType, "Token type cannot be null or empty");

        logger.info("Revoking token of type: {}", tokenType);

        try {
            // Build request body using UriQueryBuilder
            String requestBody = new UriQueryBuilder()
                    .addEncoded("token", token)
                    .addEncoded("token_type_hint", tokenType)
                    .build();

            // Build HTTP request
            HttpRequest.Builder httpRequestBuilder = buildHttpRequestBuilder(requestBody);
            HttpRequest httpRequest = httpRequestBuilder.build();

            // Send request
            logger.debug("Sending revoke token request to: {}", serviceEndpointResolver.resolveConsumer(serviceName, "oauth2.token"));
            HttpResponse<String> response = httpClient.send(httpRequest, 
                    HttpResponse.BodyHandlers.ofString());

            // Process response
            if (response.statusCode() != 200) {
                logger.error("Token revocation failed with status: {}", response.statusCode());
                throw OAuth2TokenException.invalidRequest(
                        "Token revocation failed with status: " + response.statusCode());
            }

            logger.info("Token revoked successfully");

        } catch (OAuth2TokenException e) {
            throw e;
        } catch (Exception e) {
            throw handleTokenException("Error revoking token", "Failed to revoke token", e);
        }
    }
    /**
     * Builds the token request body from a TokenRequest object using {@link UriQueryBuilder}.
     *
     * @param request the token request
     * @return the URL-encoded request body
     */
    private String buildTokenRequestBody(TokenRequest request) {

        // Build request body with required parameters using addEncoded to avoid double-encoding
        UriQueryBuilder builder = new UriQueryBuilder()
                .addEncoded("grant_type", "authorization_code")
                .addEncoded("code", request.getCode());

        // Add optional parameters
        if (request.getRedirectUri() != null && !request.getRedirectUri().isEmpty()) {
            builder.addEncoded("redirect_uri", request.getRedirectUri());
        }
        if (request.getClientId() != null && !request.getClientId().isEmpty()) {
            builder.addEncoded("client_id", request.getClientId());
        }

        // Extract scope from additional parameters if present
        if (request.getAdditionalParameters() != null && request.getAdditionalParameters().containsKey("scope")) {
            Object scope = request.getAdditionalParameters().get("scope");
            if (scope != null) {
                builder.addEncoded("scope", scope.toString());
            }
        }

        // Return request body
        return builder.build();
    }

    /**
     * Processes the token response from the authorization server.
     *
     * @param response the HTTP response
     * @return the token response
     * @throws OAuth2TokenException if the response indicates an error
     */
    private TokenResponse processTokenResponse(HttpResponse<String> response) throws IOException {

        // Get response body
        String responseBody = response.body();
        logger.debug("Received token response with status: {}", response.statusCode());
        
        // Check for successful response
        if (response.statusCode() != 200) {
            return processErrorResponse(responseBody);
        }
        
        // Parse successful response
        JsonNode jsonNode = objectMapper.readTree(responseBody);

        String accessToken = jsonNode.path("access_token").asText();
        String tokenType = jsonNode.path("token_type").asText();
        long expiresIn = jsonNode.path("expires_in").asLong(3600);
        String scope = jsonNode.has("scope") ? jsonNode.path("scope").asText() : null;
        String refreshToken = jsonNode.has("refresh_token") ? jsonNode.path("refresh_token").asText() : null;

        // Parse id_token if present (OIDC Core 1.0 Section 3.1.3.3)
        String idToken = jsonNode.has("id_token") ? jsonNode.path("id_token").asText() : null;

        // Build token response
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(tokenType)
                .expiresIn(expiresIn)
                .scope(scope)
                .refreshToken(refreshToken)
                .idToken(idToken)
                .build();
        
        logger.info("Access token received successfully, id_token present: {}", idToken != null);
        return tokenResponse;
    }

    /**
     * Processes an error response from the authorization server.
     *
     * @param responseBody the error response body
     * @throws OAuth2TokenException always throws an exception
     */
    private TokenResponse processErrorResponse(String responseBody) throws IOException {

        // Parse error response
        JsonNode jsonNode = objectMapper.readTree(responseBody);
        
        String error = jsonNode.path("error").asText("unknown_error");
        String errorDescription = jsonNode.has("error_description") 
                ? jsonNode.path("error_description").asText() 
                : "Unknown error";
        
        logger.error("Token request failed: {} - {}", error, errorDescription);
        throw OAuth2TokenException.oauthError(error, errorDescription);
    }

    /**
     * Handles exceptions during token operations.
     *
     * @param logMessage the message to log
     * @param errorMessage the error message for the exception
     * @param cause the underlying cause
     * @return a TokenException with appropriate error code
     */
    private OAuth2TokenException handleTokenException(String logMessage, String errorMessage, Throwable cause) {
        logger.error(logMessage, cause);
        return OAuth2TokenException.serverError(errorMessage + ": " + cause.getMessage(), cause);
    }
    /**
     * Builds HTTP request builder with common headers and pluggable authentication.
     * <p>
     * This method delegates client authentication to the configured
     * {@link OAuth2ClientAuthentication} strategy, which may add headers
     * (e.g., Authorization for Basic Auth) or modify the request body
     * (e.g., client_assertion parameters for private_key_jwt).
     * </p>
     *
     * @param requestBody the request body
     * @return the HTTP request builder
     */
    private HttpRequest.Builder buildHttpRequestBuilder(String requestBody) {

        // Resolve token endpoint URL
        String tokenEndpoint = serviceEndpointResolver.resolveConsumer(serviceName, "oauth2.token");
        if (tokenEndpoint == null) {
            throw new IllegalStateException(
                "Cannot resolve token endpoint for service: " + serviceName + 
                ". Please check your configuration under 'open-agent-auth.services.consumers." + serviceName + "'."
            );
        }

        // Build mutable request body map for authentication strategy to modify
        Map<String, String> requestBodyMap = parseFormUrlEncodedBody(requestBody);

        // Build HTTP request
        HttpRequest.Builder httpRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json");

        // Apply pluggable client authentication strategy (RFC 6749 Section 2.3)
        httpRequestBuilder = authentication.applyAuthentication(httpRequestBuilder, requestBodyMap);
        logger.debug("{} authentication applied for client: {}",
                authentication.getAuthenticationMethod(), authentication.getClientId());

        // Rebuild request body from potentially modified map
        String authenticatedRequestBody = buildFormUrlEncodedBody(requestBodyMap);
        httpRequestBuilder.POST(HttpRequest.BodyPublishers.ofString(authenticatedRequestBody));

        return httpRequestBuilder;
    }

    /**
     * Parses a URL-encoded form body into a mutable map of decoded values.
     * <p>
     * Delegates to {@link UriQueryBuilder#parse(String)} which URL-decodes both
     * parameter names and values. This ensures consistency when the map is later
     * modified by {@link OAuth2ClientAuthentication#applyAuthentication} (which
     * adds raw values) and then re-encoded by {@link #buildFormUrlEncodedBody}.
     * </p>
     *
     * @param formBody the URL-encoded form body string
     * @return a mutable map of decoded parameter name-value pairs
     */
    private Map<String, String> parseFormUrlEncodedBody(String formBody) {
        return UriQueryBuilder.parse(formBody);
    }

    /**
     * Builds a URL-encoded form body from a map of parameters using {@link UriQueryBuilder}.
     * <p>
     * Uses {@link UriQueryBuilder#addEncoded(String, String)} to properly URL-encode
     * the raw (decoded) values from the map. The map contains decoded values because
     * {@link #parseFormUrlEncodedBody(String)} decodes them during parsing, ensuring
     * consistency with raw values added by {@link OAuth2ClientAuthentication#applyAuthentication}.
     * </p>
     *
     * @param parameters the map of raw (decoded) parameters
     * @return the URL-encoded form body string
     */
    private String buildFormUrlEncodedBody(Map<String, String> parameters) {
        UriQueryBuilder queryBuilder = new UriQueryBuilder();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            queryBuilder.addEncoded(entry.getKey(), entry.getValue());
        }
        return queryBuilder.build();
    }

    /**
     * Returns the client authentication strategy used by this token client.
     *
     * @return the OAuth2 client authentication strategy
     */
    public OAuth2ClientAuthentication getAuthentication() {
        return authentication;
    }

    /**
     * Gets the client ID from the authentication strategy.
     *
     * @return the client ID
     */
    public String getClientId() {
        return authentication.getClientId();
    }
}