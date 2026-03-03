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
import com.alibaba.openagentauth.core.util.UriQueryBuilder;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

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
 *   <li>Basic authentication for confidential clients</li>
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
     * The client ID for authentication.
     */
    private final String clientId;

    /**
     * The client secret for authentication (null for public clients).
     */
    private final String clientSecret;

    /**
     * The service name for resolving consumer endpoints (e.g., "agent-user-idp", "authorization-server").
     */
    private final String serviceName;

    /**
     * Creates a new DefaultTokenClient for confidential clients.
     * <p>
     * Confidential clients use Basic authentication with client credentials.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param serviceName the service name for resolving consumer endpoints
     * @param clientId the client ID
     * @param clientSecret the client secret (null for public clients)
     */
    public DefaultOAuth2TokenClient(ServiceEndpointResolver serviceEndpointResolver, String serviceName, String clientId, String clientSecret) {

        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.serviceName = ValidationUtils.validateNotEmpty(serviceName, "Service name");
        this.clientId = ValidationUtils.validateNotNull(clientId, "Client ID");
        this.clientSecret = ValidationUtils.validateNotNull(clientSecret, "Client secret");
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        
        logger.info("DefaultTokenClient initialized with service endpoint resolver, service_name: {}, client_id: {}", 
                serviceName, clientId);
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
            // Build request body
            String requestBody = String.format(
                    "grant_type=refresh_token&refresh_token=%s",
                    URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)
            );

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
            // Build request body
            String requestBody = String.format(
                    "token=%s&token_type_hint=%s",
                    URLEncoder.encode(token, StandardCharsets.UTF_8),
                    URLEncoder.encode(tokenType, StandardCharsets.UTF_8)
            );

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
     * Builds the token request body from a TokenRequest object.
     *
     * @param request the token request
     * @return the URL-encoded request body
     */
    private String buildTokenRequestBody(TokenRequest request) {

        // Build request body with required parameters
        UriQueryBuilder builder = new UriQueryBuilder()
                .add("grant_type", "authorization_code")
                .add("code", URLEncoder.encode(request.getCode(), StandardCharsets.UTF_8));

        // Add optional parameters
        if (request.getRedirectUri() != null && !request.getRedirectUri().isEmpty()) {
            builder.add("redirect_uri", URLEncoder.encode(request.getRedirectUri(), StandardCharsets.UTF_8));
        }
        if (request.getClientId() != null && !request.getClientId().isEmpty()) {
            builder.add("client_id", URLEncoder.encode(request.getClientId(), StandardCharsets.UTF_8));
        }

        // Extract scope from additional parameters if present
        if (request.getAdditionalParameters() != null && request.getAdditionalParameters().containsKey("scope")) {
            Object scope = request.getAdditionalParameters().get("scope");
            if (scope != null) {
                builder.add("scope", URLEncoder.encode(scope.toString(), StandardCharsets.UTF_8));
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
     * Builds HTTP request builder with common headers and authentication.
     *
     * @param requestBody the request body
     * @return the HTTP request builder
     */
    private HttpRequest.Builder buildHttpRequestBuilder(String requestBody) {

        // Build HTTP request - use consumer endpoint instead of provider endpoint
        String tokenEndpoint = serviceEndpointResolver.resolveConsumer(serviceName, "oauth2.token");
        if (tokenEndpoint == null) {
            throw new IllegalStateException(
                "Cannot resolve token endpoint for service: " + serviceName + 
                ". Please check your configuration under 'open-agent-auth.services.consumers." + serviceName + "'."
            );
        }
        
        HttpRequest.Builder httpRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody));

        // Add Basic authentication for confidential clients
        String credentials = clientId + ":" + clientSecret;
        byte[] credentialsBytes = credentials.getBytes(StandardCharsets.UTF_8);
        String encodedCredentials = Base64.getEncoder().encodeToString(credentialsBytes);
        httpRequestBuilder.header("Authorization", "Basic " + encodedCredentials);
        logger.debug("Basic authentication header added");

        return httpRequestBuilder;
    }



    /**
     * Gets the client ID.
     *
     * @return the client ID
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Gets the client secret.
     *
     * @return the client secret, or null if not configured
     */
    public String getClientSecret() {
        return clientSecret;
    }

}