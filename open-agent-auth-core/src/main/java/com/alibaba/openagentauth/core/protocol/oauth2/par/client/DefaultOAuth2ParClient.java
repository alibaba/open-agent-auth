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
package com.alibaba.openagentauth.core.protocol.oauth2.par.client;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.BasicAuthAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.client.ParClientAuthentication;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OAuth2ParClient} using Java 11 HttpClient.
 * <p>
 * This implementation follows RFC 9126 specification for submitting
 * Pushed Authorization Requests to the Authorization Server.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Uses Java 11+ HttpClient for HTTP communication</li>
 *   <li>Supports pluggable client authentication strategies (Basic Auth, Client Assertion)</li>
 *   <li>Handles standard OAuth 2.0 error responses</li>
 *   <li>Follows RFC 9126 request/response format requirements</li>
 *   <li>Backward compatible with existing Basic Auth implementations</li>
 * </ul>
 * <p>
 * <b>Authentication Methods:</b></p>
 * <ul>
 *   <li><b>Basic Auth (client_secret_basic)</b>: Traditional client_id and client_secret authentication</li>
 *   <li><b>Client Assertion (private_key_jwt)</b>: JWT-based authentication per RFC 7523</li>
 *   <li><b>Custom</b>: Implement ParClientAuthentication interface for custom authentication</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class DefaultOAuth2ParClient implements OAuth2ParClient {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2ParClient.class);

    /**
     * HTTP client used for submitting PAR requests to the Authorization Server.
     * Configured with HTTP/2, 30-second connection timeout, and appropriate headers for OAuth 2.0 communication.
     * Can be customized via constructor for advanced use cases (e.g., custom retry policies, proxy settings).
     */
    private final HttpClient httpClient;

    /**
     * The service endpoint resolver for resolving endpoint URLs.
     */
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * OAuth 2.0 client identifier registered with the Authorization Server.
     * Used for client authentication and for request validation.
     * May be null when using client_assertion authentication.
     */
    private final String clientId;

    /**
     * OAuth 2.0 client secret for authentication with the Authorization Server.
     * Combined with clientId to form Basic Auth credentials for PAR endpoint access.
     * May be null when using client_assertion authentication.
     */
    private final String clientSecret;

    /**
     * Authentication strategy for PAR client authentication.
     * Supports pluggable authentication methods including Basic Auth and Client Assertion.
     * Defaults to BasicAuthAuthentication for backward compatibility.
     */
    private final ParClientAuthentication authentication;

    /**
     * Creates a new DefaultParClient with Basic Authentication.
     * <p>
     * This constructor is provided for backward compatibility and uses BasicAuthAuthentication
     * as the authentication strategy. For new code, consider using the constructor with
     * ParClientAuthentication parameter for more flexibility.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param clientId the client identifier
     * @param clientSecret the client secret for authentication
     * @throws IllegalArgumentException if any parameter is null or blank
     */
    public DefaultOAuth2ParClient(ServiceEndpointResolver serviceEndpointResolver, String clientId, String clientSecret) {

        // Validate parameters
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.clientId = ValidationUtils.validateNotEmpty(clientId, "Client ID");
        this.clientSecret = ValidationUtils.validateNotEmpty(clientSecret, "Client secret");

        // Create HTTP client
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(30))
                .build();

        // Use BasicAuthAuthentication for backward compatibility
        this.authentication = new BasicAuthAuthentication(clientId, clientSecret);

        logger.info("DefaultParClient initialized with Basic Authentication");
    }

    /**
     * Creates a new DefaultParClient with custom HttpClient and Basic Authentication.
     *
     * @param httpClient the HTTP client to use
     * @param serviceEndpointResolver the service endpoint resolver
     * @param clientId the client identifier
     * @param clientSecret the client secret for authentication
     */
    public DefaultOAuth2ParClient(HttpClient httpClient, ServiceEndpointResolver serviceEndpointResolver, String clientId, String clientSecret) {
        this.httpClient = ValidationUtils.validateNotNull(httpClient, "HTTP client");
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.clientId = ValidationUtils.validateNotEmpty(clientId, "Client ID");
        this.clientSecret = ValidationUtils.validateNotEmpty(clientSecret, "Client secret");

        // Use BasicAuthAuthentication for backward compatibility
        this.authentication = new BasicAuthAuthentication(clientId, clientSecret);
    }

    /**
     * Creates a new DefaultParClient with pluggable authentication strategy.
     * <p>
     * This constructor allows using different authentication methods such as Basic Auth,
     * Client Assertion (private_key_jwt), or custom implementations. The authentication
     * strategy is applied when building HTTP requests for PAR submission.
     * </p>
     * <p>
     * <b>Usage Example:</b></p>
     * <pre>{@code
     * // Create client with Client Assertion authentication
     * ClientAssertionGenerator assertionGenerator = new ClientAssertionGenerator(
     *     clientId, signingKey, JWSAlgorithm.RS256
     * );
     * ParClientAuthentication auth = new ClientAssertionAuthentication(
     *     clientId, tokenEndpoint, assertionGenerator
     * );
     * ParClient client = new DefaultParClient(serviceEndpointResolver, auth);
     * }</pre>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param authentication the authentication strategy (e.g., BasicAuthAuthentication, ClientAssertionAuthentication)
     * @throws IllegalArgumentException if serviceEndpointResolver is null
     * @throws NullPointerException if authentication is null
     */
    public DefaultOAuth2ParClient(ServiceEndpointResolver serviceEndpointResolver, ParClientAuthentication authentication) {

        // Validate parameters
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.authentication = ValidationUtils.validateNotNull(authentication, "Authentication strategy");

        // Extract client ID from authentication if available
        this.clientId = authentication.getClientId();
        this.clientSecret = null;

        // Create HTTP client
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(30))
                .build();

        logger.info("DefaultParClient initialized with {} authentication",
                authentication.getAuthenticationMethod());
    }

    /**
     * Creates a new DefaultParClient with custom HttpClient and pluggable authentication strategy.
     *
     * @param httpClient the HTTP client to use
     * @param serviceEndpointResolver the service endpoint resolver
     * @param authentication the authentication strategy
     * @throws IllegalArgumentException if serviceEndpointResolver is null
     * @throws NullPointerException if httpClient or authentication is null
     */
    public DefaultOAuth2ParClient(HttpClient httpClient, ServiceEndpointResolver serviceEndpointResolver, ParClientAuthentication authentication) {

        // Validate parameters
        this.httpClient = ValidationUtils.validateNotNull(httpClient, "HTTP client");
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.authentication = ValidationUtils.validateNotNull(authentication, "Authentication strategy");

        // Extract client ID from authentication if available
        this.clientId = authentication.getClientId();
        this.clientSecret = null;
    }

    @Override
    public ParResponse submitParRequest(ParRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(request, "PAR request");
        logger.debug("Submitting PAR request for client: {}", clientId);

        try {
            // Build HTTP request
            HttpRequest httpRequest = buildHttpRequest(request);
            
            // Send request
            HttpResponse<String> httpResponse = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );
            
            // Parse response
            return parseResponse(httpResponse);
            
        } catch (ParException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error submitting PAR request", e);
            throw ParException.internalError("Failed to submit PAR request: " + e.getMessage(), e);
        }
    }

    /**
     * Builds the HTTP request for PAR submission.
     * <p>
     * This method applies the authentication strategy to the HTTP request builder.
     * The authentication strategy may add headers (e.g., Authorization for Basic Auth)
     * or modify the request body (e.g., client_assertion parameters for private_key_jwt).
     * </p>
     *
     * @param request the PAR request
     * @return the HTTP request
     */
    private HttpRequest buildHttpRequest(ParRequest request) {

        // Build request body with standard PAR parameter (RFC 9126 Section 2.1)
        Map<String, String> requestBodyMap = new HashMap<>();
        requestBodyMap.put("request", request.getRequestJwt());

        // Add state parameter if provided (RFC 6749 Section 4.1.1)
        // State parameter should be sent as a separate parameter, not just in the JWT
        if (!ValidationUtils.isNullOrEmpty(request.getState())) {
            requestBodyMap.put("state", request.getState());
            logger.debug("State parameter added to PAR request body: {}", request.getState());
        }

        // Build HTTP request builder
        String parEndpoint = serviceEndpointResolver.resolveConsumer("authorization-server", "oauth2.par");
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(parEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json");

        // Apply authentication strategy (may add headers or modify request body)
        requestBuilder = authentication.applyAuthentication(requestBuilder, requestBodyMap);

        // Build request body from map
        String requestBody = buildFormUrlEncodedBody(requestBodyMap);

        return requestBuilder.POST(HttpRequest.BodyPublishers.ofString(requestBody)).build();
    }

    /**
     * Builds a URL-encoded form body from a map of parameters.
     *
     * @param parameters the map of parameters
     * @return the URL-encoded form body
     */
    private String buildFormUrlEncodedBody(Map<String, String> parameters) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (!body.isEmpty()) {
                body.append("&");
            }
            body.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            body.append("=");
            body.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return body.toString();
    }

    /**
     * Parses the HTTP response into a ParResponse.
     *
     * @param httpResponse the HTTP response
     * @return the PAR response
     * @throws ParException if the response indicates an error
     */
    private ParResponse parseResponse(HttpResponse<String> httpResponse) {

        // Get status code and response body
        int statusCode = httpResponse.statusCode();
        String responseBody = httpResponse.body();
        
        logger.debug("Received PAR response with status: {}", statusCode);
        
        // Check for error response
        if (statusCode >= 400) {
            parseErrorResponse(statusCode, responseBody);
        }
        
        // Parse successful response
        return parseSuccessResponse(responseBody);
    }

    /**
     * Parses a successful PAR response.
     *
     * @param responseBody the response body
     * @return the PAR response
     * @throws ParException if parsing fails
     */
    private ParResponse parseSuccessResponse(String responseBody) {
        try {
            // Simple JSON parsing (in production, use a proper JSON library)
            String requestUri = extractJsonValue(responseBody, "request_uri");
            String expiresInStr = extractJsonValue(responseBody, "expires_in");

            assert expiresInStr != null;
            int expiresIn = Integer.parseInt(expiresInStr);
            
            logger.debug("Parsed successful PAR response: request_uri={}, expires_in={}", 
                    requestUri, expiresIn);
            
            return ParResponse.success(requestUri, expiresIn);
            
        } catch (Exception e) {
            logger.error("Failed to parse PAR response: {}", responseBody, e);
            throw ParException.internalError("Failed to parse PAR response", e);
        }
    }

    /**
     * Parses an error response.
     *
     * @param statusCode the HTTP status code
     * @param responseBody the response body
     * @throws ParException always thrown
     */
    private void parseErrorResponse(int statusCode, String responseBody) {
        String errorCode = extractJsonValue(responseBody, "error");
        String errorDescription = extractJsonValue(responseBody, "error_description");
        
        logger.error("PAR request failed: status={}, error={}, description={}", 
                statusCode, errorCode, errorDescription);
        
        throw ParException.httpResponseError(statusCode, errorCode, errorDescription);
    }

    /**
     * Extracts a JSON value by key (simplified implementation).
     *
     * @param json the JSON string
     * @param key the key to extract
     * @return the value, or null if not found
     */
    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) {
            return null;
        }
        
        int colonIndex = json.indexOf(":", keyIndex);
        if (colonIndex == -1) {
            return null;
        }
        
        // Skip whitespace after colon
        int valueStart = colonIndex + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }
        
        // Check if value is a string (starts with quote)
        if (valueStart < json.length() && json.charAt(valueStart) == '"') {
            // String value
            valueStart++; // Skip opening quote
            int valueEnd = json.indexOf("\"", valueStart);
            if (valueEnd == -1) {
                return null;
            }
            return json.substring(valueStart, valueEnd);
        } else {
            // Numeric value
            int valueEnd = valueStart;
            while (valueEnd < json.length() && 
                   (Character.isDigit(json.charAt(valueEnd)) || 
                    json.charAt(valueEnd) == '-' ||
                    json.charAt(valueEnd) == '.')) {
                valueEnd++;
            }
            String value = json.substring(valueStart, valueEnd).trim();
            // Check if we actually found a number
            if (value.isEmpty()) {
                return null;
            }
            return value;
        }
    }


}