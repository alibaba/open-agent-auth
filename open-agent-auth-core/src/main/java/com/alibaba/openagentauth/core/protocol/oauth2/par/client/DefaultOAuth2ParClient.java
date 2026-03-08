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
import com.alibaba.openagentauth.core.protocol.oauth2.client.OAuth2ClientAuthentication;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.openagentauth.core.util.UriQueryBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
 *   <li>Follows RFC 9126 request/response format requirements</li>
 * </ul>
 * <p>
 * <b>Authentication Methods:</b></p>
 * <ul>
 *   <li><b>Basic Auth (client_secret_basic)</b>: Traditional client_id and client_secret authentication</li>
 *   <li><b>Client Assertion (private_key_jwt)</b>: JWT-based authentication per RFC 7523</li>
 *   <li><b>Custom</b>: Implement OAuth2ClientAuthentication interface for custom authentication</li>
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
     * Authentication strategy for PAR client authentication.
     * <p>
     * Supports pluggable authentication methods including Basic Auth and Client Assertion.
     * Per RFC 9126 Section 2.1, the PAR endpoint uses the same client authentication
     * methods as the Token endpoint.
     * </p>
     */
    private final OAuth2ClientAuthentication authentication;

    /**
     * Creates a new DefaultParClient with pluggable authentication strategy.
     * <p>
     * This is the preferred constructor that supports any OAuth 2.0 client authentication
     * method through the {@link OAuth2ClientAuthentication} strategy interface. Per RFC 9126
     * Section 2.1, the PAR endpoint uses the same client authentication methods as the
     * Token endpoint.
     * </p>
     * <p>
     * <b>Usage Example:</b></p>
     * <pre>{@code
     * // Basic Authentication
     * OAuth2ClientAuthentication auth = new BasicAuthAuthentication(clientId, clientSecret);
     * OAuth2ParClient client = new DefaultOAuth2ParClient(resolver, auth);
     *
     * // Per-request Client Assertion Authentication (e.g., WIMSE WIT)
     * OAuth2ClientAuthentication auth = new ClientAssertionAuthentication();
     * OAuth2ParClient client = new DefaultOAuth2ParClient(resolver, auth);
     * }</pre>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param authentication the client authentication strategy
     * @throws IllegalArgumentException if any required parameter is null
     */
    public DefaultOAuth2ParClient(ServiceEndpointResolver serviceEndpointResolver, OAuth2ClientAuthentication authentication) {

        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.authentication = ValidationUtils.validateNotNull(authentication, "Authentication strategy");

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
     * @param authentication the client authentication strategy
     * @throws IllegalArgumentException if any required parameter is null
     */
    public DefaultOAuth2ParClient(
            HttpClient httpClient,
            ServiceEndpointResolver serviceEndpointResolver,
            OAuth2ClientAuthentication authentication) {

        this.httpClient = ValidationUtils.validateNotNull(httpClient, "HTTP client");
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.authentication = ValidationUtils.validateNotNull(authentication, "Authentication strategy");
    }

    @Override
    public ParResponse submitParRequest(ParRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(request, "PAR request");
        logger.debug("Submitting PAR request for client: {}", authentication.getClientId());

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
     * <p>
     * <b>Client ID Propagation:</b> The {@code client_id} from the {@link ParRequest}
     * is placed into the request body map <em>before</em> the authentication strategy
     * is applied. This ensures that a DCR-registered dynamic {@code client_id} takes
     * precedence over the static client ID configured in the authentication strategy.
     * </p>
     *
     * @param request the PAR request
     * @return the HTTP request
     */
    private HttpRequest buildHttpRequest(ParRequest request) {

        // Build request body with standard PAR parameter (RFC 9126 Section 2.1)
        Map<String, String> requestBodyMap = new HashMap<>();
        requestBodyMap.put("request", request.getRequestJwt());

        // Propagate client_id from PAR request into the body map so that the
        // authentication strategy (e.g., ClientAssertionAuthentication) respects
        // the DCR-registered dynamic client_id instead of overwriting it with
        // the static default.
        if (!ValidationUtils.isNullOrEmpty(request.getClientId())) {
            requestBodyMap.put("client_id", request.getClientId());
        }

        // Add state parameter if provided (RFC 6749 Section 4.1.1)
        if (!ValidationUtils.isNullOrEmpty(request.getState())) {
            requestBodyMap.put("state", request.getState());
            logger.debug("State parameter added to PAR request body: {}", request.getState());
        }

        // Propagate additional parameters (e.g., WIT for client assertion authentication)
        // into the request body map. This allows the authentication strategy to extract
        // per-request credentials from the body map without relying on global state.
        if (request.getAdditionalParameters() != null) {
            for (Map.Entry<String, Object> entry : request.getAdditionalParameters().entrySet()) {
                if (entry.getValue() instanceof String stringValue) {
                    requestBodyMap.put(entry.getKey(), stringValue);
                }
            }
        }

        // Build HTTP request builder
        String parEndpoint = serviceEndpointResolver.resolveConsumer("authorization-server", "oauth2.par");
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(parEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json");

        // Apply authentication strategy (may add headers or modify request body)
        requestBuilder = authentication.applyAuthentication(requestBuilder, requestBodyMap);

        // Build request body from map using UriQueryBuilder
        String requestBody = buildFormUrlEncodedBody(requestBodyMap);

        return requestBuilder.POST(HttpRequest.BodyPublishers.ofString(requestBody)).build();
    }

    /**
     * Builds a URL-encoded form body from a map of parameters using {@link UriQueryBuilder}.
     *
     * @param parameters the map of parameters
     * @return the URL-encoded form body
     */
    private String buildFormUrlEncodedBody(Map<String, String> parameters) {
        UriQueryBuilder queryBuilder = new UriQueryBuilder();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            queryBuilder.addEncoded(entry.getKey(), entry.getValue());
        }
        return queryBuilder.build();
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