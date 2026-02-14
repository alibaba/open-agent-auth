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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.client;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.OAuth2DcrClientAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.NoAuthOAuth2DcrClientAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.WimseOAuth2DcrClientAuthentication;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Default implementation of {@link OAuth2DcrClient} using Java 11 HttpClient.
 * <p>
 * This implementation follows RFC 7591 specification for Dynamic Client Registration
 * with pluggable authentication strategies using the Strategy Pattern.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Uses Java 11+ HttpClient for HTTP communication</li>
 *   <li>Supports pluggable authentication strategies (WIMSE, None, Bearer, etc.)</li>
 *   <li>Handles standard OAuth 2.0 error responses</li>
 *   <li>Follows RFC 7591 request/response format requirements</li>
 * </ul>
 * <p>
 * <b>Authentication Strategies:</b></p>
 * <ul>
 *   <li><b>WIMSE</b>: Workload Identity Token (WIT) authentication for workload-based clients</li>
 *   <li><b>None</b>: No authentication for initial registration (when AS allows it)</li>
 *   <li><b>Bearer</b>: Bearer token authentication</li>
 * </ul>
 * <p>
 * <b>WIMSE Integration:</b></p>
 * <p>
 * When using WIMSE authentication, the WIT is included in the Authorization
 * header as a Bearer token. The Authorization Server validates the WIT signature
 * and claims before registering the client. This binds the OAuth client to the
 * workload identity specified in the WIT.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">
 *     draft-ietf-wimse-workload-creds</a>
 * @see OAuth2DcrClientAuthentication
 * @since 1.0
 */
public class DefaultOAuth2DcrClient implements OAuth2DcrClient {

    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2DcrClient.class);

    /**
     * HTTP client used for DCR requests.
     */
    private final HttpClient httpClient;

    /**
     * The service endpoint resolver for resolving endpoint URLs.
     */
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * ObjectMapper for JSON serialization/deserialization.
     */
    private final ObjectMapper objectMapper;

    /**
     * Authentication strategy for DCR requests.
     */
    private final OAuth2DcrClientAuthentication authentication;

    /**
     * Creates a new DefaultDcrClient with no authentication.
     * <p>
     * This constructor creates a client with {@link NoAuthOAuth2DcrClientAuthentication},
     * suitable for scenarios where the Authorization Server does not require
     * authentication for initial client registration.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @throws IllegalArgumentException if serviceEndpointResolver is null
     */
    public DefaultOAuth2DcrClient(ServiceEndpointResolver serviceEndpointResolver) {
        this(serviceEndpointResolver, new NoAuthOAuth2DcrClientAuthentication());
    }

    /**
     * Creates a new DefaultDcrClient with custom authentication strategy.
     * <p>
     * This constructor allows specifying the authentication strategy to use for
     * DCR requests. Common strategies include:
     * <ul>
     *   <li>{@link WimseOAuth2DcrClientAuthentication} - WIMSE protocol with WIT</li>
     *   <li>{@link NoAuthOAuth2DcrClientAuthentication} - No authentication</li>
     * </ul>
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param authentication the authentication strategy
     * @throws IllegalArgumentException if serviceEndpointResolver is null
     * @throws NullPointerException if authentication is null
     */
    public DefaultOAuth2DcrClient(ServiceEndpointResolver serviceEndpointResolver, OAuth2DcrClientAuthentication authentication) {
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        this.authentication = ValidationUtils.validateNotNull(authentication, "Authentication strategy");
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.objectMapper = new ObjectMapper();

        logger.info("DefaultDcrClient initialized with service endpoint resolver, authentication: {}",
                authentication.getAuthenticationMethod());
    }

    @Override
    public DcrResponse registerClient(DcrRequest request) {

        // Validate parameters
        ValidationUtils.validateNotNull(request, "DCR request");
        logger.info("Registering OAuth client with name: {}", request.getClientName());

        try {
            // Build HTTP request
            HttpRequest httpRequest = buildRegisterRequest(request);
            
            // Send request
            HttpResponse<String> httpResponse = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );
            
            // Parse response
            return parseResponse(httpResponse);
            
        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error registering client", e);
            throw DcrException.httpResponseError(500, "server_error", "Failed to register client: " + e.getMessage());
        }
    }

    @Override
    public DcrResponse readClient(String registrationClientUri, String registrationAccessToken) {

        // Validate parameters
        ValidationUtils.validateNotNull(registrationClientUri, "Registration client URI");
        ValidationUtils.validateNotNull(registrationAccessToken, "Registration access token");
        
        logger.debug("Reading client registration from: {}", registrationClientUri);

        try {
            // Build HTTP request
            HttpRequest httpRequest = buildReadRequest(registrationClientUri, registrationAccessToken);
            
            // Send request
            HttpResponse<String> httpResponse = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );
            
            // Parse response
            return parseResponse(httpResponse);
            
        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error reading client registration", e);
            throw DcrException.httpResponseError(500, "server_error", "Failed to read client: " + e.getMessage());
        }
    }

    @Override
    public DcrResponse updateClient(String registrationClientUri, String registrationAccessToken, DcrRequest request) {

        // Validate parameters
        ValidationUtils.validateNotNull(registrationClientUri, "Registration client URI");
        ValidationUtils.validateNotNull(registrationAccessToken, "Registration access token");
        ValidationUtils.validateNotNull(request, "DCR request");
        
        logger.info("Updating client registration at: {}", registrationClientUri);

        try {
            // Build HTTP request
            HttpRequest httpRequest = buildUpdateRequest(registrationClientUri, registrationAccessToken, request);
            
            // Send request
            HttpResponse<String> httpResponse = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );
            
            // Parse response
            return parseResponse(httpResponse);
            
        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error updating client registration", e);
            throw DcrException.httpResponseError(500, "server_error", "Failed to update client: " + e.getMessage());
        }
    }

    @Override
    public void deleteClient(String registrationClientUri, String registrationAccessToken) {

        // Validate parameters
        ValidationUtils.validateNotNull(registrationClientUri, "Registration client URI");
        ValidationUtils.validateNotNull(registrationAccessToken, "Registration access token");
        
        logger.info("Deleting client registration at: {}", registrationClientUri);

        try {
            // Build HTTP request
            HttpRequest httpRequest = buildDeleteRequest(registrationClientUri, registrationAccessToken);
            
            // Send request
            HttpResponse<String> httpResponse = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );
            
            // Check for error response
            if (httpResponse.statusCode() >= 400) {
                parseErrorResponse(httpResponse.statusCode(), httpResponse.body());
            }
            
            logger.info("Successfully deleted client registration");
            
        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error deleting client registration", e);
            throw DcrException.httpResponseError(500, "server_error", "Failed to delete client: " + e.getMessage());
        }
    }

    /**
     * Builds the HTTP request for client registration.
     *
     * @param request the DCR request
     * @return the HTTP request
     */
    private HttpRequest buildRegisterRequest(DcrRequest request) {
        try {
            String requestBody = objectMapper.writeValueAsString(request);
            String registrationEndpoint = serviceEndpointResolver.resolveConsumer("authorization-server", "oauth2.dcr");
            
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(registrationEndpoint))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody));
            
            // Apply authentication strategy
            builder = authentication.applyAuthentication(builder, request);
            
            return builder.build();
            
        } catch (Exception e) {
            logger.error("Failed to serialize DCR request", e);
            throw DcrException.invalidClientMetadata("Failed to serialize request: " + e.getMessage());
        }
    }

    /**
     * Builds the HTTP request for reading client registration.
     *
     * @param registrationClientUri the registration client URI
     * @param registrationAccessToken the registration access token
     * @return the HTTP request
     */
    private HttpRequest buildReadRequest(String registrationClientUri, String registrationAccessToken) {
        return HttpRequest.newBuilder()
                .uri(URI.create(registrationClientUri))
                .header("Authorization", "Bearer " + registrationAccessToken)
                .header("Accept", "application/json")
                .GET()
                .build();
    }

    /**
     * Builds the HTTP request for updating client registration.
     *
     * @param registrationClientUri the registration client URI
     * @param registrationAccessToken the registration access token
     * @param request the DCR request with updated metadata
     * @return the HTTP request
     */
    private HttpRequest buildUpdateRequest(String registrationClientUri, String registrationAccessToken, DcrRequest request) {
        try {
            String requestBody = objectMapper.writeValueAsString(request);
            
            return HttpRequest.newBuilder()
                    .uri(URI.create(registrationClientUri))
                    .header("Authorization", "Bearer " + registrationAccessToken)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            
        } catch (Exception e) {
            logger.error("Failed to serialize DCR request", e);
            throw DcrException.invalidClientMetadata("Failed to serialize request: " + e.getMessage());
        }
    }

    /**
     * Builds the HTTP request for deleting client registration.
     *
     * @param registrationClientUri the registration client URI
     * @param registrationAccessToken the registration access token
     * @return the HTTP request
     */
    private HttpRequest buildDeleteRequest(String registrationClientUri, String registrationAccessToken) {
        return HttpRequest.newBuilder()
                .uri(URI.create(registrationClientUri))
                .header("Authorization", "Bearer " + registrationAccessToken)
                .DELETE()
                .build();
    }

    /**
     * Parses the HTTP response into a DcrResponse.
     *
     * @param httpResponse the HTTP response
     * @return the DCR response
     * @throws DcrException if the response indicates an error
     */
    private DcrResponse parseResponse(HttpResponse<String> httpResponse) {
        int statusCode = httpResponse.statusCode();
        String responseBody = httpResponse.body();
        
        logger.debug("Received DCR response with status: {}", statusCode);
        
        // Check for error response
        if (statusCode >= 400) {
            parseErrorResponse(statusCode, responseBody);
        }
        
        // Parse successful response
        return parseSuccessResponse(responseBody);
    }

    /**
     * Parses a successful DCR response.
     *
     * @param responseBody the response body
     * @return the DCR response
     * @throws DcrException if parsing fails
     */
    private DcrResponse parseSuccessResponse(String responseBody) {
        try {
            DcrResponse response = objectMapper.readValue(responseBody, DcrResponse.class);
            logger.info("Successfully parsed DCR response for client: {}", response.getClientId());
            return response;
        } catch (Exception e) {
            logger.error("Failed to parse DCR response: {}", responseBody, e);
            throw DcrException.httpResponseError(500, "server_error", "Failed to parse response");
        }
    }

    /**
     * Parses an error response.
     *
     * @param statusCode the HTTP status code
     * @param responseBody the response body
     * @throws DcrException always thrown
     */
    private void parseErrorResponse(int statusCode, String responseBody) {
        String errorCode = extractJsonValue(responseBody, "error");
        String errorDescription = extractJsonValue(responseBody, "error_description");
        
        logger.error("DCR request failed: status={}, error={}, description={}", 
                statusCode, errorCode, errorDescription);
        
        throw DcrException.httpResponseError(statusCode, errorCode, errorDescription);
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
        
        int valueStart = json.indexOf("\"", colonIndex) + 1;
        if (valueStart == 0) {
            return null;
        }
        
        int valueEnd = json.indexOf("\"", valueStart);
        if (valueEnd == -1) {
            return null;
        }
        
        return json.substring(valueStart, valueEnd);
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