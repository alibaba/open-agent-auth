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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller for OAuth 2.0 Dynamic Client Registration (DCR) endpoint.
 * <p>
 * This controller handles DCR requests according to RFC 7591 specification.
 * It supports client registration, read, update, and delete operations.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7592">RFC 7592 - OAuth 2.0 Dynamic Client Registration Management</a>
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "open-agent-auth.roles.authorization-server", name = "enabled", havingValue = "true")
public class OAuth2DcrController {

    /**
     * The logger for the OAuth 2.0 DCR controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(OAuth2DcrController.class);

    /**
     * The DCR server.
     */
    private final OAuth2DcrServer dcrServer;

    /**
     * Creates a new DCR controller.
     *
     * @param dcrServer the DCR server
     */
    public OAuth2DcrController(OAuth2DcrServer dcrServer) {
        this.dcrServer = dcrServer;
    }

    /**
     * Registers a new OAuth 2.0 client.
     * <p>
     * This endpoint handles client registration requests according to RFC 7591.
     * </p>
     *
     * @param requestBody the DCR request body
     * @return the DCR response with registered client information
     */
    @PostMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.dcr:/oauth2/register}")
    public ResponseEntity<Map<String, Object>> registerClient(
            @RequestBody Map<String, Object> requestBody
    ) {
        try {
            logger.info("Received client registration request");

            DcrRequest request = parseDcrRequest(requestBody);
            DcrResponse response = dcrServer.registerClient(request);

            logger.info("Client registered successfully: {}", response.getClientId());

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(buildDcrResponseMap(response));

        } catch (DcrException e) {
            logger.error("Client registration failed: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", e.getErrorCode(),
                            "error_description", e.getMessage()
                    ));
        } catch (Exception e) {
            logger.error("Unexpected error during client registration: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "error", "server_error",
                            "error_description", "Internal server error"
                    ));
        }
    }

    /**
     * Reads the current registration for a registered client.
     * <p>
     * This endpoint handles client read requests according to RFC 7592.
     * </p>
     *
     * @param clientId the client identifier
     * @param authorization the registration access token in Authorization header
     * @return the DCR response with client metadata
     */
    @GetMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.dcr:/oauth2/register}/{clientId}")
    public ResponseEntity<Map<String, Object>> readClient(
            @PathVariable String clientId,
            String authorization
    ) {
        try {
            logger.info("Reading client registration: {}", clientId);

            String registrationAccessToken = extractRegistrationAccessToken(authorization);
            DcrResponse response = dcrServer.readClient(clientId, registrationAccessToken);

            return ResponseEntity.ok(buildDcrResponseMap(response));

        } catch (DcrException e) {
            logger.error("Failed to read client registration: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", e.getErrorCode(),
                            "error_description", e.getMessage()
                    ));
        }
    }

    /**
     * Updates the registration for a registered client.
     * <p>
     * This endpoint handles client update requests according to RFC 7592.
     * </p>
     *
     * @param clientId the client identifier
     * @param requestBody the DCR request body with updated metadata
     * @param authorization the registration access token in Authorization header
     * @return the updated DCR response
     */
    @PutMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.dcr:/oauth2/register}/{clientId}")
    public ResponseEntity<Map<String, Object>> updateClient(
            @PathVariable String clientId,
            @RequestBody Map<String, Object> requestBody,
            String authorization
    ) {
        try {
            logger.info("Updating client registration: {}", clientId);

            String registrationAccessToken = extractRegistrationAccessToken(authorization);
            DcrRequest request = parseDcrRequest(requestBody);
            DcrResponse response = dcrServer.updateClient(clientId, registrationAccessToken, request);

            return ResponseEntity.ok(buildDcrResponseMap(response));

        } catch (DcrException e) {
            logger.error("Failed to update client registration: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", e.getErrorCode(),
                            "error_description", e.getMessage()
                    ));
        }
    }

    /**
     * Deletes the registration for a registered client.
     * <p>
     * This endpoint handles client delete requests according to RFC 7592.
     * </p>
     *
     * @param clientId the client identifier
     * @param authorization the registration access token in Authorization header
     * @return no content on success
     */
    @DeleteMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.dcr:/oauth2/register}/{clientId}")
    public ResponseEntity<Void> deleteClient(
            @PathVariable String clientId,
            String authorization
    ) {
        try {
            logger.info("Deleting client registration: {}", clientId);

            String registrationAccessToken = extractRegistrationAccessToken(authorization);
            dcrServer.deleteClient(clientId, registrationAccessToken);

            logger.info("Client deleted successfully: {}", clientId);
            return ResponseEntity.noContent().build();

        } catch (DcrException e) {
            logger.error("Failed to delete client registration: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    /**
     * Parses the DCR request from the request body.
     *
     * @param requestBody the request body
     * @return the parsed DcrRequest
     */
    private DcrRequest parseDcrRequest(Map<String, Object> requestBody) {
        DcrRequest.Builder builder = DcrRequest.builder();

        if (requestBody.containsKey("redirect_uris")) {
            Object redirectUrisObj = requestBody.get("redirect_uris");
            if (redirectUrisObj instanceof List) {
                builder.redirectUris((List<String>) redirectUrisObj);
            } else if (redirectUrisObj instanceof String) {
                builder.redirectUris(List.of((String) redirectUrisObj));
            }
        }
        if (requestBody.containsKey("client_name")) {
            builder.clientName((String) requestBody.get("client_name"));
        }
        if (requestBody.containsKey("scope")) {
            builder.scope((String) requestBody.get("scope"));
        }
        if (requestBody.containsKey("grant_types")) {
            Object grantTypesObj = requestBody.get("grant_types");
            if (grantTypesObj instanceof List) {
                builder.grantTypes((List<String>) grantTypesObj);
            } else if (grantTypesObj instanceof String) {
                builder.grantTypes(List.of((String) grantTypesObj));
            }
        }
        if (requestBody.containsKey("response_types")) {
            Object responseTypesObj = requestBody.get("response_types");
            if (responseTypesObj instanceof List) {
                builder.responseTypes((List<String>) responseTypesObj);
            } else if (responseTypesObj instanceof String) {
                builder.responseTypes(List.of((String) responseTypesObj));
            }
        }
        if (requestBody.containsKey("token_endpoint_auth_method")) {
            builder.tokenEndpointAuthMethod((String) requestBody.get("token_endpoint_auth_method"));
        }

        return builder.build();
    }

    /**
     * Extracts the registration access token from the Authorization header.
     *
     * @param authorization the Authorization header value
     * @return the registration access token
     */
    private String extractRegistrationAccessToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Missing or invalid Authorization header");
        }
        return authorization.substring(7);
    }

    /**
     * Builds a map from the DCR response.
     *
     * @param response the DCR response
     * @return the response map
     */
    private Map<String, Object> buildDcrResponseMap(DcrResponse response) {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("client_id", response.getClientId());
        responseMap.put("client_secret", response.getClientSecret());
        responseMap.put("client_id_issued_at", response.getClientIdIssuedAt());
        responseMap.put("client_secret_expires_at", response.getClientSecretExpiresAt());
        responseMap.put("registration_access_token", response.getRegistrationAccessToken());
        responseMap.put("registration_client_uri", response.getRegistrationClientUri());
        responseMap.put("client_name", response.getClientName());
        responseMap.put("redirect_uris", response.getRedirectUris());
        responseMap.put("scope", response.getScope());
        responseMap.put("grant_types", response.getGrantTypes());
        responseMap.put("response_types", response.getResponseTypes());
        responseMap.put("token_endpoint_auth_method", response.getTokenEndpointAuthMethod());
        return responseMap;
    }
}