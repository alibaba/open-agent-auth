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
import java.util.Map;

/**
 * Client Assertion authentication implementation for PAR client authentication.
 * <p>
 * This implementation uses JWT-based client assertions according to RFC 7523.
 * The assertion is included in the request body as the {@code client_assertion} parameter.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 1.0
 */
public class ClientAssertionAuthentication implements ParClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(ClientAssertionAuthentication.class);

    /**
     * The client identifier.
     */
    private final String clientId;

    /**
     * The generator for creating client assertions.
     */
    private final ClientAssertionGenerator assertionGenerator;

    /**
     * The token endpoint URL (audience for the assertion).
     */
    private final String tokenEndpoint;

    /**
     * Creates a new ClientAssertionAuthentication.
     *
     * @param clientId the client identifier
     * @param assertionGenerator the generator for creating client assertions
     * @param tokenEndpoint the token endpoint URL (used as audience)
     * @throws IllegalArgumentException if any parameter is null or blank
     */
    public ClientAssertionAuthentication(
            String clientId,
            ClientAssertionGenerator assertionGenerator,
            String tokenEndpoint
    ) {
        this.clientId = ValidationUtils.validateNotEmpty(clientId, "Client ID");
        this.assertionGenerator = ValidationUtils.validateNotNull(assertionGenerator, "Assertion generator");
        this.tokenEndpoint = ValidationUtils.validateNotEmpty(tokenEndpoint, "Token endpoint");
        
        logger.debug("ClientAssertionAuthentication initialized for client: {}", clientId);
    }

    @Override
    public HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, Map<String, String> requestBody) {
        try {
            // Generate client assertion
            String assertion = assertionGenerator.generateAssertion(tokenEndpoint);
            
            // Add client_assertion parameters to request body
            requestBody.put("client_id", clientId);
            requestBody.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            requestBody.put("client_assertion", assertion);
            
            logger.debug("Applied client assertion authentication for client: {}", clientId);
            
            return requestBuilder;
            
        } catch (Exception e) {
            logger.error("Failed to apply client assertion authentication", e);
            throw new RuntimeException("Failed to apply client assertion authentication: " + e.getMessage(), e);
        }
    }

    @Override
    public String getAuthenticationMethod() {
        return "private_key_jwt";
    }

    @Override
    public String getClientId() {
        return clientId;
    }

}