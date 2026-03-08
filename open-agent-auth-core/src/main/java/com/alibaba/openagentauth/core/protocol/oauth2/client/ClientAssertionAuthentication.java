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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpRequest;
import java.util.Map;

/**
 * Per-request client assertion authentication for OAuth 2.0 endpoints.
 * <p>
 * This implementation supports two modes of operation:
 * </p>
 * <ul>
 *   <li><b>Standard private_key_jwt mode:</b> When an {@code authorizationServerUrl} is provided
 *       and the request body contains a {@code workload_private_key}, this class generates a
 *       standard RFC 7523 client assertion JWT using the workload's private key. The assertion
 *       is signed with the private key and contains the required claims for OAuth 2.0 client
 *       authentication.</li>
 *   <li><b>Pre-signed assertion mode:</b> When no {@code workload_private_key} is present,
 *       this class extracts a pre-existing {@code client_assertion} JWT from the request body
 *       map (e.g., a WIMSE Workload Identity Token) and applies it as the OAuth 2.0 client
 *       authentication.</li>
 * </ul>
 * <p>
 * <b>Standard private_key_jwt Flow:</b></p>
 * <ol>
 *   <li>The caller provides the workload's private key via {@code workload_private_key} parameter</li>
 *   <li>The private key is parsed as a JWK</li>
 *   <li>A standard client assertion JWT is generated using {@link ClientAssertionGenerator}</li>
 *   <li>The generated assertion replaces any existing {@code client_assertion} in the request body</li>
 *   <li>The {@code workload_private_key} is removed from the request body (not sent to AS)</li>
 *   <li>The {@code client_assertion_type} is set to {@code urn:ietf:params:oauth:client-assertion-type:jwt-bearer}</li>
 * </ol>
 * <p>
 * <b>Pre-signed Assertion Flow:</b></p>
 * <p>
 * This mode expects the caller to provide a pre-signed JWT (e.g., a WIMSE Workload Identity Token)
 * via the request's {@code additionalParameters}. The transport layer forwards these parameters
 * into the request body map, where this class picks up the {@code client_assertion} value and
 * adds the required {@code client_assertion_type}.
 * </p>
 * <p>
 * This approach provides stronger security guarantees compared to self-asserted
 * {@code private_key_jwt} because the assertion JWT can be issued by a trusted
 * third-party identity provider, and the Authorization Server verifies the signature
 * against the provider's published JWKS.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @see ClientAssertionGenerator
 * @since 1.0
 */
public class ClientAssertionAuthentication implements OAuth2ClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(ClientAssertionAuthentication.class);

    /**
     * The standard OAuth 2.0 parameter name for client assertion (RFC 7523 Section 2.2).
     * <p>
     * In standard mode, this is populated by {@link ClientAssertionGenerator}.
     * In pre-signed mode, callers propagate the assertion JWT through {@code additionalParameters}
     * using this key. The transport layer forwards it into the request body map, and this
     * class ensures the corresponding {@code client_assertion_type} is also set.
     * </p>
     */
    public static final String CLIENT_ASSERTION_PARAM = "client_assertion";

    /**
     * The parameter name for the workload private key in JWK format.
     * <p>
     * When present, this key is used to generate a standard client assertion JWT.
     * The private key is removed from the request body before sending to the AS.
     * </p>
     */
    public static final String WORKLOAD_PRIVATE_KEY_PARAM = "workload_private_key";

    /**
     * The parameter name for client ID in the request body.
     * <p>
     * Required when generating a standard client assertion JWT.
     * </p>
     */
    public static final String CLIENT_ID_PARAM = "client_id";

    private static final String CLIENT_ASSERTION_TYPE_PARAM = "client_assertion_type";
    private static final String JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * The authorization server URL for generating standard client assertions.
     * <p>
     * When non-null, this enables standard private_key_jwt mode where client assertions
     * are generated using the workload's private key. When null, only pre-signed assertions
     * are supported.
     * </p>
     */
    private final String authorizationServerUrl;

    /**
     * Creates a new ClientAssertionAuthentication for pre-signed assertion mode.
     * <p>
     * No constructor parameters are needed because the client assertion JWT is
     * propagated per-request through the request body map. This mode only supports
     * pre-signed assertions and does not generate new assertions.
     * </p>
     */
    public ClientAssertionAuthentication() {
        this(null);
    }

    /**
     * Creates a new ClientAssertionAuthentication for standard private_key_jwt mode.
     * <p>
     * When an {@code authorizationServerUrl} is provided, this class will generate
     * standard RFC 7523 client assertions using the workload's private key when
     * the {@code workload_private_key} parameter is present in the request body.
     * </p>
     *
     * @param authorizationServerUrl the authorization server token endpoint URL,
     *                               or {@code null} for pre-signed assertion mode only
     */
    public ClientAssertionAuthentication(String authorizationServerUrl) {
        this.authorizationServerUrl = authorizationServerUrl;
        logger.debug("ClientAssertionAuthentication initialized with authorizationServerUrl: {}", authorizationServerUrl);
    }

    @Override
    public HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, Map<String, String> requestBody) {
        // Check if we should generate a standard client assertion
        String workloadPrivateKeyJson = requestBody.get(WORKLOAD_PRIVATE_KEY_PARAM);
        
        if (workloadPrivateKeyJson != null && !workloadPrivateKeyJson.isBlank() && 
            authorizationServerUrl != null && !authorizationServerUrl.isBlank()) {
            // Standard private_key_jwt mode: generate assertion from workload private key
            logger.debug("Generating standard client assertion from workload private key");
            
            try {
                // Parse the workload private key
                JWK privateKey = JWK.parse(workloadPrivateKeyJson);
                
                // Get client ID from request body
                String clientId = requestBody.get(CLIENT_ID_PARAM);
                if (clientId == null || clientId.isBlank()) {
                    throw new IllegalStateException(
                            "client_id not found in request body. Required for generating client assertion.");
                }
                
                // Generate standard client assertion
                String clientAssertion = ClientAssertionGenerator.generateClientAssertion(
                        clientId, authorizationServerUrl, privateKey);
                
                // Replace the client_assertion in the request body
                requestBody.put(CLIENT_ASSERTION_PARAM, clientAssertion);
                
                // Remove the workload_private_key (should not be sent to AS)
                requestBody.remove(WORKLOAD_PRIVATE_KEY_PARAM);
                
                logger.debug("Standard client assertion generated and applied for client: {}", clientId);
                
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to generate client assertion: " + e.getMessage(), e);
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse workload private key: " + e.getMessage(), e);
            }
        } else {
            // Pre-signed assertion mode: use existing client_assertion
            String assertionToken = requestBody.get(CLIENT_ASSERTION_PARAM);
            if (assertionToken == null || assertionToken.isBlank()) {
                throw new IllegalStateException(
                        "client_assertion not found in request body. The caller must place the " +
                        "assertion JWT into the request's additionalParameters using the key '" +
                        CLIENT_ASSERTION_PARAM + "'.");
            }
            
            logger.debug("Applied pre-signed client assertion authentication");
        }

        // Set the client_assertion_type
        requestBody.put(CLIENT_ASSERTION_TYPE_PARAM, JWT_BEARER_ASSERTION_TYPE);

        return requestBuilder;
    }

    @Override
    public String getAuthenticationMethod() {
        return "private_key_jwt";
    }

    /**
     * Returns {@code null} as the client ID is not statically bound.
     * <p>
     * The client identity is determined dynamically per-request. The {@code client_id}
     * for OAuth flows is managed separately (e.g., via DCR) and propagated through
     * the request body by the caller.
     * </p>
     *
     * @return {@code null}, as the client ID is determined per-request
     */
    @Override
    public String getClientId() {
        return null;
    }

}