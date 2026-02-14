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
package com.alibaba.openagentauth.spring.autoconfigure.initializer;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;

/**
 * Auto-registration initializer for OAuth 2.0 clients.
 * <p>
 * This component automatically registers OAuth 2.0 clients using the Dynamic Client
 * Registration (DCR) mechanism after all beans are created. It reads client
 * configurations from {@link OpenAgentAuthProperties} and registers them with
 * the DCR server.
 * </p>
 * <p>
 * <b>OAuth 2.0 Redirect URI Flow:</b></p>
 * <ul>
 *   <li>Client registers a list of allowed redirect URIs (redirect_uris)</li>
 *   <li>Client includes redirect_uri in the authorization request</li>
 *   <li>Authorization server validates that the requested redirect_uri is in the registered list</li>
 *   <li>Authorization server redirects to the requested redirect_uri (not the first one)</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2">RFC 6749 - Redirection Endpoint</a>
 * @since 1.0
 */
@Component
@ConditionalOnExpression("'${open-agent-auth.capabilities.oauth2-server.auto-register-clients.enabled:false}' == 'true'")
public class PredefinedClientInitializer {

    private static final Logger logger = LoggerFactory.getLogger(PredefinedClientInitializer.class);

    private final OAuth2DcrServer oauth2DcrServer;
    private final OAuth2DcrClientStore oauth2DcrClientStore;
    private final OpenAgentAuthProperties openAgentAuthProperties;

    /**
     * Creates a new PredefinedClientInitializer.
     *
     * @param oauth2DcrServer the DCR server
     * @param oauth2DcrClientStore the DCR client store
     * @param openAgentAuthProperties the global configuration properties
     */
    public PredefinedClientInitializer(
            OAuth2DcrServer oauth2DcrServer,
            OAuth2DcrClientStore oauth2DcrClientStore,
            OpenAgentAuthProperties openAgentAuthProperties) {
        this.oauth2DcrServer = oauth2DcrServer;
        this.oauth2DcrClientStore = oauth2DcrClientStore;
        this.openAgentAuthProperties = openAgentAuthProperties;
    }

    /**
     * Auto-registers OAuth 2.0 clients.
     * <p>
     * This method registers all clients configured in
     * {@link OpenAgentAuthProperties} using the DCR mechanism.
     * </p>
     */
    @PostConstruct
    public void initializeClients() {
        logger.info("Auto-registering OAuth 2.0 clients");

        var oauth2ServerProps = openAgentAuthProperties.getCapabilities().getOAuth2Server();
        if (oauth2ServerProps == null || !oauth2ServerProps.getAutoRegisterClients().isEnabled()) {
            logger.info("Auto-registration is not enabled, skipping");
            return;
        }

        var clients = oauth2ServerProps.getAutoRegisterClients().getClients();
        if (clients.isEmpty()) {
            logger.info("No clients configured for auto-registration, skipping");
            return;
        }

        for (var clientConfig : clients) {
            try {
                initializeClient(clientConfig);
            } catch (Exception e) {
                logger.error("Failed to auto-register client: {}", clientConfig.getClientName(), e);
                throw new RuntimeException("Failed to auto-register client: " + clientConfig.getClientName(), e);
            }
        }
    }

    /**
     * Auto-registers a single client.
     *
     * @param clientConfig the client configuration
     */
    private void initializeClient(OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties clientConfig) {
        logger.info("Auto-registering client: {}", clientConfig.getClientName());

        // Build DCR request from configuration
        DcrRequest.Builder requestBuilder = DcrRequest.builder()
                .redirectUris(clientConfig.getRedirectUris())
                .clientName(clientConfig.getClientName())
                .grantTypes(clientConfig.getGrantTypes())
                .responseTypes(clientConfig.getResponseTypes())
                .tokenEndpointAuthMethod(clientConfig.getTokenEndpointAuthMethod())
                .scope(String.join(" ", clientConfig.getScopes()));

        DcrRequest dcrRequest = requestBuilder.build();

        // Register the client with DCR server
        DcrResponse dcrResponse = oauth2DcrServer.registerClient(dcrRequest);

        // Determine client_id and client_secret
        // Use configured values if provided, otherwise use generated values
        String clientId = clientConfig.getClientId() != null
                ? clientConfig.getClientId()
                : dcrRequest.getClientName();

        String clientSecret = clientConfig.getClientSecret() != null
                ? clientConfig.getClientSecret()
                : dcrResponse.getClientSecret();

        String registrationAccessToken = dcrResponse.getRegistrationAccessToken();

        // Create a new DcrResponse with custom client_id and client_secret
        DcrResponse responseWithCustomCredentials = DcrResponse.builder()
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientIdIssuedAt(dcrResponse.getClientIdIssuedAt())
                .clientSecretExpiresAt(dcrResponse.getClientSecretExpiresAt())
                .registrationAccessToken(registrationAccessToken)
                .registrationClientUri(dcrResponse.getRegistrationClientUri())
                .redirectUris(dcrResponse.getRedirectUris())
                .clientName(dcrResponse.getClientName())
                .grantTypes(dcrResponse.getGrantTypes())
                .responseTypes(dcrResponse.getResponseTypes())
                .tokenEndpointAuthMethod(dcrResponse.getTokenEndpointAuthMethod())
                .scope(dcrResponse.getScope())
                .build();

        // Store the client with client_id as the key
        oauth2DcrClientStore.store(clientId, registrationAccessToken, dcrRequest, responseWithCustomCredentials);

        logger.info("Auto-registered client: {} with client_id: {} and redirect_uris: {}",
                clientConfig.getClientName(),
                clientId,
                dcrResponse.getRedirectUris());

        // Log the credentials for easy reference
        logger.info("====================================================================");
        logger.info("IMPORTANT: Use the following credentials for client {}:", clientConfig.getClientName());
        logger.info("client_id: {}", clientId);
        logger.info("client_secret: {}", clientSecret);
        logger.info("====================================================================");
    }
}
