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

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;

/**
 * Auto-registration initializer for predefined OAuth 2.0 clients.
 * <p>
 * This component automatically registers OAuth 2.0 clients from static configuration
 * (application.yml) into the {@link OAuth2ClientStore} after all beans are created.
 * Unlike Dynamic Client Registration (DCR), this initializer works with predefined
 * client configurations and does not require the DCR protocol.
 * </p>
 * <p>
 * <b>Design Rationale:</b></p>
 * <p>
 * Predefined client registration is fundamentally different from DCR:
 * </p>
 * <ul>
 *   <li>DCR (RFC 7591): Runtime protocol for unknown clients to self-register</li>
 *   <li>Predefined registration: Static configuration loading at startup</li>
 * </ul>
 * <p>
 * By depending only on {@link OAuth2ClientStore}, this initializer can work with
 * any role that has client storage capability, without requiring DCR infrastructure.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2">RFC 6749 - Client Registration</a>
 * @since 1.0
 */
@Component
@ConditionalOnExpression("'${open-agent-auth.capabilities.oauth2-server.auto-register-clients.enabled:false}' == 'true'")
public class PredefinedClientInitializer {

    private static final Logger logger = LoggerFactory.getLogger(PredefinedClientInitializer.class);

    private final OAuth2ClientStore clientStore;
    private final OpenAgentAuthProperties openAgentAuthProperties;

    /**
     * Creates a new PredefinedClientInitializer.
     *
     * @param clientStore the client store for registering predefined clients
     * @param openAgentAuthProperties the global configuration properties
     */
    public PredefinedClientInitializer(
            OAuth2ClientStore clientStore,
            OpenAgentAuthProperties openAgentAuthProperties) {
        this.clientStore = clientStore;
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
     * Registers a single predefined client.
     *
     * @param clientConfig the client configuration from application properties
     */
    private void initializeClient(OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties clientConfig) {
        logger.info("Registering predefined client: {}", clientConfig.getClientName());

        String clientId = clientConfig.getClientId() != null
                ? clientConfig.getClientId()
                : clientConfig.getClientName();

        OAuth2RegisteredClient registeredClient = OAuth2RegisteredClient.builder()
                .clientId(clientId)
                .clientSecret(clientConfig.getClientSecret())
                .clientName(clientConfig.getClientName())
                .redirectUris(clientConfig.getRedirectUris())
                .grantTypes(clientConfig.getGrantTypes())
                .responseTypes(clientConfig.getResponseTypes())
                .tokenEndpointAuthMethod(clientConfig.getTokenEndpointAuthMethod())
                .scope(String.join(" ", clientConfig.getScopes()))
                .build();

        clientStore.register(registeredClient);

        logger.info("Registered predefined client: {} with client_id: {} and redirect_uris: {}",
                clientConfig.getClientName(),
                clientId,
                clientConfig.getRedirectUris());

        logger.info("====================================================================");
        logger.info("IMPORTANT: Use the following credentials for client {}:", clientConfig.getClientName());
        logger.info("client_id: {}", clientId);
        logger.info("client_secret: {}", clientConfig.getClientSecret());
        logger.info("====================================================================");
    }
}
