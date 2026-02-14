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
package com.alibaba.openagentauth.spring.autoconfigure.role;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.OAuth2DcrClient;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for automatic DCR registration with Authorization Server.
 * <p>
 * This configuration handles the automatic registration of the Agent as an OAuth 2.0 client
 * with the Authorization Server using Dynamic Client Registration (DCR) protocol.
 * </p>
 * <p>
 * <b>NOTE:</b> This is a simplified configuration for sample purposes.
 * According to the architecture design, DCR registration should be performed
 * dynamically during the authorization flow using WIT as authentication proof,
 * with WIT.sub as the client_id and private_key_jwt as the authentication method.
 * </p>
 * <p>
 * For production use, the Agent framework (DefaultAgent) handles DCR registration
 * automatically when creating workloads and submitting PAR requests.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
@Configuration
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent", name = "enabled", havingValue = "true")
public class AgentDcrAutoRegistrationConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(AgentDcrAutoRegistrationConfiguration.class);

    private final OpenAgentAuthProperties openAgentAuthProperties;
    private final OAuth2DcrClient dcrClient;

    /**
     * Creates a new AgentDcrAutoRegistrationConfiguration.
     *
     * @param openAgentAuthProperties the configuration properties
     * @param dcrClient the DCR client for registration
     */
    public AgentDcrAutoRegistrationConfiguration(
            OpenAgentAuthProperties openAgentAuthProperties,
            OAuth2DcrClient dcrClient) {
        this.openAgentAuthProperties = openAgentAuthProperties;
        this.dcrClient = dcrClient;
    }
    /**
     * Performs automatic DCR registration on startup if needed.
     * <p>
     * <b>DEPRECATED:</b> This method is deprecated and should not be used.
     * According to the architecture design, DCR registration should be performed
     * dynamically during the authorization flow using WIT as authentication proof.
     * </p>
     * <p>
     * The correct flow is:
     * </p>
     * <ol>
     *   <li>Agent creates a workload and obtains WIT from Agent IDP</li>
     *   <li>Agent uses WIT to register OAuth client with Authorization Server</li>
     *   <li>WIT.sub becomes the client_id</li>
     *   <li>token_endpoint_auth_method is set to private_key_jwt</li>
     * </ol>
     * <p>
     * This method is kept for backward compatibility but should be removed in production.
     * </p>
     */
    @PostConstruct
    @Deprecated
    public void autoRegisterIfNeeded() {
        logger.warn("================================================================================");
        logger.warn("DEPRECATED: Startup DCR registration is not recommended!");
        logger.warn("");
        logger.warn("According to the architecture design, DCR registration should be");
        logger.warn("performed dynamically during the authorization flow using WIT.");
        logger.warn("");
        logger.warn("The correct flow:");
        logger.warn("  1. Agent creates workload and obtains WIT from Agent IDP");
        logger.warn("  2. Agent uses WIT to register OAuth client with Authorization Server");
        logger.warn("  3. WIT.sub becomes the client_id");
        logger.warn("  4. token_endpoint_auth_method is set to private_key_jwt");
        logger.warn("");
        logger.warn("Please set auto-register: false in application.yml and");
        logger.warn("let the Agent framework handle DCR registration automatically.");
        logger.warn("================================================================================");

        OAuth2ClientProperties.OAuth2ClientCallbackProperties callback = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback();

        // Check if auto-registration is enabled
        if (!callback.isEnabled() || !callback.isAutoRegister()) {
            logger.info("DCR auto-registration is disabled (correct configuration)");
            return;
        }

        logger.warn("Startup DCR registration is enabled but this is not the recommended approach.");
        logger.warn("Skipping startup DCR registration. Please use the Agent framework's");
        logger.warn("dynamic DCR registration during authorization flow instead.");
    }
}
