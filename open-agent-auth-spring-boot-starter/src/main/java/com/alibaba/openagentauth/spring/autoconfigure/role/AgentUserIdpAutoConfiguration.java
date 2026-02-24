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

import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.UserIdentityProvider;
import com.alibaba.openagentauth.framework.orchestration.DefaultUserIdentityProvider;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.capability.SharedCapabilityAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

/**
 * Auto-configuration for the Agent User IDP role.
 * <p>
 * This configuration class sets up the necessary components for the Agent User IDP role,
 * which provides OpenID Connect (OIDC) Identity Provider functionality for agents.
 * It enables agents to authenticate users and issue ID tokens.
 * </p>
 * <p>
 * The Agent User IDP role provides:
 * </p>
 * <ul>
 *   <li>OAuth 2.0 Authorization Server for OIDC flows</li>
 *   <li>OpenID Connect (OIDC) Identity Provider functionality</li>
 *   <li>Local user authentication (no external IDP required)</li>
 *   <li>Session management for cross-domain OAuth flows</li>
 *   <li>User consent page for authorization</li>
 * </ul>
 *
 * @since 1.0
 */
@AutoConfiguration(after = {CoreAutoConfiguration.class, SharedCapabilityAutoConfiguration.class})
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent-user-idp", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AgentUserIdpAutoConfiguration {

    /**
     * User IDP Core Configuration - manages core business beans.
     */
    @Configuration(proxyBeanMethods = false)
    public static class UserIdpCoreConfiguration {

        /**
         * The logger for the User IDP core configuration.
         */
        private static final Logger logger = LoggerFactory.getLogger(UserIdpCoreConfiguration.class);

        /**
         * Creates the Agent User IDP Service bean if not already defined.
         * <p>
         * This service manages user authentication and token issuance.
         * It provides the core functionality for the Agent User IDP role.
         * </p>
         *
         * @param authenticationProvider the authentication provider for user authentication
         * @param tokenServer the OAuth2 token server for token issuance
         * @param openAgentAuthProperties the global configuration properties
         * @return the Agent User IDP Service bean
         * @throws IllegalStateException if issuer is not configured
         */
        @Bean
        @ConditionalOnMissingBean
        public UserIdentityProvider agentUserIdpService(
                AuthenticationProvider authenticationProvider,
                OAuth2TokenServer tokenServer,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {

            // Get issuer from roles configuration
            String issuer = null;
            if (openAgentAuthProperties.getRoles() != null) {
                var role = openAgentAuthProperties.getRoles().get(ROLE_AGENT_USER_IDP);
                if (role != null) {
                    issuer = role.getIssuer();
                }
            }
            
            if (ValidationUtils.isNullOrEmpty(issuer)) {
                throw new IllegalStateException(
                    "Agent User IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-user-idp.issuer' in your configuration. " +
                    "This is a required configuration for token generation."
                );
            }

            logger.info("Creating AgentUserIdpService with issuer: {}", issuer);

            return new DefaultUserIdentityProvider(
                    authenticationProvider,
                    tokenServer
            );
        }
    }
}