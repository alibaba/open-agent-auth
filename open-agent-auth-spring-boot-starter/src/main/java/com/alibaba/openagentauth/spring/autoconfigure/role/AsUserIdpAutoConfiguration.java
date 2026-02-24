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

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

/**
 * Auto-configuration for AS User IDP role.
 * <p>
 * This configuration provides automatic setup for the Authorization Server User Identity Provider role,
 * which is responsible for authenticating users for the authorization server's authorization flow.
 * </p>
 * <p>
 * <b>Role Identification:</b></p>
 * <p>
 * Enable this configuration by setting:
 * </p>
 * <pre>
 * open-agent-auth:
 *     role: as-user-idp
 * </pre>
 * <p>
 * This role is typically used in scenarios where:
 * </p>
 * <ul>
 *   <li>Your application provides user identity authentication for Authorization Servers</li>
 *   <li>You need to issue ID Tokens that can be verified by Authorization Servers</li>
 *   <li>You want to provide user authentication as a service for OAuth 2.0 authorization flows</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *     enabled: true
 *     role: as-user-idp
 *     issuer: https://as-user-idp.example.com
 *     as-user-idp:
 *       id-token-expiration-seconds: 3600
 *       refresh-token-expiration-seconds: 86400
 * </pre>
 * <p>
 * <b>Provided Beans:</b></p>
 * <ul>
 *   <li><code>asUserIdpService</code>: AS User IDP service implementation</li>
 * </ul>
 * <p>
 * <b>Dependency Management:</b></p>
 * <ul>
 *   <li><code>TokenService</code>: Provided by {@link CoreAutoConfiguration}</li>
 *   <li><code>KeyManager</code>: Provided by {@link CoreAutoConfiguration}</li>
 *   <li><code>TrustDomain</code>: Provided by {@link CoreAutoConfiguration}</li>
 *   <li><code>UserRegistry</code>: Provided by {@link CoreAutoConfiguration}</li>
 * </ul>
 *
 * @see CoreAutoConfiguration
 * @see AuthorizationServerAutoConfiguration
 * @since 1.0
 */
@AutoConfiguration(after = {CoreAutoConfiguration.class, SharedCapabilityAutoConfiguration.class})
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.as-user-idp", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AsUserIdpAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(AsUserIdpAutoConfiguration.class);

    /**
     * Creates the AS User IDP Service bean if not already defined.
     * <p>
     * This service manages user authentication and token issuance.
     * It provides the core functionality for the AS User IDP role.
     * </p>
     *
     * @param authenticationProvider the authentication provider for user authentication
     * @param tokenServer the OAuth2 token server for token issuance
     * @param openAgentAuthProperties the global configuration propertie
     * @return the AS User IDP Service bean
     * @throws IllegalStateException if issuer is not configured
     */
    @Bean
    @ConditionalOnMissingBean
    public UserIdentityProvider asUserIdpService(
            AuthenticationProvider authenticationProvider,
            OAuth2TokenServer tokenServer,
            OpenAgentAuthProperties openAgentAuthProperties) {

        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get(ROLE_AS_USER_IDP);
            if (role != null) {
                issuer = role.getIssuer();
            }
        }

        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException(
                "AS User IDP issuer is not configured. Please set 'open-agent-auth.roles.as-user-idp.issuer' in your configuration. " +
                "This is a required configuration for token generation."
            );
        }

        logger.info("Creating AsUserIdpService with issuer: {}", issuer);

        return new DefaultUserIdentityProvider(
                authenticationProvider,
                tokenServer
        );
    }

}