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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.InMemoryWorkloadRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import com.alibaba.openagentauth.framework.orchestration.DefaultAgentIdentityProvider;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for Agent IDP role.
 * <p>
 * This configuration provides automatic setup for the Agent IDP role,
 * which is responsible for managing workload identities and issuing Workload Identity Tokens (WIT).
 * </p>
 * <p>
 * <b>Role Identification:</b></p>
 * <p>
 * Enable this configuration by setting:
 * </p>
 * <pre>
 * open-agent-auth:
 *     role: agent-idp
 * </pre>
 * <p>
 * This role is typically used in scenarios where:
 * </p>
 * <ul>
 *   <li>Your application manages workload identities for AI Agents</li>
 *   <li>You need to issue WITs that can be verified by Authorization Servers and Resource Servers</li>
 *   <li>You want to provide workload identity management following the WIMSE protocol</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *     enabled: true
 *     role: agent-idp
 *     issuer: https://agent-idp.example.com
 *     agent-idp:
 *       key-algorithm: ES256
 *       wit-expiration-seconds: 3600
 * </pre>
 * <p>
 * <b>Dependency Management:</b></p>
 * <p>
 * This configuration depends on {@link CoreAutoConfiguration} which provides the following shared beans:
 * </p>
 * <ul>
 *   <li><code>TokenService</code>: Token generation and validation (reused from Core)</li>
 *   <li><code>WitValidator</code>: WIT validation (reused from Core)</li>
 *   <li><code>IdTokenValidator</code>: ID Token validation (reused from Core)</li>
 *   <li><code>KeyManager</code>: Key management (reused from Core)</li>
 *   <li><code>TrustDomain</code>: Trust domain configuration (reused from Core)</li>
 * </ul>
 * <p>
 * <b>Role-Specific Beans:</b></p>
 * <ul>
 *   <li><code>workloadRegistry</code>: In-memory storage for workload information</li>
 *   <li><code>agentIdentityProvider</code>: Agent IDP service implementation</li>
 * </ul>
 * <p>
 * <b>Note:</b> Session-related beans (SessionMappingStore, SessionManager, SessionMappingBizService) are not
 * provided by this configuration as they are only required by the {@code agent} and {@code authorization-server} roles.
 * </p>
 *
 * @see CoreAutoConfiguration
 * @see AgentUserIdpAutoConfiguration
 * @see AuthorizationServerAutoConfiguration
 * @since 1.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent-idp", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AgentIdpAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(AgentIdpAutoConfiguration.class);

    /**
     * Creates the WorkloadRegistry bean if not already defined.
     * <p>
     * This registry provides storage for workload information.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the WorkloadRegistry bean
     */
    @Bean
    @ConditionalOnMissingBean
    public WorkloadRegistry workloadRegistry() {
        logger.info("Creating WorkloadRegistry bean");
        return new InMemoryWorkloadRegistry();
    }

    /**
     * Creates the Agent IDP Service bean if not already defined.
     * <p>
     * This service manages agent workload identities and issues Workload Identity Tokens (WIT).
     * It provides the core functionality for the Agent IDP role.
     * </p>
     * <p>
     * <b>Bean Dependencies:</b></p>
     * <ul>
     *   <li><code>tokenService</code>: Provided by {@link CoreAutoConfiguration}</li>
     *   <li><code>witValidator</code>: Provided by {@link CoreAutoConfiguration}</li>
     *   <li><code>idTokenValidator</code>: Provided by {@link CoreAutoConfiguration}</li>
     *   <li><code>workloadRegistry</code>: Created locally in this configuration</li>
     * </ul>
     *
     * @param tokenService the token service for WIT generation
     * @param idTokenValidator the ID Token validator for validating user identity tokens
     * @param workloadRegistry the workload registry for persisting workload information
     * @param openAgentAuthProperties the global configuration properties
     * @return the Agent IDP Service bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AgentIdentityProvider agentIdentityProvider(
            TokenService tokenService,
            IdTokenValidator idTokenValidator,
            WorkloadRegistry workloadRegistry,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        // Get issuer from roles configuration
        String issuer = openAgentAuthProperties.getRoleIssuer(ROLE_AGENT_IDP);
        logger.debug("Issuer from role: {}", issuer);

        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException(
                "Agent IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-idp.issuer' in your configuration. " +
                "This is a required configuration for WIT generation."
            );
        }

        // Agent User IDP issuer for ID Token validation
        JwksConsumerProperties agentUserIdpConsumer =
                openAgentAuthProperties.getJwksConsumer(SERVICE_AGENT_USER_IDP);
        String agentUserIdpIssuer =
                agentUserIdpConsumer != null ? agentUserIdpConsumer.getIssuer() : null;

        if (ValidationUtils.isNullOrEmpty(agentUserIdpIssuer)) {
            throw new IllegalStateException(
                "Agent User IDP issuer is not configured. Please set 'open-agent-auth.infrastructure.jwks.consumers.agent-user-idp.issuer' in your configuration. " +
                "This is a required configuration for ID Token validation."
            );
        }

        logger.info("Creating AgentIdentityProvider with issuer: {}, agentUserIdpIssuer: {}", issuer, agentUserIdpIssuer);

        return new DefaultAgentIdentityProvider(
                tokenService,
                idTokenValidator,
                issuer,
                agentUserIdpIssuer,
                workloadRegistry
        );
    }

    /**
     * Creates the IdTokenValidator bean for Agent IDP.
     * <p>
     * This validator is configured to validate ID Tokens issued by the Agent User IDP.
     * </p>
     *
     * <p><b>Important:</b> The Agent User IDP's issuer URL is configured separately from
     * the Agent IDP's issuer URL. This is because:</p>
     * <ul>
     *   <li>Agent IDP issues WIT tokens (issuer: http://localhost:8082)</li>
     *   <li>Agent User IDP issues ID Tokens (issuer: http://localhost:8083)</li>
     *   <li>Agent IDP needs to validate ID Tokens from Agent User IDP</li>
     * </ul>
     *
     * @param keyManager the key manager for resolving verification keys
     * @param properties the configuration properties
     * @return the configured IdTokenValidator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public IdTokenValidator idTokenValidator(KeyManager keyManager, OpenAgentAuthProperties properties) {
        String keyId = properties.getKeyDefinition(KEY_ID_TOKEN_VERIFICATION).getKeyId();
        logger.info("Creating IdTokenValidator bean. Key ID: {}", keyId);
        return new DefaultIdTokenValidator(keyManager, keyId);
    }
}