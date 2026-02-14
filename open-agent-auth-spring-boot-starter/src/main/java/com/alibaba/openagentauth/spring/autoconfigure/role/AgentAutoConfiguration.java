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
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.DefaultOAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.OAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.par.client.DefaultOAuth2ParClient;
import com.alibaba.openagentauth.core.protocol.oauth2.par.client.OAuth2ParClient;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.DefaultOAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.protocol.vc.DefaultVcSigner;
import com.alibaba.openagentauth.core.protocol.vc.VcSigner;
import com.alibaba.openagentauth.core.protocol.vc.chain.DefaultPromptProtectionChain;
import com.alibaba.openagentauth.core.protocol.vc.chain.PromptProtectionChain;
import com.alibaba.openagentauth.core.protocol.vc.decision.DefaultUserPromptDecision;
import com.alibaba.openagentauth.core.protocol.vc.decision.UserPromptDecision;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptEncryptionService;
import com.alibaba.openagentauth.core.protocol.vc.sanitization.DefaultPromptSanitizer;
import com.alibaba.openagentauth.core.protocol.vc.sanitization.PromptSanitizer;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.workload.client.RestWorkloadClient;
import com.alibaba.openagentauth.core.protocol.wimse.workload.client.WorkloadClient;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.trust.model.TrustAnchor;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.executor.config.AgentAapExecutorConfig;
import com.alibaba.openagentauth.framework.executor.impl.DefaultAgentAapExecutor;
import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.orchestration.DefaultAgent;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.web.interceptor.AgentAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.spring.web.interceptor.SpringAgentAuthenticationInterceptor;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Auto-configuration for Agent role.
 * <p>
 * This configuration provides automatic setup for the AI Agent role,
 * which represents users and requests access to protected resources.
 * </p>
 * <p>
 * <b>Role Identification:</b></p>
 * <p>
 * Enable this configuration by setting:
 * </p>
 * <pre>
 * open-agent-auth:
 *   roles:
 *     agent:
 *       enabled: true
 * </pre>
 * <p>
 * This role is typically used in scenarios where:
 * </p>
 * <ul>
 *   <li>Your application is an AI Agent that needs to access protected resources on behalf of users</li>
 *   <li>You need to manage user authentication and authorization flows</li>
 *   <li>You want to provide secure access to resources with proper audit trails</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   enabled: true
 *   roles:
 *     agent:
 *       enabled: true
 *       instance-id: agent-1
 *       issuer: http://localhost:8081
 *       capabilities:
 *         - oauth2-client
 *         - operation-authorization
 *   infrastructures:
 *     trust-domain: wimse://example.trust.domain
 *     jwks:
 *       enabled: false
 *       consumers:
 *         agent-user-idp:
 *           enabled: true
 *           jwks-endpoint: https://agent-user-idp.example.com/.well-known/jwks.json
 *           issuer: https://agent-user-idp.example.com
 *         agent-idp:
 *           enabled: true
 *           jwks-endpoint: https://agent-idp.example.com/.well-known/jwks.json
 *           issuer: https://agent-idp.example.com
 *         authorization-server:
 *           enabled: true
 *           jwks-endpoint: https://authorization-server.example.com/.well-known/jwks.json
 *           issuer: https://authorization-server.example.com
 *     agent:
 *       enabled: true
 *       authentication:
 *         enabled: true
 *         include-paths:
 *           - /api/**
 *         exclude-paths:
 *           - /health
 *           - /metrics
 *       session-mapping:
 *         enabled: true
 *         session-ttl-seconds: 3600
 * </pre>
 * <p>
 * <b>Provided Beans:</b></p>
 * <ul>
 *   <li><code>sessionMappingService</code>: Session mapping service for managing user sessions</li>
 *   <li><code>agent</code>: Agent service for managing agent operations</li>
 *   <li><code>agentAuthenticationInterceptor</code>: Authentication interceptor for protecting endpoints</li>
 * </ul>
 *
 * @see CoreAutoConfiguration
 * @see AgentUserIdpAutoConfiguration
 * @see AgentIdpAutoConfiguration
 * @since 1.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AgentAutoConfiguration {

    /**
     * The logger for the AgentAutoConfiguration.
     */
    private static final Logger logger = LoggerFactory.getLogger(AgentAutoConfiguration.class);

    /**
     * Creates the PolicyBuilder bean.
     * <p>
     * This bean is used to build the policy for agent operations.
     * Default implementation uses default builder.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyBuilder policyBuilder() {
        return PolicyBuilder.defaultBuilder();
    }

    /**
     * Creates the SessionMappingStore bean.
     * <p>
     * This store provides the underlying storage for session mappings.
     * Default implementation uses in-memory storage.
     * </p>
     *
     * @return the Session Mapping Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingStore sessionMappingStore() {
        logger.info("Creating SessionMappingStore bean");
        return new InMemorySessionMappingStore();
    }

    /**
     * Creates the prompt sanitizer bean.
     * <p>
     * This bean provides intelligent sanitization capabilities with dual detection
     * mechanism for comprehensive sensitive information protection.
     * </p>
     *
     * @return the prompt sanitizer instance
     */
    @Bean
    @ConditionalOnMissingBean
    public PromptSanitizer promptSanitizer() {
        return new DefaultPromptSanitizer();
    }

    /**
     * Creates the user prompt decision bean.
     * <p>
     * This bean manages user interaction for prompt protection, providing
     * intelligent recommendations and collecting user decisions.
     * </p>
     *
     * @return the user prompt decision instance
     */
    @Bean
    @ConditionalOnMissingBean
    public UserPromptDecision userPromptDecision() {
        return new DefaultUserPromptDecision();
    }

    /**
     * Creates the prompt protection chain bean.
     * <p>
     * This bean orchestrates the complete three-layer prompt protection process.
     * It coordinates sanitization, user decision, and JWE encryption layers.
     * </p>
     *
     * @param promptEncryptionService the prompt encryption service (optional, may be null)
     * @param promptSanitizer         the prompt sanitizer
     * @param userPromptDecision      the user prompt decision service
     * @return the prompt protection chain instance
     */
    @Bean
    @ConditionalOnMissingBean
    public PromptProtectionChain promptProtectionChain(
            PromptEncryptionService promptEncryptionService,
            PromptSanitizer promptSanitizer,
            UserPromptDecision userPromptDecision
    ) {

        return new DefaultPromptProtectionChain(
                promptEncryptionService,
                promptSanitizer,
                userPromptDecision
        );
    }

    /**
     * Creates the SessionMappingBizService bean.
     * <p>
     * This service provides high-level session mapping operations with business logic.
     * </p>
     *
     * @param sessionMappingStore the session mapping store
     * @return the Session Mapping Business Service bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingBizService sessionMappingBizService(
            SessionMappingStore sessionMappingStore
    ) {
        logger.info("Creating SessionMappingBizService bean");
        return new SessionMappingBizService(sessionMappingStore);
    }

    /**
     * Creates the WorkloadClient bean if not already defined.
     * <p>
     * This client is used to communicate with the Agent IDP for workload management.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @return the WorkloadClient bean
     */
    @Bean
    @ConditionalOnMissingBean
    public WorkloadClient workloadClient(ServiceEndpointResolver serviceEndpointResolver) {
        logger.info("Creating WorkloadClient bean with ServiceEndpointResolver");
        return new RestWorkloadClient(serviceEndpointResolver);
    }

    /**
     * Creates the OAuth2DcrClient bean for DCR registration with Agent User IDP.
     * <p>
     * This client is used to register the Agent as an OAuth 2.0 client with the
     * Agent User IDP using Dynamic Client Registration (DCR) protocol.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @return the OAuth2DcrClient bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2DcrClient oauth2DcrClient(ServiceEndpointResolver serviceEndpointResolver) {
        logger.info("Creating OAuth2DcrClient bean with ServiceEndpointResolver");
        return new DefaultOAuth2DcrClient(serviceEndpointResolver);
    }

    /**
     * AgentProvider bean implementing AgentService interface.
     * <p>
     * This bean provides the core Agent functionality for workload identity management
     * and Agent Operation Authorization (AOA) flow. It orchestrates interactions between
     * the Agent, Agent IDP, Agent User IDP, and Authorization Server.
     * </p>
     * <p>
     * <b>Key Responsibilities:</b></p>
     * <ul>
     *   <li>Workload Identity Token (WIT) issuance and validation</li>
     *   <li>OAuth 2.0 authorization flow management</li>
     *   <li>PAR (Pushed Authorization Request) handling</li>
     *   <li>DCR (Dynamic Client Registration) support</li>
     *   <li>User authentication integration with Agent User IDP</li>
     * </ul>
     * <p>
     * <b>Dependencies:</b></p>
     * <ul>
     *   <li><code>workloadClient</code>: For communicating with Agent IDP workload endpoints</li>
     *   <li><code>tokenService</code>: For token creation and validation</li>
     *   <li><code>witValidator</code>: For validating WITs from other agents</li>
     *   <li><code>idTokenValidator</code>: For validating ID tokens from Agent User IDP</li>
     *   <li><code>agentOperationAuthorizationParClient</code>: For PAR requests to Authorization Server</li>
     *   <li><code>agentOperationAuthorizationDcrClient</code>: For DCR with Authorization Server</li>
     *   <li><code>userAuthenticationTokenClient</code>: For token exchange with Agent User IDP</li>
     *   <li><code>agentOperationAuthorizationTokenClient</code>: For token exchange with Authorization Server</li>
     *   <li><code>aapParJwtGenerator</code>: For generating PAR-JWTs for AOA flow</li>
     * </ul>
     *
     * @param workloadClient                         the workload client for Agent IDP communication
     * @param tokenService                           the token service for token operations
     * @param witValidator                           the WIT validator for workload identity verification
     * @param idTokenValidator                       the ID token validator for user authentication
     * @param agentOperationAuthorizationParClient   the PAR client for AOA flow
     * @param agentOperationAuthorizationDcrClient   the DCR client for AOA flow
     * @param openAgentAuthProperties                the global OPEN AGENT AUTH authentication properties
     * @param userAuthenticationTokenClient          the OAuth2 token client for user authentication
     * @param agentOperationAuthorizationTokenClient the OAuth2 token client for AOA flow
     * @param aapParJwtGenerator                     the PAR-JWT generator for AOA flow
     * @return the configured Agent bean
     */
    @Bean
    @ConditionalOnMissingBean
    public Agent agentProvider(
            WorkloadClient workloadClient,
            TokenService tokenService,
            WitValidator witValidator,
            IdTokenValidator idTokenValidator,
            OAuth2ParClient agentOperationAuthorizationParClient,
            OAuth2DcrClient agentOperationAuthorizationDcrClient,
            OpenAgentAuthProperties openAgentAuthProperties,
            @Qualifier("userAuthenticationTokenClient") OAuth2TokenClient userAuthenticationTokenClient,
            @Qualifier("agentOperationAuthorizationTokenClient") OAuth2TokenClient agentOperationAuthorizationTokenClient,
            AapParJwtGenerator aapParJwtGenerator
    ) {
        // Get the properties
        String authorizationServerUrl = openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("authorization-server").getBaseUrl();
        String agentUserIdpUrl = openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("agent-user-idp").getBaseUrl();
        String clientId = openAgentAuthProperties.getCapabilities().getOperationAuthorization().getOauth2Client().getClientId();
        String oAuthCallbacksRedirectUri = openAgentAuthProperties.getCapabilities().getOperationAuthorization().getOauth2Client().getOauthCallbacksRedirectUri();

        // Create the agent
        return new DefaultAgent(
                workloadClient,
                tokenService,
                witValidator,
                idTokenValidator,
                agentOperationAuthorizationParClient,
                agentOperationAuthorizationDcrClient,
                userAuthenticationTokenClient,
                agentOperationAuthorizationTokenClient,
                aapParJwtGenerator,
                authorizationServerUrl,
                agentUserIdpUrl,
                clientId,
                oAuthCallbacksRedirectUri
        );
    }

    /**
     * AgentAapExecutor bean for Agent Operation Authorization flow.
     * <p>
     * This bean provides the execution engine for the Agent Operation Authorization (AOA) protocol.
     * It orchestrates the complete AOA flow, including:
     * </p>
     * <ul>
     *   <li>PAR-JWT generation and submission</li>
     *   <li>Evidence VC creation and signing</li>
     *   <li>Policy evaluation for authorization decisions</li>
     *   <li>Prompt protection (sanitization, user decision, encryption)</li>
     *   <li>Authorization request handling</li>
     * </ul>
     * <p>
     * <b>Key Components:</b></p>
     * <ul>
     *   <li><code>agentProvider</code>: Provides core Agent functionality and identity management</li>
     *   <li><code>vcSigner</code>: Signs Evidence VCs to prove user intent</li>
     *   <li><code>policyBuilder</code>: Builds Rego policies for authorization evaluation</li>
     *   <li><code>promptProtectionChain</code>: Applies three-layer prompt protection</li>
     *   <li><code>agentAapExecutorConfig</code>: Configuration for AOA execution</li>
     * </ul>
     * <p>
     * <b>Prompt Protection Layers:</b></p>
     * <ol>
     *   <li><b>Sanitization</b>: Removes sensitive information from prompts</li>
     *   <li><b>User Decision</b>: Collects user consent for sensitive operations</li>
     *   <li><b>Encryption</b>: Encrypts prompts with Authorization Server's public key</li>
     * </ol>
     *
     * @param agentProvider          the Agent provider for core Agent functionality
     * @param vcSigner               the VC signer for Evidence VC creation
     * @param policyBuilder          the policy builder for Rego policy generation
     * @param promptProtectionChain  the prompt protection chain for security
     * @param agentAapExecutorConfig the configuration for AOA execution
     * @return the configured AgentAapExecutor bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AgentAapExecutor agentAapExecutor(
            Agent agentProvider,
            VcSigner vcSigner,
            PolicyBuilder policyBuilder,
            PromptProtectionChain promptProtectionChain,
            AgentAapExecutorConfig agentAapExecutorConfig
    ) {
        return new DefaultAgentAapExecutor(
                agentProvider,
                vcSigner,
                policyBuilder,
                promptProtectionChain,
                agentAapExecutorConfig
        );
    }

    /**
     * Creates the OAuth2TokenClient bean for user authentication flow.
     * <p>
     * This client is used to exchange authorization codes for access tokens
     * in the user authentication flow with Agent User IDP.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param openAgentAuthProperties      the global configuration properties
     * @return the OAuth2TokenClient bean for user authentication
     */
    @Bean(name = "userAuthenticationTokenClient")
    @ConditionalOnMissingBean(name = "userAuthenticationTokenClient")
    public OAuth2TokenClient userAuthenticationTokenClient(
            ServiceEndpointResolver serviceEndpointResolver,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        String clientId = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientId();
        String clientSecret = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientSecret();
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            throw new IllegalStateException(
                    "OAuth client ID is not configured. " +
                            "Please set 'open-agent-auth.capabilities.oauth2-client.callback.client-id' in your configuration. " +
                            "This is a required configuration for OAuth 2.0 flows."
            );
        }
        logger.info("Creating userAuthenticationTokenClient bean with ServiceEndpointResolver, " +
                "serviceName: agent-user-idp, clientId: {}", clientId);
        return new DefaultOAuth2TokenClient(serviceEndpointResolver, "agent-user-idp", clientId, clientSecret);
    }

    /**
     * Creates the OAuth2TokenClient bean for agent operation authorization flow.
     * <p>
     * This client is used to exchange authorization codes for access tokens
     * in the agent operation authorization flow with Authorization Server.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver
     * @param openAgentAuthProperties      the global configuration properties
     * @return the OAuth2TokenClient bean for agent operation authorization
     */
    @Bean(name = "agentOperationAuthorizationTokenClient")
    @ConditionalOnMissingBean(name = "agentOperationAuthorizationTokenClient")
    public OAuth2TokenClient agentOperationAuthorizationTokenClient(
            ServiceEndpointResolver serviceEndpointResolver,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        String clientId = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientId();
        String clientSecret = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientSecret();
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException(
                    "OAuth client ID is not configured. " +
                            "Please set 'open-agent-auth.server.callback.client-id' in your configuration. " +
                            "This is a required configuration for OAuth 2.0 flows."
            );
        }
        logger.info("Creating agentOperationAuthorizationTokenClient bean with ServiceEndpointResolver, " +
                "serviceName: authorization-server, clientId: {}", clientId);
        return new DefaultOAuth2TokenClient(serviceEndpointResolver, "authorization-server", clientId, clientSecret);
    }

    /**
     * Creates the ServiceEndpointResolver bean.
     * <p>
     * This resolver is used to resolve service endpoints for different services.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public ServiceEndpointResolver serviceEndpointResolver(OpenAgentAuthProperties openAgentAuthProperties) {

        // Convert new architecture service discovery to legacy ServiceProperties format
        ServiceProperties serviceProperties = new ServiceProperties();

        // Map service discovery services to consumer services
        Map<String, ServiceProperties.ConsumerServiceProperties> consumers = new HashMap<>();
        openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().forEach((name, service) -> {
            ServiceProperties.ConsumerServiceProperties consumer = new ServiceProperties.ConsumerServiceProperties();
            consumer.setBaseUrl(service.getBaseUrl());
            consumer.setEndpoints(service.getEndpoints());
            consumers.put(name, consumer);
        });
        serviceProperties.setConsumers(consumers);

        return new DefaultServiceEndpointResolver(serviceProperties);
    }

    /**
     * Creates the framework-level Agent authentication interceptor bean.
     * <p>
     * This interceptor is created only when:
     * </p>
     * <ul>
     *   <li>AgentAapExecutor bean is available</li>
     *   <li>SessionMappingBizService bean is available</li>
     *   <li>Authentication is enabled in configuration</li>
     * </ul>
     *
     * @param agentAapExecutor         the AgentAapExecutor bean
     * @param sessionMappingBizService the SessionMappingBizService bean
     * @return the AgentAuthenticationInterceptor bean
     */
    @Bean
    @ConditionalOnBean({AgentAapExecutor.class, SessionMappingBizService.class})
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.oauth2-client.authentication", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AgentAuthenticationInterceptor agentAuthenticationInterceptor(
            AgentAapExecutor agentAapExecutor,
            SessionMappingBizService sessionMappingBizService,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating AgentAuthenticationInterceptor bean");
        List<String> excludedPaths = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication().getExcludePaths();
        logger.info("Configured excluded paths: {}", excludedPaths);
        return new AgentAuthenticationInterceptor(agentAapExecutor, sessionMappingBizService, excludedPaths);
    }

    /**
     * Creates the Spring adapter for AgentAuthenticationInterceptor.
     * <p>
     * This adapter wraps the framework-level interceptor and implements Spring's
     * HandlerInterceptor interface for integration with Spring MVC.
     * </p>
     *
     * @param agentAuthenticationInterceptor the framework-level interceptor
     * @return the Spring adapter bean
     */
    @Bean
    @ConditionalOnBean(AgentAuthenticationInterceptor.class)
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.oauth2-client.authentication", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SpringAgentAuthenticationInterceptor springAgentAuthenticationInterceptor(
            AgentAuthenticationInterceptor agentAuthenticationInterceptor
    ) {
        logger.info("Creating SpringAgentAuthenticationInterceptor bean");
        return new SpringAgentAuthenticationInterceptor(agentAuthenticationInterceptor);
    }

    /**
     * Creates the OAuth2CallbackService bean.
     * <p>
     * This service handles OAuth 2.0 callback processing logic.
     * </p>
     *
     * @param oauth2TokenClient        the framework-level token client
     * @param sessionMappingBizService the session mapping business service
     * @param openAgentAuthProperties       the global configuration properties
     * @return the OAuth2CallbackService bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2CallbackService callbackService(
            FrameworkOAuth2TokenClient oauth2TokenClient,
            SessionMappingBizService sessionMappingBizService,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating OAuth2CallbackService bean");
        String callbackEndpoint = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getEndpoint();
        if (callbackEndpoint == null || callbackEndpoint.isBlank()) {
            callbackEndpoint = "/callback";
        }
        return new OAuth2CallbackService(
                oauth2TokenClient,
                sessionMappingBizService,
                callbackEndpoint
        );
    }

    /**
     * Creates the OAuth2CallbackController bean.
     * <p>
     * This controller handles OAuth 2.0 authorization code callbacks from the authorization server.
     * It delegates the business logic to OAuth2CallbackService.
     * </p>
     *
     * @param callbackService    the callback service
     * @param openAgentAuthProperties the global configuration properties
     * @return the OAuth2CallbackController bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2CallbackController oauth2CallbackController(
            OAuth2CallbackService callbackService,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating OAuth2CallbackController bean");
        return new OAuth2CallbackController(
                callbackService,
                openAgentAuthProperties
        );
    }

    /**
     * AgentAapExecutorConfig bean with default configuration
     */
    @Bean
    @ConditionalOnMissingBean
    public AgentAapExecutorConfig agentAapExecutorConfig(OpenAgentAuthProperties openAgentAuthProperties) {
        var operationAuthProps = openAgentAuthProperties.getCapabilities().getOperationAuthorization();

        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null && openAgentAuthProperties.getRoles().get("agent") != null) {
            var role = openAgentAuthProperties.getRoles().get("agent");
            if (role.getIssuer() != null) {
                issuer = role.getIssuer();
            }
        }

        return AgentAapExecutorConfig.builder()
                .clientId(operationAuthProps.getOauth2Client().getClientId())
                .channel(operationAuthProps.getAgentContext().getDefaultChannel())
                .language(operationAuthProps.getAgentContext().getDefaultLanguage())
                .platform(operationAuthProps.getAgentContext().getDefaultPlatform())
                .redirectUri(operationAuthProps.getOauth2Client().getOauthCallbacksRedirectUri())
                .agentClient(operationAuthProps.getAgentContext().getDefaultClient())
                .expirationSeconds(operationAuthProps.getAuthorization().getExpirationSeconds())
                .issuer(issuer)
                .deviceFingerprint(operationAuthProps.getAgentContext().getDefaultDeviceFingerprint())
                .promptProtectionEnabled(operationAuthProps.getPromptProtection().isEnabled())
                .encryptionEnabled(operationAuthProps.getPromptProtection().isEncryptionEnabled())
                .sanitizationLevel(operationAuthProps.getPromptProtection().getSanitizationLevel())
                .requireUserInteraction(operationAuthProps.getAuthorization().isRequireUserInteraction())
                .build();
    }

    /**
     * Web MVC configuration for registering the authentication interceptor.
     * <p>
     * This configuration is created only when:
     * </p>
     * <ul>
     *   <li>Role is set to "agent"</li>
     *   <li>Authentication is enabled in configuration</li>
     * </ul>
     * <p>
     * It registers the SpringAgentAuthenticationInterceptor with the configured
     * include and exclude paths.
     * </p>
     * <p>
     * <b>Note:</b> We don't use @ConditionalOnBean(SpringAgentAuthenticationInterceptor.class) here
     * because it would create a circular dependency issue. Instead, we directly inject
     * the interceptor through constructor injection, which allows Spring to properly
     * manage the bean lifecycle and registration order.
     * </p>
     */
    @Configuration
    @ConditionalOnExpression("'${open-agent-auth.roles.agent.enabled:false}' == 'true' and '${open-agent-auth.capabilities.oauth2-client.authentication.enabled:true}' == 'true'")
    public static class AgentWebMvcConfiguration implements WebMvcConfigurer {

        private static final Logger logger = LoggerFactory.getLogger(AgentWebMvcConfiguration.class);

        private final SpringAgentAuthenticationInterceptor agentAuthenticationInterceptor;
        private final OpenAgentAuthProperties openAgentAuthProperties;

        public AgentWebMvcConfiguration(
                SpringAgentAuthenticationInterceptor agentAuthenticationInterceptor,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            this.agentAuthenticationInterceptor = agentAuthenticationInterceptor;
            this.openAgentAuthProperties = openAgentAuthProperties;
            logger.info("Initializing AgentWebMvcConfiguration");
        }

        @Override
        public void addInterceptors(@NonNull InterceptorRegistry registry) {
            var authProps = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication();

            logger.info("Registering SpringAgentAuthenticationInterceptor");
            logger.info("Include paths: {}", authProps.getIncludePaths());
            logger.info("Exclude paths: {}", authProps.getExcludePaths());

            if (authProps.getIncludePaths().isEmpty()) {
                logger.warn("No include paths configured for authentication, defaulting to /**");
                registry.addInterceptor(agentAuthenticationInterceptor)
                        .addPathPatterns("/**")
                        .excludePathPatterns(authProps.getExcludePaths());
            } else {
                registry.addInterceptor(agentAuthenticationInterceptor)
                        .addPathPatterns(authProps.getIncludePaths())
                        .excludePathPatterns(authProps.getExcludePaths());
            }
        }
    }

    /**
     * Creates the IdTokenValidator bean for validating ID Tokens from Agent User IDP.
     * <p>
     * This validator is configured to validate ID Tokens issued by the Agent User IDP.
     * It fetches the public keys from the Agent User IDP's JWKS endpoint for signature verification.
     * </p>
     *
     * <p><b>Note:</b> The Agent User IDP's issuer URL is configured separately from
     * the Agent IDP's issuer URL. This is because:</p>
     * <ul>
     *   <li>Agent IDP issues WIT tokens (issuer: http://localhost:8082)</li>
     *   <li>Agent User IDP issues ID Tokens (issuer: http://localhost:8083)</li>
     *   <li>Agent IDP needs to validate ID Tokens from Agent User IDP</li>
     * </ul>
     *
     * <p><b>Configuration:</b> The JWKS endpoint is retrieved from
     * <code>open-agent-auth.jwks.consumers.agent-user-idp.jwks-endpoint</code>.</p>
     *
     * @param properties the configuration properties containing JWKS endpoint configuration
     * @return the configured IdTokenValidator bean
     * @throws IllegalStateException if JWKS endpoint is not configured or validator creation fails
     */
    @Bean
    @ConditionalOnMissingBean
    public IdTokenValidator idTokenValidator(OpenAgentAuthProperties properties) {
        try {
            String jwksEndpoint = properties.getInfrastructures().getJwks().getConsumers().get("agent-user-idp").getJwksEndpoint();

            if (ValidationUtils.isNullOrEmpty(jwksEndpoint)) {
                throw new IllegalStateException(
                        "Agent User IDP JWKS endpoint is not configured. Please set 'agent-user-idp.jwks-endpoint' in your configuration."
                );
            }

            JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwksEndpoint));
            return new DefaultIdTokenValidator(jwkSource);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to create IdTokenValidator: " + e.getMessage(), e);
        }
    }

    /**
     * Creates the OAuth2ParClient bean for Agent Operation Authorization PAR requests.
     * <p>
     * This client is used to make Pushed Authorization Request (PAR) calls to the
     * Authorization Server as part of the Agent Operation Authorization (AOA) flow.
     * </p>
     * <p>
     * <b>PAR Protocol:</b> PAR is an OAuth 2.0 extension that allows clients to push
     * authorization request parameters to the authorization server using a direct request,
     * preventing them from being exposed in the browser URL or leaked through Referer headers.
     * </p>
     * <p>
     * <b>Usage in AOA Flow:</b></p>
     * <ul>
     *   <li>The Agent creates a PAR-JWT containing the operation details and authorization request</li>
     *   <li>The PAR-JWT is pushed to the Authorization Server via the PAR endpoint</li>
     *   <li>The Authorization Server returns a <code>request_uri</code></li>
     *   <li>The Agent uses the <code>request_uri</code> to initiate the authorization flow</li>
     * </ul>
     * <p>
     * <b>Configuration:</b></p>
     * <ul>
     *   <li>PAR endpoint: Resolved from <code>open-agent-auth.services.consumers.authorization-server.endpoints.oauth2.par</code></li>
     *   <li>Client ID: Retrieved from <code>open-agent-auth.agent.client-id</code></li>
     *   <li>Client Secret: Retrieved from <code>open-agent-auth.agent.client-secret</code></li>
     * </ul>
     *
     * @param serviceEndpointResolver the service endpoint resolver for resolving PAR endpoint
     * @param openAgentAuthProperties      the global configuration properties containing client credentials
     * @return the configured OAuth2ParClient bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2ParClient agentOperationAuthorizationParClient(
            ServiceEndpointResolver serviceEndpointResolver,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOperationAuthorization().getOauth2Client();
        String clientId = oauth2ClientProps.getClientId();
        String clientSecret = oauth2ClientProps.getClientSecret();
        return new DefaultOAuth2ParClient(serviceEndpointResolver, clientId, clientSecret);
    }

    /**
     * Initialize JWE encryption key in KeyManager.
     * <p>
     * This bean creates a key pair for JWE encryption/decryption.
     * The private key is used for decrypting prompts from other agents,
     * and the public key is exposed in JWKS for encryption by others.
     * </p>
     * <p>
     * Uses RS256 algorithm (RSA with SHA-256) for RSA-OAEP-256 encryption.
     * </p>
     *
     * @param keyManager the key manager for registering the encryption key
     * @return the encryption key ID
     */
    @Bean
    @ConditionalOnMissingBean
    public String jweEncryptionKeyId(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
        String keyId = openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption().getEncryptionKeyId();

        // Get key algorithm from key definition, not from encryption-algorithm
        // encryption-algorithm is for JWE (e.g., RSA-OAEP-256), but key generation uses JWS algorithm (e.g., RS256)
        // Need to find the key definition where key-id matches the encryptionKeyId
        KeyAlgorithm keyAlgorithm = null;
        for (Map.Entry<String, KeyDefinitionProperties> entry :
             openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().entrySet()) {
            if (keyId.equals(entry.getValue().getKeyId())) {
                keyAlgorithm = KeyAlgorithm.fromValue(entry.getValue().getAlgorithm());
                break;
            }
        }

        if (keyAlgorithm == null) {
            throw new IllegalStateException("Key definition not found for key ID: " + keyId);
        }

        try {
            keyManager.getOrGenerateKey(keyId, keyAlgorithm);
            return keyId;

        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to register JWE encryption key with KeyManager", e);
        }
    }

    /**
     * VcSigner bean for signing Verifiable Credentials.
     * <p>
     * This bean creates a VcSigner that uses a dedicated VC signing key
     * to sign Evidence VCs. The signed VCs are included in PAR requests as
     * cryptographic proof of the user's original intent.
     * </p>
     *
     * @return the VcSigner bean
     */
    @Bean
    public VcSigner vcSigner(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {

        // Get params from properties
        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("agent");
            if (role != null) {
                issuer = role.getIssuer();
            }
        }

        String keyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("vc-signing").getKeyId();
        KeyAlgorithm keyAlgorithm = KeyAlgorithm.fromValue(openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("vc-signing").getAlgorithm());

        // Get or generate VC signing key from KeyManager
        JWK vcSigningKey;
        try {
            vcSigningKey = (JWK) keyManager.getOrGenerateKey(keyId, keyAlgorithm);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to register VC signing key with KeyManager", e);
        }
        logger.info("Creating VcSigner bean with keyId: {}, issuer: {}", vcSigningKey.getKeyID(), issuer);
        return new DefaultVcSigner(vcSigningKey, vcSigningKey.getKeyID(), issuer);
    }

    /**
     * AapParJwtGenerator bean for generating PAR-JWTs for Agent Operation Authorization
     */
    @Bean
    @ConditionalOnMissingBean
    public AapParJwtGenerator aapParJwtGenerator(
            OpenAgentAuthProperties openAgentAuthProperties,
            KeyManager keyManager
    ) {
        // Get params from properties
        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("agent");
            if (role != null) {
                issuer = role.getIssuer();
            }
        }

        String authorizationServerUrl = openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("authorization-server").getBaseUrl();
        String keyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("par-jwt-signing").getKeyId();
        KeyAlgorithm keyAlgorithm = KeyAlgorithm.fromValue(openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("par-jwt-signing").getAlgorithm());

        // Get or generate PAR-JWT signing key from KeyManager
        RSAKey parJwtSigningKey;
        try {
            parJwtSigningKey =  (RSAKey) keyManager.getOrGenerateKey(keyId, keyAlgorithm);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to register PAR-JWT signing key with KeyManager", e);
        }
        logger.info("Creating AapParJwtGenerator bean with issuer: {}", issuer);
        return new AapParJwtGenerator(parJwtSigningKey, JWSAlgorithm.RS256, issuer, authorizationServerUrl);
    }

    /**
     * WIT verification key fetched from Agent IDP's JWKS endpoint.
     * <p>
     * This key is used to verify WIT signatures issued by the Agent IDP.
     * The Agent IDP uses ES256 algorithm (EC key with P-256 curve) by default, so we fetch the public key
     * from the JWKS endpoint to ensure signature verification works correctly.
     * </p>
     * <p>
     * This bean will fail to initialize if the Agent IDP is not available or returns invalid keys.
     * This is intentional - the system cannot operate without a valid WIT verification key.
     * No fallback mechanism is provided, as it would only mask configuration issues and
     * provide a false sense of security.
     * </p>
     *
     * @return the EC public key for WIT verification
     * @throws IllegalStateException if the Agent IDP is unavailable or returns invalid keys
     */
    @Bean
    @ConditionalOnMissingBean
    public ECKey witVerificationKey(OpenAgentAuthProperties openAgentAuthProperties) {

        // Get params from properties
        String agentIdpUrl = openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("agent-idp").getBaseUrl();
        String keyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("wit-verification").getKeyId();

        try {
            // Construct JWKS endpoint URL
            String jwksEndpoint = agentIdpUrl + "/.well-known/jwks.json";
            logger.info("Attempting to fetch WIT verification key from Agent IDP JWKS endpoint: {}", jwksEndpoint);

            // Create JWK source to fetch keys from Agent IDP
            JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwksEndpoint));

            // Create a JWK selector to get all keys
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());

            // Get the JWK list from the source
            List<JWK> jwkList = jwkSource.get(selector, null);
            if (jwkList == null || jwkList.isEmpty()) {
                throw new IllegalStateException("No keys found in Agent IDP JWKS endpoint: " + jwksEndpoint);
            }

            // Find the WIT signing key by kid, and agent IDP may have multiple keys,
            // So we need to select the one used for WIT signature verification
            JWK witSigningKey = jwkList.stream()
                    .filter(jwk -> keyId.equals(jwk.getKeyID()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "WIT signing key not found in Agent IDP JWKS endpoint: " + jwksEndpoint +
                                    ". Available keys: " + jwkList.stream()
                                    .map(JWK::getKeyID)
                                    .toList()));

            if (!(witSigningKey instanceof ECKey)) {
                throw new IllegalStateException("WIT signing key is not an EC key. Expected EC key with P-256 curve for ES256 algorithm, but got: " + witSigningKey.getKeyType());
            }

            ECKey ecPublicKey = witSigningKey.toECKey();
            logger.info("Successfully fetched WIT verification key from Agent IDP. Key ID: {}, Algorithm: {}, Curve: {}",
                    ecPublicKey.getKeyID(), ecPublicKey.getAlgorithm(), ecPublicKey.getCurve());

            return ecPublicKey;

        } catch (Exception e) {
            logger.error("Failed to fetch WIT verification key from Agent IDP: {}", e.getMessage(), e);
            throw new IllegalStateException(
                    "Failed to initialize WIT verification key. This is a critical error - " +
                            "the system cannot operate without a valid WIT verification key from the Agent IDP. " +
                            "Please ensure: " +
                            "1. The Agent IDP is running and accessible at: " + agentIdpUrl + " " +
                            "2. The JWKS endpoint is available at: " + agentIdpUrl + "/.well-known/jwks.json " +
                            "3. The Agent IDP is configured with an EC signing key (ES256 algorithm with P-256 curve)", e);
        }
    }

    /**
     * WitValidator bean that uses the correct WIT verification key from Agent IDP.
     * <p>
     * This bean overrides the default WitValidator from CoreAutoConfiguration to ensure
     * that WIT signatures are verified using the correct public key from Agent IDP's JWKS endpoint.
     * </p>
     *
     * @param witVerificationKey the WIT verification key fetched from Agent IDP
     * @return the configured WitValidator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public WitValidator witValidator(ECKey witVerificationKey, OpenAgentAuthProperties openAgentAuthProperties) {
        String trustDomain = openAgentAuthProperties.getInfrastructures().getTrustDomain();
        logger.info("Creating WitValidator bean with verification key from Agent IDP. Key ID: {}, Trust Domain: {}",
                witVerificationKey.getKeyID(), trustDomain);

        // Create TrustDomain from string
        TrustDomain trustDomainObj = new TrustDomain(trustDomain);

        // Create TrustAnchor with the EC public key from Agent IDP
        // WIT uses ES256 algorithm (ECDSA with P-256 curve)
        TrustAnchor trustAnchor;
        try {
            trustAnchor = new TrustAnchor(
                    witVerificationKey.toPublicKey(),
                    witVerificationKey.getKeyID(),
                    KeyAlgorithm.ES256,
                    trustDomainObj
            );
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to convert ECKey to PublicKey", e);
        }

        logger.info("Created TrustAnchor: keyId={}, algorithm={}, trustDomain={}",
                trustAnchor.getKeyId(), trustAnchor.getAlgorithm(), trustAnchor.getTrustDomain().getDomainId());

        // Create WitValidator with TrustAnchor
        return new WitValidator(trustAnchor);
    }

}