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

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.audit.impl.RemoteAuditService;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.binding.RemoteBindingInstanceStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.ClientAssertionAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.WimseOAuth2DcrClientAuthentication;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.RemoteWorkloadRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.protocol.oauth2.client.BasicAuthAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.client.OAuth2ClientAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.DefaultOAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.OAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.WimseOAuth2DcrClientAuthentication;
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
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.executor.config.AgentAapExecutorConfig;
import com.alibaba.openagentauth.framework.executor.impl.DefaultAgentAapExecutor;
import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.orchestration.DefaultAgent;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.web.interceptor.AgentAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.spring.web.interceptor.SpringAgentAuthenticationInterceptor;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
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
     * Configuration for infrastructure-related beans.
     * <p>
     * This configuration provides beans for service discovery, session management,
     * and binding instance storage.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class InfrastructureConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(InfrastructureConfiguration.class);

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
         * Creates a RemoteBindingInstanceStore bean for querying binding instances
         * from the Authorization Server.
         * <p>
         * This enables the Agent to view its related authorization bindings
         * through the admin dashboard by remotely querying the Authorization Server.
         * </p>
         *
         * @param serviceEndpointResolver the service endpoint resolver
         * @return the RemoteBindingInstanceStore
         */
        @Bean
        @ConditionalOnMissingBean
        public BindingInstanceStore bindingInstanceStore(ServiceEndpointResolver serviceEndpointResolver) {
            logger.info("Creating RemoteBindingInstanceStore bean for Agent role");
            return new RemoteBindingInstanceStore(serviceEndpointResolver);
        }

        /**
         * Creates a RemoteAuditService bean for querying audit events
         * from the Authorization Server.
         * <p>
         * This enables the Agent to view its related audit records
         * through the admin dashboard by remotely querying the Authorization Server.
         * </p>
         *
         * @param serviceEndpointResolver the service endpoint resolver
         * @return the RemoteAuditService
         */
        @Bean
        @ConditionalOnMissingBean
        public AuditService auditService(ServiceEndpointResolver serviceEndpointResolver) {
            logger.info("Creating RemoteAuditService bean for Agent role");
            return new RemoteAuditService(serviceEndpointResolver);
        }

        /**
         * Creates a RemoteWorkloadRegistry bean for querying workload identities
         * from the Agent IDP.
         * <p>
         * This enables the Agent to view its related workload identity information
         * through the admin dashboard by remotely querying the Agent IDP.
         * </p>
         *
         * @param serviceEndpointResolver the service endpoint resolver
         * @return the RemoteWorkloadRegistry
         */
        @Bean
        @ConditionalOnMissingBean
        public WorkloadRegistry workloadRegistry(ServiceEndpointResolver serviceEndpointResolver) {
            logger.info("Creating RemoteWorkloadRegistry bean for Agent role");
            return new RemoteWorkloadRegistry(serviceEndpointResolver);
        }
    }

    /**
     * OAuth2 Client Configuration - manages OAuth2 client-related beans.
     */
    @Configuration(proxyBeanMethods = false)
    static class OAuth2ClientConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientConfiguration.class);

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
         * Creates the OAuth2DcrClient bean for DCR registration with Authorization Server.
         * <p>
         * This client uses WIMSE authentication to include the Workload Identity Token (WIT)
         * in DCR requests. The WIT is sent in the {@code Workload-Identity-Token} HTTP header,
         * enabling the Authorization Server to authenticate the workload and use the WIT subject
         * as the {@code client_id}.
         * </p>
         *
         * @param serviceEndpointResolver the service endpoint resolver
         * @return the OAuth2DcrClient bean with WIMSE authentication
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2DcrClient oauth2DcrClient(ServiceEndpointResolver serviceEndpointResolver) {
            logger.info("Creating OAuth2DcrClient bean with WIMSE authentication");
            return new DefaultOAuth2DcrClient(serviceEndpointResolver, new WimseOAuth2DcrClientAuthentication());
        }

        /**
         * Creates the OAuth2TokenClient bean for user authentication flow.
         * <p>
         * This client is used to exchange authorization codes for access tokens
         * in the user authentication flow with Agent User IDP.
         * </p>
         *
         * @param serviceEndpointResolver the service endpoint resolver
         * @param openAgentAuthProperties the global configuration properties
         * @return the OAuth2TokenClient bean for user authentication
         */
        @Bean(name = "userAuthenticationTokenClient")
        @ConditionalOnMissingBean(name = "userAuthenticationTokenClient")
        public OAuth2TokenClient userAuthenticationTokenClient(
                ServiceEndpointResolver serviceEndpointResolver,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            String clientId = openAgentAuthProperties.getCapabilities().getOAuth2Client().getClientId();
            String clientSecret = openAgentAuthProperties.getCapabilities().getOAuth2Client().getClientSecret();
            if (ValidationUtils.isNullOrEmpty(clientId)) {
                throw new IllegalStateException(
                        "OAuth client ID is not configured. " +
                                "Please set 'open-agent-auth.capabilities.oauth2-client.client-id' in your configuration. " +
                                "This is a required configuration for OAuth 2.0 flows."
                );
            }
            logger.info("Creating userAuthenticationTokenClient bean with ServiceEndpointResolver, " +
                    "serviceName: agent-user-idp, clientId: {}", clientId);
            OAuth2ClientAuthentication userIdpAuthentication = new BasicAuthAuthentication(clientId, clientSecret);
            return new DefaultOAuth2TokenClient(serviceEndpointResolver, SERVICE_AGENT_USER_IDP, userIdpAuthentication);
        }

        /**
         * Creates the OAuth2TokenClient bean for agent operation authorization flow.
         * <p>
         * This client is used to exchange authorization codes for access tokens
         * in the agent operation authorization flow with Authorization Server.
         * </p>
         *
         * @param serviceEndpointResolver the service endpoint resolver
         * @return the OAuth2TokenClient bean for agent operation authorization
         */
        @Bean(name = "agentOperationAuthorizationTokenClient")
        @ConditionalOnMissingBean(name = "agentOperationAuthorizationTokenClient")
        public OAuth2TokenClient agentOperationAuthorizationTokenClient(
                ServiceEndpointResolver serviceEndpointResolver,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            // Use standard private_key_jwt authentication (RFC 7523) for token exchange.
            // The workload's private key is propagated per-request through
            // TokenRequest.additionalParameters by the DefaultAgent orchestration layer.
            // ClientAssertionAuthentication generates a standard client_assertion JWT
            // signed with the workload's private key.
            String authorizationServerUrl = openAgentAuthProperties.getServiceUrl(SERVICE_AUTHORIZATION_SERVER);
            OAuth2ClientAuthentication authServerAuthentication = new ClientAssertionAuthentication(authorizationServerUrl);
            logger.info("Creating agentOperationAuthorizationTokenClient bean with standard " +
                    "private_key_jwt authentication, authorizationServerUrl: {}", authorizationServerUrl);
            return new DefaultOAuth2TokenClient(serviceEndpointResolver, SERVICE_AUTHORIZATION_SERVER, authServerAuthentication);
        }

        /**
         * Creates the OAuth2CallbackService bean.
         * <p>
         * This service handles OAuth 2.0 callback processing logic.
         * </p>
         *
         * @return the OAuth2CallbackService bean
         */
        @Bean
        @ConditionalOnMissingBean(OAuth2AuthorizationRequestStorage.class)
        public OAuth2AuthorizationRequestStorage authorizationRequestStorage() {
            logger.info("Creating fallback OAuth2AuthorizationRequestStorage bean for Agent role");
            return new InMemoryOAuth2AuthorizationRequestStorage();
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2CallbackService callbackService(
                FrameworkOAuth2TokenClient oauth2TokenClient,
                Agent agentProvider,
                SessionMappingBizService sessionMappingBizService,
                OAuth2AuthorizationRequestStorage authorizationRequestStorage,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            logger.info("Creating OAuth2CallbackService bean with Agent support");
            String callbackEndpoint = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getEndpoint();
            if (callbackEndpoint == null || callbackEndpoint.isBlank()) {
                callbackEndpoint = DEFAULT_CALLBACK_ENDPOINT;
            }
            return new OAuth2CallbackService(
                    oauth2TokenClient,
                    agentProvider,
                    sessionMappingBizService,
                    authorizationRequestStorage,
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
         * @param callbackService         the callback service
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
    }

    /**
     * Crypto Configuration - manages cryptography, signing, and verification beans.
     */
    @Configuration(proxyBeanMethods = false)
    static class CryptoConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(CryptoConfiguration.class);

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
        public IdTokenValidator idTokenValidator(KeyManager keyManager, OpenAgentAuthProperties properties) {
            String keyId = properties.getInfrastructures().getKeyManagement().getKeys().get(KEY_ID_TOKEN_VERIFICATION).getKeyId();
            logger.info("Creating IdTokenValidator bean. Key ID: {}", keyId);
            return new DefaultIdTokenValidator(keyManager, keyId);
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
         * @return the configured OAuth2ParClient bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2ParClient agentOperationAuthorizationParClient(
                ServiceEndpointResolver serviceEndpointResolver,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            // Use standard private_key_jwt authentication (RFC 7523) for PAR requests.
            // The workload's private key is propagated per-request through
            // ParRequest.additionalParameters by the DefaultAgent orchestration layer.
            // ClientAssertionAuthentication generates a standard client_assertion JWT
            // signed with the workload's private key.
            String authorizationServerUrl = openAgentAuthProperties.getServiceUrl(SERVICE_AUTHORIZATION_SERVER);
            OAuth2ClientAuthentication parAuthentication = new ClientAssertionAuthentication(authorizationServerUrl);

            logger.info("Creating PAR client with standard private_key_jwt authentication, " +
                    "authorizationServerUrl: {}", authorizationServerUrl);
            return new DefaultOAuth2ParClient(serviceEndpointResolver, parAuthentication);
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

            Map<String, KeyDefinitionProperties> keyDefinitions = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys();

            // Strategy 1: Look up by well-known key definition name "jwe-encryption" (peers-based inference)
            KeyDefinitionProperties encryptionKeyDef = keyDefinitions.get(KEY_JWE_ENCRYPTION);
            if (encryptionKeyDef != null && encryptionKeyDef.getKeyId() != null) {
                String keyId = encryptionKeyDef.getKeyId();
                logger.info("Found JWE encryption key definition '{}' with keyId: {}", KEY_JWE_ENCRYPTION, keyId);

                // Remote keys (with jwks-consumer) are resolved at encryption time, no need to pre-generate
                if (encryptionKeyDef.getJwksConsumer() == null || encryptionKeyDef.getJwksConsumer().isBlank()) {
                    try {
                        KeyAlgorithm keyAlgorithm = KeyAlgorithm.fromValue(encryptionKeyDef.getAlgorithm());
                        keyManager.getOrGenerateKey(keyId, keyAlgorithm);
                    } catch (KeyManagementException e) {
                        throw new IllegalStateException("Failed to register JWE encryption key with KeyManager", e);
                    }
                }
                return keyId;
            }

            // Strategy 2: Fall back to explicit encryption-key-id from capabilities config
            String keyId = openAgentAuthProperties.getCapabilities()
                    .getOperationAuthorization().getPromptEncryption().getEncryptionKeyId();
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalStateException("Encryption key ID must be configured via " +
                        "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id " +
                        "or inferred from peers configuration");
            }

            // Find key algorithm from key definitions by matching keyId field
            KeyAlgorithm keyAlgorithm = null;
            for (Map.Entry<String, KeyDefinitionProperties> entry : keyDefinitions.entrySet()) {
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
            String issuer = openAgentAuthProperties.getRoleIssuer(ROLE_AGENT);

            String keyId = openAgentAuthProperties.getKeyDefinition(KEY_VC_SIGNING).getKeyId();
            String keyAlgorithmName = openAgentAuthProperties.getKeyDefinition(KEY_VC_SIGNING).getAlgorithm();
            KeyAlgorithm keyAlgorithm = KeyAlgorithm.fromValue(keyAlgorithmName);

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
            String issuer = openAgentAuthProperties.getRoleIssuer(ROLE_AGENT);

            String authorizationServerUrl = openAgentAuthProperties.getServiceUrl(SERVICE_AUTHORIZATION_SERVER);
            String keyId = openAgentAuthProperties.getKeyDefinition(KEY_PAR_JWT_SIGNING).getKeyId();
            KeyAlgorithm keyAlgorithm = KeyAlgorithm.fromValue(
                    openAgentAuthProperties.getKeyDefinition(KEY_PAR_JWT_SIGNING).getAlgorithm());

            // Get or generate PAR-JWT signing key from KeyManager
            RSAKey parJwtSigningKey;
            try {
                parJwtSigningKey = (RSAKey) keyManager.getOrGenerateKey(keyId, keyAlgorithm);
            } catch (KeyManagementException e) {
                throw new IllegalStateException("Failed to register PAR-JWT signing key with KeyManager", e);
            }
            logger.info("Creating AapParJwtGenerator bean with issuer: {}", issuer);
            return new AapParJwtGenerator(parJwtSigningKey, JWSAlgorithm.RS256, issuer, authorizationServerUrl);
        }

        /**
         * WitValidator bean that verifies WIT signatures from Agent IDP.
         * <p>
         * Uses {@link KeyManager#resolveVerificationKey(String)} to obtain the verification key.
         * </p>
         *
         * @param keyManager the key manager for resolving verification keys
         * @param openAgentAuthProperties the configuration properties
         * @return the configured WitValidator bean
         */
        @Bean
        @ConditionalOnMissingBean
        public WitValidator witValidator(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {

            String keyId = openAgentAuthProperties.getKeyDefinition(KEY_WIT_VERIFICATION).getKeyId();
            String trustDomain = openAgentAuthProperties.getTrustDomain();
            logger.info("Creating WitValidator bean. Key ID: {}, Trust Domain: {}", keyId, trustDomain);

            TrustDomain trustDomainObj = new TrustDomain(trustDomain);
            return new WitValidator(keyManager, keyId, trustDomainObj);
        }
    }

    /**
     * Agent Core Configuration - manages core Agent functionality beans.
     */
    @Configuration(proxyBeanMethods = false)
    static class AgentCoreConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(AgentCoreConfiguration.class);

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
            String authorizationServerUrl = openAgentAuthProperties.getServiceUrl(SERVICE_AUTHORIZATION_SERVER);
            String agentUserIdpUrl = openAgentAuthProperties.getServiceUrl(SERVICE_AGENT_USER_IDP);

            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String clientId = oauth2ClientProps.getClientId();

            // Derive redirect URI from role issuer + callback endpoint
            String callbackEndpoint = oauth2ClientProps.getCallback().getEndpoint();
            String roleIssuer = openAgentAuthProperties.getRoleIssuer(ROLE_AGENT);
            String oAuthCallbacksRedirectUri = (roleIssuer != null ? roleIssuer : "") + (callbackEndpoint != null ? callbackEndpoint : "/callback");

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
         * AgentAapExecutorConfig bean with default configuration
         */
        @Bean
        @ConditionalOnMissingBean
        public AgentAapExecutorConfig agentAapExecutorConfig(
                OpenAgentAuthProperties openAgentAuthProperties,
                OAuth2AuthorizationRequestStorage authorizationRequestStorage) {
            var operationAuthProps = openAgentAuthProperties.getCapabilities().getOperationAuthorization();

            // Get issuer from roles configuration
            String issuer = openAgentAuthProperties.getRoleIssuer(ROLE_AGENT);

            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();

            // Derive redirect URI from role issuer + callback endpoint
            String callbackEndpoint = oauth2ClientProps.getCallback().getEndpoint();
            String redirectUri = (issuer != null ? issuer : "") + (callbackEndpoint != null ? callbackEndpoint : "/callback");

            return AgentAapExecutorConfig.builder()
                    .clientId(oauth2ClientProps.getClientId())
                    .channel(operationAuthProps.getAgentContext().getDefaultChannel())
                    .language(operationAuthProps.getAgentContext().getDefaultLanguage())
                    .platform(operationAuthProps.getAgentContext().getDefaultPlatform())
                    .redirectUri(redirectUri)
                    .agentClient(operationAuthProps.getAgentContext().getDefaultClient())
                    .expirationSeconds(operationAuthProps.getAuthorization().getExpirationSeconds())
                    .issuer(issuer)
                    .deviceFingerprint(operationAuthProps.getAgentContext().getDefaultDeviceFingerprint())
                    .promptProtectionEnabled(operationAuthProps.getPromptProtection().isEnabled())
                    .encryptionEnabled(operationAuthProps.getPromptProtection().isEncryptionEnabled())
                    .sanitizationLevel(operationAuthProps.getPromptProtection().getSanitizationLevel())
                    .requireUserInteraction(operationAuthProps.getAuthorization().isRequireUserInteraction())
                    .authorizationRequestStorage(authorizationRequestStorage)
                    .build();
        }
    }

    /**
     * Prompt Protection Configuration - manages prompt protection beans.
     */
    @Configuration(proxyBeanMethods = false)
    static class PromptProtectionConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(PromptProtectionConfiguration.class);

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
    }

    /**
     * Authentication Interceptor Configuration - creates interceptor beans.
     * <p>
     * This configuration is separated from AgentWebMvcConfiguration to avoid circular
     * dependency: AgentWebMvcConfiguration implements WebMvcConfigurer and injects
     * SpringAgentAuthenticationInterceptor via constructor, so the interceptor beans
     * must be defined in a separate configuration class that is processed first.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.oauth2-client.authentication", name = "enabled", havingValue = "true", matchIfMissing = true)
    static class AuthenticationInterceptorConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(AuthenticationInterceptorConfiguration.class);

        /**
         * Creates the framework-level Agent authentication interceptor bean.
         *
         * @param agentAapExecutor         the AgentAapExecutor bean
         * @param openAgentAuthProperties  the global configuration properties
         * @return the AgentAuthenticationInterceptor bean
         */
        @Bean
        @ConditionalOnMissingBean
        public AgentAuthenticationInterceptor agentAuthenticationInterceptor(
                AgentAapExecutor agentAapExecutor,
                OpenAgentAuthProperties openAgentAuthProperties,
                OAuth2AuthorizationRequestStorage authorizationRequestStorage
        ) {
            logger.info("Creating AgentAuthenticationInterceptor bean with shared repository");
            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            List<String> excludedPaths = oauth2ClientProps.getAuthentication().getExcludePaths();
            logger.info("Configured excluded paths: {}", excludedPaths);
            return new AgentAuthenticationInterceptor(agentAapExecutor, excludedPaths, authorizationRequestStorage);
        }

        /**
         * Creates the Spring adapter for AgentAuthenticationInterceptor.
         *
         * @param agentAuthenticationInterceptor the framework-level interceptor
         * @return the Spring adapter bean
         */
        @Bean
        @ConditionalOnMissingBean
        public SpringAgentAuthenticationInterceptor springAgentAuthenticationInterceptor(
                AgentAuthenticationInterceptor agentAuthenticationInterceptor
        ) {
            logger.info("Creating SpringAgentAuthenticationInterceptor bean");
            return new SpringAgentAuthenticationInterceptor(agentAuthenticationInterceptor);
        }
    }

    /**
     * Web MVC configuration for registering the authentication interceptor.
     * <p>
     * This configuration injects the SpringAgentAuthenticationInterceptor created by
     * AuthenticationInterceptorConfiguration and registers it with Spring MVC.
     * Uses ObjectProvider for graceful handling when the interceptor bean is not available.
     * </p>
     */
    @Configuration
    @ConditionalOnExpression("'${open-agent-auth.roles.agent.enabled:false}' == 'true' and '${open-agent-auth.capabilities.oauth2-client.authentication.enabled:true}' == 'true'")
    public static class AgentWebMvcConfiguration implements WebMvcConfigurer {

        private static final Logger logger = LoggerFactory.getLogger(AgentWebMvcConfiguration.class);

        private final ObjectProvider<SpringAgentAuthenticationInterceptor> agentAuthenticationInterceptorProvider;
        private final OpenAgentAuthProperties openAgentAuthProperties;

        public AgentWebMvcConfiguration(
                ObjectProvider<SpringAgentAuthenticationInterceptor> agentAuthenticationInterceptorProvider,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            this.agentAuthenticationInterceptorProvider = agentAuthenticationInterceptorProvider;
            this.openAgentAuthProperties = openAgentAuthProperties;
            logger.info("Initializing AgentWebMvcConfiguration");
        }

        @Override
        public void addInterceptors(@NonNull InterceptorRegistry registry) {
            SpringAgentAuthenticationInterceptor interceptor = agentAuthenticationInterceptorProvider.getIfAvailable();
            if (interceptor == null) {
                logger.warn("SpringAgentAuthenticationInterceptor not available, skipping interceptor registration");
                return;
            }

            var authProps = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication();

            logger.info("Registering SpringAgentAuthenticationInterceptor");
            logger.info("Include paths: {}", authProps.getIncludePaths());
            logger.info("Exclude paths: {}", authProps.getExcludePaths());

            if (authProps.getIncludePaths().isEmpty()) {
                logger.warn("No include paths configured for authentication, defaulting to /**");
                registry.addInterceptor(interceptor)
                        .addPathPatterns("/**")
                        .excludePathPatterns(authProps.getExcludePaths());
            } else {
                registry.addInterceptor(interceptor)
                        .addPathPatterns(authProps.getIncludePaths())
                        .excludePathPatterns(authProps.getExcludePaths());
            }
        }
    }

}