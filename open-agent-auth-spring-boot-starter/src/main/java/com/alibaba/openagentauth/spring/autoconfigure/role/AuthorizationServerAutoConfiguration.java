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
import com.alibaba.openagentauth.core.audit.factory.AuditFactory;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.binding.InMemoryBindingInstanceStore;
import com.alibaba.openagentauth.core.crypto.jwk.JwksProvider;
import com.alibaba.openagentauth.core.crypto.jwk.RemoteJwksProvider;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.policy.registry.InMemoryPolicyRegistry;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.DefaultOAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.DefaultOAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.InMemoryOAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.DefaultOAuth2ParRequestValidator;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.DefaultOAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParRequestValidator;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.InMemoryOAuth2ParRequestStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.OAuth2ParRequestStore;
import com.alibaba.openagentauth.core.protocol.oauth2.token.aoat.AoatTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.aoat.AoatTokenGeneratorAdapter;
import com.alibaba.openagentauth.core.protocol.oauth2.token.aoat.DefaultAoatTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.DefaultOAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.DefaultOAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.vc.DefaultVcVerifier;
import com.alibaba.openagentauth.core.protocol.vc.VcVerificationPolicy;
import com.alibaba.openagentauth.core.protocol.vc.VcVerifier;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.aoat.AoatGenerator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.AuthorizationServer;
import com.alibaba.openagentauth.framework.orchestration.DefaultAuthorizationServer;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.web.interceptor.AsUserIdpUserAuthInterceptor;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Auto-configuration for Authorization Server role.
 * <p>
 * This configuration provides automatic setup for the Authorization Server role,
 * which is responsible for handling OAuth 2.0 authorization flows and issuing Agent OA Tokens.
 * </p>
 * <p>
 * <b>Role Identification:</b></p>
 * <p>
 * Enable this configuration by setting:
 * </p>
 * <pre>
 * open-agent-auth:
 *   roles:
 *     authorization-server:
 *       enabled: true
 * </pre>
 * <p>
 * This role is typically used in scenarios where:
 * </p>
 * <ul>
 *   <li>Your application manages the OAuth 2.0 authorization flow for AI Agent operations</li>
 *   <li>You need to issue Agent OA Tokens that grant access to resources</li>
 *   <li>You want to provide fine-grained access control for AI Agent operations</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   enabled: true
 *   roles:
 *     authorization-server:
 *       enabled: true
 *       instance-id: authz-server-1
 *       issuer: https://authorization-server.example.com
 *       capabilities:
 *         - oauth2-server
 *         - operation-authorization
 *   capabilities:
 *     oauth2-server:
 *       enabled: true
 *       par:
 *         enabled: true
 *       token:
 *         access-token-expiry: 3600
 * </pre>
 * <p>
 * <b>Provided Beans:</b></p>
 * <ul>
 *   <li><code>parRequestStore</code>: Storage for PAR requests</li>
 *   <li><code>parRequestValidator</code>: Validator for PAR requests</li>
 *   <li><code>parServer</code>: PAR server implementation</li>
 *   <li><code>authorizationCodeStorage</code>: Storage for authorization codes</li>
 *   <li><code>authorizationServer</code>: OAuth 2.0 authorization server implementation</li>
 *   <li><code>tokenServer</code>: OAuth 2.0 token server implementation</li>
 *   <li><code>dcrServer</code>: DCR server implementation (requires custom implementation)</li>
 * </ul>
 *
 * @see CoreAutoConfiguration
 * @see AgentIdpAutoConfiguration
 * @see ResourceServerAutoConfiguration
 * @since 1.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.authorization-server", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AuthorizationServerAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerAutoConfiguration.class);


    /**
     * Creates the PAR Request Store bean if not already defined.
     * <p>
     * This storage provides storage for PAR requests.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the PAR Request Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2ParRequestStore parRequestStore() {
        logger.info("Creating OAuth2ParRequestStore bean");
        return new InMemoryOAuth2ParRequestStore();
    }

    /**
     * Creates the Audit Service bean if not already defined.
     * <p>
     * This service provides audit logging functionality for authorization events.
     * The default implementation uses in-memory storage for audit events.
     * </p>
     *
     * @param openAgentAuthProperties the global configuration properties
     * @return the Audit Service bean
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.audit", name = "enabled", havingValue = "true")
    public AuditService auditService(OpenAgentAuthProperties openAgentAuthProperties) {
        // Audit is no longer a separate capability, it's integrated into operation authorization
        // For now, we'll create the audit service if operation authorization is enabled
        if (openAgentAuthProperties.getCapabilities().getOperationAuthorization().isEnabled()) {
            logger.info("Creating AuditService bean with in-memory storage");
            return AuditFactory.createInMemoryAuditService();
        }
        logger.info("Audit functionality is disabled, skipping AuditService bean creation");
        return null;
    }

    /**
     * Creates the PAR Server bean if not already defined.
     * <p>
     * This server provides PAR endpoint for processing PAR requests.
     * Note: OAuth2ParRequestValidator is created as a local variable since it's a stateless validator.
     * </p>
     *
     * @param parRequestStore the PAR request store
     * @return the PAR Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2ParServer parServer(OAuth2ParRequestStore parRequestStore) {
        logger.info("Creating OAuth2ParServer bean");
        OAuth2ParRequestValidator validator = new DefaultOAuth2ParRequestValidator();
        return new DefaultOAuth2ParServer(parRequestStore, validator);
    }

    /**
     * Creates the Authorization Code Storage bean if not already defined.
     * <p>
     * This storage provides storage for authorization codes.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @param openAgentAuthProperties the global configuration properties
     * @return the Authorization Code Storage bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationCodeStorage authorizationCodeStorage(OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating OAuth2AuthorizationCodeStorage bean");
        return new InMemoryOAuth2AuthorizationCodeStorage(openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getAuthorizationCodeExpiry());
    }

    /**
     * Creates the Authorization Server bean if not already defined.
     * <p>
     * This server provides OAuth 2.0 authorization endpoint for processing authorization requests.
     * </p>
     *
     * @param authorizationCodeStorage the authorization code storage
     * @param parServer the PAR server
     * @param dcrClientStore the DCR client store
     * @return the Authorization Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationServer authorizationServer(
            OAuth2AuthorizationCodeStorage authorizationCodeStorage,
            OAuth2ParServer parServer,
            OAuth2DcrClientStore dcrClientStore) {
        logger.info("Creating OAuth2AuthorizationServer bean");
        return new DefaultOAuth2AuthorizationServer(authorizationCodeStorage, parServer, dcrClientStore);
    }

    /**
     * Creates the Token Server bean if not already defined.
     * <p>
     * This server provides OAuth 2.0 token endpoint for issuing access tokens.
     * </p>
     *
     * @param authorizationCodeStorage the authorization code storage
     * @param tokenGenerator the token generator
     * @return the Token Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2TokenServer tokenServer(
            OAuth2AuthorizationCodeStorage authorizationCodeStorage,
            TokenGenerator tokenGenerator) {
        logger.info("Creating OAuth2TokenServer bean");
        return new DefaultOAuth2TokenServer(authorizationCodeStorage, tokenGenerator);
    }

    /**
     * Creates the DCR Server bean if not already defined.
     * <p>
     * This server provides OAuth 2.0 DCR endpoint for dynamic client registration.
     * </p>
     *
     * @param dcrClientStore the DCR client store
     * @return the DCR Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2DcrServer dcrServer(OAuth2DcrClientStore dcrClientStore) {
        logger.info("Creating OAuth2DcrServer bean");
        // Note: WIMSE authenticator should be configured separately in production
        // For development/testing, we use an empty authenticator list
        return new DefaultOAuth2DcrServer(dcrClientStore);
    }

    /**
     * Creates the DCR Client Store bean if not already defined.
     * <p>
     * This store provides storage for DCR client registrations.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the DCR Client Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2DcrClientStore dcrClientStore() {
        logger.info("Creating OAuth2DcrClientStore bean");
        return new InMemoryOAuth2DcrClientStore();
    }

    /**
     * Creates the AOAT Token Generator bean if not already defined.
     * <p>
     * This generator provides AOAT token generation for Agent Operation Authorization Tokens.
     * </p>
     *
     * @param policyRegistry the policy registry
     * @param aoatGenerator the AOAT generator
     * @param vcVerifier the VC verifier
     * @param bindingInstanceStore the binding instance store
     * @param promptDecryptionService the prompt decryption service (optional)
     * @return the AOAT Token Generator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AoatTokenGenerator aoatTokenGenerator(
            PolicyRegistry policyRegistry,
            AoatGenerator aoatGenerator,
            VcVerifier vcVerifier,
            BindingInstanceStore bindingInstanceStore,
            PromptDecryptionService promptDecryptionService) {
        logger.info("Creating AoatTokenGenerator bean");
        return new DefaultAoatTokenGenerator(
                aoatGenerator,
                vcVerifier,
                policyRegistry,
                bindingInstanceStore,
                promptDecryptionService,
                3600 // Default expiration: 1 hour
        );
    }

    /**
     * Creates the Token Generator bean if not already defined.
     * <p>
     * This generator provides token generation for access tokens.
     * It uses the AOAT Token Generator adapter for Agent Operation Authorization Tokens.
     * </p>
     *
     * @param aoatTokenGenerator the AOAT token generator
     * @param parServer the PAR server
     * @return the Token Generator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenGenerator tokenGenerator(AoatTokenGenerator aoatTokenGenerator, OAuth2ParServer parServer) {
        logger.info("Creating TokenGenerator bean");
        return new AoatTokenGeneratorAdapter(aoatTokenGenerator, parServer);
    }

    /**
     * Creates the AOAT Generator bean if not already defined.
     * <p>
     * This generator provides AOAT signing and serialization capabilities.
     * </p>
     *
     * @param keyManager the key manager
     * @param openAgentAuthProperties the global configuration properties
     * @return the AOAT Generator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AoatGenerator aoatGenerator(
            KeyManager keyManager,
            OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating AoatGenerator bean");
        
        // Generate or get RSA signing key from KeyManager
        String aoatKeyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("aoat-signing").getKeyId();
        String aoatAlgorithm = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("aoat-signing").getAlgorithm();
        logger.info("Getting or generating AOAT signing key with ID: {}, Algorithm: {}", aoatKeyId, aoatAlgorithm);
        
        RSAKey signingKey;
        try {
            KeyAlgorithm keyAlgorithm = KeyAlgorithm.valueOf(aoatAlgorithm);
            Object signingJwk = keyManager.getOrGenerateKey(aoatKeyId, keyAlgorithm);
            if (signingJwk instanceof RSAKey) {
                signingKey = (RSAKey) signingJwk;
            } else {
                logger.error("Expected RSAKey but got: {}", signingJwk.getClass());
                throw new RuntimeException("Expected RSAKey for AOAT signing");
            }
            logger.info("AOAT signing key ready. Key ID: {}", aoatKeyId);
        } catch (KeyManagementException e) {
            logger.error("Failed to get or generate AOAT signing key", e);
            throw new RuntimeException("Failed to initialize AOAT signing key", e);
        }
        
        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("authorization-server");
            if (role != null) {
                issuer = role.getIssuer();
            }
        }

        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException(
                "Authorization Server issuer is not configured. Please set 'open-agent-auth.roles.authorization-server.issuer' in your configuration. " +
                "This is a required configuration for AOAT generation."
            );
        }
        
        // AOAT audience should be the Resource Server's identifier (issuer)
        // According to OAuth 2.0, the audience (aud) claim identifies the intended recipient(s) of the token
        String audience = openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("resource-server").getBaseUrl();
        
        return new AoatGenerator(
                signingKey,
                com.nimbusds.jose.JWSAlgorithm.parse(aoatAlgorithm),
                issuer,
                audience
        );
    }

    /**
     * Creates the Policy Registry bean if not already defined.
     * <p>
     * This registry provides storage for policies.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the Policy Registry bean
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyRegistry policyRegistry() {
        logger.info("Creating PolicyRegistry bean");
        return new InMemoryPolicyRegistry();
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
        if (openAgentAuthProperties.getInfrastructures().getServiceDiscovery() != null
                && openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices() != null) {
            openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().forEach((name, service) -> {
                ServiceProperties.ConsumerServiceProperties consumer = new ServiceProperties.ConsumerServiceProperties();
                consumer.setBaseUrl(service.getBaseUrl());
                consumer.setEndpoints(service.getEndpoints());
                consumers.put(name, consumer);
            });
        }
        serviceProperties.setConsumers(consumers);
        
        return new DefaultServiceEndpointResolver(serviceProperties);
    }

    /**
     * Creates the Session Mapping Store bean if not already defined.
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
     * Creates the Session Mapping Business Service bean if not already defined.
     * <p>
     * This service provides business logic for session mapping operations.
     * It coordinates between the session mapping store and other components.
     * </p>
     *
     * @param sessionMappingStore the session mapping store
     * @return the Session Mapping Business Service bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingBizService sessionMappingBizService(SessionMappingStore sessionMappingStore) {
        logger.info("Creating SessionMappingBizService bean for Authorization Server");
        return new SessionMappingBizService(sessionMappingStore);
    }

    /**
     * Creates the Binding Instance Store bean if not already defined.
     * <p>
     * This store provides storage for binding instances that establish
     * the relationship between user identities and workload identities.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the Binding Instance Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public BindingInstanceStore bindingInstanceStore() {
        logger.info("Creating BindingInstanceStore bean");
        return new InMemoryBindingInstanceStore();
    }

    /**
     * Creates the User Authentication Interceptor bean if not already defined.
     * <p>
     * This interceptor provides user authentication for the OAuth 2.0 authorization flow.
     * It uses AS User IDP for authentication.
     * </p>
     *
     * @param sessionMappingBizService the session mapping business service
     * @param openAgentAuthProperties the global configuration properties
     * @return the User Authentication Interceptor bean
     */
    @Bean
    @ConditionalOnMissingBean
    public UserAuthenticationInterceptor userAuthenticationInterceptor(
            SessionMappingBizService sessionMappingBizService,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating UserAuthenticationInterceptor bean with AsUserIdpUserAuthInterceptor");
        
        // Get AS User IDP configuration
        String asUserIdpIssuer;
        if (openAgentAuthProperties.getInfrastructures().getJwks() != null
                && openAgentAuthProperties.getInfrastructures().getJwks().getConsumers() != null
                && openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().get("as-user-idp") != null) {
            asUserIdpIssuer = openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().get("as-user-idp").getIssuer();
        } else {
            throw new IllegalStateException(
                "AS User IDP issuer configuration not found. Please configure open-agent-auth.infrastructure.jwks.consumers.as-user-idp in application.yml");
        }

        String clientId = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientId();
        
        // Get issuer from roles configuration
        String callbackUrl = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("authorization-server");
            if (role != null) {
                callbackUrl = role.getIssuer();
            }
        }
        
        // Use excluded paths from oauth2-client.authentication.exclude-paths
        // This configuration already has default values, so users don't need to configure it explicitly
        List<String> excludedPaths = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication().getExcludePaths();
        
        logger.debug("Using excluded paths: {}", excludedPaths);
        
        return new AsUserIdpUserAuthInterceptor(
                sessionMappingBizService,
                excludedPaths,
                asUserIdpIssuer,
                clientId,
                callbackUrl + "/callback");
    }

    /**
     * Creates the Consent Page Provider bean if not already defined.
     * <p>
     * This provider provides rendering and handling of the user consent page
     * for the Agent Operation Authorization flow. The default implementation uses
     * a Thymeleaf template located at {@code oauth2/aoa_consent}.
     * </p>
     *
     * @return the Consent Page Provider bean
     */
    @Bean
    @ConditionalOnMissingBean
    public ConsentPageProvider consentPageProvider() {
        logger.info("Creating ConsentPageProvider bean with DefaultConsentPageProvider for Authorization Server");
        return new DefaultConsentPageProvider("oauth2/aoa_consent");
    }



    /**
     * Creates the OAuth2TokenClient bean for user authentication flow with AS User IDP.
     * <p>
     * This client is used to exchange authorization codes for access tokens
     * in the user authentication flow with AS User IDP.
     * </p>
     *
     * @param openAgentAuthProperties the global configuration properties
     * @return the OAuth2TokenClient bean for user authentication
     */
    @Bean(name = "userAuthenticationTokenClient")
    @ConditionalOnMissingBean(name = "userAuthenticationTokenClient")
    public OAuth2TokenClient userAuthenticationTokenClient(
            OpenAgentAuthProperties openAgentAuthProperties,
            ServiceEndpointResolver serviceEndpointResolver) {
        logger.info("Creating userAuthenticationTokenClient bean for Authorization Server role");
        
        // Debug: log configuration binding status
        logger.debug("OpenAgentAuthProperties.getInfrastructure().getJwks() = {}", openAgentAuthProperties.getInfrastructures().getJwks());
        if (openAgentAuthProperties.getInfrastructures().getJwks() != null) {
            logger.debug("Consumers = {}", openAgentAuthProperties.getInfrastructures().getJwks().getConsumers());
            logger.debug("Consumers.keySet() = {}", 
                openAgentAuthProperties.getInfrastructures().getJwks() != null ?
                openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().keySet() : "null");
        }
        
        // Get AS User IDP configuration
        String asUserIdpUrl = null;
        if (openAgentAuthProperties.getInfrastructures().getJwks() != null &&
            openAgentAuthProperties.getInfrastructures().getJwks().getConsumers() != null) {
            JwksConsumerProperties asUserIdpConfig = openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().get("as-user-idp");
            logger.debug("asUserIdpConfig = {}", asUserIdpConfig);
            if (asUserIdpConfig != null) {
                asUserIdpUrl = asUserIdpConfig.getIssuer();
                logger.debug("asUserIdpUrl = {}", asUserIdpUrl);
            }
        }
        
        if (asUserIdpUrl == null || asUserIdpUrl.isBlank()) {
            logger.error("AS User IDP configuration not found in open-agent-auth.infrastructure.jwks.consumers.as-user-idp");
            logger.error("Available consumer keys: {}", 
                openAgentAuthProperties.getInfrastructures().getJwks() != null && openAgentAuthProperties.getInfrastructures().getJwks().getConsumers() != null ?
                openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().keySet() : "null");
            throw new IllegalStateException(
                "AS User IDP configuration not found. Please configure open-agent-auth.infrastructure.jwks.consumers.as-user-idp in application.yml"
            );
        }

        String clientId = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientId();
        String clientSecret = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientSecret();
        
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException(
                "OAuth client ID is not configured. Please set 'open-agent-auth.capabilities.oauth2-client.callback.client-id' in your configuration. " +
                "This is a required configuration for OAuth 2.0 token exchange."
            );
        }
        
        logger.info("Creating userAuthenticationTokenClient bean with clientId: {}", clientId);
        return new DefaultOAuth2TokenClient(serviceEndpointResolver, "as-user-idp", clientId, clientSecret);
    }

    /**
     * Creates the OAuth2TokenClient bean for agent operation authorization flow.
     * <p>
     * This client is used to exchange authorization codes for access tokens
     * in the agent operation authorization flow with Authorization Server.
     * For authorization-server role, this client points to itself to handle callbacks.
     * </p>
     *
     * @param openAgentAuthProperties the global configuration properties
     * @return the OAuth2TokenClient bean for agent operation authorization
     */
    @Bean(name = "agentOperationAuthorizationTokenClient")
    @ConditionalOnMissingBean(name = "agentOperationAuthorizationTokenClient")
    public OAuth2TokenClient agentOperationAuthorizationTokenClient(
            OpenAgentAuthProperties openAgentAuthProperties,
            ServiceEndpointResolver serviceEndpointResolver) {
        logger.info("Creating agentOperationAuthorizationTokenClient bean for Authorization Server role");
        
        // For authorization-server role, this client points to itself
        // This is needed for OAuth2CallbackController to handle agent operation authorization flow callbacks
        String clientId = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientId();
        String clientSecret = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getClientSecret();
        
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException(
                "OAuth client ID is not configured. Please set 'open-agent-auth.server.callback.client-id' in your configuration. " +
                "This is a required configuration for OAuth 2.0 token exchange."
            );
        }
        
        logger.info("Creating agentOperationAuthorizationTokenClient bean with clientId: {}", clientId);
        return new DefaultOAuth2TokenClient(serviceEndpointResolver, "authorization-server", clientId, clientSecret);
    }

    /**
     * Creates the OAuth2CallbackService bean for Authorization Server role.
     * <p>
     * This service handles OAuth 2.0 authorization code callbacks from the authorization server.
     * It exchanges the authorization code for an access token and redirects the user to the
     * application's home page.
     * </p>
     *
     * @param authorizationServerProvider the AuthorizationServer bean (implements FrameworkOAuth2TokenClient)
     * @param sessionMappingBizService the session mapping business service
     * @param openAgentAuthProperties the global configuration properties
     * @return the OAuth2CallbackService bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2CallbackService callbackService(
            AuthorizationServer authorizationServerProvider,
            SessionMappingBizService sessionMappingBizService,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating OAuth2CallbackService bean for Authorization Server role");
        String callbackEndpoint = openAgentAuthProperties.getCapabilities().getOAuth2Client().getCallback().getEndpoint();
        if (callbackEndpoint == null || callbackEndpoint.isBlank()) {
            callbackEndpoint = "/callback";
        }
        return new OAuth2CallbackService(
                authorizationServerProvider,
                sessionMappingBizService,
                callbackEndpoint
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2CallbackController oauth2CallbackController(
            OAuth2CallbackService callbackService,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating OAuth2CallbackController bean for Authorization Server role");
        return new OAuth2CallbackController(
                callbackService,
                openAgentAuthProperties
        );
    }

    /**
     * Configures the signing keys for JWKS endpoint.
     * <p>
     * This bean provides the public keys that should be exposed through the JWKS endpoint
     * for token verification by other services.
     * </p>
     *
     * @param keyManager the key manager
     * @param openAgentAuthProperties the global configuration properties
     * @return the list of signing keys
     */
    @Bean
    @ConditionalOnMissingBean
    public List<JWK> signingKeys(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
        List<JWK> keys = new ArrayList<>();
        
        // Get the public key for JWKS exposure
        String aoatKeyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("aoat-signing").getKeyId();
        try {
            PublicKey publicKey = keyManager.getVerificationKey(aoatKeyId);
            if (publicKey != null) {
                JWK jwk = convertToJWK(publicKey, aoatKeyId);
                keys.add(jwk);
            }
        } catch (Exception e) {
            logger.error("Failed to get public key for JWKS: {}", aoatKeyId, e);
        }
        
        return keys;
    }

    /**
     * Converts a PublicKey to JWK.
     *
     * @param publicKey the public key
     * @param keyId the key ID
     * @return the JWK
     */
    private JWK convertToJWK(PublicKey publicKey, String keyId) {
        if (publicKey instanceof RSAPublicKey) {
            return new RSAKey.Builder((RSAPublicKey) publicKey)
                    .keyID(keyId)
                    .build();
        } else if (publicKey instanceof ECPublicKey ecPublicKey) {
            Curve curve = Curve.forECParameterSpec(ecPublicKey.getParams());
            return new ECKey.Builder(curve, ecPublicKey)
                    .keyID(keyId)
                    .build();
        }
        throw new IllegalArgumentException("Unsupported key type: " + publicKey.getClass().getName());
    }

    /**
     * Creates the VC Verifier bean if not already defined.
     * <p>
     * This verifier provides verification capabilities for Verifiable Credentials.
     * Supports both local and remote JWKS providers based on configuration.
     * </p>
     *
     * @param openAgentAuthProperties the global configuration properties
     * @return the VC Verifier bean
     */
    @Bean
    @ConditionalOnMissingBean
    @Lazy
    public VcVerifier vcVerifier(OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating VcVerifier bean");
        
        try {
            // Check if Agent's JWKS endpoint is configured
            String agentJwksEndpoint = null;
            if (openAgentAuthProperties.getInfrastructures().getServiceDiscovery() != null &&
                openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices() != null &&
                openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("agent") != null &&
                openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("agent").getBaseUrl() != null) {
                agentJwksEndpoint = openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().get("agent").getBaseUrl() + "/.well-known/jwks.json";
            }
            
            JwksProvider jwksProvider;
            if (agentJwksEndpoint != null && !agentJwksEndpoint.isBlank()) {
                logger.info("Using remote JWKS provider for VcVerifier: {}", agentJwksEndpoint);
                jwksProvider = new RemoteJwksProvider(agentJwksEndpoint);
            } else {
                logger.info("Using local JWKS provider for VcVerifier");
                // Create a simple JWKS provider that uses the KeyManager
                jwksProvider = new JwksProvider() {
                    @Override
                    public JWKSource<SecurityContext> getJwkSource() {
                        return (jwkSelector, context) -> new java.util.ArrayList<>();
                    }

                    @Override
                    public JWKSet getJwkSet() {
                        return new com.nimbusds.jose.jwk.JWKSet();
                    }

                    @Override
                    public void refresh() {
                        // No-op for simple implementation
                    }
                };
            }
            
            return new DefaultVcVerifier(jwksProvider, new VcVerificationPolicy());
        } catch (Exception e) {
            logger.error("Failed to create VcVerifier: {}", e.getMessage(), e);
            throw new IllegalStateException("Failed to initialize VcVerifier", e);
        }
    }

    /**
     * Creates the AuthorizationServer (Framework layer) bean if not already defined.
     * <p>
     * This is the main orchestrator that coordinates all authorization server operations.
     * It provides the high-level API for authorization processing.
     * </p>
     *
     * @param parServer the PAR server
     * @param dcrClientStore the DCR client store
     * @param userAuthenticationTokenClient the user authentication token client
     * @param oauth2TokenServer the OAuth2 token server
     * @param keyManager the key manager
     * @param openAgentAuthProperties the global configuration properties
     * @return the AuthorizationServer bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationServer authorizationServerProvider(
            OAuth2ParServer parServer,
            OAuth2DcrClientStore dcrClientStore,
            @Qualifier("userAuthenticationTokenClient") OAuth2TokenClient userAuthenticationTokenClient,
            OAuth2TokenServer oauth2TokenServer,
            KeyManager keyManager,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        logger.info("Creating AuthorizationServer (Framework layer) bean");
        
        String verificationKeyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("wit-verification").getKeyId();
        String algorithm = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("wit-verification").getAlgorithm();
        
        // Generate RSA key pair if not exists
        try {
            keyManager.generateKeyPair(KeyAlgorithm.valueOf(algorithm), verificationKeyId);
        } catch (Exception e) {
            // Key may already exist
        }
        
        PublicKey publicKey = keyManager.getVerificationKey(verificationKeyId);
        JWK witVerificationKey = convertToJWK(publicKey, verificationKeyId);
        
        return new DefaultAuthorizationServer(
                parServer,
                dcrClientStore,
                userAuthenticationTokenClient,
                oauth2TokenServer,
                witVerificationKey,
                openAgentAuthProperties.getInfrastructures().getTrustDomain()
        );
    }
}