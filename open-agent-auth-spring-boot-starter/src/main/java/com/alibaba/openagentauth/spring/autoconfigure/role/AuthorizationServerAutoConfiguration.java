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
import com.alibaba.openagentauth.core.audit.impl.DefaultAuditService;
import com.alibaba.openagentauth.core.audit.impl.InMemoryAuditStorage;
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
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.DefaultOAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.InMemoryOAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.DefaultOAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.DefaultOAuth2ParRequestValidator;
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
import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.vc.DefaultVcVerifier;
import com.alibaba.openagentauth.core.protocol.vc.VcVerificationPolicy;
import com.alibaba.openagentauth.core.protocol.vc.VcVerifier;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.aoat.AoatGenerator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.AuthorizationServer;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.orchestration.DefaultAuthorizationServer;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.web.interceptor.AsUserIdpUserAuthInterceptor;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.beans.factory.annotation.Qualifier;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Auto-configuration for the Authorization Server role.
 * <p>
 * This configuration class sets up all the necessary beans for running an OAuth 2.0 Authorization Server
 * with support for Agent Operation Authorization (AOA) and Agent Operation Authorization Token (AOAT).
 * </p>
 * <p>
 * This configuration is automatically enabled when the following property is set:
 * <pre>
 * open-agent-auth.roles.authorization-server.enabled=true
 * </pre>
 * </p>
 *
 * @author Open Agent Auth Team
 * @since 1.0.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.authorization-server", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AuthorizationServerAutoConfiguration {

    // Package-private static method for converting PublicKey to JWK
    // Shared by CryptoConfiguration and AuthorizationCoreConfiguration
    static JWK convertToJWK(PublicKey publicKey, String keyId) {
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
     * Configuration for infrastructure-related beans.
     * <p>
     * This configuration provides beans for service discovery, session management,
     * and binding instance storage.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class InfrastructureConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(InfrastructureConfiguration.class);

        @Bean
        @ConditionalOnMissingBean
        public ServiceEndpointResolver serviceEndpointResolver(OpenAgentAuthProperties openAgentAuthProperties) {
            ServiceProperties serviceProperties = new ServiceProperties();
            Map<String, ServiceProperties.ConsumerServiceProperties> consumers = new HashMap<>();
            var serviceDiscovery = openAgentAuthProperties.getInfrastructures().getServiceDiscovery();
            if (serviceDiscovery != null && serviceDiscovery.getServices() != null) {
                serviceDiscovery.getServices().forEach((name, service) -> {
                    ServiceProperties.ConsumerServiceProperties consumer = new ServiceProperties.ConsumerServiceProperties();
                    consumer.setBaseUrl(service.getBaseUrl());
                    consumer.setEndpoints(service.getEndpoints());
                    consumers.put(name, consumer);
                });
            }
            serviceProperties.setConsumers(consumers);
            return new DefaultServiceEndpointResolver(serviceProperties);
        }

        @Bean
        @ConditionalOnMissingBean
        public BindingInstanceStore bindingInstanceStore() {
            logger.info("Creating BindingInstanceStore bean");
            return new InMemoryBindingInstanceStore();
        }
    }

    /**
     * Configuration for OAuth2 server-related beans.
     * <p>
     * This configuration provides beans for OAuth2 authorization server functionality,
     * including PAR (Pushed Authorization Requests), DCR (Dynamic Client Registration),
     * and token generation.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class OAuth2ServerConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(OAuth2ServerConfiguration.class);

        @Bean
        @ConditionalOnMissingBean
        public OAuth2ParRequestStore parRequestStore() {
            logger.info("Creating OAuth2ParRequestStore bean");
            return new InMemoryOAuth2ParRequestStore();
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.audit", name = "enabled", havingValue = "true")
        public AuditService auditService() {
            logger.info("Creating AuditService bean");
            return new DefaultAuditService(new InMemoryAuditStorage());
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2ParRequestValidator parRequestValidator() {
            logger.info("Creating OAuth2ParRequestValidator bean");
            return new DefaultOAuth2ParRequestValidator();
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2ParServer parServer(OAuth2ParRequestStore parRequestStore, OAuth2ParRequestValidator parRequestValidator) {
            logger.info("Creating OAuth2ParServer bean");
            return new DefaultOAuth2ParServer(parRequestStore, parRequestValidator);
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2AuthorizationCodeStorage authorizationCodeStorage(OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating OAuth2AuthorizationCodeStorage bean");
            return new InMemoryOAuth2AuthorizationCodeStorage();
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2AuthorizationServer authorizationServer(OAuth2AuthorizationCodeStorage authorizationCodeStorage, OAuth2ClientStore clientStore, OAuth2ParServer parServer) {
            logger.info("Creating OAuth2AuthorizationServer bean (with PAR support)");
            return new DefaultOAuth2AuthorizationServer(authorizationCodeStorage, clientStore, parServer);
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2TokenServer tokenServer(OAuth2AuthorizationCodeStorage authorizationCodeStorage, TokenGenerator tokenGenerator) {
            logger.info("Creating OAuth2TokenServer bean");
            return new DefaultOAuth2TokenServer(authorizationCodeStorage, tokenGenerator);
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2DcrServer dcrServer(OAuth2DcrClientStore dcrClientStore) {
            logger.info("Creating OAuth2DcrServer bean");
            return new DefaultOAuth2DcrServer(dcrClientStore);
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2DcrClientStore dcrClientStore() {
            logger.info("Creating OAuth2DcrClientStore bean");
            return new InMemoryOAuth2DcrClientStore();
        }

        @Bean
        @ConditionalOnMissingBean
        public TokenGenerator tokenGenerator(AoatTokenGenerator aoatTokenGenerator, OAuth2ParServer parServer) {
            logger.info("Creating TokenGenerator bean");
            return new AoatTokenGeneratorAdapter(aoatTokenGenerator, parServer);
        }
    }

    /**
     * Configuration for OAuth2 client-related beans.
     * <p>
     * This configuration provides beans for OAuth2 client functionality,
     * including token clients and callback handling.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class OAuth2ClientConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientConfiguration.class);

        @Bean(name = "userAuthenticationTokenClient")
        @ConditionalOnMissingBean(name = "userAuthenticationTokenClient")
        public OAuth2TokenClient userAuthenticationTokenClient(
                OpenAgentAuthProperties openAgentAuthProperties,
                ServiceEndpointResolver serviceEndpointResolver) {
            logger.info("Creating userAuthenticationTokenClient bean for Authorization Server role");
            
            JwksConsumerProperties asUserIdpConfig = openAgentAuthProperties.getJwksConsumer(SERVICE_AS_USER_IDP);
            String asUserIdpUrl = asUserIdpConfig != null ? asUserIdpConfig.getIssuer() : null;
            
            logger.debug("AS User IDP config: {}, URL: {}", asUserIdpConfig, asUserIdpUrl);
            
            if (asUserIdpUrl == null || asUserIdpUrl.isBlank()) {
                logger.error("AS User IDP configuration not found in open-agent-auth.infrastructure.jwks.consumers.as-user-idp");
                logger.error("Available consumer keys: {}", asUserIdpConfig);
                throw new IllegalStateException(
                    "AS User IDP configuration not found. Please configure open-agent-auth.infrastructure.jwks.consumers.as-user-idp in application.yml"
                );
            }

            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String clientId = oauth2ClientProps.getClientId();
            String clientSecret = oauth2ClientProps.getClientSecret();
            
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalStateException(
                    "OAuth client ID is not configured. Please set 'open-agent-auth.capabilities.oauth2-client.client-id' in your configuration. " +
                    "This is a required configuration for OAuth 2.0 token exchange."
                );
            }
            
            logger.info("Creating userAuthenticationTokenClient bean with clientId: {}", clientId);
            return new DefaultOAuth2TokenClient(serviceEndpointResolver, SERVICE_AS_USER_IDP, clientId, clientSecret);
        }

        @Bean(name = "agentOperationAuthorizationTokenClient")
        @ConditionalOnMissingBean(name = "agentOperationAuthorizationTokenClient")
        public OAuth2TokenClient agentOperationAuthorizationTokenClient(
                OpenAgentAuthProperties openAgentAuthProperties,
                ServiceEndpointResolver serviceEndpointResolver) {
            logger.info("Creating agentOperationAuthorizationTokenClient bean for Authorization Server role");
            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String clientId = oauth2ClientProps.getClientId();
            String clientSecret = oauth2ClientProps.getClientSecret();
            
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalStateException(
                    "OAuth client ID is not configured. Please set 'open-agent-auth.capabilities.oauth2-client.client-id' in your configuration. " +
                    "This is a required configuration for OAuth 2.0 token exchange."
                );
            }
            
            logger.info("Creating agentOperationAuthorizationTokenClient bean with clientId: {}", clientId);
            return new DefaultOAuth2TokenClient(serviceEndpointResolver, SERVICE_AUTHORIZATION_SERVER, clientId, clientSecret);
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2CallbackService callbackService(
                FrameworkOAuth2TokenClient frameworkOAuth2TokenClient,
                SessionMappingBizService sessionMappingBizService,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            logger.info("Creating OAuth2CallbackService bean for Authorization Server role");
            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String callbackEndpoint = oauth2ClientProps.getCallback().getEndpoint();
            if (callbackEndpoint == null || callbackEndpoint.isBlank()) {
                callbackEndpoint = DEFAULT_CALLBACK_ENDPOINT;
            }
            return new OAuth2CallbackService(
                    frameworkOAuth2TokenClient,
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
    }

    /**
     * Configuration for cryptography-related beans.
     * <p>
     * This configuration provides beans for cryptographic operations,
     * including key generation, signing, and verification.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class CryptoConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(CryptoConfiguration.class);

        @Bean
        @ConditionalOnMissingBean
        public AoatGenerator aoatGenerator(
                KeyManager keyManager,
                OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating AoatGenerator bean");
            KeyDefinitionProperties aoatKeyDef = openAgentAuthProperties.getKeyDefinition(KEY_AOAT_SIGNING);
            String aoatKeyId = aoatKeyDef.getKeyId();
            String aoatAlgorithm = aoatKeyDef.getAlgorithm();
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
            
            String issuer = openAgentAuthProperties.getRoleIssuer(ROLE_AUTHORIZATION_SERVER);

            if (ValidationUtils.isNullOrEmpty(issuer)) {
                throw new IllegalStateException(
                    "Authorization Server issuer is not configured. Please set 'open-agent-auth.roles.authorization-server.issuer' in your configuration. " +
                    "This is a required configuration for AOAT generation."
                );
            }
            
            String audience = openAgentAuthProperties.getServiceUrl(SERVICE_RESOURCE_SERVER);
            
            return new AoatGenerator(
                    signingKey,
                    JWSAlgorithm.parse(aoatAlgorithm),
                    issuer,
                    audience
            );
        }

        @Bean
        @ConditionalOnMissingBean
        public List<JWK> signingKeys(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
            List<JWK> keys = new ArrayList<>();
            String aoatKeyId = openAgentAuthProperties.getKeyDefinition(KEY_AOAT_SIGNING).getKeyId();
            try {
                PublicKey publicKey = keyManager.getVerificationKey(aoatKeyId);
                if (publicKey != null) {
                    JWK jwk = AuthorizationServerAutoConfiguration.convertToJWK(publicKey, aoatKeyId);
                    keys.add(jwk);
                }
            } catch (Exception e) {
                logger.error("Failed to get public key for JWKS: {}", aoatKeyId, e);
            }
            return keys;
        }

        @Bean
        @ConditionalOnMissingBean
        @Lazy
        public VcVerifier vcVerifier(OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating VcVerifier bean");
            try {
                String agentBaseUrl = openAgentAuthProperties.getServiceUrl(SERVICE_AGENT);
                String agentJwksEndpoint = null;
                if (agentBaseUrl != null && !agentBaseUrl.isBlank()) {
                    agentJwksEndpoint = agentBaseUrl + JWKS_WELL_KNOWN_PATH;
                }
                
                JwksProvider jwksProvider;
                if (agentJwksEndpoint != null && !agentJwksEndpoint.isBlank()) {
                    logger.info("Using remote JWKS provider for VcVerifier: {}", agentJwksEndpoint);
                    jwksProvider = new RemoteJwksProvider(agentJwksEndpoint);
                } else {
                    logger.info("Using local JWKS provider for VcVerifier");
                    jwksProvider = new JwksProvider() {
                        @Override
                        public JWKSource<SecurityContext> getJwkSource() {
                            return (jwkSelector, context) -> new ArrayList<>();
                        }

                        @Override
                        public JWKSet getJwkSet() {
                            return new JWKSet();
                        }

                        @Override
                        public void refresh() {
                        }
                    };
                }
                return new DefaultVcVerifier(jwksProvider, new VcVerificationPolicy());
            } catch (Exception e) {
                logger.error("Failed to create VcVerifier: {}", e.getMessage(), e);
                throw new IllegalStateException("Failed to initialize VcVerifier", e);
            }
        }
    }

    /**
     * Configuration for authorization core-related beans.
     * <p>
     * This configuration provides beans for core authorization functionality,
     * including AOAT token generation, policy registry, and audit service.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class AuthorizationCoreConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(AuthorizationCoreConfiguration.class);

        @Bean
        @ConditionalOnMissingBean
        public AoatTokenGenerator aoatTokenGenerator(AoatGenerator aoatGenerator, VcVerifier vcVerifier, PolicyRegistry policyRegistry, BindingInstanceStore bindingInstanceStore, PromptDecryptionService promptDecryptionService, OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating AoatTokenGenerator bean");
            var tokenProps = openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken();
            long tokenExpiration = tokenProps.getAccessTokenExpiry();
            return new DefaultAoatTokenGenerator(aoatGenerator, vcVerifier, policyRegistry, bindingInstanceStore, promptDecryptionService, tokenExpiration);
        }

        @Bean
        @ConditionalOnMissingBean
        public PolicyRegistry policyRegistry() {
            logger.info("Creating PolicyRegistry bean");
            return new InMemoryPolicyRegistry();
        }

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
            String verificationKeyId = openAgentAuthProperties.getKeyDefinition(KEY_WIT_VERIFICATION).getKeyId();
            String trustDomain = openAgentAuthProperties.getTrustDomain();
            
            return new DefaultAuthorizationServer(
                    parServer,
                    dcrClientStore,
                    userAuthenticationTokenClient,
                    oauth2TokenServer,
                    keyManager,
                    verificationKeyId,
                    trustDomain
            );
        }
    }

    /**
     * Configuration for web-related beans.
     * <p>
     * This configuration provides beans for web layer functionality,
     * including interceptors and controllers.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    static class WebConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(WebConfiguration.class);

        @Bean
        @ConditionalOnMissingBean
        public UserAuthenticationInterceptor userAuthenticationInterceptor(
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            logger.info("Creating UserAuthenticationInterceptor bean with AsUserIdpUserAuthInterceptor");
            
            JwksConsumerProperties asUserIdpConfig = openAgentAuthProperties.getJwksConsumer(SERVICE_AS_USER_IDP);
            String asUserIdpIssuer = asUserIdpConfig != null ? asUserIdpConfig.getIssuer() : null;
            
            if (asUserIdpIssuer == null || asUserIdpIssuer.isBlank()) {
                throw new IllegalStateException(
                    "AS User IDP issuer configuration not found. Please configure open-agent-auth.infrastructure.jwks.consumers.as-user-idp in application.yml");
            }

            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String clientId = oauth2ClientProps.getClientId();
            String callbackUrl = openAgentAuthProperties.getRoleIssuer(ROLE_AUTHORIZATION_SERVER);
            
            List<String> excludedPaths = oauth2ClientProps.getAuthentication().getExcludePaths();
            logger.debug("Using excluded paths: {}", excludedPaths);
            
            return new AsUserIdpUserAuthInterceptor(
                    excludedPaths,
                    asUserIdpIssuer,
                    clientId,
                    callbackUrl + "/callback");
        }

        @Bean
        @ConditionalOnMissingBean
        public ConsentPageProvider consentPageProvider() {
            logger.info("Creating ConsentPageProvider bean with DefaultConsentPageProvider for Authorization Server");
            return new DefaultConsentPageProvider(CONSENT_TEMPLATE_AOA);
        }
    }
}
