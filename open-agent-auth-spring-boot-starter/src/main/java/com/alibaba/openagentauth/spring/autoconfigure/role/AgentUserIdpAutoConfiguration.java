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
import com.alibaba.openagentauth.core.protocol.oauth2.token.oidc.IdTokenGeneratorAdapter;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.DefaultOAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.factory.OidcFactory;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultAuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.registry.InMemoryUserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.UserIdentityProvider;
import com.alibaba.openagentauth.framework.orchestration.DefaultUserIdentityProvider;
import com.alibaba.openagentauth.framework.web.interceptor.LocalUserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.util.UserRegistryUtils;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.List;

/**
 * Auto-configuration for Agent User IDP role.
 * <p>
 * This configuration provides automatic setup for the Agent User Identity Provider role,
 * which is responsible for authenticating users for AI Agents and issuing ID Tokens.
 * </p>
 * <p>
 * <b>Role Identification:</b></p>
 * <p>
 * Enable this configuration by setting:
 * </p>
 * <pre>
 * open-agent-auth:
 *   roles:
 *     agent-user-idp:
 *       enabled: true
 * </pre>
 * <p>
 * This role is typically used in scenarios where:
 * </p>
 * <ul>
 *   <li>Your application provides user identity authentication for AI Agents</li>
 *   <li>You need to issue ID Tokens that can be verified by Agent IDPs</li>
 *   <li>You want to provide user authentication as a service for AI Agent platforms</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   enabled: true
 *   roles:
 *     agent-user-idp:
 *       enabled: true
 *       issuer: https://agent-user-idp.example.com
 *       capabilities:
 *         - oauth2-server
 *         - user-authentication
 *       keys:
 *         id-token:
 *           key-id: agent-user-id-token-signing-key
 *           algorithm: ES256
 * </pre>
 * <p>
 * <b>Dependency Management:</b></p>
 * <p>
 * This configuration depends on beans provided by {@link CoreAutoConfiguration}:
 * </p>
 * <ul>
 *   <li>{@code KeyManager} - For cryptographic key management</li>
 *   <li>{@code TrustDomain} - For trust domain configuration</li>
 *   <li>{@code UserRegistry} - For user authentication and profile management</li>
 * </ul>
 * <p>
 * <b>Role-Specific Beans:</b></p>
 * <ul>
 *   <li><code>sessionMappingStore</code>: Storage for session mappings</li>
 *   <li><code>sessionMappingBizService</code>: Service for managing session mappings</li>
 *   <li><code>idTokenGenerator</code>: ID Token generator for authenticated users</li>
 *   <li><code>tokenGenerator</code>: Token generator adapter for OAuth 2.0 token endpoint</li>
 *   <li><code>parRequestStore</code>: Storage for PAR requests</li>
 *   <li><code>parServer</code>: PAR endpoint server</li>
 * </ul>
 *
 * @since 1.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent-user-idp", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AgentUserIdpAutoConfiguration {

    /**
     * The logger for the Agent User IDP auto-configuration.
     */
    private static final Logger logger = LoggerFactory.getLogger(AgentUserIdpAutoConfiguration.class);

    /**
     * Creates the SessionMappingStore bean if not already defined.
     * <p>
     * This bean provides storage for session mappings across OAuth flows.
     * It allows sessions to be restored after OAuth callbacks when SameSite=Lax
     * causes session cookies to be lost during cross-domain redirects.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the SessionMappingStore bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingStore sessionMappingStore() {
        logger.info("Creating SessionMappingStore bean for Agent User IDP");
        return new InMemorySessionMappingStore();
    }

    /**
     * Creates the SessionMappingBizService bean if not already defined.
     * <p>
     * This bean manages session mappings across OAuth flows. It is required
     * by OAuth2AuthorizationController for managing sessions that need to be
     * restored after OAuth callbacks when SameSite=Lax causes session cookies
     * to be lost during cross-domain redirects.
     * </p>
     *
     * @param sessionMappingStore the session mapping store
     * @return the SessionMappingBizService bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingBizService sessionMappingBizService(SessionMappingStore sessionMappingStore) {
        logger.info("Creating SessionMappingBizService bean for Agent User IDP");
        return new SessionMappingBizService(sessionMappingStore);
    }
    /**
     * Creates the OidcFactory bean if not already defined.
     * <p>
     * This factory provides a centralized way to create OIDC components
     * with consistent configuration. It uses the configuration from
     * OpenAgentAuthProperties to set up the factory.
     * </p>
     *
     * @param keyManager the key manager for retrieving signing keys
     * @param openAgentAuthProperties the global configuration properties
     * @return the configured OIDC factory
     */
    @Bean
    @ConditionalOnMissingBean
    public OidcFactory oidcFactory(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
        
        // Get issuer from roles configuration
        String issuer = null;
        logger.debug("OpenAgentAuthProperties: {}", openAgentAuthProperties);
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("agent-user-idp");
            logger.debug("Agent User IDP role: {}", role);
            if (role != null) {
                issuer = role.getIssuer();
                logger.debug("Issuer from role: {}", issuer);
            }
        }
        
        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException(
                "Agent User IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-user-idp.issuer' in your configuration. " +
                "This is a required configuration for OIDC factory."
            );
        }

        logger.info("Creating OidcFactory with issuer: {}", issuer);

        // Get signing key configuration from infrastructure
        var keyDefinitions = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys();
        if (keyDefinitions == null || keyDefinitions.isEmpty()) {
            throw new IllegalStateException(
                "No key definitions found in open-agent-auth.infrastructures.key-management.keys configuration. " +
                "Please configure at least one key for ID token signing."
            );
        }
        
        // Get the first key definition for ID token signing
        // In production, you might want to specify which key to use via configuration
        var keyDefinition = keyDefinitions.values().iterator().next();
        String keyId = keyDefinition.getKeyId();
        String algorithm = keyDefinition.getAlgorithm();
        
        if (ValidationUtils.isNullOrEmpty(keyId) || ValidationUtils.isNullOrEmpty(algorithm)) {
            throw new IllegalStateException(
                "Key definition is missing required fields (keyId or algorithm). " +
                "Please ensure your key definition includes both keyId and algorithm."
            );
        }
        
        // Get signing JWK from KeyManager - ensure key exists first
        Object signingKey = keyManager.getOrGenerateKey(keyId, KeyAlgorithm.fromValue(algorithm));
        
        return OidcFactory.builder()
                .issuer(issuer)
                .algorithm(algorithm)
                .signingKey(signingKey)
                .verificationKey(signingKey)
                .build();
    }

    /**
     * Creates the UserRegistry bean if not already defined.
     * <p>
     * This bean provides user authentication and profile management.
     * The default implementation uses in-memory storage configured with demo users.
     * Users can override this bean to use custom implementations.
     * </p>
     *
     * @param openAgentAuthProperties the global configuration properties
     * @return the configured user registry
     */
    @Bean
    @ConditionalOnMissingBean
    public UserRegistry userRegistry(OpenAgentAuthProperties openAgentAuthProperties) {
        var userAuthProps = openAgentAuthProperties.getCapabilities().getUserAuthentication();
        if (userAuthProps != null && userAuthProps.getUserRegistry() != null) {
            var userRegistryProps = userAuthProps.getUserRegistry();
            logger.info("Creating UserRegistry from capabilities.user-authentication.user-registry");
            return UserRegistryUtils.createUserRegistryFromCapabilities(userRegistryProps, "Agent User IDP");
        }
        
        logger.warn("No user registry configuration found, creating empty UserRegistry");
        return new InMemoryUserRegistry();
    }

    /**
     * Creates the IdTokenGenerator bean if not already defined.
     * <p>
     * This generator is responsible for generating ID Tokens for authenticated users.
     * Now uses the OidcFactory for consistent configuration.
     * </p>
     *
     * @param oidcFactory the OIDC factory
     * @param openAgentAuthProperties the global configuration properties
     * @throws IllegalStateException if issuer is not configured
     */
    @Bean
    @ConditionalOnMissingBean
    public IdTokenGenerator idTokenGenerator(OidcFactory oidcFactory, OpenAgentAuthProperties openAgentAuthProperties) {

        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("agent-user-idp");
            if (role != null) {
                issuer = role.getIssuer();
            }
        }
        
        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException(
                "Agent User IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-user-idp.issuer' in your configuration. " +
                "This is a required configuration for ID Token generation."
            );
        }

        logger.info("Creating IdTokenGenerator with issuer: {}", issuer);

        // Use the OidcFactory to create the ID Token generator
        return oidcFactory.createIdTokenGenerator();
    }

    /**
     * Creates the AuthenticationProvider bean if not already defined.
     * <p>
     * This bean provides user authentication functionality. It uses the framework-provided
     * IdTokenGenerator and UserRegistry beans to create the authentication provider.
     * Unlike OidcFactory.createAuthenticationProvider(), this method uses the configured
     * UserRegistry bean instead of creating a new InMemoryUserRegistry, allowing user
     * configuration from YAML to take effect.
     * </p>
     *
     * @param idTokenGenerator the ID Token generator provided by the framework
     * @param userRegistry the user registry provided by the framework
     * @param openAgentAuthProperties the global configuration properties
     * @return the configured authentication provider
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationProvider authenticationProvider(
            IdTokenGenerator idTokenGenerator,
            UserRegistry userRegistry,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        // Get token lifetime from OAuth2ServerProperties
        long tokenLifetime = openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getIdTokenExpiry();
        
        logger.info("Creating AuthenticationProvider with tokenLifetime: {} seconds", tokenLifetime);

        // Create authentication provider using framework-provided beans
        return new DefaultAuthenticationProvider(
                idTokenGenerator,
                userRegistry,
                tokenLifetime
        );
    }

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
            var role = openAgentAuthProperties.getRoles().get("agent-user-idp");
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

    /**
     * Creates the PAR Request Store bean if not already defined.
     * <p>
     * This store provides storage for PAR requests.
     * The default implementation uses in-memory storage.
     * </p>
     *
     * @return the PAR Request Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2ParRequestStore parRequestStore() {
        logger.info("Creating OAuth2ParRequestStore bean for Agent User IDP");
        return new InMemoryOAuth2ParRequestStore();
    }

    /**
     * Creates the PAR Server bean if not already defined.
     * <p>
     * This server provides PAR endpoint for processing PAR requests.
     * The validator is created as a local variable to reduce global Bean count.
     * </p>
     *
     * @param parRequestStore the PAR request store
     * @return the PAR Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2ParServer parServer(OAuth2ParRequestStore parRequestStore) {
        logger.info("Creating OAuth2ParServer bean for Agent User IDP");
        OAuth2ParRequestValidator validator = new DefaultOAuth2ParRequestValidator();
        return new DefaultOAuth2ParServer(parRequestStore, validator);
    }

    /**
     * Creates the Authorization Code Storage bean if not already defined.
     * <p>
     * This storage provides storage for authorization codes.
     * The default implementation uses in-memory storage with 600 seconds expiration.
     * This bean is kept as an independent bean because Store classes hold state
     * and should be managed by the Spring container for proper lifecycle management.
     * </p>
     *
     * @return the Authorization Code Storage bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationCodeStorage authorizationCodeStorage() {
        logger.info("Creating OAuth2AuthorizationCodeStorage bean for Agent User IDP");
        return new InMemoryOAuth2AuthorizationCodeStorage(600);
    }

    /**
     * Creates the DCR Client Store bean if not already defined.
     * <p>
     * This store provides storage for DCR client registrations.
     * The default implementation uses in-memory storage.
     * This bean is kept as an independent bean because Store classes hold state
     * and should be managed by the Spring container for proper lifecycle management.
     * </p>
     *
     * @return the DCR Client Store bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2DcrClientStore dcrClientStore() {
        logger.info("Creating OAuth2DcrClientStore bean for Agent User IDP");
        return new InMemoryOAuth2DcrClientStore();
    }

    /**
     * Creates the DCR Server bean if not already defined.
     * <p>
     * This server provides DCR endpoint for processing client registration requests.
     * </p>
     *
     * @param dcrClientStore the DCR client store
     * @return the DCR Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2DcrServer dcrServer(OAuth2DcrClientStore dcrClientStore) {
        logger.info("Creating OAuth2DcrServer bean for Agent User IDP");
        return new DefaultOAuth2DcrServer(dcrClientStore);
    }

    /**
     * Creates the Authorization Server bean if not already defined.
     * <p>
     * This server provides OAuth 2.0 authorization endpoint for processing authorization requests
     * in the Agent User IDP role.
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
        logger.info("Creating OAuth2AuthorizationServer bean for Agent User IDP");
        return new DefaultOAuth2AuthorizationServer(authorizationCodeStorage, parServer, dcrClientStore);
    }

    /**
     * Creates the Consent Page Provider bean if not already defined.
     * <p>
     * This provider provides rendering and handling of the user consent page
     * for the OIDC authorization flow. The default implementation uses
     * a Thymeleaf template located at {@code oauth2/oidc_consent}.
     * </p>
     *
     * @return the Consent Page Provider bean
     */
    @Bean
    @ConditionalOnMissingBean
    public ConsentPageProvider consentPageProvider() {
        logger.info("Creating ConsentPageProvider bean with DefaultConsentPageProvider for Agent User IDP");
        return new DefaultConsentPageProvider("oauth2/oidc_consent", "Agent User IDP");
    }

    /**
     * Creates the Token Generator bean if not already defined.
     * <p>
     * This generator provides token generation for ID Tokens (OIDC).
     * It uses the IdTokenGeneratorAdapter to bridge IdTokenGenerator and TokenGenerator.
     * </p>
     *
     * @param idTokenGenerator the ID Token generator
     * @param openAgentAuthProperties the global configuration properties
     * @return the Token Generator bean
     * @throws IllegalStateException if issuer is not configured
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenGenerator tokenGenerator(IdTokenGenerator idTokenGenerator, OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating TokenGenerator bean (IdTokenGeneratorAdapter) for Agent User IDP");
        // Get issuer from roles configuration
        String issuer = null;
        if (openAgentAuthProperties.getRoles() != null) {
            var role = openAgentAuthProperties.getRoles().get("agent-user-idp");
            if (role != null) {
                issuer = role.getIssuer();
            }
        }
        
        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException(
                "Agent User IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-user-idp.issuer' in your configuration. " +
                "This is a required configuration for ID Token generation."
            );
        }
        
        return new IdTokenGeneratorAdapter(idTokenGenerator, issuer);
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
            TokenGenerator tokenGenerator
    ) {
        logger.info("Creating OAuth2TokenServer bean for Agent User IDP");
        return new DefaultOAuth2TokenServer(authorizationCodeStorage, tokenGenerator);
    }

    /**
     * Creates the UserAuthenticationInterceptor bean if not already defined.
     * <p>
     * This bean provides local authentication for the Agent User IDP role.
     * It redirects unauthenticated users to the local login page instead of
     * an external IDP, since Agent User IDP itself is an IDP.
     * </p>
     *
     * @param sessionMappingBizService the session mapping business service
     * @param openAgentAuthProperties the global configuration properties
     * @return the UserAuthenticationInterceptor bean
     */
    @Bean
    @ConditionalOnMissingBean
    public UserAuthenticationInterceptor userAuthenticationInterceptor(
            SessionMappingBizService sessionMappingBizService,
            OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating UserAuthenticationInterceptor bean (LocalUserAuthenticationInterceptor) for Agent User IDP");
        
        // Use excluded paths from oauth2-client.authentication.exclude-paths
        // This configuration already has default values, so users don't need to configure it explicitly
        List<String> excludedPaths = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication().getExcludePaths();
        
        logger.debug("Using excluded paths: {}", excludedPaths);
        
        return new LocalUserAuthenticationInterceptor(sessionMappingBizService, excludedPaths);
    }

}