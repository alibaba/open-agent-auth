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
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.InMemoryOAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.token.oidc.IdTokenGeneratorAdapter;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.DefaultOAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultAuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.InMemoryUserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.UserIdentityProvider;
import com.alibaba.openagentauth.framework.orchestration.DefaultUserIdentityProvider;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.util.UserRegistryUtils;
import com.alibaba.openagentauth.framework.web.interceptor.LocalUserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

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
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent-user-idp", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AgentUserIdpAutoConfiguration {

    /**
     * Infrastructure Configuration - manages session mapping and storage beans.
     */
    @Configuration(proxyBeanMethods = false)
    public static class InfrastructureConfiguration {

        /**
         * The logger for the infrastructure configuration.
         */
        private static final Logger logger = LoggerFactory.getLogger(InfrastructureConfiguration.class);

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
    }

    /**
     * OAuth2 Server Configuration - manages OAuth 2.0 authorization server beans.
     */
    @Configuration(proxyBeanMethods = false)
    public static class OAuth2ServerConfiguration {

        /**
         * The logger for the OAuth2 server configuration.
         */
        private static final Logger logger = LoggerFactory.getLogger(OAuth2ServerConfiguration.class);

        /**
         * Creates the Authorization Code Storage bean if not already defined.
         * <p>
         * This storage provides storage for authorization codes.
         * The default implementation uses in-memory storage with expiration
         * configured via {@code open-agent-auth.capabilities.oauth2-server.token.authorization-code-expiry}.
         * </p>
         *
         * @param openAgentAuthProperties the global configuration properties
         * @return the Authorization Code Storage bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2AuthorizationCodeStorage authorizationCodeStorage(OpenAgentAuthProperties openAgentAuthProperties) {
            int authorizationCodeExpiry = openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getAuthorizationCodeExpiry();
            logger.info("Creating OAuth2AuthorizationCodeStorage bean for Agent User IDP with expiry: {} seconds", authorizationCodeExpiry);
            return new InMemoryOAuth2AuthorizationCodeStorage(authorizationCodeExpiry);
        }

        /**
         * Creates the OAuth2 Client Store bean if not already defined.
         * <p>
         * This store provides storage for OAuth 2.0 client registrations.
         * The default implementation uses in-memory storage.
         * This bean is kept as an independent bean because Store classes hold state
         * and should be managed by the Spring container for proper lifecycle management.
         * </p>
         *
         * @return the OAuth2 Client Store bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2ClientStore clientStore() {
            logger.info("Creating OAuth2ClientStore bean for Agent User IDP");
            return new InMemoryOAuth2ClientStore();
        }

        /**
         * Creates the Authorization Server bean if not already defined.
         * <p>
         * This server provides OAuth 2.0 authorization endpoint for processing authorization requests
         * in the Agent User IDP role. PAR is not required for IDP roles, so only the client store
         * and authorization code storage are injected.
         * </p>
         *
         * @param authorizationCodeStorage the authorization code storage
         * @param clientStore the client store for validating OAuth 2.0 clients
         * @return the Authorization Server bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2AuthorizationServer authorizationServer(
                OAuth2AuthorizationCodeStorage authorizationCodeStorage,
                OAuth2ClientStore clientStore
        ) {
            logger.info("Creating OAuth2AuthorizationServer bean for Agent User IDP (without PAR)");
            return new DefaultOAuth2AuthorizationServer(authorizationCodeStorage, clientStore);
        }

        /**
         * Creates the Token Generator bean if not already defined.
         * <p>
         * This generator provides token generation for ID Tokens (OIDC).
         * It uses the IdTokenGeneratorAdapter to bridge IdTokenGenerator and TokenGenerator.
         * The token expiration is configured via
         * {@code open-agent-auth.capabilities.oauth2-server.token.id-token-expiry}.
         * </p>
         *
         * @param idTokenGenerator the ID Token generator
         * @param openAgentAuthProperties the global configuration properties
         * @return the Token Generator bean
         * @throws IllegalStateException if issuer is not configured
         */
        @Bean
        @ConditionalOnMissingBean
        public TokenGenerator tokenGenerator(
                IdTokenGenerator idTokenGenerator,
                OpenAgentAuthProperties openAgentAuthProperties
        ) {
            logger.info("Creating TokenGenerator bean (IdTokenGeneratorAdapter) for Agent User IDP");

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
                    "This is a required configuration for ID Token generation."
                );
            }

            return new IdTokenGeneratorAdapter(
                    idTokenGenerator,
                    openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getIdTokenExpiry(),
                    issuer
            );
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
    }

    /**
     * OIDC Configuration - manages OpenID Connect related beans.
     */
    @Configuration(proxyBeanMethods = false)
    public static class OidcConfiguration {

        /**
         * The logger for the OIDC configuration.
         */
        private static final Logger logger = LoggerFactory.getLogger(OidcConfiguration.class);

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
         * It directly constructs a {@link DefaultIdTokenGenerator} using the signing key
         * from the key management infrastructure.
         * </p>
         *
         * @param keyManager the key manager for retrieving signing keys
         * @param openAgentAuthProperties the global configuration properties
         * @return the ID Token generator
         * @throws IllegalStateException if issuer or key configuration is missing
         */
        @Bean
        @ConditionalOnMissingBean
        public IdTokenGenerator idTokenGenerator(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {

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
                    "This is a required configuration for ID Token generation."
                );
            }

            // Get signing key from key management infrastructure
            var keyConfig = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get(KEY_ID_TOKEN_SIGNING);
            if (keyConfig == null) {
                throw new IllegalStateException(
                    "ID token signing key '" + KEY_ID_TOKEN_SIGNING + "' is not configured. " +
                    "Please configure 'open-agent-auth.infrastructures.key-management.keys." + KEY_ID_TOKEN_SIGNING + "' in your configuration."
                );
            }

            String keyId = keyConfig.getKeyId();
            String algorithm = keyConfig.getAlgorithm();
            Object signingKey = keyManager.getOrGenerateKey(keyId, KeyAlgorithm.fromValue(algorithm));

            logger.info("Creating IdTokenGenerator with issuer: {}, algorithm: {}", issuer, algorithm);

            return new DefaultIdTokenGenerator(issuer, algorithm, signingKey);
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
    }

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
            return new DefaultConsentPageProvider(CONSENT_TEMPLATE_OIDC, "Agent User IDP");
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
}