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
package com.alibaba.openagentauth.spring.autoconfigure.capability;

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
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.framework.web.interceptor.LocalUserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
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
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

/**
 * Shared Capability Auto-Configuration (Layer 1).
 * <p>
 * This configuration provides shared infrastructure beans that are common across
 * multiple roles and have no role-specific differences. By extracting these beans
 * into a shared configuration, we eliminate code duplication and enable role
 * co-existence scenarios.
 * </p>
 *
 * <h3>Shared Infrastructure Beans</h3>
 * <ul>
 *   <li>{@link SessionMappingStore} — In-memory session mapping storage</li>
 *   <li>{@link SessionMappingBizService} — Session mapping business service</li>
 * </ul>
 *
 * <h3>Shared OAuth2 Server Beans (oauth2-server capability)</h3>
 * <ul>
 *   <li>{@link IdTokenGenerator} — ID Token generator for OIDC flows</li>
 *   <li>{@link TokenGenerator} — Token generator adapter bridging IdTokenGenerator</li>
 *   <li>{@link OAuth2AuthorizationCodeStorage} — Authorization code storage</li>
 *   <li>{@link OAuth2ClientStore} — OAuth2 client registration store</li>
 *   <li>{@link OAuth2AuthorizationServer} — OAuth2 authorization server (without PAR)</li>
 *   <li>{@link OAuth2TokenServer} — OAuth2 token server</li>
 * </ul>
 *
 * <h3>Shared User Authentication Beans (user-authentication capability)</h3>
 * <ul>
 *   <li>{@link UserRegistry} — User authentication and profile management</li>
 *   <li>{@link AuthenticationProvider} — OIDC authentication provider</li>
 * </ul>
 *
 * <h3>Shared User IDP Beans</h3>
 * <ul>
 *   <li>{@link ConsentPageProvider} — Consent page rendering for OIDC authorization</li>
 *   <li>{@link UserAuthenticationInterceptor} — Local user authentication interceptor</li>
 * </ul>
 *
 * @since 1.0
 * @see CoreAutoConfiguration
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SharedCapabilityAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(SharedCapabilityAutoConfiguration.class);

    /** User IDP role names used for issuer resolution, in priority order. */
    private static final List<String> USER_IDP_ROLES = List.of(ROLE_AGENT_USER_IDP, ROLE_AS_USER_IDP);

    /**
     * Resolves the issuer from the first enabled User IDP role.
     * <p>
     * This method supports role co-existence by searching across all User IDP roles
     * (agent-user-idp, as-user-idp) and returning the first configured issuer.
     * </p>
     *
     * @param properties the global configuration properties
     * @return the resolved issuer, or null if no User IDP role has an issuer configured
     */
    static String resolveUserIdpIssuer(OpenAgentAuthProperties properties) {
        Map<String, RolesProperties.RoleProperties> roles = properties.getRoles();
        if (roles == null) {
            return null;
        }
        for (String roleName : USER_IDP_ROLES) {
            RolesProperties.RoleProperties role = roles.get(roleName);
            if (role != null && role.isEnabled() && !ValidationUtils.isNullOrEmpty(role.getIssuer())) {
                return role.getIssuer();
            }
        }
        return null;
    }

    /**
     * Returns a human-readable name for the first enabled User IDP role.
     *
     * @param properties the global configuration properties
     * @return the role display name
     */
    private static String resolveUserIdpRoleName(OpenAgentAuthProperties properties) {
        Map<String, RolesProperties.RoleProperties> roles = properties.getRoles();
        if (roles != null) {
            for (String roleName : USER_IDP_ROLES) {
                RolesProperties.RoleProperties role = roles.get(roleName);
                if (role != null && role.isEnabled()) {
                    return roleName;
                }
            }
        }
        return "user-idp";
    }

    // ==================== Shared Infrastructure Beans ====================

    /**
     * Creates the shared OAuth2AuthorizationRequestStorage bean.
     * <p>
     * This repository stores authorization request metadata (flow type, session ID)
     * keyed by opaque state values. It is shared between {@link UserAuthenticationInterceptor}
     * (which saves requests during login redirect) and {@code OAuth2CallbackService}
     * (which resolves requests during callback), ensuring both components operate
     * on the same state storage.
     * </p>
     *
     * @return the shared OAuth2AuthorizationRequestStorage bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationRequestStorage authorizationRequestStorage() {
        logger.info("Creating shared OAuth2AuthorizationRequestStorage bean");
        return new InMemoryOAuth2AuthorizationRequestStorage();
    }

    /**
     * Creates the SessionMappingStore bean if not already defined.
     *
     * @return the SessionMappingStore bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingStore sessionMappingStore() {
        logger.info("Creating shared SessionMappingStore bean");
        return new InMemorySessionMappingStore();
    }

    /**
     * Creates the SessionMappingBizService bean if not already defined.
     *
     * @param sessionMappingStore the session mapping store
     * @return the SessionMappingBizService bean
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMappingBizService sessionMappingBizService(SessionMappingStore sessionMappingStore) {
        logger.info("Creating shared SessionMappingBizService bean");
        return new SessionMappingBizService(sessionMappingStore);
    }

    // ==================== OAuth2 Server Capability Beans ====================

    /**
     * Shared OAuth2 Server configuration providing common infrastructure beans.
     * <p>
     * These beans are activated when the oauth2-server capability is enabled and provide
     * the OAuth2 storage and client infrastructure shared across all roles that use
     * OAuth2 server functionality (User IDPs and Authorization Server).
     * </p>
     * <p>
     * Note: Role-specific beans such as {@code IdTokenGenerator}, {@code TokenGenerator},
     * {@code OAuth2AuthorizationServer}, and {@code OAuth2TokenServer} are <b>not</b>
     * included here. They are defined in {@link UserIdpOAuth2ServerConfiguration} which
     * has an additional condition requiring at least one User IDP role to be enabled.
     * The Authorization Server role provides its own versions of these beans with
     * PAR support and AOAT token generation.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.oauth2-server", name = "enabled", havingValue = "true")
    public static class SharedOAuth2ServerConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(SharedOAuth2ServerConfiguration.class);

        /**
         * Creates the Authorization Code Storage bean if not already defined.
         *
         * @param openAgentAuthProperties the global configuration properties
         * @return the Authorization Code Storage bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2AuthorizationCodeStorage authorizationCodeStorage(OpenAgentAuthProperties openAgentAuthProperties) {
            int authorizationCodeExpiry = openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getAuthorizationCodeExpiry();
            logger.info("Creating shared OAuth2AuthorizationCodeStorage with expiry: {} seconds", authorizationCodeExpiry);
            return new InMemoryOAuth2AuthorizationCodeStorage(authorizationCodeExpiry);
        }

        /**
         * Creates the OAuth2 Client Store bean if not already defined.
         *
         * @return the OAuth2 Client Store bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2ClientStore clientStore() {
            logger.info("Creating shared OAuth2ClientStore");
            return new InMemoryOAuth2ClientStore();
        }
    }

    // ==================== User IDP OAuth2 Server Beans ====================

    /**
     * User IDP-specific OAuth2 server configuration.
     * <p>
     * These beans are only created when the oauth2-server capability is enabled <b>and</b>
     * at least one User IDP role ({@code agent-user-idp} or {@code as-user-idp}) is enabled.
     * This prevents these beans from being created in the Authorization Server scenario,
     * which provides its own versions with PAR support and AOAT token generation.
     * </p>
     * <p>
     * Beans provided:
     * <ul>
     *   <li>{@link IdTokenGenerator} — ID Token generator for OIDC flows</li>
     *   <li>{@link TokenGenerator} — Token generator adapter bridging IdTokenGenerator</li>
     *   <li>{@link OAuth2AuthorizationServer} — OAuth2 authorization server (without PAR)</li>
     *   <li>{@link OAuth2TokenServer} — OAuth2 token server</li>
     * </ul>
     * </p>
     *
     * @see UserIdpRoleEnabledCondition
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.oauth2-server", name = "enabled", havingValue = "true")
    @Conditional(UserIdpRoleEnabledCondition.class)
    public static class UserIdpOAuth2ServerConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(UserIdpOAuth2ServerConfiguration.class);

        /**
         * Creates the IdTokenGenerator bean if not already defined.
         * <p>
         * This generator creates ID Tokens for authenticated users using the signing key
         * from the key management infrastructure. The issuer is resolved from the first
         * enabled User IDP role.
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
            String issuer = resolveUserIdpIssuer(openAgentAuthProperties);
            if (ValidationUtils.isNullOrEmpty(issuer)) {
                throw new IllegalStateException(
                    "User IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-user-idp.issuer' " +
                    "or 'open-agent-auth.roles.as-user-idp.issuer' in your configuration. " +
                    "This is a required configuration for ID Token generation."
                );
            }

            var keyConfig = openAgentAuthProperties.getKeyDefinition(KEY_ID_TOKEN_SIGNING);
            if (keyConfig == null) {
                throw new IllegalStateException(
                    "ID token signing key '" + KEY_ID_TOKEN_SIGNING + "' is not configured. " +
                    "Please configure 'open-agent-auth.infrastructures.key-management.keys." + KEY_ID_TOKEN_SIGNING + "' in your configuration."
                );
            }

            String keyId = keyConfig.getKeyId();
            String algorithm = keyConfig.getAlgorithm();
            Object signingKey = keyManager.getOrGenerateKey(keyId, KeyAlgorithm.fromValue(algorithm));

            logger.info("Creating User IDP IdTokenGenerator with issuer: {}, algorithm: {}", issuer, algorithm);
            return new DefaultIdTokenGenerator(issuer, algorithm, signingKey);
        }

        /**
         * Creates the TokenGenerator bean if not already defined.
         * <p>
         * This generator bridges {@link IdTokenGenerator} to the {@link TokenGenerator} interface
         * using {@link IdTokenGeneratorAdapter}. The issuer is resolved from the first enabled
         * User IDP role.
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
            String issuer = resolveUserIdpIssuer(openAgentAuthProperties);
            if (ValidationUtils.isNullOrEmpty(issuer)) {
                throw new IllegalStateException(
                    "User IDP issuer is not configured. Please set 'open-agent-auth.roles.agent-user-idp.issuer' " +
                    "or 'open-agent-auth.roles.as-user-idp.issuer' in your configuration. " +
                    "This is a required configuration for Token generation."
                );
            }

            logger.info("Creating User IDP TokenGenerator (IdTokenGeneratorAdapter)");
            return new IdTokenGeneratorAdapter(
                    idTokenGenerator,
                    openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getIdTokenExpiry(),
                    issuer
            );
        }

        /**
         * Creates the Authorization Server bean if not already defined.
         * <p>
         * This creates an OAuth2 authorization server without PAR support,
         * which is the standard configuration for User IDP roles.
         * The Authorization Server role provides its own PAR-enabled version.
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
                OAuth2ClientStore clientStore) {
            logger.info("Creating User IDP OAuth2AuthorizationServer (without PAR)");
            return new DefaultOAuth2AuthorizationServer(authorizationCodeStorage, clientStore);
        }

        /**
         * Creates the Token Server bean if not already defined.
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
            logger.info("Creating User IDP OAuth2TokenServer");
            return new DefaultOAuth2TokenServer(authorizationCodeStorage, tokenGenerator);
        }
    }

    // ==================== User Authentication Capability Beans ====================

    /**
     * Shared User Authentication configuration for User IDP roles.
     * <p>
     * These beans are activated when the user-authentication capability is enabled
     * and provide user registry and authentication functionality shared by both
     * Agent User IDP and AS User IDP.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.user-authentication", name = "enabled", havingValue = "true")
    public static class SharedUserAuthenticationConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(SharedUserAuthenticationConfiguration.class);

        /**
         * Creates the UserRegistry bean if not already defined.
         *
         * @param openAgentAuthProperties the global configuration properties
         * @return the configured user registry
         */
        @Bean
        @ConditionalOnMissingBean
        public UserRegistry userRegistry(OpenAgentAuthProperties openAgentAuthProperties) {
            String roleName = resolveUserIdpRoleName(openAgentAuthProperties);
            var userAuthProps = openAgentAuthProperties.getCapabilities().getUserAuthentication();
            if (userAuthProps != null && userAuthProps.getUserRegistry() != null) {
                var userRegistryProps = userAuthProps.getUserRegistry();
                logger.info("Creating shared UserRegistry from capabilities.user-authentication.user-registry");
                return UserRegistryUtils.createUserRegistryFromCapabilities(userRegistryProps, roleName);
            }

            logger.warn("No user registry configuration found, creating empty UserRegistry");
            return new InMemoryUserRegistry();
        }

        /**
         * Creates the AuthenticationProvider bean if not already defined.
         *
         * @param idTokenGenerator the ID Token generator
         * @param userRegistry the user registry for authentication
         * @param openAgentAuthProperties the global configuration properties
         * @return the configured authentication provider
         */
        @Bean
        @ConditionalOnMissingBean
        public AuthenticationProvider authenticationProvider(
                IdTokenGenerator idTokenGenerator,
                UserRegistry userRegistry,
                OpenAgentAuthProperties openAgentAuthProperties) {
            long tokenLifetime = openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getIdTokenExpiry();
            logger.info("Creating shared AuthenticationProvider with tokenLifetime: {} seconds", tokenLifetime);
            return new DefaultAuthenticationProvider(idTokenGenerator, userRegistry, tokenLifetime);
        }
    }

    // ==================== User IDP Common Beans ====================

    /**
     * Shared User IDP configuration for consent page and authentication interceptor.
     * <p>
     * These beans are common to both Agent User IDP and AS User IDP roles and are
     * activated when the user-authentication capability is enabled.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "open-agent-auth.capabilities.user-authentication", name = "enabled", havingValue = "true")
    public static class SharedUserIdpConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(SharedUserIdpConfiguration.class);

        /**
         * Creates the ConsentPageProvider bean if not already defined.
         *
         * @param openAgentAuthProperties the global configuration properties
         * @return the Consent Page Provider bean
         */
        @Bean
        @ConditionalOnMissingBean
        public ConsentPageProvider consentPageProvider(OpenAgentAuthProperties openAgentAuthProperties) {
            String roleName = resolveUserIdpRoleName(openAgentAuthProperties);
            logger.info("Creating shared ConsentPageProvider for {}", roleName);
            return new DefaultConsentPageProvider(CONSENT_TEMPLATE_OIDC, roleName);
        }

        /**
         * Creates the UserAuthenticationInterceptor bean if not already defined.
         *
         * @param openAgentAuthProperties the global configuration properties
         * @return the UserAuthenticationInterceptor bean
         */
        @Bean
        @ConditionalOnMissingBean
        public UserAuthenticationInterceptor userAuthenticationInterceptor(
                OpenAgentAuthProperties openAgentAuthProperties,
                OAuth2AuthorizationRequestStorage authorizationRequestStorage) {
            String roleName = resolveUserIdpRoleName(openAgentAuthProperties);
            List<String> excludedPaths = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication().getExcludePaths();
            logger.info("Creating shared UserAuthenticationInterceptor (LocalUserAuthenticationInterceptor) for {}", roleName);
            logger.debug("Using excluded paths: {}", excludedPaths);
            return new LocalUserAuthenticationInterceptor(excludedPaths, authorizationRequestStorage);
        }
    }
}