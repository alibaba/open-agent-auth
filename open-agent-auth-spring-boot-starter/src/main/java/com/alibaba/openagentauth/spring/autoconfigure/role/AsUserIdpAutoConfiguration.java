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
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultAuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
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
 *   <li><code>idTokenGenerator</code>: ID Token generator for generating ID Tokens</li>
 *   <li><code>asUserIdpService</code>: AS User IDP service implementation</li>
 *   <li><code>authorizationServer</code>: OAuth 2.0 authorization server</li>
 *   <li><code>tokenServer</code>: OAuth 2.0 token server</li>
 *   <li><code>parServer</code>: OAuth 2.0 PAR server</li>
 *   <li><code>dcrServer</code>: OAuth 2.0 DCR server</li>
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
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.as-user-idp", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AsUserIdpAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(AsUserIdpAutoConfiguration.class);

    /**
     * Creates the IdTokenGenerator bean if not already defined.
     * <p>
     * This generator is responsible for generating ID Tokens for authenticated users.
     * </p>
     *
     * @param keyManager the key manager
     * @param openAgentAuthProperties the global configuration properties
     * @return the IdTokenGenerator bean
     * @throws IllegalStateException if issuer is not configured
     */
    @Bean
    @ConditionalOnMissingBean
    public IdTokenGenerator idTokenGenerator(
            KeyManager keyManager,
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
                "This is a required configuration for ID Token generation."
            );
        }

        logger.info("Creating IdTokenGenerator with issuer: {}", issuer);

        // Get signing key configuration
        String keyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get(KEY_ID_TOKEN_SIGNING).getKeyId();
        String algorithm = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get(KEY_ID_TOKEN_SIGNING).getAlgorithm();
        
        // Get or generate ID Token signing key
        Object signingJWK;
        try {
            signingJWK = keyManager.getSigningJWK(keyId);
        } catch (Exception e) {
            logger.warn("Failed to get ID token signing key, generating new key: {}", e.getMessage());
            keyManager.generateKeyPair(KeyAlgorithm.ES256, keyId);
            signingJWK = keyManager.getSigningJWK(keyId);
        }

        return new DefaultIdTokenGenerator(
                issuer,
                algorithm,
                signingJWK
        );
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
            return UserRegistryUtils.createUserRegistryFromCapabilities(userRegistryProps, "AS User IDP");
        }
        
        logger.warn("No user registry configuration found, creating empty UserRegistry");
        return new InMemoryUserRegistry();
    }

    /**
     * Creates the Authentication Provider bean if not already defined.
     * <p>
     * This provider provides user authentication for the OAuth 2.0 authorization flow.
     * The default implementation uses session-based authentication.
     * </p>
     *
     * @param idTokenGenerator the ID token generator
     * @param userRegistry the user registry for authentication
     * @param openAgentAuthProperties the global configuration properties
     * @return the Authentication Provider bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationProvider authenticationProvider(
            IdTokenGenerator idTokenGenerator,
            UserRegistry userRegistry,
            OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating AuthenticationProvider bean");
        
        return new DefaultAuthenticationProvider(
                idTokenGenerator,
                userRegistry,
                (long) openAgentAuthProperties.getCapabilities().getOAuth2Server().getToken().getIdTokenExpiry()
        );
    }

    /**
     * Creates the Token Generator bean if not already defined.
     * <p>
     * This generator provides token generation for access tokens.
     * It uses the ID Token Generator adapter for OAuth 2.0 tokens.
     * </p>
     *
     * @param idTokenGenerator the ID token generator
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
        logger.info("Creating TokenGenerator bean");
        
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
            TokenGenerator tokenGenerator) {
        logger.info("Creating OAuth2TokenServer bean");
        return new DefaultOAuth2TokenServer(authorizationCodeStorage, tokenGenerator);
    }

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
        logger.info("Creating OAuth2ParRequestStore bean");
        return new InMemoryOAuth2ParRequestStore();
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
     * Creates the DCR Server bean if not already defined.
     * <p>
     * This server provides OAuth 2.0 Dynamic Client Registration endpoint
     * for processing DCR requests.
     * </p>
     *
     * @param dcrClientStore the DCR client store
     * @return the DCR Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2DcrServer dcrServer(OAuth2DcrClientStore dcrClientStore) {
        logger.info("Creating OAuth2DcrServer bean for AS User IDP");
        // Note: WIMSE authenticator should be configured separately in production
        // For development/testing, we use an empty authenticator list
        return new DefaultOAuth2DcrServer(dcrClientStore);
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
        logger.info("Creating SessionMappingStore bean for AS User IDP");
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
        logger.info("Creating SessionMappingBizService bean for AS User IDP");
        return new SessionMappingBizService(sessionMappingStore);
    }

    /**
     * Creates the UserAuthenticationInterceptor bean if not already defined.
     * <p>
     * This bean provides local authentication for the AS User IDP role.
     * It redirects unauthenticated users to the local login page instead of
     * an external IDP, since AS User IDP itself is an IDP.
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
        logger.info("Creating UserAuthenticationInterceptor bean (LocalUserAuthenticationInterceptor) for AS User IDP");
        
        // Use excluded paths from oauth2-client.authentication.exclude-paths
        // This configuration already has default values, so users don't need to configure it explicitly
        List<String> excludedPaths = openAgentAuthProperties.getCapabilities().getOAuth2Client().getAuthentication().getExcludePaths();
        
        logger.debug("Using excluded paths: {}", excludedPaths);
        
        return new LocalUserAuthenticationInterceptor(sessionMappingBizService, excludedPaths);
    }

    /**
     * Creates the ConsentPageProvider bean if not already defined.
     * <p>
     * This provider provides consent page rendering for the OIDC authorization flow.
     * The default implementation uses a Thymeleaf template located at {@code oauth2/oidc_consent}.
     * </p>
     *
     * @return the Consent Page Provider bean
     */
    @Bean
    @ConditionalOnMissingBean
    public ConsentPageProvider consentPageProvider() {
        logger.info("Creating ConsentPageProvider bean with DefaultConsentPageProvider for AS User IDP");
        return new DefaultConsentPageProvider(CONSENT_TEMPLATE_OIDC, "AS User IDP");
    }

}