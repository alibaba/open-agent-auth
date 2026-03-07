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
package com.alibaba.openagentauth.spring.autoconfigure;

import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.BasicAuthAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.DefaultOAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.framework.web.interceptor.AsUserIdpUserAuthInterceptor;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.spring.autoconfigure.properties.AdminProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.role.AgentAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.role.AgentIdpAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.role.AgentUserIdpAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.role.AsUserIdpAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.role.AuthorizationServerAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.role.ResourceServerAutoConfiguration;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.interceptor.AdminAccessInterceptor;
import com.alibaba.openagentauth.spring.web.interceptor.SpringUserAuthenticationInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Auto-configuration for the Admin Console.
 * <p>
 * This configuration is only activated when the admin console is explicitly enabled
 * via {@code open-agent-auth.admin.enabled=true}. It registers the
 * {@link AdminAccessInterceptor} to enforce access control on all admin endpoints.
 * </p>
 * <p>
 * <b>Design Rationale:</b>
 * </p>
 * <ul>
 *   <li><b>Opt-in by default:</b> The admin console is disabled by default to follow
 *       the principle of least privilege. Operators must explicitly enable it.</li>
 *   <li><b>Centralized access control:</b> A single interceptor handles access control
 *       for all admin endpoints, avoiding scattered security logic across controllers.</li>
 *   <li><b>Session-based authorization:</b> Integrates with the framework's existing
 *       session-based authentication, checking the authenticated user's subject against
 *       a configurable allowlist.</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   admin:
 *     enabled: true
 *     access-control:
 *       enabled: true
 *       allowed-session-subjects:
 *         - admin
 *         - operator
 * </pre>
 *
 * @since 1.0
 * @see AdminProperties
 * @see AdminAccessInterceptor
 */
@AutoConfiguration(
        after = {
                AgentAutoConfiguration.class,
                AgentIdpAutoConfiguration.class,
                AgentUserIdpAutoConfiguration.class,
                AsUserIdpAutoConfiguration.class,
                AuthorizationServerAutoConfiguration.class,
                ResourceServerAutoConfiguration.class
        },
        before = SpringWebAutoConfiguration.class
)
@EnableConfigurationProperties(OpenAgentAuthProperties.class)
@ConditionalOnProperty(prefix = "open-agent-auth.admin", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AdminAutoConfiguration implements WebMvcConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(AdminAutoConfiguration.class);

    /** User IDP service names to search for when creating a fallback interceptor. */
    private static final String[] USER_IDP_SERVICE_NAMES = {
            ConfigConstants.SERVICE_AGENT_USER_IDP,
            ConfigConstants.SERVICE_AS_USER_IDP
    };

    private final OpenAgentAuthProperties properties;
    private final AdminProperties adminProperties;
    private final ObjectProvider<UserAuthenticationInterceptor> userAuthInterceptorProvider;
    private final ObjectProvider<OAuth2AuthorizationRequestStorage> authorizationRequestStorageProvider;

    /**
     * Creates a new AdminAutoConfiguration.
     *
     * @param properties the root configuration properties
     * @param userAuthInterceptorProvider optional user authentication interceptor from any role
     * @param authorizationRequestStorageProvider optional shared authorization request storage
     */
    public AdminAutoConfiguration(OpenAgentAuthProperties properties,
                                  ObjectProvider<UserAuthenticationInterceptor> userAuthInterceptorProvider,
                                  ObjectProvider<OAuth2AuthorizationRequestStorage> authorizationRequestStorageProvider) {
        this.properties = properties;
        this.adminProperties = properties.getAdmin();
        this.userAuthInterceptorProvider = userAuthInterceptorProvider;
        this.authorizationRequestStorageProvider = authorizationRequestStorageProvider;
        logger.info("Admin console enabled with access-control={}", adminProperties.getAccessControl().isEnabled());
    }

    /**
     * Creates the admin access control interceptor bean.
     *
     * @return the admin access interceptor
     */
    @Bean
    public AdminAccessInterceptor adminAccessInterceptor() {
        return new AdminAccessInterceptor(adminProperties.getAccessControl());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        AdminProperties.EndpointProperties endpoints = adminProperties.getEndpoints();
        String[] adminPaths = {
                endpoints.getDashboard(),
                endpoints.getWorkloads(),
                endpoints.getBindings(),
                endpoints.getPolicies(),
                endpoints.getAudit()
        };

        // Register user authentication interceptor first (order matters: authenticate before authorize)
        UserAuthenticationInterceptor userAuthInterceptor = resolveUserAuthInterceptor();
        if (userAuthInterceptor != null) {
            SpringUserAuthenticationInterceptor springAdapter =
                    new SpringUserAuthenticationInterceptor(userAuthInterceptor);
            registry.addInterceptor(springAdapter).addPathPatterns(adminPaths);
            logger.info("User authentication interceptor registered for admin paths");
        } else {
            logger.warn("No UserAuthenticationInterceptor available and no User IDP peer configured; "
                    + "admin pages will not require user login");
        }

        // Register admin access control interceptor (runs after authentication)
        registry.addInterceptor(adminAccessInterceptor()).addPathPatterns(adminPaths);

        logger.info("Admin access control interceptor registered for paths: {}, {}, {}, {}, {}",
                endpoints.getDashboard(), endpoints.getWorkloads(), endpoints.getBindings(),
                endpoints.getPolicies(), endpoints.getAudit());
    }

    /**
     * Resolves the user authentication interceptor for admin pages.
     * <p>
     * Resolution order:
     * <ol>
     *   <li>Use the existing {@link UserAuthenticationInterceptor} bean if available
     *       (created by role-specific configurations like SharedCapabilityAutoConfiguration
     *       or AuthorizationServerAutoConfiguration)</li>
     *   <li>If no bean exists, attempt to create a fallback {@link AsUserIdpUserAuthInterceptor}
     *       by discovering a User IDP peer service (agent-user-idp or as-user-idp) from
     *       the JWKS consumer configuration. This enables roles without user-authentication
     *       capability (e.g., agent-idp) to delegate admin login to an external User IDP.</li>
     * </ol>
     * </p>
     *
     * @return the resolved interceptor, or null if no authentication is available
     */
    private UserAuthenticationInterceptor resolveUserAuthInterceptor() {
        UserAuthenticationInterceptor existingBean = userAuthInterceptorProvider.getIfAvailable();
        if (existingBean != null) {
            logger.debug("Using existing UserAuthenticationInterceptor bean for admin authentication");
            return existingBean;
        }

        return createFallbackUserAuthInterceptor();
    }

    /**
     * Creates a fallback user authentication interceptor by discovering a User IDP
     * from the JWKS consumer configuration.
     * <p>
     * This method searches for configured User IDP services (agent-user-idp, as-user-idp)
     * in the JWKS consumers and uses the OAuth2 client configuration to build an
     * {@link AsUserIdpUserAuthInterceptor} that redirects unauthenticated admin users
     * to the external User IDP for OAuth2 login.
     * </p>
     *
     * @return the fallback interceptor, or null if no User IDP is configured
     */
    private UserAuthenticationInterceptor createFallbackUserAuthInterceptor() {
        for (String serviceName : USER_IDP_SERVICE_NAMES) {
            JwksConsumerProperties consumerConfig = properties.getJwksConsumer(serviceName);
            if (consumerConfig == null) {
                continue;
            }

            String userIdpIssuer = consumerConfig.getIssuer();
            if (userIdpIssuer == null || userIdpIssuer.isBlank()) {
                continue;
            }

            var oauth2ClientProps = properties.getCapabilities().getOAuth2Client();
            String clientId = oauth2ClientProps.getClientId();
            if (clientId == null || clientId.isBlank()) {
                logger.warn("Found User IDP peer '{}' (issuer: {}) but no OAuth2 client-id configured; "
                        + "cannot create fallback admin authentication interceptor. "
                        + "Configure 'open-agent-auth.capabilities.oauth2-client.client-id' to enable admin login.",
                        serviceName, userIdpIssuer);
                continue;
            }

            // Determine the callback URL from the current service's role issuer
            String callbackUrl = resolveCallbackUrl();
            if (callbackUrl == null) {
                logger.warn("Cannot determine callback URL for admin authentication; "
                        + "no role issuer configured");
                continue;
            }

            List<String> excludedPaths = oauth2ClientProps.getAuthentication().getExcludePaths();

            logger.info("Creating fallback admin authentication interceptor using User IDP '{}' (issuer: {})",
                    serviceName, userIdpIssuer);

            // Use the shared repository if available (created by AdminOAuth2CallbackConfiguration),
            // otherwise fall back to a default instance. This ensures the interceptor and
            // OAuth2CallbackService share the same repository for state validation.
            OAuth2AuthorizationRequestStorage storage = authorizationRequestStorageProvider.getIfAvailable(
                            InMemoryOAuth2AuthorizationRequestStorage::new);

            return new AsUserIdpUserAuthInterceptor(
                    excludedPaths,
                    storage,
                    userIdpIssuer,
                    clientId,
                    callbackUrl + ConfigConstants.DEFAULT_CALLBACK_ENDPOINT);
        }

        return null;
    }

    /**
     * Resolves the callback URL from the first enabled role's issuer.
     *
     * @return the callback base URL, or null if no role issuer is configured
     */
    private String resolveCallbackUrl() {
        var roles = properties.getRoles();
        if (roles == null) {
            return null;
        }
        for (var entry : roles.entrySet()) {
            if (entry.getValue().isEnabled() && entry.getValue().getIssuer() != null) {
                return entry.getValue().getIssuer();
            }
        }
        return null;
    }

    // ==================== OAuth2 Callback Fallback Configuration ====================

    /**
     * Provides fallback OAuth2 callback beans for roles that do not have their own
     * {@link OAuth2CallbackService} (e.g., agent-idp).
     * <p>
     * When the admin console delegates user authentication to an external User IDP via
     * {@link AsUserIdpUserAuthInterceptor}, the User IDP redirects back to the current
     * service's {@code /callback} endpoint after login. This configuration ensures that
     * the callback endpoint exists and can process the authorization code exchange.
     * </p>
     * <p>
     * <b>Design Rationale:</b> Roles like Agent and Authorization Server already provide
     * their own {@code OAuth2CallbackService} and {@code OAuth2CallbackController} beans.
     * This fallback configuration only activates when those beans are missing.
     * </p>
     * <p>
     * <b>Important:</b> The {@code @ConditionalOnMissingBean(OAuth2CallbackService.class)}
     * guard on this inner class prevents all fallback beans from being created when a
     * role-specific configuration (e.g., AuthorizationServerAutoConfiguration) already
     * provides an {@code OAuth2CallbackService}. This avoids subtle conflicts where
     * fallback beans (e.g., {@code AdminFrameworkOAuth2TokenClientAdapter}) could shadow
     * role-specific beans due to type hierarchy differences in {@code @ConditionalOnMissingBean}
     * checks.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(OAuth2CallbackService.class)
    static class AdminOAuth2CallbackConfiguration {

        private static final Logger logger = LoggerFactory.getLogger(AdminOAuth2CallbackConfiguration.class);

        /**
         * Creates a shared {@link OAuth2AuthorizationRequestStorage} bean.
         * <p>
         * This repository is shared between the fallback {@link AsUserIdpUserAuthInterceptor}
         * (which stores authorization requests during login redirect) and the fallback
         * {@link OAuth2CallbackService} (which resolves them during callback processing).
         * </p>
         *
         * @return the shared authorization request storage
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2AuthorizationRequestStorage authorizationRequestStorage() {
            logger.info("Creating shared OAuth2AuthorizationRequestStorage for admin OAuth2 flow");
            return new InMemoryOAuth2AuthorizationRequestStorage();
        }

        @Bean
        @ConditionalOnMissingBean
        public ServiceEndpointResolver serviceEndpointResolver(OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating fallback ServiceEndpointResolver for admin OAuth2 callback");

            ServiceProperties serviceProperties = new ServiceProperties();
            Map<String, ServiceProperties.ConsumerServiceProperties> consumers = new HashMap<>();
            openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices()
                    .forEach((name, service) -> {
                        ServiceProperties.ConsumerServiceProperties consumer =
                                new ServiceProperties.ConsumerServiceProperties();
                        consumer.setBaseUrl(service.getBaseUrl());
                        consumer.setEndpoints(service.getEndpoints());
                        consumers.put(name, consumer);
                    });
            serviceProperties.setConsumers(consumers);

            return new DefaultServiceEndpointResolver(serviceProperties);
        }

        @Bean
        @ConditionalOnMissingBean
        public FrameworkOAuth2TokenClient frameworkOAuth2TokenClient(
                ServiceEndpointResolver serviceEndpointResolver,
                OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating fallback FrameworkOAuth2TokenClient for admin OAuth2 callback");

            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String clientId = oauth2ClientProps.getClientId();
            String clientSecret = oauth2ClientProps.getClientSecret();

            // Determine which User IDP service to use for token exchange
            String serviceName = resolveUserIdpServiceName(openAgentAuthProperties);

            var authentication = new BasicAuthAuthentication(clientId, clientSecret);
            OAuth2TokenClient coreTokenClient = new DefaultOAuth2TokenClient(
                    serviceEndpointResolver, serviceName, authentication);

            return new AdminFrameworkOAuth2TokenClientAdapter(coreTokenClient);
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2CallbackService callbackService(
                FrameworkOAuth2TokenClient frameworkOAuth2TokenClient,
                SessionMappingBizService sessionMappingBizService,
                OAuth2AuthorizationRequestStorage authorizationRequestStorage,
                OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating fallback OAuth2CallbackService for admin OAuth2 callback");
            var oauth2ClientProps = openAgentAuthProperties.getCapabilities().getOAuth2Client();
            String callbackEndpoint = oauth2ClientProps.getCallback().getEndpoint();
            if (callbackEndpoint == null || callbackEndpoint.isBlank()) {
                callbackEndpoint = ConfigConstants.DEFAULT_CALLBACK_ENDPOINT;
            }
            return new OAuth2CallbackService(
                    frameworkOAuth2TokenClient,
                    null,
                    sessionMappingBizService,
                    authorizationRequestStorage,
                    callbackEndpoint);
        }

        /**
         * Creates the fallback OAuth2CallbackController bean.
         * <p>
         * This controller handles the {@code /callback} endpoint for roles that do not
         * provide their own controller (e.g., agent-idp). Without this bean, the callback
         * endpoint would not exist, resulting in a 404 after User IDP login redirect.
         * </p>
         *
         * @param callbackService        the OAuth2 callback service
         * @param openAgentAuthProperties the global configuration properties
         * @return the OAuth2CallbackController bean
         */
        @Bean
        @ConditionalOnMissingBean
        public OAuth2CallbackController oauth2CallbackController(
                OAuth2CallbackService callbackService,
                OpenAgentAuthProperties openAgentAuthProperties) {
            logger.info("Creating fallback OAuth2CallbackController for admin OAuth2 callback");
            return new OAuth2CallbackController(callbackService, openAgentAuthProperties);
        }

        /**
         * Resolves the User IDP service name from JWKS consumer configuration.
         *
         * @param properties the configuration properties
         * @return the service name (e.g., "agent-user-idp" or "as-user-idp")
         * @throws IllegalStateException if no User IDP is configured
         */
        private static String resolveUserIdpServiceName(OpenAgentAuthProperties properties) {
            for (String serviceName : USER_IDP_SERVICE_NAMES) {
                JwksConsumerProperties consumerConfig = properties.getJwksConsumer(serviceName);
                if (consumerConfig != null && consumerConfig.getIssuer() != null
                        && !consumerConfig.getIssuer().isBlank()) {
                    return serviceName;
                }
            }
            throw new IllegalStateException(
                    "No User IDP peer configured for admin OAuth2 callback. "
                    + "Please configure 'open-agent-auth.peers.agent-user-idp' or "
                    + "'open-agent-auth.peers.as-user-idp' in your application.yml.");
        }
    }

    /**
     * Adapter that bridges the core-layer {@link OAuth2TokenClient} to the
     * framework-layer {@link FrameworkOAuth2TokenClient} interface.
     * <p>
     * This adapter is used exclusively by the admin fallback configuration to enable
     * OAuth2 callback processing in roles that do not have a full Agent or
     * AuthorizationServer actor (which normally implement {@code FrameworkOAuth2TokenClient}).
     * </p>
     */
    private static class AdminFrameworkOAuth2TokenClientAdapter implements FrameworkOAuth2TokenClient {

        private final OAuth2TokenClient coreTokenClient;

        AdminFrameworkOAuth2TokenClientAdapter(OAuth2TokenClient coreTokenClient) {
            this.coreTokenClient = coreTokenClient;
        }

        @Override
        public AuthenticationResponse exchangeCodeForToken(ExchangeCodeForTokenRequest request) {
            TokenRequest coreRequest = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code(request.getCode())
                    .redirectUri(request.getRedirectUri())
                    .clientId(request.getClientId())
                    .build();

            TokenResponse coreResponse = coreTokenClient.exchangeCodeForToken(coreRequest);

            String idToken = coreResponse.getIdToken() != null
                    ? coreResponse.getIdToken()
                    : coreResponse.getAccessToken();

            long expiresIn = coreResponse.getExpiresIn() != null
                    ? coreResponse.getExpiresIn()
                    : 3600L;

            return AuthenticationResponse.builder()
                    .success(true)
                    .idToken(idToken)
                    .tokenType(coreResponse.getTokenType())
                    .expiresIn(expiresIn)
                    .build();
        }
    }
}
