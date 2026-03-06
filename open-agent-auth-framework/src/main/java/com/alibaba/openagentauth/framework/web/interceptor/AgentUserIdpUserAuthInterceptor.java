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
package com.alibaba.openagentauth.framework.web.interceptor;

import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * User authentication interceptor for Agent User IDP integration.
 * <p>
 * This interceptor extends {@link UserAuthenticationInterceptor} to provide
 * Agent User IDP-specific authentication flow. It uses {@link AgentAapExecutor}
 * to initiate the OIDC authorization flow with the Agent User IDP.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Template Method Pattern (extends UserAuthenticationInterceptor)
 * </p>
 *
 * <h3>Usage Example (Interceptor Mode):</h3>
 * <pre>
 * // In Spring configuration
 * @Bean
 * public AgentUserIdpUserAuthInterceptor agentUserIdpInterceptor(
 *         SessionMappingBizService sessionMappingBizService,
 *         AgentAapExecutor agentAapExecutor) {
 *     List<String> excludedPaths = List.of("/callback", "/public/**");
 *     return new AgentUserIdpUserAuthInterceptor(
 *         sessionMappingBizService, excludedPaths, agentAapExecutor);
 * }
 * </pre>
 *
 * <h3>Usage Example (Provider Mode):</h3>
 * <pre>
 * // In UserAuthenticationProvider implementation
 * @Component
 * public class AgentUserIdpUserAuthenticationProvider implements UserAuthenticationProvider {
 *     private final AgentUserIdpUserAuthInterceptor interceptor;
 *
 *     @Override
 *     public String getLoginUrl(HttpServletRequest request) {
 *         return interceptor.getLoginUrl(request);
 *     }
 *
 *     @Override
 *     public String authenticate(HttpServletRequest request) {
 *         return interceptor.authenticate(request);
 *     }
 * }
 * </pre>
 *
 * @since 1.0
 */
public class AgentUserIdpUserAuthInterceptor extends UserAuthenticationInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(AgentUserIdpUserAuthInterceptor.class);

    private final AgentAapExecutor agentAapExecutor;

    /**
     * Constructs a new AgentUserIdpUserAuthInterceptor with a default repository.
     *
     * @param excludedPaths the list of paths to exclude from authentication
     * @param agentAapExecutor the Agent AAP executor
     */
    public AgentUserIdpUserAuthInterceptor(
            List<String> excludedPaths,
            AgentAapExecutor agentAapExecutor
    ) {
        super(excludedPaths);
        this.agentAapExecutor = agentAapExecutor;
        logger.info("AgentUserIdpUserAuthInterceptor initialized");
    }

    /**
     * Constructs a new AgentUserIdpUserAuthInterceptor with a shared repository.
     *
     * @param excludedPaths the list of paths to exclude from authentication
     * @param agentAapExecutor the Agent AAP executor
     * @param authorizationRequestStorage the shared repository for storing authorization requests
     */
    public AgentUserIdpUserAuthInterceptor(
            List<String> excludedPaths,
            AgentAapExecutor agentAapExecutor,
            OAuth2AuthorizationRequestStorage authorizationRequestStorage
    ) {
        super(excludedPaths, authorizationRequestStorage);
        this.agentAapExecutor = agentAapExecutor;
        logger.info("AgentUserIdpUserAuthInterceptor initialized with shared repository");
    }

    /**
     * Builds the authorization URL for Agent User IDP.
     * <p>
     * This method uses {@link AgentAapExecutor#initiateUserAuthentication(InitiateAuthorizationRequest)}
     * to generate the authorization URL. The executor handles the complete OIDC
     * authorization code flow initialization.
     * </p>
     *
     * @param request the HTTP request
     * @param state the state parameter for CSRF protection
     * @return the authorization URL
     */
    @Override
    protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
        String redirectUri = buildRedirectUri(request);
        
        InitiateAuthorizationRequest authRequest = InitiateAuthorizationRequest.builder()
                .redirectUri(redirectUri)
                .state(state)
                .build();

        String authorizationUrl = agentAapExecutor.initiateUserAuthentication(authRequest);
        
        logger.debug("Built authorization URL for Agent User IDP: {}", authorizationUrl);
        return authorizationUrl;
    }

    /**
     * Builds the redirect URI for OAuth callback.
     *
     * @param request the HTTP request
     * @return the redirect URI
     */
    private String buildRedirectUri(HttpServletRequest request) {
        return UrlBuilder.buildUrl(request, "/callback");
    }
}