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

import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * User authentication interceptor for AS User IDP integration.
 * <p>
 * This interceptor extends {@link UserAuthenticationInterceptor} to provide
 * AS User IDP-specific authentication flow. It builds OAuth 2.0 authorization URLs
 * for the AS User IDP, which is used in Authorization Server scenarios.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Template Method Pattern (extends UserAuthenticationInterceptor)
 * </p>
 *
 * <h3>Usage Example (Interceptor Mode):</h3>
 * <pre>
 * // In Spring configuration
 * @Bean
 * public AsUserIdpUserAuthInterceptor asUserIdpInterceptor(
 *         SessionMappingBizService sessionMappingBizService,
 *         OpenAgentAuthProperties properties) {
 *     List<String> excludedPaths = List.of("/callback", "/public/**");
 *     String issuer = properties.getJwks().getConsumers().get("as-user-idp").getIssuer();
 *     String clientId = "your-client-id";
 *     String callbackUrl = "https://example.com/callback";
 *     return new AsUserIdpUserAuthInterceptor(
 *         sessionMappingBizService, excludedPaths, issuer, clientId, callbackUrl);
 * }
 * </pre>
 *
 * <h3>Usage Example (Provider Mode):</h3>
 * <pre>
 * // In UserAuthenticationProvider implementation
 * @Component
 * public class AsUserIdpUserAuthenticationProvider implements UserAuthenticationProvider {
 *     private final AsUserIdpUserAuthInterceptor interceptor;
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
public class AsUserIdpUserAuthInterceptor extends UserAuthenticationInterceptor {

    /**
     * The logger for the AS User IDP user authentication interceptor.
     */
    private static final Logger logger = LoggerFactory.getLogger(AsUserIdpUserAuthInterceptor.class);

    /**
     * Secure random generator for generating state parameter.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * The AS User IDP issuer URL.
     */
    private final String issuer;

    /**
     * The OAuth 2.0 client ID.
     */
    private final String clientId;

    /**
     * The callback URL for OAuth 2.0 flow.
     */
    private final String callbackUrl;

    /**
     * Constructs a new AsUserIdpUserAuthInterceptor with a default repository.
     *
     * @param excludedPaths the list of paths to exclude from authentication
     * @param issuer the AS User IDP issuer URL
     * @param clientId the OAuth 2.0 client ID
     * @param callbackUrl the callback URL for OAuth 2.0 flow
     */
    public AsUserIdpUserAuthInterceptor(
            List<String> excludedPaths,
            String issuer,
            String clientId,
            String callbackUrl
    ) {
        super(excludedPaths);
        this.issuer = issuer;
        this.clientId = clientId;
        this.callbackUrl = callbackUrl;
        logger.info("AsUserIdpUserAuthInterceptor initialized with issuer: {}, clientId: {}", issuer, clientId);
    }

    /**
     * Constructs a new AsUserIdpUserAuthInterceptor with a shared repository.
     *
     * @param excludedPaths the list of paths to exclude from authentication
     * @param authorizationRequestStorage the shared repository for storing authorization requests
     * @param issuer the AS User IDP issuer URL
     * @param clientId the OAuth 2.0 client ID
     * @param callbackUrl the callback URL for OAuth 2.0 flow
     */
    public AsUserIdpUserAuthInterceptor(
            List<String> excludedPaths,
            OAuth2AuthorizationRequestStorage authorizationRequestStorage,
            String issuer,
            String clientId,
            String callbackUrl
    ) {
        super(excludedPaths, authorizationRequestStorage);
        this.issuer = issuer;
        this.clientId = clientId;
        this.callbackUrl = callbackUrl;
        logger.info("AsUserIdpUserAuthInterceptor initialized with shared repository, issuer: {}, clientId: {}", issuer, clientId);
    }

    /**
     * Builds the authorization URL for AS User IDP.
     * <p>
     * This method constructs the OAuth 2.0 authorization URL with the following parameters:
     * </p>
     * <ul>
     *   <li>response_type=code</li>
     *   <li>client_id</li>
     *   <li>redirect_uri</li>
     *   <li>scope=openid profile email</li>
     *   <li>state</li>
     * </ul>
     *
     * @param request the HTTP request
     * @param state the state parameter for CSRF protection
     * @return the authorization URL
     */
    @Override
    protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
        String baseUrl = issuer + "/oauth2/authorize";
        String url = UrlBuilder.buildUrlWithParams(
            baseUrl,
            "response_type", "code",
            "client_id", clientId,
            "redirect_uri", callbackUrl,
            "scope", "openid profile email",
            "state", state
        );
        
        logger.debug("Built authorization URL for AS User IDP: {}", url);
        return url;
    }

    /**
     * Generates a secure random state parameter for CSRF protection.
     * <p>
     * This method uses Base64 URL encoding with 32 bytes of random data,
     * providing 256 bits of entropy for strong CSRF protection.
     * </p>
     *
     * @return the state parameter
     */
    @Override
    protected String generateState() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}