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

import com.alibaba.openagentauth.framework.web.callback.OAuth2AuthorizationRequestRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Local user authentication interceptor for IDP roles.
 * <p>
 * This interceptor provides a simple local authentication flow that redirects
 * to the local login page instead of an external IDP. It is designed for
 * IDP roles (agent-user-idp, as-user-idp) that provide their own login page.
 * </p>
 *
 * @since 1.0
 */
public class LocalUserAuthenticationInterceptor extends UserAuthenticationInterceptor {

    /**
     * The logger for the local user authentication interceptor.
     */
    private static final Logger logger = LoggerFactory.getLogger(LocalUserAuthenticationInterceptor.class);

    /**
     * Constructs a new LocalUserAuthenticationInterceptor with a default repository.
     *
     * @param excludedPaths the list of paths to exclude from authentication
     */
    public LocalUserAuthenticationInterceptor(List<String> excludedPaths) {
        super(excludedPaths);
        logger.info("LocalUserAuthenticationInterceptor initialized");
    }

    /**
     * Constructs a new LocalUserAuthenticationInterceptor with a shared repository.
     *
     * @param excludedPaths the list of paths to exclude from authentication
     * @param authorizationRequestRepository the shared repository for storing authorization requests
     */
    public LocalUserAuthenticationInterceptor(
            List<String> excludedPaths,
            OAuth2AuthorizationRequestRepository authorizationRequestRepository) {
        super(excludedPaths, authorizationRequestRepository);
        logger.info("LocalUserAuthenticationInterceptor initialized with shared repository");
    }

    /**
     * Builds the authorization URL for local login.
     * <p>
     * This method returns the local login page URL with redirect_uri parameter.
     * The redirect_uri contains the authorization endpoint URL that the user
     * should be redirected to after successful login.
     * </p>
     *
     * @param request the HTTP request
     * @param state the state parameter for CSRF protection
     * @return the local login URL
     */
    @Override
    protected String buildAuthorizationUrl(HttpServletRequest request, String state) {

        // Build redirect_uri: the authorization endpoint that should be accessed after login
        String redirectUri = UrlBuilder.buildCurrentRequestUrl(request);
        
        // Build login URL with redirect_uri parameter
        String baseUrl = UrlBuilder.buildBaseUrl(request);
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        String loginUrl = baseUrl + "/login?redirect_uri=" + encodedRedirectUri;

        logger.debug("Built local login URL: {}", loginUrl);
        return loginUrl;
    }
}
