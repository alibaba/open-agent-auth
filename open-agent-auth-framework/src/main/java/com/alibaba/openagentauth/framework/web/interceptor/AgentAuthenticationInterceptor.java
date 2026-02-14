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
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Agent authentication interceptor.
 * <p>
 * This interceptor checks if the user is authenticated before allowing access to protected resources.
 * If the user is not authenticated, it redirects to the Agent User IDP for login.
 * </p>
 * <p>
 * <b>Refactored:</b> Now delegates to {@link AgentUserIdpUserAuthInterceptor} for consistent
 * authentication logic across Authorization Server and Agent scenarios.
 * </p>
 * <p>
 * This is a framework-level interceptor that provides authentication capabilities
 * without depending on any specific web framework. Spring-specific implementations
 * should extend or wrap this class in the spring-boot-starter module by implementing
 * Spring's HandlerInterceptor interface.
 * </p>
 *
 * <h3>Authentication Flow:</h3>
 * <ol>
 *   <li>Interceptor checks session for authenticated user</li>
 *   <li>If not authenticated, delegates to AgentUserIdpUserAuthInterceptor</li>
 *   <li>Redirects user to Agent User IDP login page</li>
 *   <li>After login, callback endpoint exchanges code for ID Token</li>
 *   <li>ID Token is stored in session for subsequent requests</li>
 * </ol>
 *
 * @since 1.0
 */
public class AgentAuthenticationInterceptor {

    /**
     * The logger for the AgentAuthenticationInterceptor.
     */
    private static final Logger logger = LoggerFactory.getLogger(AgentAuthenticationInterceptor.class);

    /**
     * The framework-level AgentUserIdpUserAuthInterceptor.
     */
    private final AgentUserIdpUserAuthInterceptor delegate;

    /**
     * Constructs a new AgentAuthenticationInterceptor with external configuration.
     *
     * @param agentAapExecutor the Agent AAP executor
     * @param sessionMappingBizService the session mapping business service
     * @param excludedPaths the list of paths to exclude from authentication
     */
    public AgentAuthenticationInterceptor(
            AgentAapExecutor agentAapExecutor,
            SessionMappingBizService sessionMappingBizService,
            List<String> excludedPaths
    ) {
        this.delegate = new AgentUserIdpUserAuthInterceptor(
                sessionMappingBizService,
                excludedPaths,
                agentAapExecutor);
        logger.info("AgentAuthenticationInterceptor initialized with excluded paths: {}", excludedPaths);
    }

    /**
     * Pre-handle method for checking authentication.
     * <p>
     * This method delegates to {@link AgentUserIdpUserAuthInterceptor#preHandle(HttpServletRequest, HttpServletResponse)}.
     * </p>
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @return true if the request should proceed, false if it was handled (redirected)
     */
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response) {
        try {
            return delegate.preHandle(request, response);
        } catch (Exception e) {
            logger.error("Error during authentication check", e);
            throw new RuntimeException("Authentication check failed", e);
        }
    }
}