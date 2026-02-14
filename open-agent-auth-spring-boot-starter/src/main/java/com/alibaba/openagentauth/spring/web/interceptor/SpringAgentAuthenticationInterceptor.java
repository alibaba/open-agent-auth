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
package com.alibaba.openagentauth.spring.web.interceptor;

import com.alibaba.openagentauth.framework.web.interceptor.AgentAuthenticationInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;

/**
 * Spring adapter for AgentAuthenticationInterceptor.
 * <p>
 * This class acts as a bridge between the framework-level AgentAuthenticationInterceptor
 * and Spring's HandlerInterceptor interface. It delegates all interceptor logic to the
 * framework implementation while providing the Spring-specific integration.
 * </p>
 * <p>
 * This adapter is registered in the Spring MVC configuration via AgentAutoConfiguration
 * and handles authentication checks for protected endpoints.
 * </p>
 *
 * @see AgentAuthenticationInterceptor
 * @since 1.0
 */
public class SpringAgentAuthenticationInterceptor implements HandlerInterceptor {

    /**
     * The logger for the Spring adapter.
     */
    private static final Logger logger = LoggerFactory.getLogger(SpringAgentAuthenticationInterceptor.class);

    /**
     * The framework-level AgentAuthenticationInterceptor.
     */
    private final AgentAuthenticationInterceptor delegate;

    /**
     * Creates a new Spring adapter for the given framework interceptor.
     *
     * @param delegate the framework-level AgentAuthenticationInterceptor
     */
    public SpringAgentAuthenticationInterceptor(AgentAuthenticationInterceptor delegate) {
        this.delegate = delegate;
        logger.info("SpringAgentAuthenticationInterceptor initialized with delegate");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        logger.debug("Delegating preHandle to AgentAuthenticationInterceptor");
        // Handler parameter is not used in the framework implementation
        return delegate.preHandle(request, response);
    }
}
