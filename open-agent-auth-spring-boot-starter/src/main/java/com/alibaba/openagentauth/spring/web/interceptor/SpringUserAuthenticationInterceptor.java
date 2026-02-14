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

import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Spring adapter for {@link UserAuthenticationInterceptor}.
 * <p>
 * This class adapts the framework-level {@link UserAuthenticationInterceptor} to Spring's
 * {@link HandlerInterceptor} interface, allowing it to be used in Spring MVC applications.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Adapter Pattern
 * </p>
 *
 * <h3>Usage Example:</h3>
 * <pre>
 * // In Spring configuration
 * &#64;Bean
 * public SpringUserAuthenticationInterceptor springUserAuthInterceptor(
 *         UserAuthenticationInterceptor userAuthInterceptor) {
 *     return new SpringUserAuthenticationInterceptor(userAuthInterceptor);
 * }
 *
 * // Register as Spring HandlerInterceptor
 * &#64;Override
 * public void addInterceptors(InterceptorRegistry registry) {
 *     registry.addInterceptor(springUserAuthInterceptor)
 *             .addPathPatterns("/**")
 *             .excludePathPatterns("/login", "/callback", "/public/**");
 * }
 * </pre>
 *
 * @since 1.0
 */
public class SpringUserAuthenticationInterceptor implements HandlerInterceptor {

    private final UserAuthenticationInterceptor delegate;

    /**
     * Constructs a new SpringUserAuthenticationInterceptor.
     *
     * @param delegate the framework-level user authentication interceptor
     */
    public SpringUserAuthenticationInterceptor(UserAuthenticationInterceptor delegate) {
        this.delegate = delegate;
    }

    /**
     * Pre-handle method for checking authentication.
     * <p>
     * This method delegates to {@link UserAuthenticationInterceptor#preHandle(HttpServletRequest, HttpServletResponse)}.
     * </p>
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param handler the handler (unused)
     * @return true if the request should proceed, false if it was handled (redirected)
     * @throws Exception if an error occurs
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        return delegate.preHandle(request, response);
    }
}
