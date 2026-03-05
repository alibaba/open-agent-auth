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

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.SessionCookieProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.server.Cookie;
import org.springframework.boot.web.servlet.server.AbstractServletWebServerFactory;
import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;

import java.util.Locale;
import java.util.Map;

/**
 * Auto-configuration for security-related settings.
 * <p>
 * This configuration provides secure defaults for session cookies, including
 * {@code HttpOnly}, {@code Secure}, and {@code SameSite} attributes. These settings
 * are essential for protecting session cookies against XSS, CSRF, and session hijacking
 * attacks in OAuth 2.0 authorization flows.
 * </p>
 * <p>
 * <b>Configuration:</b></p>
 * <pre>
 * open-agent-auth:
 *   security:
 *     session-cookie:
 *       http-only: true
 *       secure: false
 *       same-site: Lax
 * </pre>
 * <p>
 * <b>Note on SameSite and OAuth Flows:</b></p>
 * <p>
 * The default {@code SameSite=Lax} setting allows session cookies to be sent during
 * top-level navigations (e.g., OAuth authorization redirects) while still providing
 * CSRF protection. If your deployment involves cross-origin redirects where session
 * cookies are lost, consider using the session mapping mechanism provided by
 * {@code SessionMappingBizService} instead of changing to {@code SameSite=None}.
 * </p>
 *
 * @since 1.0
 * @see SessionCookieProperties
 */
@AutoConfiguration
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAutoConfiguration.class);

    /**
     * Configures the SameSite attribute for session cookies.
     * <p>
     * Spring Boot uses {@link CookieSameSiteSupplier} to apply the SameSite attribute
     * to all session cookies. This is the recommended approach as it works with
     * the embedded servlet container's cookie handling.
     * </p>
     *
     * @param properties the global configuration properties
     * @return a supplier that provides the SameSite attribute for cookies
     */
    @Bean
    public CookieSameSiteSupplier sessionCookieSameSiteSupplier(OpenAgentAuthProperties properties) {
        SessionCookieProperties cookieProperties = properties.getSecurity().getSessionCookie();
        String sameSiteValue = cookieProperties.getSameSite();

        logger.info("Configuring session cookie: SameSite={}, HttpOnly={}, Secure={}",
                sameSiteValue, cookieProperties.isHttpOnly(), cookieProperties.isSecure());

        return CookieSameSiteSupplier.of(Cookie.SameSite.valueOf(sameSiteValue.toUpperCase())
        );
    }

    /**
     * Customizes the session cookie name to prevent cookie collisions.
     * <p>
     * When multiple services run on the same domain (e.g., {@code localhost} with different ports),
     * they share the same cookie namespace. Using the default {@code JSESSIONID} for all services
     * causes one service's session cookie to overwrite another's, leading to session loss during
     * OAuth 2.0 redirect flows.
     * </p>
     * <p>
     * The cookie name is resolved in the following order:
     * </p>
     * <ol>
     *   <li><b>Explicit configuration:</b> {@code open-agent-auth.security.session-cookie.name}</li>
     *   <li><b>Auto-derived from role:</b> First enabled role name converted to uppercase with
     *       underscores and {@code _SESSION} suffix (e.g., {@code authorization-server} →
     *       {@code AUTHORIZATION_SERVER_SESSION})</li>
     *   <li><b>Servlet container default:</b> {@code JSESSIONID} (when no roles are enabled)</li>
     * </ol>
     *
     * @param properties the global configuration properties
     * @return a web server factory customizer that sets the session cookie name
     */
    @Bean
    public WebServerFactoryCustomizer<AbstractServletWebServerFactory> sessionCookieNameCustomizer(
            OpenAgentAuthProperties properties) {
        return factory -> {
            String cookieName = resolveSessionCookieName(properties);
            if (cookieName != null && !cookieName.isBlank()) {
                factory.getSession().getCookie().setName(cookieName);
                logger.info("Configured session cookie name: {}", cookieName);
            }
        };
    }

    /**
     * Resolves the session cookie name from explicit configuration or auto-derives it from the
     * first enabled role.
     *
     * @param properties the global configuration properties
     * @return the resolved cookie name, or {@code null} to use the servlet container default
     */
    private String resolveSessionCookieName(OpenAgentAuthProperties properties) {
        SessionCookieProperties cookieProperties = properties.getSecurity().getSessionCookie();
        String explicitName = cookieProperties.getName();
        if (explicitName != null && !explicitName.isBlank()) {
            logger.debug("Using explicitly configured session cookie name: {}", explicitName);
            return explicitName;
        }

        String derivedName = deriveSessionCookieNameFromRole(properties);
        if (derivedName != null) {
            logger.info("Auto-derived session cookie name from role: {}", derivedName);
            return derivedName;
        }

        return null;
    }

    /**
     * Derives a unique session cookie name from the first enabled role.
     * <p>
     * Converts the role name from kebab-case to UPPER_SNAKE_CASE and appends {@code _SESSION}.
     * For example: {@code authorization-server} → {@code AUTHORIZATION_SERVER_SESSION}.
     * </p>
     *
     * @param properties the global configuration properties
     * @return the derived cookie name, or {@code null} if no roles are enabled
     */
    private String deriveSessionCookieNameFromRole(OpenAgentAuthProperties properties) {
        Map<String, RolesProperties.RoleProperties> roles = properties.getRoles();
        if (roles == null || roles.isEmpty()) {
            return null;
        }

        for (Map.Entry<String, RolesProperties.RoleProperties> entry : roles.entrySet()) {
            if (entry.getValue() != null && entry.getValue().isEnabled()) {
                String roleName = entry.getKey();
                String upperSnakeCase = roleName.replace('-', '_').toUpperCase(Locale.ROOT);
                return upperSnakeCase + "_SESSION";
            }
        }

        return null;
    }
}
