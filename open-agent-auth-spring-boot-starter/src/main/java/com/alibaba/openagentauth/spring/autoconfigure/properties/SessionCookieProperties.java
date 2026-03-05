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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

/**
 * Session cookie configuration properties.
 * <p>
 * Controls the security attributes of the HTTP session cookie. These settings
 * are critical for preventing session hijacking, CSRF attacks, and ensuring
 * proper behavior during cross-domain OAuth 2.0 authorization flows.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   security:
 *     session-cookie:
 *       http-only: true
 *       secure: false
 *       same-site: Lax
 * </pre>
 * <p>
 * <b>SameSite Policy Guidance:</b></p>
 * <ul>
 *   <li><b>Lax</b> (default): Cookies are sent with top-level navigations and GET requests
 *       from third-party sites. This is the recommended setting for most OAuth 2.0 flows
 *       as it allows session cookies to be sent during authorization redirects while still
 *       providing CSRF protection.</li>
 *   <li><b>Strict</b>: Cookies are only sent in first-party context. This may cause session
 *       loss during OAuth redirects from external authorization servers.</li>
 *   <li><b>None</b>: Cookies are sent with all requests (requires {@code secure=true}).
 *       Use only when cross-origin cookie access is explicitly required.</li>
 * </ul>
 *
 * @since 1.0
 */
public class SessionCookieProperties {

    /**
     * Custom name for the session cookie.
     * <p>
     * When multiple services run on the same domain (e.g., {@code localhost} with different ports),
     * they share the same cookie namespace. Using the default {@code JSESSIONID} for all services
     * causes session cookie collisions — one service's session cookie overwrites another's.
     * </p>
     * <p>
     * Setting a unique cookie name per service (e.g., {@code AS_SESSION}, {@code IDP_SESSION})
     * prevents this collision. This is the standard approach used by Spring Security, Keycloak,
     * and other OAuth2/OIDC implementations.
     * </p>
     * <p>
     * When {@code null} (default), the servlet container's default name ({@code JSESSIONID}) is used.
     * </p>
     */
    private String name;

    /**
     * Whether the session cookie should be marked as HttpOnly.
     * <p>
     * When {@code true}, the cookie is not accessible via JavaScript's {@code document.cookie},
     * which helps mitigate cross-site scripting (XSS) attacks.
     * </p>
     */
    private boolean httpOnly = true;

    /**
     * Whether the session cookie should be marked as Secure.
     * <p>
     * When {@code true}, the cookie is only sent over HTTPS connections.
     * Should be set to {@code true} in production environments.
     * Defaults to {@code false} for development convenience.
     * </p>
     */
    private boolean secure = false;

    /**
     * The SameSite attribute for the session cookie.
     * <p>
     * Controls whether the cookie is sent with cross-site requests.
     * Valid values: {@code Lax}, {@code Strict}, {@code None}.
     * </p>
     */
    private String sameSite = "Lax";

    /**
     * Gets the custom session cookie name.
     *
     * @return the cookie name, or null if using the default
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the custom session cookie name.
     *
     * @param name the cookie name (e.g., "AS_SESSION", "IDP_SESSION")
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets whether the session cookie is HttpOnly.
     *
     * @return whether the cookie is HttpOnly
     */
    public boolean isHttpOnly() {
        return httpOnly;
    }

    /**
     * Sets whether the session cookie is HttpOnly.
     *
     * @param httpOnly whether to mark the cookie as HttpOnly
     */
    public void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    /**
     * Gets whether the session cookie is Secure.
     *
     * @return whether the cookie is Secure
     */
    public boolean isSecure() {
        return secure;
    }

    /**
     * Sets whether the session cookie is Secure.
     *
     * @param secure whether to mark the cookie as Secure
     */
    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    /**
     * Gets the SameSite attribute for the session cookie.
     *
     * @return the SameSite attribute value
     */
    public String getSameSite() {
        return sameSite;
    }

    /**
     * Sets the SameSite attribute for the session cookie.
     *
     * @param sameSite the SameSite attribute value (Lax, Strict, or None)
     */
    public void setSameSite(String sameSite) {
        this.sameSite = sameSite;
    }
}
