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

import java.util.ArrayList;
import java.util.List;

/**
 * Security configuration properties.
 * <p>
 * Controls security features including CSRF protection and CORS settings.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   security:
 *     csrf:
 *       enabled: true
 *     cors:
 *       enabled: false
 *       allowed-origins:
 *         - http://localhost:3000
 * </pre>
 *
 * @since 1.0
 */
public class SecurityProperties {

    /**
     * CSRF configuration.
     */
    private CsrfProperties csrf = new CsrfProperties();

    /**
     * CORS configuration.
     */
    private CorsProperties cors = new CorsProperties();

    /**
     * Session cookie configuration.
     */
    private SessionCookieProperties sessionCookie = new SessionCookieProperties();

    /**
     * Gets the CSRF configuration.
     *
     * @return the CSRF properties
     */
    public CsrfProperties getCsrf() {
        return csrf;
    }

    /**
     * Sets the CSRF configuration.
     *
     * @param csrf the CSRF properties to set
     */
    public void setCsrf(CsrfProperties csrf) {
        this.csrf = csrf;
    }

    /**
     * Gets the CORS configuration.
     *
     * @return the CORS properties
     */
    public CorsProperties getCors() {
        return cors;
    }

    /**
     * Sets the CORS configuration.
     *
     * @param cors the CORS properties to set
     */
    public void setCors(CorsProperties cors) {
        this.cors = cors;
    }

    /**
     * Gets the session cookie configuration.
     *
     * @return the session cookie properties
     */
    public SessionCookieProperties getSessionCookie() {
        return sessionCookie;
    }

    /**
     * Sets the session cookie configuration.
     *
     * @param sessionCookie the session cookie properties to set
     */
    public void setSessionCookie(SessionCookieProperties sessionCookie) {
        this.sessionCookie = sessionCookie;
    }

    /**
     * CSRF configuration properties.
     * <p>
     * Controls Cross-Site Request Forgery protection for the application.
     * </p>
     */
    public static class CsrfProperties {

        /**
         * Whether CSRF protection is enabled.
         * <p>
         * When enabled, the application will generate and validate CSRF tokens
         * to protect against cross-site request forgery attacks.
         * </p>
         */
        private boolean enabled = true;

        /**
         * Gets whether CSRF protection is enabled.
         *
         * @return whether CSRF protection is enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether CSRF protection is enabled.
         *
         * @param enabled whether to enable CSRF protection
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * CORS configuration properties.
     * <p>
     * Controls Cross-Origin Resource Sharing settings for the application.
     * </p>
     */
    public static class CorsProperties {

        /**
         * Whether CORS is enabled.
         * <p>
         * When enabled, the application will allow cross-origin requests
         * based on the configured allowed origins.
         * </p>
         */
        private boolean enabled = false;

        /**
         * Allowed origins for CORS requests.
         * <p>
         * A list of origin URLs that are allowed to make
         * cross-origin requests to this application.
         * </p>
         */
        private List<String> allowedOrigins = new ArrayList<>();

        /**
         * Gets whether CORS is enabled.
         *
         * @return whether CORS is enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether CORS is enabled.
         *
         * @param enabled whether to enable CORS
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the allowed origins for CORS requests.
         *
         * @return the list of allowed origins
         */
        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        /**
         * Sets the allowed origins for CORS requests.
         *
         * @param allowedOrigins the list of allowed origins
         */
        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }
    }
}
