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
package com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures;

/**
 * JWKS provider configuration properties.
 * <p>
 * This class defines configuration for the JWKS (JSON Web Key Set) provider,
 * which is responsible for serving public keys used for verifying JWT signatures.
 * The JWKS endpoint follows the standard defined in RFC 7517 and is typically
 * exposed at {@code /.well-known/jwks.json}.
 * </p>
 * <p>
 * The JWKS provider is a critical infrastructure component that enables other
 * services to discover and retrieve the public keys needed to verify digital
 * signatures on tokens issued by this authorization server.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     jwks:
 *       provider:
 *         enabled: true
 *         path: /.well-known/jwks.json
 *         cache-duration-seconds: 300
 *         cache-headers-enabled: true
 * </pre>
 *
 * @since 2.0
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 */
public class JwksProviderProperties {

    /**
     * Whether the JWKS provider is enabled.
     * <p>
     * When enabled, the application will expose a JWKS endpoint at the configured path,
     * allowing clients to retrieve the public keys needed for verifying JWT signatures.
     * When disabled, the JWKS endpoint will not be available.
     * </p>
     * <p>
     * Default value: {@code true}
     * </p>
     */
    private boolean enabled = true;

    /**
     * JWKS endpoint path.
     * <p>
     * The HTTP path where the JWKS endpoint will be exposed. This path should
     * follow the standard convention of {@code /.well-known/jwks.json} for
     * compatibility with OAuth 2.0 and OpenID Connect clients.
     * </p>
     * <p>
     * Default value: {@code /.well-known/jwks.json}
     * </p>
     */
    private String path = "/.well-known/jwks.json";

    /**
     * Cache duration in seconds.
     * <p>
     * The duration (in seconds) for which clients should cache the JWKS response.
     * This value is used to set the {@code Cache-Control} header in HTTP responses
     * to reduce the load on the server and improve performance.
     * </p>
     * <p>
     * A longer cache duration reduces server load but may delay the propagation
     * of new keys. A shorter cache duration ensures faster key rotation but
     * increases server load.
     * </p>
     * <p>
     * Default value: {@code 300} (5 minutes)
     * </p>
     */
    private int cacheDurationSeconds = 300;

    /**
     * Whether to include cache headers.
     * <p>
     * When enabled, the HTTP response will include cache control headers
     * (such as {@code Cache-Control} and {@code ETag}) to allow clients
     * to cache the JWKS response efficiently. When disabled, no cache headers
     * will be included in the response.
     * </p>
     * <p>
     * Default value: {@code true}
     * </p>
     */
    private boolean cacheHeadersEnabled = true;

    /**
     * Gets whether the JWKS provider is enabled.
     *
     * @return {@code true} if the JWKS provider is enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the JWKS provider is enabled.
     *
     * @param enabled {@code true} to enable the JWKS provider, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the JWKS endpoint path.
     *
     * @return the JWKS endpoint path
     */
    public String getPath() {
        return path;
    }

    /**
     * Sets the JWKS endpoint path.
     *
     * @param path the JWKS endpoint path to set
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Gets the cache duration in seconds.
     *
     * @return the cache duration in seconds
     */
    public int getCacheDurationSeconds() {
        return cacheDurationSeconds;
    }

    /**
     * Sets the cache duration in seconds.
     *
     * @param cacheDurationSeconds the cache duration in seconds to set
     */
    public void setCacheDurationSeconds(int cacheDurationSeconds) {
        this.cacheDurationSeconds = cacheDurationSeconds;
    }

    /**
     * Gets whether cache headers are enabled.
     *
     * @return {@code true} if cache headers are enabled, {@code false} otherwise
     */
    public boolean isCacheHeadersEnabled() {
        return cacheHeadersEnabled;
    }

    /**
     * Sets whether cache headers are enabled.
     *
     * @param cacheHeadersEnabled {@code true} to enable cache headers, {@code false} to disable
     */
    public void setCacheHeadersEnabled(boolean cacheHeadersEnabled) {
        this.cacheHeadersEnabled = cacheHeadersEnabled;
    }
}