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
package com.alibaba.openagentauth.core.crypto.jwk;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

/**
 * Default implementation of {@link JwksProvider} that fetches keys from a remote JWKS endpoint.
 * <p>
 * This implementation uses the RemoteJWKSet from NimbusDS to fetch and cache public keys
 * from a remote JWKS endpoint. It supports automatic refresh of cached keys.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class RemoteJwksProvider implements JwksProvider {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(RemoteJwksProvider.class);

    /**
     * The JWK source for fetching keys.
     */
    private final JWKSource<SecurityContext> jwkSource;

    /**
     * The JWKS endpoint URL.
     */
    private final URL jwksUrl;

    /**
     * Creates a new DefaultJwksProvider with the specified JWKS endpoint URL.
     *
     * @param jwksUrl the JWKS endpoint URL
     * @throws IllegalArgumentException if the URL is null
     */
    public RemoteJwksProvider(URL jwksUrl) {
        ValidationUtils.validateNotNull(jwksUrl, "JWKS URL");
        this.jwksUrl = jwksUrl;
        this.jwkSource = new RemoteJWKSet<>(jwksUrl);
        logger.info("DefaultJwksProvider initialized with JWKS URL: {}", jwksUrl);
    }

    /**
     * Creates a new DefaultJwksProvider with the specified JWKS endpoint URL string.
     *
     * @param jwksUrl the JWKS endpoint URL string
     * @throws IllegalArgumentException if the URL is null or invalid
     * @throws IOException if the URL is invalid
     */
    public RemoteJwksProvider(String jwksUrl) throws IOException {
        this(new URL(jwksUrl));
    }

    @Override
    public JWKSource<SecurityContext> getJwkSource() {
        return jwkSource;
    }

    @Override
    public JWKSet getJwkSet() throws IOException {
        // RemoteJWKSet does not have getJWKSet method
        // We need to fetch the keys by making a request to the JWKS endpoint
        try {
            return JWKSet.load(jwksUrl);
        } catch (java.text.ParseException e) {
            throw new IOException("Failed to parse JWKSet from JWKS endpoint", e);
        }
    }

    @Override
    public void refresh() {
        logger.info("Refreshing JWKS from: {}", jwksUrl);
        // RemoteJWKSet automatically refreshes when needed
        // This method is kept for API compatibility
        logger.info("JWKS refresh completed");
    }

    /**
     * Gets the JWKS endpoint URL.
     *
     * @return the JWKS URL
     */
    public URL getJwksUrl() {
        return jwksUrl;
    }
}