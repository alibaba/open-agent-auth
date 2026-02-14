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
package com.alibaba.openagentauth.core.protocol.oauth2.token.oidc;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Adapter that bridges {@link TokenGenerator} and {@link IdTokenGenerator}.
 * <p>
 * This class adapts the ID Token generation logic to work with the standard
 * OAuth 2.0 token generation interface, allowing the OAuth2TokenServer to
 * delegate token generation for OIDC (OpenID Connect) scenarios.
 * </p>
 * <p>
 * <b>Use Case:</b></p>
 * <p>
 * This adapter is used in OIDC authorization code flows where the token endpoint
 * needs to issue ID Tokens for user authentication. Unlike {@code AoatTokenGeneratorAdapter}
 * which uses PAR (Pushed Authorization Request) to generate Agent Operation Authorization
 * Tokens, this adapter generates standard OIDC ID Tokens.
 * </p>
 * <p>
 * <b>Flow:</b></p>
 * <pre>
 * 1. Extract user subject from authorization code
 * 2. Build ID Token claims with required OIDC fields
 * 3. Generate signed ID Token using IdTokenGenerator
 * 4. Return ID Token string as access token
 * </pre>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0</a>
 * @since 1.0
 */
public class IdTokenGeneratorAdapter implements TokenGenerator {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(IdTokenGeneratorAdapter.class);

    /**
     * The ID Token generator.
     */
    private final IdTokenGenerator idTokenGenerator;

    /**
     * The default token expiration time in seconds.
     */
    private final long defaultExpirationSeconds;

    /**
     * The issuer identifier for ID Tokens.
     */
    private final String issuer;

    /**
     * Creates a new IdTokenGeneratorAdapter.
     *
     * @param idTokenGenerator the ID Token generator
     * @param defaultExpirationSeconds the default expiration time in seconds
     * @param issuer the issuer identifier for ID Tokens
     */
    public IdTokenGeneratorAdapter(IdTokenGenerator idTokenGenerator, long defaultExpirationSeconds, String issuer) {
        this.idTokenGenerator = idTokenGenerator;
        this.defaultExpirationSeconds = defaultExpirationSeconds;
        this.issuer = issuer;
        logger.info("IdTokenGeneratorAdapter initialized with issuer: {}, expiration: {} seconds", 
                issuer, defaultExpirationSeconds);
    }

    /**
     * Creates a new IdTokenGeneratorAdapter with default expiration (3600 seconds).
     *
     * @param idTokenGenerator the ID Token generator
     * @param issuer the issuer identifier for ID Tokens
     */
    public IdTokenGeneratorAdapter(IdTokenGenerator idTokenGenerator, String issuer) {
        this(idTokenGenerator, 3600L, issuer);
    }

    @Override
    public String generateToken(AuthorizationCode authCode, TokenRequest request) {
        logger.info("Generating ID Token for code: {}, subject: {}", authCode.getCode(), authCode.getSubject());

        try {
            // Step 1: Build ID Token claims
            IdTokenClaims claims = buildIdTokenClaims(authCode, request);

            // Step 2: Generate ID Token
            IdToken idToken = idTokenGenerator.generate(claims, defaultExpirationSeconds);

            logger.info("ID Token generated successfully for subject: {}", claims.getSub());
            return idToken.getTokenValue();

        } catch (Exception e) {
            logger.error("Failed to generate ID Token", e);
            throw OAuth2TokenException.serverError("Failed to generate access token: " + e.getMessage(), e);
        }
    }

    @Override
    public long getExpirationSeconds() {
        return defaultExpirationSeconds;
    }

    /**
     * Builds ID Token claims from authorization code and token request.
     *
     * @param authCode the authorization code
     * @param request the token request
     * @return the ID Token claims
     */
    private IdTokenClaims buildIdTokenClaims(AuthorizationCode authCode, TokenRequest request) {

        Instant now = Instant.now();
        Instant expirationTime = now.plusSeconds(defaultExpirationSeconds);

        return IdTokenClaims.builder()
                .iss(issuer)
                .sub(authCode.getSubject())
                .aud(request.getClientId())
                .iat(now)
                .exp(expirationTime)
                .authTime(authCode.getIssuedAt())
                .build();
    }

    /**
     * Gets the ID Token generator.
     *
     * @return the ID Token generator
     */
    public IdTokenGenerator getIdTokenGenerator() {
        return idTokenGenerator;
    }

    /**
     * Gets the default expiration time.
     *
     * @return the expiration time in seconds
     */
    public long getDefaultExpirationSeconds() {
        return defaultExpirationSeconds;
    }

    /**
     * Gets the issuer identifier.
     *
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

}
