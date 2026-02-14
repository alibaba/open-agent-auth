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
package com.alibaba.openagentauth.core.protocol.oidc.builder;

import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Builder for creating ID Tokens with fluent API.
 * <p>
 * This builder provides a convenient way to create ID Tokens without directly
 * dealing with the IdTokenClaims builder. It automatically handles common
 * claim values like timestamps and provides sensible defaults.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>
 * IdToken idToken = IdTokenBuilder.create(generator)
 *     .issuer("https://example.com")
 *     .subject("user123")
 *     .audience("client123")
 *     .nonce("abc123")
 *     .lifetime(3600)
 *     .build();
 * </pre>
 *
 * @see IdToken
 * @see IdTokenClaims
 * @since 1.0
 */
public class IdTokenBuilder {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(IdTokenBuilder.class);

    /**
     * Default token lifetime in seconds (1 hour).
     */
    private static final long DEFAULT_LIFETIME_SECONDS = 3600;

    /**
     * The ID Token generator.
     */
    private final IdTokenGenerator generator;

    /**
     * The issuer identifier.
     */
    private String issuer;

    /**
     * The subject identifier.
     */
    private String subject;

    /**
     * The audience.
     */
    private String audience;

    /**
     * The nonce value.
     */
    private String nonce;

    /**
     * The authentication time.
     */
    private Long authTime;

    /**
     * The Authentication Context Class Reference.
     */
    private String acr;

    /**
     * The Authentication Methods References.
     */
    private String[] amr;

    /**
     * The authorized party.
     */
    private String azp;

    /**
     * The token lifetime in seconds.
     */
    private Long lifetimeInSeconds;

    /**
     * Creates a new IdTokenBuilder.
     *
     * @param generator the ID Token generator
     */
    private IdTokenBuilder(IdTokenGenerator generator) {
        this.generator = ValidationUtils.validateNotNull(generator, "ID Token generator");
    }

    /**
     * Creates a new IdTokenBuilder with the specified generator.
     *
     * @param generator the ID Token generator
     * @return a new builder instance
     */
    public static IdTokenBuilder create(IdTokenGenerator generator) {
        return new IdTokenBuilder(generator);
    }

    /**
     * Sets the issuer identifier.
     *
     * @param issuer the issuer identifier
     * @return this builder instance
     */
    public IdTokenBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Sets the subject identifier.
     *
     * @param subject the subject identifier
     * @return this builder instance
     */
    public IdTokenBuilder subject(String subject) {
        this.subject = subject;
        return this;
    }

    /**
     * Sets the audience.
     *
     * @param audience the audience
     * @return this builder instance
     */
    public IdTokenBuilder audience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Sets the nonce value.
     *
     * @param nonce the nonce value
     * @return this builder instance
     */
    public IdTokenBuilder nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the authentication time.
     *
     * @param authTime the authentication time in seconds since epoch
     * @return this builder instance
     */
    public IdTokenBuilder authTime(Long authTime) {
        this.authTime = authTime;
        return this;
    }

    /**
     * Sets the authentication time from an Instant.
     *
     * @param instant the authentication time
     * @return this builder instance
     */
    public IdTokenBuilder authTime(Instant instant) {
        this.authTime = instant.getEpochSecond();
        return this;
    }

    /**
     * Sets the Authentication Context Class Reference.
     *
     * @param acr the ACR value
     * @return this builder instance
     */
    public IdTokenBuilder acr(String acr) {
        this.acr = acr;
        return this;
    }

    /**
     * Sets the Authentication Methods References.
     *
     * @param amr the AMR values
     * @return this builder instance
     */
    public IdTokenBuilder amr(String[] amr) {
        this.amr = amr;
        return this;
    }

    /**
     * Sets the authorized party.
     *
     * @param azp the authorized party
     * @return this builder instance
     */
    public IdTokenBuilder azp(String azp) {
        this.azp = azp;
        return this;
    }

    /**
     * Sets the token lifetime in seconds.
     *
     * @param lifetimeInSeconds the lifetime in seconds
     * @return this builder instance
     */
    public IdTokenBuilder lifetime(long lifetimeInSeconds) {
        this.lifetimeInSeconds = lifetimeInSeconds;
        return this;
    }

    /**
     * Builds the ID Token.
     *
     * @return the generated ID Token
     * @throws IdTokenException if generation fails
     * @throws IllegalStateException if required fields are missing
     */
    public IdToken build() {

        // Validate required fields
        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalStateException("issuer is required");
        }
        if (ValidationUtils.isNullOrEmpty(subject)) {
            throw new IllegalStateException("subject is required");
        }
        if (ValidationUtils.isNullOrEmpty(audience)) {
            throw new IllegalStateException("audience is required");
        }

        // Calculate expiration time
        long lifetime = lifetimeInSeconds != null ? lifetimeInSeconds : DEFAULT_LIFETIME_SECONDS;
        Instant now = Instant.now();
        long iat = now.getEpochSecond();
        long exp = now.plusSeconds(lifetime).getEpochSecond();

        // Build claims
        IdTokenClaims.Builder claimsBuilder = IdTokenClaims.builder()
                .iss(issuer)
                .sub(subject)
                .aud(audience)
                .iat(iat)
                .exp(exp)
                .authTime(authTime != null ? authTime : iat);

        if (nonce != null) {
            claimsBuilder.nonce(nonce);
        }
        if (acr != null) {
            claimsBuilder.acr(acr);
        }
        if (amr != null) {
            claimsBuilder.amr(amr);
        }
        if (azp != null) {
            claimsBuilder.azp(azp);
        }

        IdTokenClaims claims = claimsBuilder.build();

        // Generate token
        return generator.generate(claims, lifetime);
    }

}