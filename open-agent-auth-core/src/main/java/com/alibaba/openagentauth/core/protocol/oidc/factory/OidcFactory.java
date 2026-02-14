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
package com.alibaba.openagentauth.core.protocol.oidc.factory;

import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.builder.IdTokenBuilder;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating OIDC components.
 * <p>
 * This factory provides a centralized way to create OIDC components with
 * consistent configuration. It follows the Factory pattern to encapsulate
 * the creation logic and provide a simple API for component instantiation.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Consistent component configuration</li>
 *   <li>Centralized creation logic</li>
 *   <li>Easy to extend with new component types</li>
 *   <li>Support for custom configurations</li>
 * </ul>
 *
 * @since 1.0
 */
public class OidcFactory {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(OidcFactory.class);

    /**
     * The issuer identifier.
     */
    private final String issuer;

    /**
     * The signing key.
     */
    private final Object signingKey;

    /**
     * The verification key.
     */
    private final Object verificationKey;

    /**
     * The signing algorithm.
     */
    private final String algorithm;

    /**
     * The UserInfo Endpoint URL.
     */
    private final String userInfoEndpoint;

    /**
     * Constructs a new OidcFactory.
     *
     * @param builder the builder
     */
    private OidcFactory(Builder builder) {
        this.issuer = builder.issuer;
        this.signingKey = builder.signingKey;
        this.verificationKey = builder.verificationKey;
        this.algorithm = builder.algorithm;
        this.userInfoEndpoint = builder.userInfoEndpoint;
        
        logger.info("OidcFactory initialized with issuer: {}, algorithm: {}", issuer, algorithm);
    }

    /**
     * Creates a new OidcFactory builder.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates an ID Token Generator.
     *
     * @return the ID Token generator
     */
    public IdTokenGenerator createIdTokenGenerator() {
        logger.debug("Creating ID Token generator");
        return new DefaultIdTokenGenerator(issuer, algorithm, signingKey);
    }

    /**
     * Creates an ID Token Validator.
     *
     * @return the ID Token validator
     */
    public IdTokenValidator createIdTokenValidator() {
        logger.debug("Creating ID Token validator");
        return new DefaultIdTokenValidator(verificationKey);
    }

    /**
     * Creates an ID Token Validator with custom clock skew.
     *
     * @param clockSkewSeconds the allowed clock skew in seconds
     * @return the ID Token validator
     */
    public IdTokenValidator createIdTokenValidator(long clockSkewSeconds) {
        logger.debug("Creating ID Token validator with clock skew: {} seconds", clockSkewSeconds);
        return new DefaultIdTokenValidator(verificationKey, clockSkewSeconds);
    }

    /**
     * Creates an IdToken Builder.
     *
     * @return the ID Token builder
     */
    public IdTokenBuilder createIdTokenBuilder() {
        logger.debug("Creating ID Token builder");
        return IdTokenBuilder.create(createIdTokenGenerator());
    }

    /**
     * Gets the issuer identifier.
     *
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the signing algorithm.
     *
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the UserInfo Endpoint URL.
     *
     * @return the endpoint URL
     */
    public String getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    /**
     * Builder for {@link OidcFactory}.
     */
    public static class Builder {
        private String issuer;
        private Object signingKey;
        private Object verificationKey;
        private String algorithm = "RS256";
        private String userInfoEndpoint;

        /**
         * Sets the issuer identifier.
         *
         * @param issuer the issuer identifier
         * @return this builder instance
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Sets the signing key.
         *
         * @param signingKey the signing key
         * @return this builder instance
         */
        public Builder signingKey(Object signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        /**
         * Sets the verification key.
         *
         * @param verificationKey the verification key
         * @return this builder instance
         */
        public Builder verificationKey(Object verificationKey) {
            this.verificationKey = verificationKey;
            return this;
        }

        /**
         * Sets both signing and verification keys (for symmetric algorithms).
         *
         * @param key the key
         * @return this builder instance
         */
        public Builder key(Object key) {
            this.signingKey = key;
            this.verificationKey = key;
            return this;
        }

        /**
         * Sets the signing algorithm.
         *
         * @param algorithm the algorithm (e.g., "RS256", "ES256")
         * @return this builder instance
         */
        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Sets the UserInfo Endpoint URL.
         *
         * @param userInfoEndpoint the endpoint URL
         * @return this builder instance
         */
        public Builder userInfoEndpoint(String userInfoEndpoint) {
            this.userInfoEndpoint = userInfoEndpoint;
            return this;
        }

        /**
         * Builds the {@link OidcFactory}.
         *
         * @return the built factory
         * @throws IllegalStateException if required fields are missing
         */
        public OidcFactory build() {
            if (ValidationUtils.isNullOrEmpty(issuer)) {
                throw new IllegalStateException("issuer is required");
            }
            if (signingKey == null) {
                throw new IllegalStateException("signingKey is required");
            }
            if (verificationKey == null) {
                throw new IllegalStateException("verificationKey is required");
            }
            if (ValidationUtils.isNullOrEmpty(algorithm)) {
                throw new IllegalStateException("algorithm is required");
            }
            return new OidcFactory(this);
        }
    }
}