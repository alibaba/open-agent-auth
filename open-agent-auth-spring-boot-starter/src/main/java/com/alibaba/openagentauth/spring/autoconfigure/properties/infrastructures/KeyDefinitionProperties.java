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

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;

/**
 * Key definition configuration properties.
 * <p>
 * This class defines the cryptographic key configuration for JWT signing and verification,
 * including key identifier, algorithm, and provider settings. It is used to configure
 * the keys that will be published in JWKS (JSON Web Key Set) and used in JWT headers.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     key-management:
 *       keys:
 *         signing-key-1:
 *           key-id: "signing-key-1"
 *           algorithm: "RS256"
 *           provider: "local"
 *         signing-key-2:
 *           key-id: "signing-key-2"
 *           algorithm: "ES256"
 *           provider: "local"
 * </pre>
 *
 * @since 2.0
 * @see OpenAgentAuthProperties
 */
public class KeyDefinitionProperties {

    /**
     * Key identifier used in JWKS and JWT headers.
     * <p>
     * This value is used as the {@code kid} (Key ID) header in JWT tokens and
     * as the key identifier in the JWKS endpoint. It must be unique across all
     * keys in the same JWKS set.
     * </p>
     * <p>
     * Default value: {@code null} (must be explicitly configured)
     * </p>
     */
    private String keyId;

    /**
     * Cryptographic algorithm for signing and verification.
     * <p>
     * Specifies the JWS (JSON Web Signature) algorithm to be used with this key.
     * Common values include:
     * </p>
     * <ul>
     *   <li>{@code RS256} - RSASSA-PKCS1-v1_5 using SHA-256</li>
     *   <li>{@code RS384} - RSASSA-PKCS1-v1_5 using SHA-384</li>
     *   <li>{@code RS512} - RSASSA-PKCS1-v1_5 using SHA-512</li>
     *   <li>{@code ES256} - ECDSA using P-256 and SHA-256</li>
     *   <li>{@code ES384} - ECDSA using P-384 and SHA-384</li>
     *   <li>{@code ES512} - ECDSA using P-521 and SHA-512</li>
     *   <li>{@code PS256} - RSASSA-PSS using SHA-256</li>
     *   <li>{@code PS384} - RSASSA-PSS using SHA-384</li>
     *   <li>{@code PS512} - RSASSA-PSS using SHA-512</li>
     * </ul>
     * <p>
     * Default value: {@code null} (must be explicitly configured)
     * </p>
     */
    private String algorithm;

    /**
     * Key provider name.
     * <p>
     * Specifies the provider that manages and stores the cryptographic key.
     * Supported providers include:
     * </p>
     * <ul>
     *   <li>{@code local} - Keys are stored locally in the application configuration</li>
     * </ul>
     * <p>
     * This field is used for signing and decryption keys. For verification and encryption keys,
     * use {@link #jwksConsumer} to specify the JWKS consumer that provides the public key.
     * </p>
     * <p>
     * Default value: {@code "local"}
     * </p>
     */
    private String provider = "local";

    /**
     * JWKS consumer name.
     * <p>
     * Specifies the JWKS consumer that provides the public key for verification or encryption.
     * This field is used for verification keys (e.g., {@code wit-verification}, {@code aoat-verification})
     * and encryption keys (e.g., {@code jwe-encryption}) to fetch public keys from remote JWKS endpoints.
     * </p>
     * <p>
     * The value must match a consumer name defined in {@code open-agent-auth.infrastructures.jwks.consumers}.
     * </p>
     * <p>
     * Default value: {@code null} (not configured)
     * </p>
     */
    private String jwksConsumer;

    /**
     * Gets the key identifier.
     *
     * @return the key identifier used in JWKS and JWT headers
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Sets the key identifier.
     *
     * @param keyId the key identifier to set, must be unique across all keys
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * Gets the cryptographic algorithm.
     *
     * @return the JWS algorithm for signing and verification
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Sets the cryptographic algorithm.
     *
     * @param algorithm the JWS algorithm to set (e.g., RS256, ES256)
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Gets the key provider name.
     *
     * @return the provider name (e.g., "local")
     */
    public String getProvider() {
        return provider;
    }

    /**
     * Sets the key provider name.
     *
     * @param provider the provider name to set (e.g., "local")
     */
    public void setProvider(String provider) {
        this.provider = provider;
    }

    /**
     * Gets the JWKS consumer name.
     *
     * @return the JWKS consumer name, or {@code null} if not configured
     */
    public String getJwksConsumer() {
        return jwksConsumer;
    }

    /**
     * Sets the JWKS consumer name.
     *
     * @param jwksConsumer the JWKS consumer name to set
     */
    public void setJwksConsumer(String jwksConsumer) {
        this.jwksConsumer = jwksConsumer;
    }
}