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

import com.alibaba.openagentauth.core.util.ValidationUtils;

/**
 * JWKS (JSON Web Key Set) consumer configuration properties.
 * <p>
 * This class defines configuration for consuming JWKS endpoints to verify JWT tokens.
 * JWKS is a specification that defines a JSON data structure for representing a set
 * of public keys that can be used to verify the signatures of JSON Web Tokens (JWT).
 * </p>
 * <p>
 * The consumer periodically fetches the JWKS from the configured endpoint and caches
 * the public keys for efficient token verification. This is essential for validating
 * tokens issued by OAuth2/OpenID Connect providers without requiring shared secrets.
 * </p>
 * <p>
 * <b>Automatic Derivation:</b>
 * The {@code jwks-endpoint} and {@code issuer} can be derived from each other
 * according to the OpenID Connect Discovery specification. You only need to
 * configure one of them:
 * </p>
 * <ul>
 *   <li>If only {@code issuer} is configured, {@code jwks-endpoint} will be
 *       automatically derived as {@code issuer + "/.well-known/jwks.json"}</li>
 *   <li>If only {@code jwks-endpoint} is configured, {@code issuer} will be
 *       automatically derived by removing the {@code "/.well-known/jwks.json"} suffix</li>
 *   <li>If both are configured, the configured values will be used directly without derivation</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * # Only need to configure one of issuer or jwks-endpoint
 * open-agent-auth:
 *   infrastructures:
 *     jwks:
 *       consumers:
 *         agent-user-idp:
 *           issuer: https://your-idp.example.com
 *           # jwks-endpoint will be derived as: https://your-idp.example.com/.well-known/jwks.json
 * 
 *         agent-idp:
 *           jwks-endpoint: https://agent-idp.example.com/.well-known/jwks.json
 *           # issuer will be derived as: https://agent-idp.example.com
 * </pre>
 *
 * @since 1.0
 */
public class JwksConsumerProperties {

    private static final String JWKS_PATH = "/.well-known/jwks.json";

    /**
     * Whether this JWKS consumer is enabled.
     * <p>
     * When enabled, the application will configure a JWKS consumer that fetches
     * and caches public keys from the specified JWKS endpoint for JWT token verification.
     * When disabled, JWT verification using this consumer will not be available.
     * </p>
     * <p>
     * Default value: {@code true}
     * </p>
     */
    private boolean enabled = true;

    /**
     * JWKS endpoint URL.
     * <p>
     * The URL of the JWKS endpoint from which public keys will be fetched.
     * This endpoint should return a JSON Web Key Set (JWKS) containing the
     * public keys used to verify JWT signatures.
     * </p>
     * <p>
     * The endpoint typically follows the OpenID Connect Discovery specification
     * and is located at {@code /.well-known/jwks.json} relative to the issuer URL.
     * If not configured, it will be automatically derived from {@code issuer}
     * by appending {@code /.well-known/jwks.json}.
     * </p>
     * <p>
     * Example: {@code https://your-idp.example.com/.well-known/jwks.json}
     * </p>
     * <p>
     * At least one of {@code jwks-endpoint} or {@code issuer} must be configured.
     * </p>
     */
    private String jwksEndpoint;

    /**
     * Issuer URL.
     * <p>
     * The issuer identifier for the authorization server that issued the JWT tokens.
     * This value is used to validate the {@code iss} claim in JWT tokens, ensuring
     * that tokens were issued by the expected authorization server.
     * </p>
     * <p>
     * The issuer URL must match the {@code iss} claim in the JWT token exactly.
     * According to the OpenID Connect specification, this should be a URL using
     * the {@code https} scheme without a query or fragment component.
     * </p>
     * <p>
     * If not configured, it will be automatically derived from {@code jwks-endpoint}
     * by removing the {@code /.well-known/jwks.json} suffix.
     * </p>
     * <p>
     * Example: {@code https://your-idp.example.com}
     * </p>
     * <p>
     * At least one of {@code jwks-endpoint} or {@code issuer} must be configured.
     * </p>
     */
    private String issuer;

    /**
     * Gets whether this JWKS consumer is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether this JWKS consumer is enabled.
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the JWKS endpoint URL.
     * <p>
     * If {@code jwks-endpoint} is not configured but {@code issuer} is configured,
     * this method will automatically derive the JWKS endpoint from the issuer.
     * </p>
     *
     * @return the JWKS endpoint URL, or {@code null} if neither jwksEndpoint nor issuer is configured
     */
    public String getJwksEndpoint() {
        if (jwksEndpoint == null && !ValidationUtils.isNullOrEmpty(issuer)) {
            return deriveJwksEndpointFromIssuer(issuer);
        }
        return jwksEndpoint;
    }

    /**
     * Sets the JWKS endpoint URL.
     *
     * @param jwksEndpoint the JWKS endpoint URL to set
     */
    public void setJwksEndpoint(String jwksEndpoint) {
        this.jwksEndpoint = jwksEndpoint;
    }

    /**
     * Gets the issuer URL.
     * <p>
     * If {@code issuer} is not configured but {@code jwks-endpoint} is configured,
     * this method will automatically derive the issuer from the JWKS endpoint.
     * </p>
     *
     * @return the issuer URL, or {@code null} if neither issuer nor jwksEndpoint is configured
     */
    public String getIssuer() {
        if (issuer == null && !ValidationUtils.isNullOrEmpty(jwksEndpoint)) {
            return deriveIssuerFromJwksEndpoint(jwksEndpoint);
        }
        return issuer;
    }

    /**
     * Sets the issuer URL.
     *
     * @param issuer the issuer URL to set
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Derives the JWKS endpoint URL from the issuer URL.
     * <p>
     * According to the OpenID Connect Discovery specification, the JWKS endpoint
     * is located at {@code /.well-known/jwks.json} relative to the issuer URL.
     * </p>
     *
     * @param issuer the issuer URL
     * @return the derived JWKS endpoint URL
     */
    private String deriveJwksEndpointFromIssuer(String issuer) {
        return issuer + JWKS_PATH;
    }

    /**
     * Derives the issuer URL from the JWKS endpoint URL.
     * <p>
     * This method removes the {@code /.well-known/jwks.json} suffix from the
     * JWKS endpoint to obtain the issuer URL.
     * </p>
     *
     * @param jwksEndpoint the JWKS endpoint URL
     * @return the derived issuer URL
     */
    private String deriveIssuerFromJwksEndpoint(String jwksEndpoint) {
        if (jwksEndpoint.endsWith(JWKS_PATH)) {
            return jwksEndpoint.substring(0, jwksEndpoint.length() - JWKS_PATH.length());
        }
        // If the endpoint doesn't end with the standard path, return as-is
        return jwksEndpoint;
    }
}