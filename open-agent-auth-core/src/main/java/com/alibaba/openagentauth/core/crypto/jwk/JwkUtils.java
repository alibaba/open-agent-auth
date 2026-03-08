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

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Utility class for common JWK operations.
 * <p>
 * Provides reusable methods for JWK comparison and selection that are shared across
 * multiple modules including WIMSE DCR authentication and OAuth2 client assertion
 * verification.
 * </p>
 *
 * @since 1.0
 */
public final class JwkUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwkUtils.class);

    private JwkUtils() {
        // Utility class, prevent instantiation
    }

    /**
     * Compares the core cryptographic key material between a {@link Jwk} (from WIT cnf claim)
     * and a NimbusDS {@link JWK} (from DCR request jwks or other sources).
     * <p>
     * Only the essential public key parameters are compared:
     * </p>
     * <ul>
     *   <li><b>EC keys</b>: kty, crv, x, y</li>
     *   <li><b>RSA keys</b>: kty, n, e</li>
     * </ul>
     * <p>
     * Metadata fields such as {@code kid}, {@code alg}, and {@code use} are intentionally
     * excluded from comparison because different representations of the same key may carry
     * different metadata while sharing the same underlying public key material.
     * </p>
     *
     * @param witJwk the JWK from the WIT cnf claim
     * @param dcrJwk the JWK from the DCR request jwks or other source
     * @return {@code true} if the public key material matches
     */
    public static boolean publicKeysMatch(Jwk witJwk, JWK dcrJwk) {
        String witKeyType = witJwk.getKeyType() != null ? witJwk.getKeyType().getValue() : null;
        String dcrKeyType = dcrJwk.getKeyType() != null ? dcrJwk.getKeyType().getValue() : null;

        if (!Objects.equals(witKeyType, dcrKeyType)) {
            logger.debug("Key type mismatch: wit={}, dcr={}", witKeyType, dcrKeyType);
            return false;
        }

        if (dcrJwk instanceof ECKey ecKey) {
            String witCurve = witJwk.getCurve() != null ? witJwk.getCurve().getValue() : null;
            String dcrCurve = ecKey.getCurve() != null ? ecKey.getCurve().getName() : null;

            boolean matches = Objects.equals(witCurve, dcrCurve)
                    && Objects.equals(witJwk.getX(), ecKey.getX().toString())
                    && Objects.equals(witJwk.getY(), ecKey.getY().toString());

            if (!matches) {
                logger.debug("EC key parameters mismatch - wit(crv={}, x={}, y={}) vs dcr(crv={}, x={}, y={})",
                        witCurve, witJwk.getX(), witJwk.getY(),
                        dcrCurve, ecKey.getX(), ecKey.getY());
            }
            return matches;
        } else if (dcrJwk instanceof RSAKey rsaKey) {
            boolean matches = Objects.equals(witJwk.getX(), rsaKey.getModulus().toString())
                    && Objects.equals(witJwk.getY(), rsaKey.getPublicExponent().toString());

            if (!matches) {
                logger.debug("RSA key parameters mismatch for wit vs dcr");
            }
            return matches;
        }

        logger.debug("Unsupported key type for comparison: {}", dcrKeyType);
        return false;
    }

    /**
     * Selects the appropriate JWK for signature verification from a JWKSet.
     * <p>
     * Selection strategy:
     * </p>
     * <ul>
     *   <li>If {@code headerKeyId} is provided and non-empty, match by kid</li>
     *   <li>If no kid is provided, use the first key in the set</li>
     * </ul>
     *
     * @param jwkSet the JWKSet to select from
     * @param headerKeyId the key ID from JWT header (may be null)
     * @return the selected JWK
     * @throws IllegalArgumentException if no suitable key is found
     */
    public static JWK selectVerificationKey(JWKSet jwkSet, String headerKeyId) {
        if (headerKeyId != null && !headerKeyId.isEmpty()) {
            JWK key = jwkSet.getKeyByKeyId(headerKeyId);
            if (key == null) {
                throw new IllegalArgumentException("No JWK found with kid: " + headerKeyId);
            }
            logger.debug("Selected JWK by kid: {}", headerKeyId);
            return key;
        }

        if (jwkSet.getKeys().isEmpty()) {
            throw new IllegalArgumentException("No keys found in JWKSet");
        }

        JWK key = jwkSet.getKeys().get(0);
        logger.debug("Selected first JWK (no kid provided): {}", key.getKeyID());
        return key;
    }
}
