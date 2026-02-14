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
package com.alibaba.openagentauth.core.token.common;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.HashMap;
import java.util.Map;

/**

/**
 * Utility class for converting between JWK maps and Jwk model objects.
 * Provides safe type conversion and serialization for JWK claims.
 */
public class JwkConverter {

    /**
     * Converts a Map to a Jwk object.
     *
     * @param jwkMap the JWK as a map
     * @return the Jwk object
     * @throws IllegalArgumentException if the map contains invalid values
     */
    public static Jwk convertMapToJwk(Map<String, Object> jwkMap) {

        // Create Jwk builder
        Jwk.Builder builder = Jwk.builder();

        // Extract key type (required)
        String ktyValue = getClaimAsString(jwkMap, "kty");
        ValidationUtils.validateNotNull(ktyValue, "Missing required 'kty' (key type) parameter in JWK");
        builder.keyType(Jwk.KeyType.fromValue(ktyValue));

        // Extract algorithm (optional)
        String alg = getClaimAsString(jwkMap, "alg");
        if (alg != null) {
            builder.algorithm(alg);
        }

        // Extract key use (optional)
        String use = getClaimAsString(jwkMap, "use");
        if (use != null) {
            builder.use(Jwk.KeyUse.fromValue(use));
        }

        // Extract curve (for EC keys)
        String crv = getClaimAsString(jwkMap, "crv");
        if (crv != null) {
            builder.curve(Jwk.Curve.fromValue(crv));
        }

        // Extract x coordinate (for EC keys)
        String x = getClaimAsString(jwkMap, "x");
        if (x != null) {
            builder.x(x);
        }

        // Extract y coordinate (for EC keys)
        String y = getClaimAsString(jwkMap, "y");
        if (y != null) {
            builder.y(y);
        }

        // Extract key ID (optional)
        String kid = getClaimAsString(jwkMap, "kid");
        if (kid != null) {
            builder.keyId(kid);
        }

        return builder.build();
    }

    /**
     * Safely extracts a String claim from a map.
     *
     * @param map the map containing the claim
     * @param key the claim key
     * @return the String value, or null if the key is not present
     * @throws IllegalArgumentException if the value is not a String
     */
    public static String getClaimAsString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return (String) value;
        }
        throw new IllegalArgumentException(String.format("Invalid claim '%s': expected String, got %s",
                key, value.getClass().getSimpleName()));
    }

    /**
     * Converts a Jwk object to a Map for proper JWT serialization.
     * <p>
     * This method ensures that all JWK fields are properly serialized, including
     * the kty (key type) field which is required by RFC 7517.
     * </p>
     *
     * @param jwk the Jwk object to convert
     * @return a Map representation of the JWK
     */
    public static Map<String, Object> convertJwkToMap(Jwk jwk) {

        // Create a new map
        Map<String, Object> jwkMap = new HashMap<>();

        // Required field: kty (key type)
        if (jwk.getKeyType() != null) {
            jwkMap.put("kty", jwk.getKeyType().getValue());
        }

        // Optional fields
        if (jwk.getAlgorithm() != null) {
            jwkMap.put("alg", jwk.getAlgorithm());
        }
        if (jwk.getUse() != null) {
            jwkMap.put("use", jwk.getUse().getValue());
        }
        if (jwk.getKeyId() != null) {
            jwkMap.put("kid", jwk.getKeyId());
        }

        // EC key specific fields
        if (jwk.getKeyType() == Jwk.KeyType.EC) {
            if (jwk.getCurve() != null) {
                jwkMap.put("crv", jwk.getCurve().getValue());
            }
            if (jwk.getX() != null) {
                jwkMap.put("x", jwk.getX());
            }
            if (jwk.getY() != null) {
                jwkMap.put("y", jwk.getY());
            }
        }

        return jwkMap;
    }
}