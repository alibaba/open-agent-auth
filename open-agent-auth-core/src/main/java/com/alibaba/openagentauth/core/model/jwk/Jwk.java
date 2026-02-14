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
package com.alibaba.openagentauth.core.model.jwk;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Objects;

/**
 * JSON Web Key (JWK) as defined in RFC 7517.
 * <p>
 * Represents a cryptographic key in JSON format with type-safe accessors.
 * Supports EC (Elliptic Curve) keys as commonly used in WIMSE protocol.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Jwk {

    /**
     * Key Type (kty).
     * <p>
     * Identifies the cryptographic algorithm family used with the key.
     * REQUIRED field.
     * </p>
     */
    @JsonProperty("kty")
    private final KeyType keyType;

    /**
     * Public Key Use (use).
     * <p>
     * Identifies the intended use of the public key.
     * OPTIONAL field.
     * </p>
     */
    @JsonProperty("use")
    private final KeyUse use;

    /**
     * Algorithm (alg).
     * <p>
     * Identifies the algorithm intended for use with the key.
     * OPTIONAL field.
     * </p>
     */
    @JsonProperty("alg")
    private final String algorithm;

    /**
     * Curve (crv).
     * <p>
     * Identifies the cryptographic curve used with the key.
     * REQUIRED for EC keys.
     * </p>
     */
    @JsonProperty("crv")
    private final Curve curve;

    /**
     * X Coordinate.
     * <p>
     * X coordinate of the elliptic curve point.
     * Base64url-encoded.
     * REQUIRED for EC keys.
     * </p>
     */
    @JsonProperty("x")
    private final String x;

    /**
     * Y Coordinate.
     * <p>
     * Y coordinate of the elliptic curve point.
     * Base64url-encoded.
     * REQUIRED for EC keys.
     * </p>
     */
    @JsonProperty("y")
    private final String y;

    /**
     * Key ID (kid).
     * <p>
     * Key identifier for matching purposes.
     * OPTIONAL field.
     * </p>
     */
    @JsonProperty("kid")
    private final String keyId;

    private Jwk(Builder builder) {
        this.keyType = builder.keyType;
        this.use = builder.use;
        this.algorithm = builder.algorithm;
        this.curve = builder.curve;
        this.x = builder.x;
        this.y = builder.y;
        this.keyId = builder.keyId;
    }

    /**
     * Gets the key type (kty).
     *
     * @return the key type
     */
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * Gets the public key use (use).
     *
     * @return the key use, or null if not present
     */
    public KeyUse getUse() {
        return use;
    }

    /**
     * Gets the algorithm (alg).
     *
     * @return the algorithm, or null if not present
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the curve (crv).
     *
     * @return the curve, or null if not present
     */
    public Curve getCurve() {
        return curve;
    }

    /**
     * Gets the X coordinate.
     *
     * @return the X coordinate, or null if not present
     */
    public String getX() {
        return x;
    }

    /**
     * Gets the Y coordinate.
     *
     * @return the Y coordinate, or null if not present
     */
    public String getY() {
        return y;
    }

    /**
     * Gets the key ID (kid).
     *
     * @return the key ID, or null if not present
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Validates that this JWK contains all required fields for its key type.
     *
     * @throws IllegalStateException if required fields are missing
     */
    public void validate() {
        if (keyType == null) {
            throw new IllegalStateException("kty (key type) is REQUIRED");
        }

        if (keyType == KeyType.EC) {
            if (curve == null) {
                throw new IllegalStateException("crv (curve) is REQUIRED for EC keys");
            }
            if (ValidationUtils.isNullOrEmpty(x)) {
                throw new IllegalStateException("x coordinate is REQUIRED for EC keys");
            }
            if (ValidationUtils.isNullOrEmpty(y)) {
                throw new IllegalStateException("y coordinate is REQUIRED for EC keys");
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Jwk jwk = (Jwk) o;
        return keyType == jwk.keyType &&
               use == jwk.use &&
               Objects.equals(algorithm, jwk.algorithm) &&
               curve == jwk.curve &&
               Objects.equals(x, jwk.x) &&
               Objects.equals(y, jwk.y) &&
               Objects.equals(keyId, jwk.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyType, use, algorithm, curve, x, y, keyId);
    }

    @Override
    public String toString() {
        return "Jwk{" +
                "keyType=" + keyType +
                ", use=" + use +
                ", algorithm='" + algorithm + '\'' +
                ", curve=" + curve +
                ", x='" + x + '\'' +
                ", y='" + y + '\'' +
                ", keyId='" + keyId + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link Jwk}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Key Type enumeration.
     */
    public enum KeyType {
        EC("EC"),
        RSA("RSA"),
        OCT("oct");

        private final String value;

        KeyType(String value) {
            this.value = value;
        }

        @JsonValue
        public String getValue() {
            return value;
        }

        /**
         * Parses a string value to KeyType.
         *
         * @param value the string value
         * @return the corresponding KeyType
         * @throws IllegalArgumentException if the value is not recognized
         */
        public static KeyType fromValue(String value) {
            for (KeyType type : values()) {
                if (type.value.equals(value)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown KeyType: " + value);
        }
    }

    /**
     * Key Use enumeration.
     */
    public enum KeyUse {
        SIGNATURE("sig"),
        ENCRYPTION("enc");

        private final String value;

        KeyUse(String value) {
            this.value = value;
        }

        @JsonValue
        public String getValue() {
            return value;
        }

        /**
         * Parses a string value to KeyUse.
         *
         * @param value the string value
         * @return the corresponding KeyUse
         * @throws IllegalArgumentException if the value is not recognized
         */
        public static KeyUse fromValue(String value) {
            for (KeyUse keyUse : values()) {
                if (keyUse.value.equals(value)) {
                    return keyUse;
                }
            }
            throw new IllegalArgumentException("Unknown KeyUse: " + value);
        }
    }

    /**
     * Curve enumeration for EC keys.
     */
    public enum Curve {
        P_256("P-256"),
        P_384("P-384"),
        P_521("P-521");

        private final String value;

        Curve(String value) {
            this.value = value;
        }

        @JsonValue
        public String getValue() {
            return value;
        }

        /**
         * Parses a string value to Curve.
         *
         * @param value the string value
         * @return the corresponding Curve
         * @throws IllegalArgumentException if the value is not recognized
         */
        public static Curve fromValue(String value) {
            for (Curve curve : values()) {
                if (curve.value.equals(value)) {
                    return curve;
                }
            }
            throw new IllegalArgumentException("Unknown Curve: " + value);
        }
    }

    /**
     * Builder for {@link Jwk}.
     */
    public static class Builder {
        private KeyType keyType;
        private KeyUse use;
        private String algorithm;
        private Curve curve;
        private String x;
        private String y;
        private String keyId;

        public Builder keyType(KeyType keyType) {
            this.keyType = keyType;
            return this;
        }

        public Builder use(KeyUse use) {
            this.use = use;
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder curve(Curve curve) {
            this.curve = curve;
            return this;
        }

        public Builder x(String x) {
            this.x = x;
            return this;
        }

        public Builder y(String y) {
            this.y = y;
            return this;
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Jwk build() {
            Jwk jwk = new Jwk(this);
            jwk.validate();
            return jwk;
        }
    }
}