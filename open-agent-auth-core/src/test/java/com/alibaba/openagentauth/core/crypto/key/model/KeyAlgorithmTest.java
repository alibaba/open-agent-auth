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
package com.alibaba.openagentauth.core.crypto.key.model;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link KeyAlgorithm}.
 * <p>
 * This test class verifies the functionality of the KeyAlgorithm enum,
 * including algorithm properties, type checking, and string conversion.
 * </p>
 */
@DisplayName("KeyAlgorithm Tests")
class KeyAlgorithmTest {

    @Nested
    @DisplayName("Enum Values Tests")
    class EnumValuesTests {

        @Test
        @DisplayName("Should have all RSA algorithms")
        void shouldHaveAllRsaAlgorithms() {
            assertThat(KeyAlgorithm.RS256).isNotNull();
            assertThat(KeyAlgorithm.RS384).isNotNull();
            assertThat(KeyAlgorithm.RS512).isNotNull();
        }

        @Test
        @DisplayName("Should have all EC algorithms")
        void shouldHaveAllEcAlgorithms() {
            assertThat(KeyAlgorithm.ES256).isNotNull();
            assertThat(KeyAlgorithm.ES384).isNotNull();
            assertThat(KeyAlgorithm.ES512).isNotNull();
        }

        @Test
        @DisplayName("Should have six algorithm values")
        void shouldHaveSixAlgorithmValues() {
            assertThat(KeyAlgorithm.values()).hasSize(6);
        }
    }

    @Nested
    @DisplayName("JWS Algorithm Tests")
    class JwsAlgorithmTests {

        @Test
        @DisplayName("Should return correct JWS algorithm for RS256")
        void shouldReturnCorrectJwsAlgorithmForRS256() {
            assertThat(KeyAlgorithm.RS256.getJwsAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should return correct JWS algorithm for RS384")
        void shouldReturnCorrectJwsAlgorithmForRS384() {
            assertThat(KeyAlgorithm.RS384.getJwsAlgorithm()).isEqualTo(JWSAlgorithm.RS384);
        }

        @Test
        @DisplayName("Should return correct JWS algorithm for RS512")
        void shouldReturnCorrectJwsAlgorithmForRS512() {
            assertThat(KeyAlgorithm.RS512.getJwsAlgorithm()).isEqualTo(JWSAlgorithm.RS512);
        }

        @Test
        @DisplayName("Should return correct JWS algorithm for ES256")
        void shouldReturnCorrectJwsAlgorithmForES256() {
            assertThat(KeyAlgorithm.ES256.getJwsAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        }

        @Test
        @DisplayName("Should return correct JWS algorithm for ES384")
        void shouldReturnCorrectJwsAlgorithmForES384() {
            assertThat(KeyAlgorithm.ES384.getJwsAlgorithm()).isEqualTo(JWSAlgorithm.ES384);
        }

        @Test
        @DisplayName("Should return correct JWS algorithm for ES512")
        void shouldReturnCorrectJwsAlgorithmForES512() {
            assertThat(KeyAlgorithm.ES512.getJwsAlgorithm()).isEqualTo(JWSAlgorithm.ES512);
        }
    }

    @Nested
    @DisplayName("Key Type Tests")
    class KeyTypeTests {

        @Test
        @DisplayName("Should return RSA key type for RSA algorithms")
        void shouldReturnRsaKeyTypeForRsaAlgorithms() {
            assertThat(KeyAlgorithm.RS256.getKeyType()).isEqualTo("RSA");
            assertThat(KeyAlgorithm.RS384.getKeyType()).isEqualTo("RSA");
            assertThat(KeyAlgorithm.RS512.getKeyType()).isEqualTo("RSA");
        }

        @Test
        @DisplayName("Should return EC key type for EC algorithms")
        void shouldReturnEcKeyTypeForEcAlgorithms() {
            assertThat(KeyAlgorithm.ES256.getKeyType()).isEqualTo("EC");
            assertThat(KeyAlgorithm.ES384.getKeyType()).isEqualTo("EC");
            assertThat(KeyAlgorithm.ES512.getKeyType()).isEqualTo("EC");
        }
    }

    @Nested
    @DisplayName("Key Size Tests")
    class KeySizeTests {

        @Test
        @DisplayName("Should return correct key size for RSA algorithms")
        void shouldReturnCorrectKeySizeForRsaAlgorithms() {
            assertThat(KeyAlgorithm.RS256.getKeySize()).isEqualTo(2048);
            assertThat(KeyAlgorithm.RS384.getKeySize()).isEqualTo(3072);
            assertThat(KeyAlgorithm.RS512.getKeySize()).isEqualTo(4096);
        }

        @Test
        @DisplayName("Should return correct key size for EC algorithms")
        void shouldReturnCorrectKeySizeForEcAlgorithms() {
            assertThat(KeyAlgorithm.ES256.getKeySize()).isEqualTo(256);
            assertThat(KeyAlgorithm.ES384.getKeySize()).isEqualTo(384);
            assertThat(KeyAlgorithm.ES512.getKeySize()).isEqualTo(521);
        }
    }

    @Nested
    @DisplayName("isRsa Tests")
    class IsRsaTests {

        @Test
        @DisplayName("Should return true for RSA algorithms")
        void shouldReturnTrueForRsaAlgorithms() {
            assertThat(KeyAlgorithm.RS256.isRsa()).isTrue();
            assertThat(KeyAlgorithm.RS384.isRsa()).isTrue();
            assertThat(KeyAlgorithm.RS512.isRsa()).isTrue();
        }

        @Test
        @DisplayName("Should return false for EC algorithms")
        void shouldReturnFalseForEcAlgorithms() {
            assertThat(KeyAlgorithm.ES256.isRsa()).isFalse();
            assertThat(KeyAlgorithm.ES384.isRsa()).isFalse();
            assertThat(KeyAlgorithm.ES512.isRsa()).isFalse();
        }
    }

    @Nested
    @DisplayName("isEc Tests")
    class IsEcTests {

        @Test
        @DisplayName("Should return true for EC algorithms")
        void shouldReturnTrueForEcAlgorithms() {
            assertThat(KeyAlgorithm.ES256.isEc()).isTrue();
            assertThat(KeyAlgorithm.ES384.isEc()).isTrue();
            assertThat(KeyAlgorithm.ES512.isEc()).isTrue();
        }

        @Test
        @DisplayName("Should return false for RSA algorithms")
        void shouldReturnFalseForRsaAlgorithms() {
            assertThat(KeyAlgorithm.RS256.isEc()).isFalse();
            assertThat(KeyAlgorithm.RS384.isEc()).isFalse();
            assertThat(KeyAlgorithm.RS512.isEc()).isFalse();
        }
    }

    @Nested
    @DisplayName("fromValue Tests")
    class FromValueTests {

        @Test
        @DisplayName("Should convert RS256 string to KeyAlgorithm")
        void shouldConvertRS256StringToKeyAlgorithm() {
            KeyAlgorithm algorithm = KeyAlgorithm.fromValue("RS256");
            assertThat(algorithm).isEqualTo(KeyAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should convert RS384 string to KeyAlgorithm")
        void shouldConvertRS384StringToKeyAlgorithm() {
            KeyAlgorithm algorithm = KeyAlgorithm.fromValue("RS384");
            assertThat(algorithm).isEqualTo(KeyAlgorithm.RS384);
        }

        @Test
        @DisplayName("Should convert RS512 string to KeyAlgorithm")
        void shouldConvertRS512StringToKeyAlgorithm() {
            KeyAlgorithm algorithm = KeyAlgorithm.fromValue("RS512");
            assertThat(algorithm).isEqualTo(KeyAlgorithm.RS512);
        }

        @Test
        @DisplayName("Should convert ES256 string to KeyAlgorithm")
        void shouldConvertES256StringToKeyAlgorithm() {
            KeyAlgorithm algorithm = KeyAlgorithm.fromValue("ES256");
            assertThat(algorithm).isEqualTo(KeyAlgorithm.ES256);
        }

        @Test
        @DisplayName("Should convert ES384 string to KeyAlgorithm")
        void shouldConvertES384StringToKeyAlgorithm() {
            KeyAlgorithm algorithm = KeyAlgorithm.fromValue("ES384");
            assertThat(algorithm).isEqualTo(KeyAlgorithm.ES384);
        }

        @Test
        @DisplayName("Should convert ES512 string to KeyAlgorithm")
        void shouldConvertES512StringToKeyAlgorithm() {
            KeyAlgorithm algorithm = KeyAlgorithm.fromValue("ES512");
            assertThat(algorithm).isEqualTo(KeyAlgorithm.ES512);
        }

        @Test
        @DisplayName("Should throw exception for null input")
        void shouldThrowExceptionForNullInput() {
            assertThatThrownBy(() -> KeyAlgorithm.fromValue(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWS algorithm name cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception for empty string")
        void shouldThrowExceptionForEmptyString() {
            assertThatThrownBy(() -> KeyAlgorithm.fromValue(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWS algorithm name cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception for blank string")
        void shouldThrowExceptionForBlankString() {
            assertThatThrownBy(() -> KeyAlgorithm.fromValue("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWS algorithm name cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception for invalid algorithm")
        void shouldThrowExceptionForInvalidAlgorithm() {
            assertThatThrownBy(() -> KeyAlgorithm.fromValue("HS256"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("No matching KeyAlgorithm for JWS algorithm: HS256");
        }

        @Test
        @DisplayName("Should be case sensitive")
        void shouldBeCaseSensitive() {
            assertThatThrownBy(() -> KeyAlgorithm.fromValue("rs256"))
                    .isInstanceOf(IllegalArgumentException.class);
            
            assertThatThrownBy(() -> KeyAlgorithm.fromValue("ES256 "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should return correct algorithm for all supported values")
        void shouldReturnCorrectAlgorithmForAllSupportedValues() {
            assertThat(KeyAlgorithm.fromValue("RS256").getJwsAlgorithm().getName()).isEqualTo("RS256");
            assertThat(KeyAlgorithm.fromValue("RS384").getJwsAlgorithm().getName()).isEqualTo("RS384");
            assertThat(KeyAlgorithm.fromValue("RS512").getJwsAlgorithm().getName()).isEqualTo("RS512");
            assertThat(KeyAlgorithm.fromValue("ES256").getJwsAlgorithm().getName()).isEqualTo("ES256");
            assertThat(KeyAlgorithm.fromValue("ES384").getJwsAlgorithm().getName()).isEqualTo("ES384");
            assertThat(KeyAlgorithm.fromValue("ES512").getJwsAlgorithm().getName()).isEqualTo("ES512");
        }
    }
}
