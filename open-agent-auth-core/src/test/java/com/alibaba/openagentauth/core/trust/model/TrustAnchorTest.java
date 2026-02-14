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
package com.alibaba.openagentauth.core.trust.model;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TrustAnchor}.
 */
@DisplayName("TrustAnchor Tests")
class TrustAnchorTest {

    private static final String VALID_KEY_ID = "key-123";
    private static final String VALID_DOMAIN_ID = "wimse://example.com";

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create trust anchor with valid parameters")
        void shouldCreateTrustAnchorWithValidParameters() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            // Act
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Assert
            assertThat(anchor).isNotNull();
            assertThat(anchor.getPublicKey()).isEqualTo(keyPair.getPublic());
            assertThat(anchor.getKeyId()).isEqualTo(VALID_KEY_ID);
            assertThat(anchor.getAlgorithm()).isEqualTo(algorithm);
            assertThat(anchor.getTrustDomain()).isEqualTo(trustDomain);
        }

        @Test
        @DisplayName("Should throw exception when public key is null")
        void shouldThrowExceptionWhenPublicKeyIsNull() {
            // Arrange
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            // Act & Assert
            assertThatThrownBy(() -> new TrustAnchor(null, VALID_KEY_ID, algorithm, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Public key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when key ID is null")
        void shouldThrowExceptionWhenKeyIdIsNull() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            // Act & Assert
            assertThatThrownBy(() -> new TrustAnchor(keyPair.getPublic(), null, algorithm, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when key ID is empty")
        void shouldThrowExceptionWhenKeyIdIsEmpty() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            // Act & Assert
            assertThatThrownBy(() -> new TrustAnchor(keyPair.getPublic(), "", algorithm, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when key ID is whitespace")
        void shouldThrowExceptionWhenKeyIdIsWhitespace() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            // Act & Assert
            assertThatThrownBy(() -> new TrustAnchor(keyPair.getPublic(), "   ", algorithm, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);

            // Act & Assert
            assertThatThrownBy(() -> new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, null, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Algorithm cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when trust domain is null")
        void shouldThrowExceptionWhenTrustDomainIsNull() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            // Act & Assert
            assertThatThrownBy(() -> new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Trust domain cannot be null");
        }
    }

    @Nested
    @DisplayName("Getters")
    class GetterTests {

        @Test
        @DisplayName("Should return correct public key")
        void shouldReturnCorrectPublicKey() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act
            var result = anchor.getPublicKey();

            // Assert
            assertThat(result).isEqualTo(keyPair.getPublic());
        }

        @Test
        @DisplayName("Should return correct key ID")
        void shouldReturnCorrectKeyId() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act
            var result = anchor.getKeyId();

            // Assert
            assertThat(result).isEqualTo(VALID_KEY_ID);
        }

        @Test
        @DisplayName("Should return correct algorithm")
        void shouldReturnCorrectAlgorithm() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act
            var result = anchor.getAlgorithm();

            // Assert
            assertThat(result).isEqualTo(algorithm);
        }

        @Test
        @DisplayName("Should return correct trust domain")
        void shouldReturnCorrectTrustDomain() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act
            var result = anchor.getTrustDomain();

            // Assert
            assertThat(result).isEqualTo(trustDomain);
        }
    }

    @Nested
    @DisplayName("equals and hashCode")
    class EqualityTests {

        @Test
        @DisplayName("Should be equal when key IDs and trust domains are same")
        void shouldBeEqualWhenKeyIdAndTrustDomainAreSame() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            KeyPair keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            TrustAnchor anchor1 = new TrustAnchor(keyPair1.getPublic(), VALID_KEY_ID, algorithm, trustDomain);
            TrustAnchor anchor2 = new TrustAnchor(keyPair2.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act & Assert
            assertThat(anchor1).isEqualTo(anchor2);
            assertThat(anchor1.hashCode()).isEqualTo(anchor2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when key IDs are different")
        void shouldNotBeEqualWhenKeyIdsAreDifferent() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            TrustAnchor anchor1 = new TrustAnchor(keyPair.getPublic(), "key-1", algorithm, trustDomain);
            TrustAnchor anchor2 = new TrustAnchor(keyPair.getPublic(), "key-2", algorithm, trustDomain);

            // Act & Assert
            assertThat(anchor1).isNotEqualTo(anchor2);
        }

        @Test
        @DisplayName("Should not be equal when trust domains are different")
        void shouldNotBeEqualWhenTrustDomainsAreDifferent() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain domain1 = new TrustDomain("wimse://domain1.com");
            TrustDomain domain2 = new TrustDomain("wimse://domain2.com");
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;

            TrustAnchor anchor1 = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, domain1);
            TrustAnchor anchor2 = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, domain2);

            // Act & Assert
            assertThat(anchor1).isNotEqualTo(anchor2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act & Assert
            assertThat(anchor).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act & Assert
            assertThat(anchor).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("toString")
    class ToStringTests {

        @Test
        @DisplayName("Should contain key ID in toString")
        void shouldContainKeyIdInToString() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act
            String result = anchor.toString();

            // Assert
            assertThat(result).contains(VALID_KEY_ID);
        }

        @Test
        @DisplayName("Should contain trust domain in toString")
        void shouldContainTrustDomainInToString() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustDomain trustDomain = new TrustDomain(VALID_DOMAIN_ID);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            TrustAnchor anchor = new TrustAnchor(keyPair.getPublic(), VALID_KEY_ID, algorithm, trustDomain);

            // Act
            String result = anchor.toString();

            // Assert
            assertThat(result).contains(VALID_DOMAIN_ID);
        }
    }
}
