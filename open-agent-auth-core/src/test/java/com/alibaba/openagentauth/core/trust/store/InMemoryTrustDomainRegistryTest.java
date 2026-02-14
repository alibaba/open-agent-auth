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
package com.alibaba.openagentauth.core.trust.store;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.trust.model.TrustAnchor;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryTrustDomainRegistry}.
 */
@DisplayName("InMemoryTrustDomainRegistry Tests")
class InMemoryTrustDomainRegistryTest {

    private InMemoryTrustDomainRegistry registry;
    private TrustDomain testDomain;
    private TrustAnchor testAnchor;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        registry = new InMemoryTrustDomainRegistry();
        testDomain = new TrustDomain("wimse://example.com");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        testAnchor = new TrustAnchor(keyPair.getPublic(), "key-123", KeyAlgorithm.RS256, testDomain);
    }

    @Nested
    @DisplayName("registerTrustAnchor")
    class RegisterTrustAnchorTests {

        @Test
        @DisplayName("Should register trust anchor successfully")
        void shouldRegisterTrustAnchorSuccessfully() {
            // Act
            registry.registerTrustAnchor(testAnchor);

            // Assert
            Optional<TrustAnchor> result = registry.getTrustAnchor("key-123", testDomain);
            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo(testAnchor);
        }

        @Test
        @DisplayName("Should overwrite existing trust anchor with same key")
        void shouldOverwriteExistingTrustAnchor() throws NoSuchAlgorithmException {
            // Arrange
            registry.registerTrustAnchor(testAnchor);
            KeyPair newKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustAnchor newAnchor = new TrustAnchor(newKeyPair.getPublic(), "key-123", KeyAlgorithm.RS256, testDomain);

            // Act
            registry.registerTrustAnchor(newAnchor);

            // Assert
            Optional<TrustAnchor> result = registry.getTrustAnchor("key-123", testDomain);
            assertThat(result).isPresent();
            assertThat(result.get().getPublicKey()).isEqualTo(newKeyPair.getPublic());
        }

        @Test
        @DisplayName("Should throw exception when trust anchor is null")
        void shouldThrowExceptionWhenTrustAnchorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> registry.registerTrustAnchor(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Trust anchor cannot be null");
        }
    }

    @Nested
    @DisplayName("getTrustAnchor")
    class GetTrustAnchorTests {

        @Test
        @DisplayName("Should return trust anchor when found")
        void shouldReturnTrustAnchorWhenFound() {
            // Arrange
            registry.registerTrustAnchor(testAnchor);

            // Act
            Optional<TrustAnchor> result = registry.getTrustAnchor("key-123", testDomain);

            // Assert
            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo(testAnchor);
        }

        @Test
        @DisplayName("Should return empty when trust anchor not found")
        void shouldReturnEmptyWhenTrustAnchorNotFound() {
            // Act
            Optional<TrustAnchor> result = registry.getTrustAnchor("key-999", testDomain);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when key ID is null")
        void shouldReturnEmptyWhenKeyIdIsNull() {
            // Act
            Optional<TrustAnchor> result = registry.getTrustAnchor(null, testDomain);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when trust domain is null")
        void shouldReturnEmptyWhenTrustDomainIsNull() {
            // Act
            Optional<TrustAnchor> result = registry.getTrustAnchor("key-123", null);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getTrustAnchors")
    class GetTrustAnchorsTests {

        @Test
        @DisplayName("Should return all trust anchors for a domain")
        void shouldReturnAllTrustAnchorsForDomain() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            KeyPair keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustAnchor anchor1 = new TrustAnchor(keyPair1.getPublic(), "key-1", KeyAlgorithm.RS256, testDomain);
            TrustAnchor anchor2 = new TrustAnchor(keyPair2.getPublic(), "key-2", KeyAlgorithm.RS256, testDomain);
            
            registry.registerTrustAnchor(anchor1);
            registry.registerTrustAnchor(anchor2);

            // Act
            List<TrustAnchor> result = registry.getTrustAnchors(testDomain);

            // Assert
            assertThat(result).hasSize(2);
            assertThat(result).contains(anchor1, anchor2);
        }

        @Test
        @DisplayName("Should return empty list when no trust anchors for domain")
        void shouldReturnEmptyListWhenNoTrustAnchorsForDomain() {
            // Act
            List<TrustAnchor> result = registry.getTrustAnchors(testDomain);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list when trust domain is null")
        void shouldReturnEmptyListWhenTrustDomainIsNull() {
            // Act
            List<TrustAnchor> result = registry.getTrustAnchors(null);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("removeTrustAnchor")
    class RemoveTrustAnchorTests {

        @Test
        @DisplayName("Should remove trust anchor successfully")
        void shouldRemoveTrustAnchorSuccessfully() {
            // Arrange
            registry.registerTrustAnchor(testAnchor);

            // Act
            registry.removeTrustAnchor("key-123", testDomain);

            // Assert
            Optional<TrustAnchor> result = registry.getTrustAnchor("key-123", testDomain);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should do nothing when trust anchor not found")
        void shouldDoNothingWhenTrustAnchorNotFound() {
            // Act & Assert - should not throw exception
            registry.removeTrustAnchor("key-999", testDomain);
        }

        @Test
        @DisplayName("Should do nothing when key ID is null")
        void shouldDoNothingWhenKeyIdIsNull() {
            // Act & Assert - should not throw exception
            registry.removeTrustAnchor(null, testDomain);
        }

        @Test
        @DisplayName("Should do nothing when trust domain is null")
        void shouldDoNothingWhenTrustDomainIsNull() {
            // Act & Assert - should not throw exception
            registry.removeTrustAnchor("key-123", null);
        }
    }

    @Nested
    @DisplayName("hasTrustAnchor")
    class HasTrustAnchorTests {

        @Test
        @DisplayName("Should return true when trust anchor exists")
        void shouldReturnTrueWhenTrustAnchorExists() {
            // Arrange
            registry.registerTrustAnchor(testAnchor);

            // Act
            boolean result = registry.hasTrustAnchor("key-123", testDomain);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false when trust anchor not found")
        void shouldReturnFalseWhenTrustAnchorNotFound() {
            // Act
            boolean result = registry.hasTrustAnchor("key-999", testDomain);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when key ID is null")
        void shouldReturnFalseWhenKeyIdIsNull() {
            // Act
            boolean result = registry.hasTrustAnchor(null, testDomain);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when trust domain is null")
        void shouldReturnFalseWhenTrustDomainIsNull() {
            // Act
            boolean result = registry.hasTrustAnchor("key-123", null);

            // Assert
            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("listTrustDomains")
    class ListTrustDomainsTests {

        @Test
        @DisplayName("Should return all unique trust domains")
        void shouldReturnAllUniqueTrustDomains() throws NoSuchAlgorithmException {
            // Arrange
            TrustDomain domain1 = new TrustDomain("wimse://domain1.com");
            TrustDomain domain2 = new TrustDomain("wimse://domain2.com");
            
            KeyPair keyPair1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            KeyPair keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            KeyPair keyPair3 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            
            TrustAnchor anchor1 = new TrustAnchor(keyPair1.getPublic(), "key-1", KeyAlgorithm.RS256, domain1);
            TrustAnchor anchor2 = new TrustAnchor(keyPair2.getPublic(), "key-2", KeyAlgorithm.RS256, domain1);
            TrustAnchor anchor3 = new TrustAnchor(keyPair3.getPublic(), "key-3", KeyAlgorithm.RS256, domain2);
            
            registry.registerTrustAnchor(anchor1);
            registry.registerTrustAnchor(anchor2);
            registry.registerTrustAnchor(anchor3);

            // Act
            List<TrustDomain> result = registry.listTrustDomains();

            // Assert
            assertThat(result).hasSize(2);
            assertThat(result).contains(domain1, domain2);
        }

        @Test
        @DisplayName("Should return empty list when no trust domains")
        void shouldReturnEmptyListWhenNoTrustDomains() {
            // Act
            List<TrustDomain> result = registry.listTrustDomains();

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("clear")
    class ClearTests {

        @Test
        @DisplayName("Should clear all trust anchors")
        void shouldClearAllTrustAnchors() throws NoSuchAlgorithmException {
            // Arrange
            KeyPair keyPair1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            KeyPair keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            TrustAnchor anchor1 = new TrustAnchor(keyPair1.getPublic(), "key-1", KeyAlgorithm.RS256, testDomain);
            TrustAnchor anchor2 = new TrustAnchor(keyPair2.getPublic(), "key-2", KeyAlgorithm.RS256, testDomain);
            
            registry.registerTrustAnchor(anchor1);
            registry.registerTrustAnchor(anchor2);

            // Act
            registry.clear();

            // Assert
            assertThat(registry.getTrustAnchors(testDomain)).isEmpty();
            assertThat(registry.listTrustDomains()).isEmpty();
        }

        @Test
        @DisplayName("Should handle clear when registry is empty")
        void shouldHandleClearWhenRegistryIsEmpty() {
            // Act & Assert - should not throw exception
            registry.clear();
        }
    }
}
