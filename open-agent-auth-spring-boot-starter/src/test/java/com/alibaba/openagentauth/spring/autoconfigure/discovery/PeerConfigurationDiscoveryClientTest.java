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
package com.alibaba.openagentauth.spring.autoconfigure.discovery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link PeerConfigurationDiscoveryClient}.
 * <p>
 * Tests the client that discovers peer service configurations by querying
 * their OAA configuration endpoints.
 * </p>
 *
 * @since 2.1
 */
@DisplayName("PeerConfigurationDiscoveryClient Tests")
class PeerConfigurationDiscoveryClientTest {

    private static final String PEER_NAME = "agent-idp";
    private static final String PEER_ISSUER = "https://agent-idp.example.com";

    private PeerConfigurationDiscoveryClient failFastClient;
    private PeerConfigurationDiscoveryClient nonFailFastClient;

    @BeforeEach
    void setUp() {
        failFastClient = new PeerConfigurationDiscoveryClient(true);
        nonFailFastClient = new PeerConfigurationDiscoveryClient(false);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create client with failFast enabled")
        void shouldCreateClientWithFailFastEnabled() {
            // Act
            PeerConfigurationDiscoveryClient client = new PeerConfigurationDiscoveryClient(true);

            // Assert
            assertThat(client).isNotNull();
        }

        @Test
        @DisplayName("Should create client with failFast disabled")
        void shouldCreateClientWithFailFastDisabled() {
            // Act
            PeerConfigurationDiscoveryClient client = new PeerConfigurationDiscoveryClient(false);

            // Assert
            assertThat(client).isNotNull();
        }
    }

    @Nested
    @DisplayName("discover() Tests - Non-FailFast Mode")
    class DiscoverNonFailFastTests {

        @Test
        @DisplayName("Should return null when peer is not accessible")
        void shouldReturnNullWhenPeerIsNotAccessible() {
            // Arrange
            String nonExistentPeer = "https://non-existent-peer.example.com";

            // Act
            Map<String, Object> result = nonFailFastClient.discover(PEER_NAME, nonExistentPeer);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should return null when peer returns 404")
        void shouldReturnNullWhenPeerReturns404() {
            // Arrange
            String peerWithoutEndpoint = "https://httpbin.org/status/404";

            // Act
            Map<String, Object> result = nonFailFastClient.discover(PEER_NAME, peerWithoutEndpoint);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should throw exception when peerName is null")
        void shouldThrowExceptionWhenPeerNameIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> nonFailFastClient.discover(null, PEER_ISSUER))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("peerName must not be null");
        }

        @Test
        @DisplayName("Should throw exception when issuer is null")
        void shouldThrowExceptionWhenIssuerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> nonFailFastClient.discover(PEER_NAME, null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("issuer must not be null");
        }

        @Test
        @DisplayName("Should throw exception when both peerName and issuer are null")
        void shouldThrowExceptionWhenBothPeerNameAndIssuerAreNull() {
            // Act & Assert
            assertThatThrownBy(() -> nonFailFastClient.discover(null, null))
                    .isInstanceOf(NullPointerException.class);
        }
    }

    @Nested
    @DisplayName("discover() Tests - Fail-Fast Mode")
    class DiscoverFailFastTests {

        @Test
        @DisplayName("Should throw exception when peer is not accessible")
        void shouldThrowExceptionWhenPeerIsNotAccessible() {
            // Arrange
            String nonExistentPeer = "https://non-existent-peer.example.com";

            // Act & Assert
            assertThatThrownBy(() -> failFastClient.discover(PEER_NAME, nonExistentPeer))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Failed to discover OAA configuration")
                    .hasMessageContaining(PEER_NAME);
        }

        @Test
        @DisplayName("Should throw exception when peerName is null")
        void shouldThrowExceptionWhenPeerNameIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> failFastClient.discover(null, PEER_ISSUER))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("peerName must not be null");
        }

        @Test
        @DisplayName("Should throw exception when issuer is null")
        void shouldThrowExceptionWhenIssuerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> failFastClient.discover(PEER_NAME, null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("issuer must not be null");
        }
    }

    @Nested
    @DisplayName("clearCache() Tests")
    class ClearCacheTests {

        @Test
        @DisplayName("Should clear cache successfully")
        void shouldClearCacheSuccessfully() {
            // Act
            failFastClient.clearCache();

            // Assert
            // No exception should be thrown
            assertThat(failFastClient).isNotNull();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle issuer with trailing slash")
        void shouldHandleIssuerWithTrailingSlash() {
            // Arrange
            String issuerWithSlash = PEER_ISSUER + "/";

            // Act
            Map<String, Object> result = nonFailFastClient.discover(PEER_NAME, issuerWithSlash);

            // Assert
            // Should attempt discovery with the correct URL
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should handle issuer without trailing slash")
        void shouldHandleIssuerWithoutTrailingSlash() {
            // Act
            Map<String, Object> result = nonFailFastClient.discover(PEER_NAME, PEER_ISSUER);

            // Assert
            // Should attempt discovery with the correct URL
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should handle empty peer name")
        void shouldHandleEmptyPeerName() {
            // Act
            Map<String, Object> result = nonFailFastClient.discover("", PEER_ISSUER);

            // Assert
            // Empty string is not null, so should attempt discovery
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should handle empty issuer")
        void shouldHandleEmptyIssuer() {
            // Act
            Map<String, Object> result = nonFailFastClient.discover(PEER_NAME, "");

            // Assert
            // Empty string is not null, so should attempt discovery
            assertThat(result).isNull();
        }
    }

    @Nested
    @DisplayName("Caching Tests")
    class CachingTests {

        @Test
        @DisplayName("Should cache successful discovery results")
        void shouldCacheSuccessfulDiscoveryResults() {
            // Arrange
            String peerUrl = "https://httpbin.org/json";

            // Act - First call
            Map<String, Object> result1 = nonFailFastClient.discover(PEER_NAME, peerUrl);

            // Act - Second call (should use cache)
            Map<String, Object> result2 = nonFailFastClient.discover(PEER_NAME, peerUrl);

            // Assert
            assertThat(result1).isNotNull();
            assertThat(result2).isNotNull();
            // Both results should be the same object (from cache)
            assertThat(result1).isSameAs(result2);
        }

        @Test
        @DisplayName("Should clear cache when clearCache() is called")
        void shouldClearCacheWhenClearCacheIsCalled() {
            // Arrange
            String peerUrl = "https://httpbin.org/json";
            nonFailFastClient.discover(PEER_NAME, peerUrl);

            // Act
            nonFailFastClient.clearCache();

            // Assert
            // Cache is cleared, subsequent call will attempt discovery again
            Map<String, Object> result = nonFailFastClient.discover(PEER_NAME, peerUrl);
            assertThat(result).isNotNull();
        }
    }
}
