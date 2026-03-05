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
package com.alibaba.openagentauth.core.protocol.oauth2.par.store;

import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("InMemoryOAuth2ParRequestStore Tests")
class InMemoryOAuth2ParRequestStoreTest {

    private InMemoryOAuth2ParRequestStore store;
    private ParRequest parRequest;

    @BeforeEach
    void setUp() {
        store = new InMemoryOAuth2ParRequestStore();
        parRequest = ParRequest.builder()
            .responseType("code")
            .clientId("client123")
            .redirectUri("redirect-uri")
            .build();
    }

    @AfterEach
    void tearDown() {
        store.shutdown();
    }

    @Nested
    @DisplayName("Store Tests")
    class StoreTests {

        @Test
        @DisplayName("Should store PAR request successfully")
        void shouldStoreParRequestSuccessfully() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            long expiresIn = 3600;

            // Act
            store.store(requestUri, parRequest, expiresIn);

            // Assert
            ParRequest retrieved = store.retrieve(requestUri);
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo("client123");
        }

        @Test
        @DisplayName("Should throw exception when requestUri is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> store.store(null, parRequest, 3600))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestUri");
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";

            // Act & Assert
            assertThatThrownBy(() -> store.store(requestUri, null, 3600))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Request");
        }

        @Test
        @DisplayName("Should throw exception when expiresIn is zero")
        void shouldThrowExceptionWhenExpiresInIsZero() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";

            // Act & Assert
            assertThatThrownBy(() -> store.store(requestUri, parRequest, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expiresIn must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expiresIn is negative")
        void shouldThrowExceptionWhenExpiresInIsNegative() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";

            // Act & Assert
            assertThatThrownBy(() -> store.store(requestUri, parRequest, -100))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expiresIn must be positive");
        }

        @Test
        @DisplayName("Should overwrite existing request with same URI")
        void shouldOverwriteExistingRequestWithSameUri() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            ParRequest firstRequest = ParRequest.builder()
                .responseType("code")
                .clientId("client1")
                .redirectUri("redirect1")
                .build();
            ParRequest secondRequest = ParRequest.builder()
                .responseType("code")
                .clientId("client2")
                .redirectUri("redirect2")
                .build();

            // Act
            store.store(requestUri, firstRequest, 3600);
            store.store(requestUri, secondRequest, 3600);

            // Assert
            ParRequest retrieved = store.retrieve(requestUri);
            assertThat(retrieved.getClientId()).isEqualTo("client2");
        }
    }

    @Nested
    @DisplayName("Retrieve Tests")
    class RetrieveTests {

        @Test
        @DisplayName("Should retrieve stored PAR request")
        void shouldRetrieveStoredParRequest() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            store.store(requestUri, parRequest, 3600);

            // Act
            ParRequest retrieved = store.retrieve(requestUri);

            // Assert
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo("client123");
            assertThat(retrieved.getResponseType()).isEqualTo("code");
        }

        @Test
        @DisplayName("Should return null when requestUri is not found")
        void shouldReturnNullWhenRequestUriIsNotFound() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:notfound";

            // Act
            ParRequest retrieved = store.retrieve(requestUri);

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should throw exception when requestUri is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> store.retrieve(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestUri");
        }

        @Test
        @DisplayName("Should return null when request is expired")
        void shouldReturnNullWhenRequestIsExpired() throws InterruptedException {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:expired";
            store.store(requestUri, parRequest, 1);
            
            // Wait for expiration
            Thread.sleep(1100);

            // Act
            ParRequest retrieved = store.retrieve(requestUri);

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should remove expired request after retrieval")
        void shouldRemoveExpiredRequestAfterRetrieval() throws InterruptedException {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:expired";
            store.store(requestUri, parRequest, 1);
            
            // Wait for expiration
            Thread.sleep(1100);

            // Act
            store.retrieve(requestUri);
            boolean removed = store.remove(requestUri);

            // Assert
            assertThat(removed).isFalse();
        }
    }

    @Nested
    @DisplayName("Remove Tests")
    class RemoveTests {

        @Test
        @DisplayName("Should remove existing PAR request")
        void shouldRemoveExistingParRequest() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            store.store(requestUri, parRequest, 3600);

            // Act
            boolean removed = store.remove(requestUri);

            // Assert
            assertThat(removed).isTrue();
            assertThat(store.retrieve(requestUri)).isNull();
        }

        @Test
        @DisplayName("Should return false when requestUri is not found")
        void shouldReturnFalseWhenRequestUriIsNotFound() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:notfound";

            // Act
            boolean removed = store.remove(requestUri);

            // Assert
            assertThat(removed).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when requestUri is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> store.remove(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestUri");
        }
    }

    @Nested
    @DisplayName("Shutdown Tests")
    class ShutdownTests {

        @Test
        @DisplayName("Should shutdown successfully")
        void shouldShutdownSuccessfully() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";
            store.store(requestUri, parRequest, 3600);

            // Act
            store.shutdown();

            // Assert - should not throw exception
        }
    }

    @Nested
    @DisplayName("Cleanup Tests")
    class CleanupTests {

        @Test
        @DisplayName("Should cleanup expired requests automatically")
        void shouldCleanupExpiredRequestsAutomatically() throws InterruptedException {
            // Arrange
            String expiredUri = "urn:ietf:params:oauth:request_uri:expired";
            String validUri = "urn:ietf:params:oauth:request_uri:valid";
            
            store.store(expiredUri, parRequest, 1);
            store.store(validUri, parRequest, 3600);
            
            // Wait for expiration and cleanup
            Thread.sleep(2000);

            // Act
            ParRequest expiredRequest = store.retrieve(expiredUri);
            ParRequest validRequest = store.retrieve(validUri);

            // Assert
            assertThat(expiredRequest).isNull();
            assertThat(validRequest).isNotNull();
        }
    }
}