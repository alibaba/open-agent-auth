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
package com.alibaba.openagentauth.framework.model.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for JwksResponse class.
 * Tests the builder pattern, getters, and immutable collections.
 */
@DisplayName("JwksResponse Tests")
class JwksResponseTest {

    @Test
    @DisplayName("Should create JwksResponse with single key using builder")
    void shouldCreateJwksResponseWithSingleKey() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("EC")
                .use("sig")
                .keyId("test-key-id")
                .algorithm("ES256")
                .parameter("x", "test-x-value")
                .parameter("y", "test-y-value")
                .build();

        JwksResponse response = JwksResponse.builder()
                .addKey(jwk)
                .build();

        // Assert
        assertNotNull(response);
        assertNotNull(response.getKeys());
        assertEquals(1, response.getKeys().size());
        assertEquals(jwk, response.getKeys().get(0));
    }

    @Test
    @DisplayName("Should create JwksResponse with multiple keys using builder")
    void shouldCreateJwksResponseWithMultipleKeys() {
        // Arrange & Act
        JwksResponse.Jwk jwk1 = JwksResponse.Jwk.builder()
                .kty("EC")
                .keyId("key-1")
                .algorithm("ES256")
                .build();

        JwksResponse.Jwk jwk2 = JwksResponse.Jwk.builder()
                .kty("RSA")
                .keyId("key-2")
                .algorithm("RS256")
                .build();

        JwksResponse response = JwksResponse.builder()
                .addKey(jwk1)
                .addKey(jwk2)
                .build();

        // Assert
        assertNotNull(response);
        assertEquals(2, response.getKeys().size());
        assertEquals(jwk1, response.getKeys().get(0));
        assertEquals(jwk2, response.getKeys().get(1));
    }

    @Test
    @DisplayName("Should create JwksResponse with additional metadata")
    void shouldCreateJwksResponseWithAdditionalMetadata() {
        // Arrange & Act
        JwksResponse response = JwksResponse.builder()
                .addMetadata("custom-field", "custom-value")
                .addMetadata("another-field", 123)
                .build();

        // Assert
        assertNotNull(response);
        assertNotNull(response.getAdditionalMetadata());
        assertEquals(2, response.getAdditionalMetadata().size());
        assertEquals("custom-value", response.getAdditionalMetadata().get("custom-field"));
        assertEquals(123, response.getAdditionalMetadata().get("another-field"));
    }

    @Test
    @DisplayName("Should create JwksResponse with keys and metadata")
    void shouldCreateJwksResponseWithKeysAndMetadata() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("EC")
                .keyId("test-key")
                .build();

        JwksResponse response = JwksResponse.builder()
                .addKey(jwk)
                .addMetadata("version", "1.0")
                .build();

        // Assert
        assertNotNull(response);
        assertEquals(1, response.getKeys().size());
        assertEquals(1, response.getAdditionalMetadata().size());
        assertEquals("1.0", response.getAdditionalMetadata().get("version"));
    }

    @Test
    @DisplayName("Should return immutable keys list")
    void shouldReturnImmutableKeysList() {
        // Arrange
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("EC")
                .keyId("test-key")
                .build();

        JwksResponse response = JwksResponse.builder()
                .addKey(jwk)
                .build();

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () -> {
            response.getKeys().add(JwksResponse.Jwk.builder().build());
        });
    }

    @Test
    @DisplayName("Should return immutable metadata map")
    void shouldReturnImmutableMetadataMap() {
        // Arrange
        JwksResponse response = JwksResponse.builder()
                .addMetadata("key", "value")
                .build();

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () -> {
            response.getAdditionalMetadata().put("new-key", "new-value");
        });
    }

    @Test
    @DisplayName("Should return empty keys list when no keys added")
    void shouldReturnEmptyKeysListWhenNoKeysAdded() {
        // Arrange & Act
        JwksResponse response = JwksResponse.builder().build();

        // Assert
        assertNotNull(response.getKeys());
        assertTrue(response.getKeys().isEmpty());
    }

    @Test
    @DisplayName("Should return empty metadata map when no metadata added")
    void shouldReturnEmptyMetadataMapWhenNoMetadataAdded() {
        // Arrange & Act
        JwksResponse response = JwksResponse.builder().build();

        // Assert
        assertNotNull(response.getAdditionalMetadata());
        assertTrue(response.getAdditionalMetadata().isEmpty());
    }

    @Test
    @DisplayName("Should support builder pattern chaining")
    void shouldSupportBuilderPatternChaining() {
        // Arrange & Act
        JwksResponse response = JwksResponse.builder()
                .addMetadata("key1", "value1")
                .addMetadata("key2", "value2")
                .addKey(JwksResponse.Jwk.builder().kty("EC").build())
                .addKey(JwksResponse.Jwk.builder().kty("RSA").build())
                .build();

        // Assert
        assertEquals(2, response.getAdditionalMetadata().size());
        assertEquals(2, response.getKeys().size());
    }

    @Test
    @DisplayName("Jwk builder should set all fields correctly")
    void jwkBuilderShouldSetAllFieldsCorrectly() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("EC")
                .use("sig")
                .keyId("my-key-id")
                .algorithm("ES256")
                .parameter("x", "x-value")
                .parameter("y", "y-value")
                .parameter("crv", "P-256")
                .build();

        // Assert
        assertEquals("EC", jwk.getKty());
        assertEquals("sig", jwk.getUse());
        assertEquals("my-key-id", jwk.getKeyId());
        assertEquals("ES256", jwk.getAlgorithm());
        assertEquals(3, jwk.getParameters().size());
        assertEquals("x-value", jwk.getParameters().get("x"));
        assertEquals("y-value", jwk.getParameters().get("y"));
        assertEquals("P-256", jwk.getParameters().get("crv"));
    }

    @Test
    @DisplayName("Jwk builder should return immutable parameters map")
    void jwkBuilderShouldReturnImmutableParametersMap() {
        // Arrange
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .parameter("key", "value")
                .build();

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () -> {
            jwk.getParameters().put("new-key", "new-value");
        });
    }

    @Test
    @DisplayName("Jwk builder should handle null key type")
    void jwkBuilderShouldHandleNullKeyType() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .keyId("test-key")
                .build();

        // Assert
        assertNull(jwk.getKty());
        assertEquals("test-key", jwk.getKeyId());
    }

    @Test
    @DisplayName("Jwk builder should handle null use field")
    void jwkBuilderShouldHandleNullUseField() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("EC")
                .build();

        // Assert
        assertEquals("EC", jwk.getKty());
        assertNull(jwk.getUse());
    }

    @Test
    @DisplayName("Jwk builder should handle null algorithm")
    void jwkBuilderShouldHandleNullAlgorithm() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("RSA")
                .keyId("key-1")
                .build();

        // Assert
        assertEquals("RSA", jwk.getKty());
        assertEquals("key-1", jwk.getKeyId());
        assertNull(jwk.getAlgorithm());
    }

    @Test
    @DisplayName("Jwk builder should return empty parameters when none set")
    void jwkBuilderShouldReturnEmptyParametersWhenNoneSet() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .kty("EC")
                .build();

        // Assert
        assertNotNull(jwk.getParameters());
        assertTrue(jwk.getParameters().isEmpty());
    }

    @Test
    @DisplayName("Jwk builder should support multiple parameters")
    void jwkBuilderShouldSupportMultipleParameters() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .parameter("param1", "value1")
                .parameter("param2", "value2")
                .parameter("param3", "value3")
                .build();

        // Assert
        assertEquals(3, jwk.getParameters().size());
        assertEquals("value1", jwk.getParameters().get("param1"));
        assertEquals("value2", jwk.getParameters().get("param2"));
        assertEquals("value3", jwk.getParameters().get("param3"));
    }

    @Test
    @DisplayName("Jwk builder should support parameter value override")
    void jwkBuilderShouldSupportParameterOverride() {
        // Arrange & Act
        JwksResponse.Jwk jwk = JwksResponse.Jwk.builder()
                .parameter("key", "original-value")
                .parameter("key", "updated-value")
                .build();

        // Assert
        assertEquals(1, jwk.getParameters().size());
        assertEquals("updated-value", jwk.getParameters().get("key"));
    }
}
