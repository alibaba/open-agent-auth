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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for OpenIdConfiguration class.
 * Tests the builder pattern, default values, getters, and immutable collections.
 */
@DisplayName("OpenIdConfiguration Tests")
class OpenIdConfigurationTest {

    @Test
    @DisplayName("Should create OpenIdConfiguration with all fields using builder")
    void shouldCreateOpenIdConfigurationWithAllFields() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .authorizationEndpoint("https://example.com/oauth2/authorize")
                .tokenEndpoint("https://example.com/oauth2/token")
                .userInfoEndpoint("https://example.com/oauth2/userinfo")
                .jwksUri("https://example.com/.well-known/jwks.json")
                .responseTypesSupported("code id_token")
                .subjectTypesSupported("public pairwise")
                .idTokenSigningAlgValuesSupported("RS256 ES256")
                .build();

        // Assert
        assertNotNull(config);
        assertEquals("https://example.com", config.getIssuer());
        assertEquals("https://example.com/oauth2/authorize", config.getAuthorizationEndpoint());
        assertEquals("https://example.com/oauth2/token", config.getTokenEndpoint());
        assertEquals("https://example.com/oauth2/userinfo", config.getUserInfoEndpoint());
        assertEquals("https://example.com/.well-known/jwks.json", config.getJwksUri());
        assertEquals("code id_token", config.getResponseTypesSupported());
        assertEquals("public pairwise", config.getSubjectTypesSupported());
        assertEquals("RS256 ES256", config.getIdTokenSigningAlgValuesSupported());
    }

    @Test
    @DisplayName("Should use default values for optional fields")
    void shouldUseDefaultValuesForOptionalFields() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .authorizationEndpoint("https://example.com/oauth2/authorize")
                .tokenEndpoint("https://example.com/oauth2/token")
                .jwksUri("https://example.com/.well-known/jwks.json")
                .build();

        // Assert
        assertEquals("code", config.getResponseTypesSupported());
        assertEquals("public", config.getSubjectTypesSupported());
        assertEquals("RS256", config.getIdTokenSigningAlgValuesSupported());
    }

    @Test
    @DisplayName("Should create OpenIdConfiguration with additional metadata")
    void shouldCreateOpenIdConfigurationWithAdditionalMetadata() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .authorizationEndpoint("https://example.com/oauth2/authorize")
                .tokenEndpoint("https://example.com/oauth2/token")
                .jwksUri("https://example.com/.well-known/jwks.json")
                .addMetadata("custom-field", "custom-value")
                .addMetadata("version", "2.0")
                .build();

        // Assert
        assertNotNull(config.getAdditionalMetadata());
        assertEquals(2, config.getAdditionalMetadata().size());
        assertEquals("custom-value", config.getAdditionalMetadata().get("custom-field"));
        assertEquals("2.0", config.getAdditionalMetadata().get("version"));
    }

    @Test
    @DisplayName("Should return immutable metadata map")
    void shouldReturnImmutableMetadataMap() {
        // Arrange
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .addMetadata("key", "value")
                .build();

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () -> {
            config.getAdditionalMetadata().put("new-key", "new-value");
        });
    }

    @Test
    @DisplayName("Should return empty metadata map when no metadata added")
    void shouldReturnEmptyMetadataMapWhenNoMetadataAdded() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .build();

        // Assert
        assertNotNull(config.getAdditionalMetadata());
        assertTrue(config.getAdditionalMetadata().isEmpty());
    }

    @Test
    @DisplayName("Should support builder pattern chaining")
    void shouldSupportBuilderPatternChaining() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .authorizationEndpoint("https://example.com/oauth2/authorize")
                .tokenEndpoint("https://example.com/oauth2/token")
                .jwksUri("https://example.com/.well-known/jwks.json")
                .addMetadata("key1", "value1")
                .addMetadata("key2", "value2")
                .responseTypesSupported("code")
                .subjectTypesSupported("public")
                .build();

        // Assert
        assertEquals("https://example.com", config.getIssuer());
        assertEquals(2, config.getAdditionalMetadata().size());
    }

    @Test
    @DisplayName("Should handle null issuer")
    void shouldHandleNullIssuer() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer(null)
                .build();

        // Assert
        assertNull(config.getIssuer());
    }

    @Test
    @DisplayName("Should handle null endpoints")
    void shouldHandleNullEndpoints() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .authorizationEndpoint(null)
                .tokenEndpoint(null)
                .userInfoEndpoint(null)
                .jwksUri(null)
                .build();

        // Assert
        assertNull(config.getAuthorizationEndpoint());
        assertNull(config.getTokenEndpoint());
        assertNull(config.getUserInfoEndpoint());
        assertNull(config.getJwksUri());
    }

    @Test
    @DisplayName("Should allow overriding default response types")
    void shouldAllowOverridingDefaultResponseTypes() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .responseTypesSupported("id_token token")
                .build();

        // Assert
        assertEquals("id_token token", config.getResponseTypesSupported());
    }

    @Test
    @DisplayName("Should allow overriding default subject types")
    void shouldAllowOverridingDefaultSubjectTypes() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .subjectTypesSupported("pairwise")
                .build();

        // Assert
        assertEquals("pairwise", config.getSubjectTypesSupported());
    }

    @Test
    @DisplayName("Should allow overriding default signing algorithms")
    void shouldAllowOverridingDefaultSigningAlgorithms() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .idTokenSigningAlgValuesSupported("ES384 ES512")
                .build();

        // Assert
        assertEquals("ES384 ES512", config.getIdTokenSigningAlgValuesSupported());
    }

    @Test
    @DisplayName("Should support multiple metadata entries")
    void shouldSupportMultipleMetadataEntries() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .addMetadata("field1", "value1")
                .addMetadata("field2", "value2")
                .addMetadata("field3", 123)
                .addMetadata("field4", true)
                .build();

        // Assert
        assertEquals(4, config.getAdditionalMetadata().size());
        assertEquals("value1", config.getAdditionalMetadata().get("field1"));
        assertEquals("value2", config.getAdditionalMetadata().get("field2"));
        assertEquals(123, config.getAdditionalMetadata().get("field3"));
        assertEquals(true, config.getAdditionalMetadata().get("field4"));
    }

    @Test
    @DisplayName("Should support metadata value override")
    void shouldSupportMetadataValueOverride() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .addMetadata("key", "original")
                .addMetadata("key", "updated")
                .build();

        // Assert
        assertEquals(1, config.getAdditionalMetadata().size());
        assertEquals("updated", config.getAdditionalMetadata().get("key"));
    }

    @Test
    @DisplayName("Should handle empty string values")
    void shouldHandleEmptyStringValues() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .authorizationEndpoint("")
                .tokenEndpoint("")
                .responseTypesSupported("")
                .build();

        // Assert
        assertEquals("", config.getAuthorizationEndpoint());
        assertEquals("", config.getTokenEndpoint());
        assertEquals("", config.getResponseTypesSupported());
    }

    @Test
    @DisplayName("Should create minimal valid configuration")
    void shouldCreateMinimalValidConfiguration() {
        // Arrange & Act
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .build();

        // Assert
        assertNotNull(config);
        assertEquals("https://example.com", config.getIssuer());
        assertNull(config.getAuthorizationEndpoint());
        assertNull(config.getTokenEndpoint());
        assertNull(config.getUserInfoEndpoint());
        assertNull(config.getJwksUri());
        assertEquals("code", config.getResponseTypesSupported());
        assertEquals("public", config.getSubjectTypesSupported());
        assertEquals("RS256", config.getIdTokenSigningAlgValuesSupported());
    }

    @Test
    @DisplayName("Should handle complex metadata values")
    void shouldHandleComplexMetadataValues() {
        // Arrange & Act
        Map<String, Object> complexValue = Map.of("nested", "value");
        OpenIdConfiguration config = OpenIdConfiguration.builder()
                .issuer("https://example.com")
                .addMetadata("complex", complexValue)
                .build();

        // Assert
        assertEquals(1, config.getAdditionalMetadata().size());
        assertEquals(complexValue, config.getAdditionalMetadata().get("complex"));
    }
}
