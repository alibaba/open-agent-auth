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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WitExtractor}.
 * Tests verify that WIT can be correctly extracted from DCR requests.
 */
@DisplayName("WIT Extractor Tests")
class WitExtractorTest {

    @Nested
    @DisplayName("Extract WIT from DCR Request Tests")
    class ExtractFromDcrRequestTests {

        @Test
        @DisplayName("Priority 1: Should extract WIT from softwareStatement field")
        void shouldExtractWitFromSoftwareStatementField() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .softwareStatement("eyJ.software.statement")
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("eyJ.software.statement");
        }

        @Test
        @DisplayName("Priority 1: softwareStatement field takes precedence over additionalParameters")
        void shouldPreferSoftwareStatementFieldOverAdditionalParameters() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("software_statement", "from-additional-params");
            additionalParams.put(WitConstants.WIT_PARAM, "from-legacy-wit");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .softwareStatement("from-field")
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("from-field");
        }

        @Test
        @DisplayName("Priority 2: Should extract WIT from software_statement in additionalParameters")
        void shouldExtractWitFromSoftwareStatementInAdditionalParameters() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("software_statement", "eyJ.from.additional");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("eyJ.from.additional");
        }

        @Test
        @DisplayName("Priority 2: software_statement in additionalParameters takes precedence over legacy wit")
        void shouldPreferSoftwareStatementOverLegacyWit() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("software_statement", "from-software-statement");
            additionalParams.put(WitConstants.WIT_PARAM, "from-legacy-wit");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("from-software-statement");
        }

        @Test
        @DisplayName("Priority 3: Should fall back to legacy wit parameter")
        void shouldExtractWitFromLegacyWitParameter() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "test.wit.jwt.string");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("test.wit.jwt.string");
        }

        @Test
        @DisplayName("Should return null when WIT is not present in additional parameters")
        void shouldReturnNullWhenWitNotPresent() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("other_param", "value");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isNull();
        }

        @Test
        @DisplayName("Should return null when additional parameters is null and no softwareStatement")
        void shouldReturnNullWhenAdditionalParametersIsNull() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isNull();
        }

        @Test
        @DisplayName("Should return null when WIT parameter is not a string")
        void shouldReturnNullWhenWitParameterIsNotString() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, 12345);

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isNull();
        }

        @Test
        @DisplayName("Should return null when WIT parameter is an object")
        void shouldReturnNullWhenWitParameterIsObject() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, Map.of("key", "value"));

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isNull();
        }

        @Test
        @DisplayName("Should throw exception when DCR request is null")
        void shouldThrowExceptionWhenDcrRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> WitExtractor.extractFromDcrRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("DCR request");
        }

        @Test
        @DisplayName("Should skip blank softwareStatement field and fall back")
        void shouldSkipBlankSoftwareStatementField() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "fallback-wit");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .softwareStatement("   ")
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("fallback-wit");
        }

        @Test
        @DisplayName("Should skip blank software_statement in additionalParameters and fall back")
        void shouldSkipBlankSoftwareStatementInAdditionalParameters() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("software_statement", "  ");
            additionalParams.put(WitConstants.WIT_PARAM, "fallback-wit");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert
            assertThat(wit).isEqualTo("fallback-wit");
        }

        @Test
        @DisplayName("Should not extract WIT from client_assertion parameter")
        void shouldNotExtractWitFromClientAssertion() {
            // Arrange - client_assertion is for OAuth2 client authentication, not WIT
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            additionalParams.put("client_assertion", "eyJ.client.assertion");

            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            String wit = WitExtractor.extractFromDcrRequest(request);

            // Assert - client_assertion should NOT be treated as WIT
            assertThat(wit).isNull();
        }
    }

    @Nested
    @DisplayName("Has WIT in DCR Request Tests")
    class HasWitInDcrRequestTests {

        @Test
        @DisplayName("Should return true when DCR request contains valid WIT")
        void shouldReturnTrueWhenDcrRequestContainsValidWit() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "test.wit.jwt.string");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isTrue();
        }

        @Test
        @DisplayName("Should return false when WIT is not present")
        void shouldReturnFalseWhenWitNotPresent() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("other_param", "value");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isFalse();
        }

        @Test
        @DisplayName("Should return false when additional parameters is null")
        void shouldReturnFalseWhenAdditionalParametersIsNull() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isFalse();
        }

        @Test
        @DisplayName("Should return false when WIT is empty string")
        void shouldReturnFalseWhenWitIsEmptyString() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isFalse();
        }

        @Test
        @DisplayName("Should return false when WIT is blank string")
        void shouldReturnFalseWhenWitIsBlankString() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "   ");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isFalse();
        }

        @Test
        @DisplayName("Should return false when WIT parameter is not a string")
        void shouldReturnFalseWhenWitParameterIsNotString() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, 12345);
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when DCR request is null")
        void shouldThrowExceptionWhenDcrRequestIsNullForHasWit() {
            // Act & Assert
            assertThatThrownBy(() -> WitExtractor.hasWitInDcrRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("DCR request");
        }

        @Test
        @DisplayName("Should return true for WIT with whitespace only content")
        void shouldReturnTrueForWitWithContentAfterTrimming() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "  test.wit.jwt.string  ");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://callback.example.com"))
                    .additionalParameters(additionalParams)
                    .build();

            // Act
            boolean hasWit = WitExtractor.hasWitInDcrRequest(request);

            // Assert
            assertThat(hasWit).isTrue();
        }
    }

    @Nested
    @DisplayName("Utility Class Tests")
    class UtilityClassTests {

        @Test
        @DisplayName("Should prevent instantiation")
        void shouldPreventInstantiation() {
            // Act & Assert
            assertThatThrownBy(() -> {
                // Use reflection to try to instantiate the utility class
                java.lang.reflect.Constructor<WitExtractor> constructor = 
                    WitExtractor.class.getDeclaredConstructor();
                constructor.setAccessible(true);
                constructor.newInstance();
            })
                    .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
                    .hasCauseExactlyInstanceOf(UnsupportedOperationException.class)
                    .hasRootCauseMessage("Utility class cannot be instantiated");
        }
    }
}
