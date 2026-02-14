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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuthenticationResponse.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * default values, and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("AuthenticationResponse.Builder Tests")
class AuthenticationResponseTest {

    private static final String TEST_ID_TOKEN = "id-token-abc123";
    private static final String TEST_REFRESH_TOKEN = "refresh-token-def456";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .tokenType("Bearer")
                .expiresIn(7200)
                .refreshToken(TEST_REFRESH_TOKEN)
                .addInfo("custom_key", "custom_value")
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getIdToken()).isEqualTo(TEST_ID_TOKEN);
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(7200);
        assertThat(response.getRefreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
        assertThat(response.getAdditionalInfo()).hasSize(1);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        AuthenticationResponse.Builder builder = AuthenticationResponse.builder();

        // When
        AuthenticationResponse response = builder
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .tokenType("Bearer")
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getIdToken()).isEqualTo(TEST_ID_TOKEN);
        assertThat(response.getTokenType()).isEqualTo("Bearer");
    }

    @Test
    @DisplayName("Should use default values when not set")
    void shouldUseDefaultValuesWhenNotSet() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(3600);
        assertThat(response.getRefreshToken()).isNull();
        assertThat(response.getAdditionalInfo()).isEmpty();
    }

    @Test
    @DisplayName("Should build instance with only success flag")
    void shouldBuildInstanceWithOnlySuccessFlagWhenOnlySuccessIsSet() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(false)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getIdToken()).isNull();
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(3600);
    }

    @Test
    @DisplayName("Should allow adding multiple additional info entries")
    void shouldAllowAddingMultipleAdditionalInfoEntriesWhenAddInfoIsCalledMultipleTimes() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .addInfo("key1", "value1")
                .addInfo("key2", "value2")
                .addInfo("key3", 123)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAdditionalInfo()).hasSize(3);
        assertThat(response.getAdditionalInfo()).containsEntry("key1", "value1");
        assertThat(response.getAdditionalInfo()).containsEntry("key2", "value2");
        assertThat(response.getAdditionalInfo()).containsEntry("key3", 123);
    }

    @Test
    @DisplayName("Should handle custom token type")
    void shouldHandleCustomTokenTypeWhenCustomTypeIsSet() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .tokenType("CustomToken")
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getTokenType()).isEqualTo("CustomToken");
    }

    @Test
    @DisplayName("Should handle custom expiration time")
    void shouldHandleCustomExpirationTimeWhenCustomTimeIsSet() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .expiresIn(1800)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getExpiresIn()).isEqualTo(1800);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        AuthenticationResponse.Builder builder1 = AuthenticationResponse.builder();
        AuthenticationResponse.Builder builder2 = AuthenticationResponse.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        AuthenticationResponse.Builder builder = AuthenticationResponse.builder();

        // When
        AuthenticationResponse response1 = builder
                .success(true)
                .idToken("token-1")
                .refreshToken("refresh-1")
                .build();

        AuthenticationResponse response2 = builder
                .success(false)
                .idToken("token-2")
                .refreshToken("refresh-2")
                .build();

        // Then
        assertThat(response1).isNotNull();
        assertThat(response2).isNotNull();
        assertThat(response1.isSuccess()).isTrue();
        assertThat(response2.isSuccess()).isFalse();
        assertThat(response1.getIdToken()).isEqualTo("token-1");
        assertThat(response2.getIdToken()).isEqualTo("token-2");
    }

    @Test
    @DisplayName("Should build successful authentication response")
    void shouldBuildSuccessfulAuthenticationResponseWhenSuccessIsTrue() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(true)
                .idToken(TEST_ID_TOKEN)
                .tokenType("Bearer")
                .expiresIn(3600)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getIdToken()).isEqualTo(TEST_ID_TOKEN);
    }

    @Test
    @DisplayName("Should build failed authentication response")
    void shouldBuildFailedAuthenticationResponseWhenSuccessIsFalse() {
        // Given
        AuthenticationResponse response = AuthenticationResponse.builder()
                .success(false)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getIdToken()).isNull();
    }
}
