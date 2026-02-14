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
package com.alibaba.openagentauth.framework.model.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PolicyRegistrationResponse.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("PolicyRegistrationResponse.Builder Tests")
class PolicyRegistrationResponseTest {

    private static final String TEST_POLICY_ID = "policy-123";
    private static final String TEST_MESSAGE = "Policy registered successfully";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        PolicyRegistrationResponse response = PolicyRegistrationResponse.builder()
                .policyId(TEST_POLICY_ID)
                .success(true)
                .message(TEST_MESSAGE)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getPolicyId()).isEqualTo(TEST_POLICY_ID);
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo(TEST_MESSAGE);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        PolicyRegistrationResponse.Builder builder = PolicyRegistrationResponse.builder();

        // When
        PolicyRegistrationResponse response = builder
                .policyId(TEST_POLICY_ID)
                .success(true)
                .message(TEST_MESSAGE)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getPolicyId()).isEqualTo(TEST_POLICY_ID);
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo(TEST_MESSAGE);
    }

    @Test
    @DisplayName("Should build instance with optional fields when only required fields are set")
    void shouldBuildInstanceWithOptionalFieldsWhenOnlyRequiredFieldsAreSet() {
        // Given
        PolicyRegistrationResponse response = PolicyRegistrationResponse.builder()
                .policyId(TEST_POLICY_ID)
                .success(false)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getPolicyId()).isEqualTo(TEST_POLICY_ID);
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isNull();
    }

    @Test
    @DisplayName("Should build instance with null values when setters receive null")
    void shouldBuildInstanceWithNullValuesWhenSettersReceiveNull() {
        // Given
        PolicyRegistrationResponse response = PolicyRegistrationResponse.builder()
                .policyId(null)
                .success(true)
                .message(null)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getPolicyId()).isNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isNull();
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        PolicyRegistrationResponse.Builder builder1 = PolicyRegistrationResponse.builder();
        PolicyRegistrationResponse.Builder builder2 = PolicyRegistrationResponse.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        PolicyRegistrationResponse.Builder builder = PolicyRegistrationResponse.builder();

        // When
        PolicyRegistrationResponse response1 = builder
                .policyId("policy-1")
                .success(true)
                .message("First policy")
                .build();

        PolicyRegistrationResponse response2 = builder
                .policyId("policy-2")
                .success(false)
                .message("Second policy")
                .build();

        // Then
        assertThat(response1).isNotNull();
        assertThat(response2).isNotNull();
        assertThat(response1.getPolicyId()).isEqualTo("policy-1");
        assertThat(response2.getPolicyId()).isEqualTo("policy-2");
        assertThat(response1.isSuccess()).isTrue();
        assertThat(response2.isSuccess()).isFalse();
    }

    @Test
    @DisplayName("Should handle boolean flag correctly when success is set")
    void shouldHandleBooleanFlagCorrectlyWhenSuccessIsSet() {
        // Given
        PolicyRegistrationResponse successResponse = PolicyRegistrationResponse.builder()
                .policyId(TEST_POLICY_ID)
                .success(true)
                .build();

        PolicyRegistrationResponse failureResponse = PolicyRegistrationResponse.builder()
                .policyId(TEST_POLICY_ID)
                .success(false)
                .build();

        // Then
        assertThat(successResponse.isSuccess()).isTrue();
        assertThat(failureResponse.isSuccess()).isFalse();
    }
}
