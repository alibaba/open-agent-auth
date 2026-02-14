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
package com.alibaba.openagentauth.framework.model.request;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AoatIssuanceRequest.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("AoatIssuanceRequest.Builder Tests")
class AoatIssuanceRequestTest {

    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_WORKLOAD_ID = "workload-456";
    private static final String TEST_POLICY_ID = "policy-789";
    private static final String TEST_OPERATION_PROPOSAL = "package auth allow true";
    private static final String TEST_AUTHORIZATION_CODE = "auth-code-abc";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final Instant TEST_EXPIRES_AT = Instant.now().plusSeconds(3600);

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        Map<String, Object> evidence = Map.of(
                "prompt_vc", "vc-abc123",
                "type", "PromptVC"
        );
        Map<String, Object> auditTrail = Map.of(
                "timestamp", "2024-01-01T00:00:00Z",
                "user_ip", "192.168.1.1"
        );

        AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                .userId(TEST_USER_ID)
                .workloadId(TEST_WORKLOAD_ID)
                .policyId(TEST_POLICY_ID)
                .operationProposal(TEST_OPERATION_PROPOSAL)
                .evidence(evidence)
                .auditTrail(auditTrail)
                .expiresAt(TEST_EXPIRES_AT)
                .authorizationCode(TEST_AUTHORIZATION_CODE)
                .redirectUri(TEST_REDIRECT_URI)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(request.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(request.getPolicyId()).isEqualTo(TEST_POLICY_ID);
        assertThat(request.getOperationProposal()).isEqualTo(TEST_OPERATION_PROPOSAL);
        assertThat(request.getEvidence()).hasSize(2);
        assertThat(request.getAuditTrail()).hasSize(2);
        assertThat(request.getExpiresAt()).isEqualTo(TEST_EXPIRES_AT);
        assertThat(request.getAuthorizationCode()).isEqualTo(TEST_AUTHORIZATION_CODE);
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        AoatIssuanceRequest.Builder builder = AoatIssuanceRequest.builder();

        // When
        AoatIssuanceRequest request = builder
                .userId(TEST_USER_ID)
                .workloadId(TEST_WORKLOAD_ID)
                .policyId(TEST_POLICY_ID)
                .operationProposal(TEST_OPERATION_PROPOSAL)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(request.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(request.getPolicyId()).isEqualTo(TEST_POLICY_ID);
        assertThat(request.getOperationProposal()).isEqualTo(TEST_OPERATION_PROPOSAL);
    }

    @Test
    @DisplayName("Should build instance with only required fields")
    void shouldBuildInstanceWithOnlyRequiredFieldsWhenOnlyRequiredFieldsAreSet() {
        // Given
        AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                .userId(TEST_USER_ID)
                .workloadId(TEST_WORKLOAD_ID)
                .policyId(TEST_POLICY_ID)
                .operationProposal(TEST_OPERATION_PROPOSAL)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(request.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(request.getPolicyId()).isEqualTo(TEST_POLICY_ID);
        assertThat(request.getOperationProposal()).isEqualTo(TEST_OPERATION_PROPOSAL);
        assertThat(request.getEvidence()).isNull();
        assertThat(request.getAuditTrail()).isNull();
        assertThat(request.getExpiresAt()).isNull();
        assertThat(request.getAuthorizationCode()).isNull();
        assertThat(request.getRedirectUri()).isNull();
    }

    @Test
    @DisplayName("Should build instance with null values when setters receive null")
    void shouldBuildInstanceWithNullValuesWhenSettersReceiveNull() {
        // Given
        AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                .userId(null)
                .workloadId(null)
                .policyId(null)
                .operationProposal(null)
                .evidence(null)
                .auditTrail(null)
                .expiresAt(null)
                .authorizationCode(null)
                .redirectUri(null)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getUserId()).isNull();
        assertThat(request.getWorkloadId()).isNull();
        assertThat(request.getPolicyId()).isNull();
    }

    @Test
    @DisplayName("Should handle empty maps for evidence and auditTrail")
    void shouldHandleEmptyMapsForEvidenceAndAuditTrail() {
        // Given
        Map<String, Object> emptyEvidence = Map.of();
        Map<String, Object> emptyAuditTrail = Map.of();

        AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                .userId(TEST_USER_ID)
                .evidence(emptyEvidence)
                .auditTrail(emptyAuditTrail)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getEvidence()).isNotNull();
        assertThat(request.getEvidence()).isEmpty();
        assertThat(request.getAuditTrail()).isNotNull();
        assertThat(request.getAuditTrail()).isEmpty();
    }

    @Test
    @DisplayName("Should handle Instant for expiresAt field")
    void shouldHandleInstantForExpiresAtField() {
        // Given
        Instant futureTime = Instant.now().plusSeconds(7200);

        AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                .userId(TEST_USER_ID)
                .expiresAt(futureTime)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getExpiresAt()).isEqualTo(futureTime);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        AoatIssuanceRequest.Builder builder1 = AoatIssuanceRequest.builder();
        AoatIssuanceRequest.Builder builder2 = AoatIssuanceRequest.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        AoatIssuanceRequest.Builder builder = AoatIssuanceRequest.builder();

        // When
        AoatIssuanceRequest request1 = builder
                .userId("user-1")
                .workloadId("workload-1")
                .build();

        AoatIssuanceRequest request2 = builder
                .userId("user-2")
                .workloadId("workload-2")
                .build();

        // Then
        assertThat(request1).isNotNull();
        assertThat(request2).isNotNull();
        assertThat(request1.getUserId()).isEqualTo("user-1");
        assertThat(request2.getUserId()).isEqualTo("user-2");
        assertThat(request1.getWorkloadId()).isEqualTo("workload-1");
        assertThat(request2.getWorkloadId()).isEqualTo("workload-2");
    }

    @Test
    @DisplayName("Should handle complex evidence map")
    void shouldHandleComplexEvidenceMapWhenEvidenceContainsComplexObjects() {
        // Given
        Map<String, Object> complexEvidence = Map.of(
                "string", "value",
                "number", 123,
                "boolean", true,
                "nested", Map.of("key", "value")
        );

        AoatIssuanceRequest request = AoatIssuanceRequest.builder()
                .userId(TEST_USER_ID)
                .evidence(complexEvidence)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getEvidence()).hasSize(4);
        assertThat(request.getEvidence()).containsEntry("string", "value");
        assertThat(request.getEvidence()).containsEntry("number", 123);
    }
}
