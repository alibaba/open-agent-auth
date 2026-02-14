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

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link ParSubmissionRequest.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, required field validation,
 * optional field settings with defaults, and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("ParSubmissionRequest.Builder Tests")
class ParSubmissionRequestTest {

    private static final String TEST_USER_IDENTITY_TOKEN = "id-token-abc123";
    private static final Integer TEST_EXPIRATION_SECONDS = 7200;
    private static final String TEST_STATE = "state-xyz789";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationProposal operationProposal = mock(AgentOperationProposal.class);
        Evidence evidence = mock(Evidence.class);
        OperationRequestContext context = mock(OperationRequestContext.class);

        ParSubmissionRequest request = ParSubmissionRequest.builder()
                .workloadContext(workloadContext)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .context(context)
                .expirationSeconds(TEST_EXPIRATION_SECONDS)
                .state(TEST_STATE)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getWorkloadContext()).isSameAs(workloadContext);
        assertThat(request.getOperationProposal()).isSameAs(operationProposal);
        assertThat(request.getEvidence()).isSameAs(evidence);
        assertThat(request.getUserIdentityToken()).isEqualTo(TEST_USER_IDENTITY_TOKEN);
        assertThat(request.getContext()).isSameAs(context);
        assertThat(request.getExpirationSeconds()).isEqualTo(TEST_EXPIRATION_SECONDS);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationProposal operationProposal = mock(AgentOperationProposal.class);
        Evidence evidence = mock(Evidence.class);

        ParSubmissionRequest.Builder builder = ParSubmissionRequest.builder();

        // When
        ParSubmissionRequest request = builder
                .workloadContext(workloadContext)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getWorkloadContext()).isSameAs(workloadContext);
        assertThat(request.getOperationProposal()).isSameAs(operationProposal);
        assertThat(request.getEvidence()).isSameAs(evidence);
        assertThat(request.getUserIdentityToken()).isEqualTo(TEST_USER_IDENTITY_TOKEN);
    }

    @Test
    @DisplayName("Should throw exception when workloadContext is null")
    void shouldThrowExceptionWhenWorkloadContextIsNull() {
        // When & Then
        assertThatThrownBy(() -> ParSubmissionRequest.builder()
                .workloadContext(null)
                .operationProposal(mock(AgentOperationProposal.class))
                .evidence(mock(Evidence.class))
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("workloadContext");
    }

    @Test
    @DisplayName("Should throw exception when operationProposal is null")
    void shouldThrowExceptionWhenOperationProposalIsNull() {
        // When & Then
        assertThatThrownBy(() -> ParSubmissionRequest.builder()
                .workloadContext(mock(WorkloadContext.class))
                .operationProposal(null)
                .evidence(mock(Evidence.class))
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("operationProposal");
    }

    @Test
    @DisplayName("Should throw exception when evidence is null")
    void shouldThrowExceptionWhenEvidenceIsNull() {
        // When & Then
        assertThatThrownBy(() -> ParSubmissionRequest.builder()
                .workloadContext(mock(WorkloadContext.class))
                .operationProposal(mock(AgentOperationProposal.class))
                .evidence(null)
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("evidence is required");
    }

    @Test
    @DisplayName("Should throw exception when userIdentityToken is null")
    void shouldThrowExceptionWhenUserIdentityTokenIsNull() {
        // When & Then
        assertThatThrownBy(() -> ParSubmissionRequest.builder()
                .workloadContext(mock(WorkloadContext.class))
                .operationProposal(mock(AgentOperationProposal.class))
                .evidence(mock(Evidence.class))
                .userIdentityToken(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("userIdentityToken");
    }

    @Test
    @DisplayName("Should throw exception when userIdentityToken is empty")
    void shouldThrowExceptionWhenUserIdentityTokenIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> ParSubmissionRequest.builder()
                .workloadContext(mock(WorkloadContext.class))
                .operationProposal(mock(AgentOperationProposal.class))
                .evidence(mock(Evidence.class))
                .userIdentityToken("")
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("userIdentityToken");
    }

    @Test
    @DisplayName("Should use default expirationSeconds when not set")
    void shouldUseDefaultExpirationSecondsWhenNotSet() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationProposal operationProposal = mock(AgentOperationProposal.class);
        Evidence evidence = mock(Evidence.class);

        ParSubmissionRequest request = ParSubmissionRequest.builder()
                .workloadContext(workloadContext)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .build();

        // Then
        assertThat(request.getExpirationSeconds()).isEqualTo(3600);
    }

    @Test
    @DisplayName("Should build instance with optional fields set to null")
    void shouldBuildInstanceWithOptionalFieldsSetToNullWhenOptionalFieldsAreSetToNull() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationProposal operationProposal = mock(AgentOperationProposal.class);
        Evidence evidence = mock(Evidence.class);

        ParSubmissionRequest request = ParSubmissionRequest.builder()
                .workloadContext(workloadContext)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .context(null)
                .state(null)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getContext()).isNull();
        assertThat(request.getState()).isNull();
        assertThat(request.getExpirationSeconds()).isEqualTo(3600);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        ParSubmissionRequest.Builder builder1 = ParSubmissionRequest.builder();
        ParSubmissionRequest.Builder builder2 = ParSubmissionRequest.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        WorkloadContext workloadContext1 = mock(WorkloadContext.class);
        WorkloadContext workloadContext2 = mock(WorkloadContext.class);
        AgentOperationProposal operationProposal = mock(AgentOperationProposal.class);
        Evidence evidence = mock(Evidence.class);

        ParSubmissionRequest.Builder builder = ParSubmissionRequest.builder();

        // When
        ParSubmissionRequest request1 = builder
                .workloadContext(workloadContext1)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken("token-1")
                .state("state-1")
                .build();

        ParSubmissionRequest request2 = builder
                .workloadContext(workloadContext2)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken("token-2")
                .state("state-2")
                .build();

        // Then
        assertThat(request1).isNotNull();
        assertThat(request2).isNotNull();
        assertThat(request1.getWorkloadContext()).isSameAs(workloadContext1);
        assertThat(request2.getWorkloadContext()).isSameAs(workloadContext2);
        assertThat(request1.getUserIdentityToken()).isEqualTo("token-1");
        assertThat(request2.getUserIdentityToken()).isEqualTo("token-2");
        assertThat(request1.getState()).isEqualTo("state-1");
        assertThat(request2.getState()).isEqualTo("state-2");
    }

    @Test
    @DisplayName("Should handle custom expirationSeconds value")
    void shouldHandleCustomExpirationSecondsValueWhenCustomValueIsSet() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationProposal operationProposal = mock(AgentOperationProposal.class);
        Evidence evidence = mock(Evidence.class);

        ParSubmissionRequest request = ParSubmissionRequest.builder()
                .workloadContext(workloadContext)
                .operationProposal(operationProposal)
                .evidence(evidence)
                .userIdentityToken(TEST_USER_IDENTITY_TOKEN)
                .expirationSeconds(1800)
                .build();

        // Then
        assertThat(request.getExpirationSeconds()).isEqualTo(1800);
    }
}
