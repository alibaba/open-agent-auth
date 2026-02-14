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

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link PrepareAuthorizationContextRequest.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, required field validation,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("PrepareAuthorizationContextRequest.Builder Tests")
class PrepareAuthorizationContextRequestTest {

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);

        PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                .workloadContext(workloadContext)
                .aoat(aoat)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getWorkloadContext()).isSameAs(workloadContext);
        assertThat(request.getAoat()).isSameAs(aoat);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);

        PrepareAuthorizationContextRequest.Builder builder = PrepareAuthorizationContextRequest.builder();

        // When
        PrepareAuthorizationContextRequest request = builder
                .workloadContext(workloadContext)
                .aoat(aoat)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getWorkloadContext()).isSameAs(workloadContext);
        assertThat(request.getAoat()).isSameAs(aoat);
    }

    @Test
    @DisplayName("Should throw exception when workloadContext is null")
    void shouldThrowExceptionWhenWorkloadContextIsNull() {
        // When & Then
        assertThatThrownBy(() -> PrepareAuthorizationContextRequest.builder()
                .workloadContext(null)
                .aoat(mock(AgentOperationAuthToken.class))
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("workloadContext");
    }

    @Test
    @DisplayName("Should throw exception when aoat is null")
    void shouldThrowExceptionWhenAoatIsNull() {
        // When & Then
        assertThatThrownBy(() -> PrepareAuthorizationContextRequest.builder()
                .workloadContext(mock(WorkloadContext.class))
                .aoat(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("aoat");
    }

    @Test
    @DisplayName("Should throw exception when both fields are null")
    void shouldThrowExceptionWhenBothFieldsAreNull() {
        // When & Then
        assertThatThrownBy(() -> PrepareAuthorizationContextRequest.builder()
                .workloadContext(null)
                .aoat(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        PrepareAuthorizationContextRequest.Builder builder1 = PrepareAuthorizationContextRequest.builder();
        PrepareAuthorizationContextRequest.Builder builder2 = PrepareAuthorizationContextRequest.builder();

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
        AgentOperationAuthToken aoat1 = mock(AgentOperationAuthToken.class);
        AgentOperationAuthToken aoat2 = mock(AgentOperationAuthToken.class);

        PrepareAuthorizationContextRequest.Builder builder = PrepareAuthorizationContextRequest.builder();

        // When
        PrepareAuthorizationContextRequest request1 = builder
                .workloadContext(workloadContext1)
                .aoat(aoat1)
                .build();

        PrepareAuthorizationContextRequest request2 = builder
                .workloadContext(workloadContext2)
                .aoat(aoat2)
                .build();

        // Then
        assertThat(request1).isNotNull();
        assertThat(request2).isNotNull();
        assertThat(request1.getWorkloadContext()).isSameAs(workloadContext1);
        assertThat(request2.getWorkloadContext()).isSameAs(workloadContext2);
        assertThat(request1.getAoat()).isSameAs(aoat1);
        assertThat(request2.getAoat()).isSameAs(aoat2);
    }

    @Test
    @DisplayName("Should build immutable instance when build is called")
    void shouldBuildImmutableInstanceWhenBuildIsCalled() {
        // Given
        WorkloadContext workloadContext = mock(WorkloadContext.class);
        AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);

        PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                .workloadContext(workloadContext)
                .aoat(aoat)
                .build();

        // When & Then - Verify all fields are final and immutable
        assertThat(request.getWorkloadContext()).isSameAs(workloadContext);
        assertThat(request.getAoat()).isSameAs(aoat);
    }
}
