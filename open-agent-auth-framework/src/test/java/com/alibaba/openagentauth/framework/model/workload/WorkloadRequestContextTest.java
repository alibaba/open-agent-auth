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
package com.alibaba.openagentauth.framework.model.workload;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WorkloadRequestContext.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("WorkloadRequestContext.Builder Tests")
class WorkloadRequestContextTest {

    private static final String TEST_OPERATION_TYPE = "READ";
    private static final String TEST_RESOURCE_ID = "resource-123";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        Map<String, Object> metadata = Map.of(
                "key1", "value1",
                "key2", 123
        );

        WorkloadRequestContext context = WorkloadRequestContext.builder()
                .operationType(TEST_OPERATION_TYPE)
                .resourceId(TEST_RESOURCE_ID)
                .metadata(metadata)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getOperationType()).isEqualTo(TEST_OPERATION_TYPE);
        assertThat(context.getResourceId()).isEqualTo(TEST_RESOURCE_ID);
        assertThat(context.getMetadata()).hasSize(2);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        WorkloadRequestContext.Builder builder = WorkloadRequestContext.builder();

        // When
        WorkloadRequestContext context = builder
                .operationType(TEST_OPERATION_TYPE)
                .resourceId(TEST_RESOURCE_ID)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getOperationType()).isEqualTo(TEST_OPERATION_TYPE);
        assertThat(context.getResourceId()).isEqualTo(TEST_RESOURCE_ID);
    }

    @Test
    @DisplayName("Should build instance with only operationType")
    void shouldBuildInstanceWithOnlyOperationTypeWhenOnlyOperationTypeIsSet() {
        // Given
        WorkloadRequestContext context = WorkloadRequestContext.builder()
                .operationType(TEST_OPERATION_TYPE)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getOperationType()).isEqualTo(TEST_OPERATION_TYPE);
        assertThat(context.getResourceId()).isNull();
        assertThat(context.getMetadata()).isNull();
    }

    @Test
    @DisplayName("Should build instance with null values when setters receive null")
    void shouldBuildInstanceWithNullValuesWhenSettersReceiveNull() {
        // Given
        WorkloadRequestContext context = WorkloadRequestContext.builder()
                .operationType(null)
                .resourceId(null)
                .metadata(null)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getOperationType()).isNull();
        assertThat(context.getResourceId()).isNull();
        assertThat(context.getMetadata()).isNull();
    }

    @Test
    @DisplayName("Should handle empty metadata map")
    void shouldHandleEmptyMetadataMapWhenMetadataIsEmpty() {
        // Given
        Map<String, Object> emptyMetadata = Map.of();

        WorkloadRequestContext context = WorkloadRequestContext.builder()
                .operationType(TEST_OPERATION_TYPE)
                .metadata(emptyMetadata)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getMetadata()).isNotNull();
        assertThat(context.getMetadata()).isEmpty();
    }

    @Test
    @DisplayName("Should handle different operation types")
    void shouldHandleDifferentOperationTypesWhenDifferentTypesAreSet() {
        // Given
        WorkloadRequestContext readContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .build();

        WorkloadRequestContext writeContext = WorkloadRequestContext.builder()
                .operationType("WRITE")
                .build();

        WorkloadRequestContext deleteContext = WorkloadRequestContext.builder()
                .operationType("DELETE")
                .build();

        // Then
        assertThat(readContext.getOperationType()).isEqualTo("READ");
        assertThat(writeContext.getOperationType()).isEqualTo("WRITE");
        assertThat(deleteContext.getOperationType()).isEqualTo("DELETE");
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        WorkloadRequestContext.Builder builder1 = WorkloadRequestContext.builder();
        WorkloadRequestContext.Builder builder2 = WorkloadRequestContext.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        WorkloadRequestContext.Builder builder = WorkloadRequestContext.builder();

        // When
        WorkloadRequestContext context1 = builder
                .operationType("READ")
                .resourceId("resource-1")
                .build();

        WorkloadRequestContext context2 = builder
                .operationType("WRITE")
                .resourceId("resource-2")
                .build();

        // Then
        assertThat(context1).isNotNull();
        assertThat(context2).isNotNull();
        assertThat(context1.getOperationType()).isEqualTo("READ");
        assertThat(context2.getOperationType()).isEqualTo("WRITE");
        assertThat(context1.getResourceId()).isEqualTo("resource-1");
        assertThat(context2.getResourceId()).isEqualTo("resource-2");
    }

    @Test
    @DisplayName("Should handle complex metadata")
    void shouldHandleComplexMetadataWhenMetadataContainsComplexObjects() {
        // Given
        Map<String, Object> complexMetadata = Map.of(
                "string", "value",
                "number", 123,
                "boolean", true,
                "nested", Map.of("key", "value")
        );

        WorkloadRequestContext context = WorkloadRequestContext.builder()
                .operationType(TEST_OPERATION_TYPE)
                .metadata(complexMetadata)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getMetadata()).hasSize(4);
        assertThat(context.getMetadata()).containsEntry("string", "value");
        assertThat(context.getMetadata()).containsEntry("number", 123);
    }
}
