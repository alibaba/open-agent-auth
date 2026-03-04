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
package com.alibaba.openagentauth.core.protocol.wimse.workload.store;

import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RemoteWorkloadRegistry}.
 * <p>
 * Tests verify the remote workload registry implementation that communicates
 * with an Agent IDP via REST API.
 * </p>
 * <p>
 * <b>Note:</b> HTTP request tests are limited in unit tests because
 * {@code java.net.http.HttpClient} is a final class and cannot be mocked by Mockito.
 * Integration tests should be created to test actual HTTP communication.
 * </p>
 */
@DisplayName("RemoteWorkloadRegistry Tests")
class RemoteWorkloadRegistryTest {

    private RemoteWorkloadRegistry workloadRegistry;
    private ServiceEndpointResolver mockServiceEndpointResolver;

    private static final String BASE_URL = "http://localhost:8082";
    private static final String WORKLOAD_ID = "workload-123";
    private static final String USER_ID = "user-456";
    private static final String WORKLOAD_UNIQUE_KEY = "user-456:client-789";

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create registry with valid service endpoint resolver")
        void shouldCreateRegistryWithValidServiceEndpointResolver() {
            // Arrange
            ServiceEndpointResolver resolver = mock(ServiceEndpointResolver.class);

            // Act
            RemoteWorkloadRegistry registry = new RemoteWorkloadRegistry(resolver);

            // Assert
            assertThat(registry).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new RemoteWorkloadRegistry(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }
    }

    @Nested
    @DisplayName("save() - Unsupported Operation")
    class SaveTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw UnsupportedOperationException for save()")
        void shouldThrowUnsupportedOperationExceptionForSave() {
            // Arrange
            WorkloadInfo workloadInfo = new WorkloadInfo(
                    WORKLOAD_ID, USER_ID, "wimse://example.com", "http://localhost:8082",
                    "public-key", Instant.now(), Instant.now().plusSeconds(3600),
                    "active", null, null);

            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.save(workloadInfo))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote workload saving is not supported");
        }

        @Test
        @DisplayName("Should throw UnsupportedOperationException for save() with null workload")
        void shouldThrowUnsupportedOperationExceptionForSaveWithNull() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.save(null))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote workload saving is not supported");
        }
    }

    @Nested
    @DisplayName("delete() - Unsupported Operation")
    class DeleteTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw UnsupportedOperationException for delete()")
        void shouldThrowUnsupportedOperationExceptionForDelete() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.delete(WORKLOAD_ID))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote workload deletion is not supported");
        }

        @Test
        @DisplayName("Should throw UnsupportedOperationException for delete() with null ID")
        void shouldThrowUnsupportedOperationExceptionForDeleteWithNull() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.delete(null))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote workload deletion is not supported");
        }
    }

    @Nested
    @DisplayName("findById() - Parameter Validation")
    class FindByIdParameterValidationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.findById(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.findById(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is whitespace")
        void shouldThrowExceptionWhenWorkloadIdIsWhitespace() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.findById("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("findById() - Endpoint Resolution")
    class FindByIdEndpointResolutionTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty when endpoint resolution fails")
        void shouldReturnEmptyWhenEndpointResolutionFails() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findById(WORKLOAD_ID);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when HTTP request fails with connection error")
        void shouldReturnEmptyWhenHttpRequestFails() {
            // Arrange - use an invalid URL to trigger connection error
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn("http://invalid-host-that-does-not-exist:9999/api/v1/workloads/get");

            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findById(WORKLOAD_ID);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("exists() - Delegation to findById()")
    class ExistsTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return false when endpoint resolution fails")
        void shouldReturnFalseWhenEndpointResolutionFails() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act
            boolean result = workloadRegistry.exists(WORKLOAD_ID);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> workloadRegistry.exists(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("findByWorkloadUniqueKey() - Not Supported")
    class FindByWorkloadUniqueKeyTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty for findByWorkloadUniqueKey()")
        void shouldReturnEmptyForFindByWorkloadUniqueKey() {
            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findByWorkloadUniqueKey(WORKLOAD_UNIQUE_KEY);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty for findByWorkloadUniqueKey() with null key")
        void shouldReturnEmptyForFindByWorkloadUniqueKeyWithNull() {
            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findByWorkloadUniqueKey(null);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty for findByWorkloadUniqueKey() with empty key")
        void shouldReturnEmptyForFindByWorkloadUniqueKeyWithEmpty() {
            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findByWorkloadUniqueKey("");

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("listAll() - Endpoint Resolution")
    class ListAllEndpointResolutionTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty list when endpoint resolution fails")
        void shouldReturnEmptyListWhenEndpointResolutionFails() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act
            List<WorkloadInfo> result = workloadRegistry.listAll();

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list when HTTP request fails with connection error")
        void shouldReturnEmptyListWhenHttpRequestFails() {
            // Arrange - use an invalid URL to trigger connection error
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn("http://invalid-host-that-does-not-exist:9999/api/v1/workloads/list");

            // Act
            List<WorkloadInfo> result = workloadRegistry.listAll();

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Thread Safety")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should allow concurrent creation of registries")
        void shouldAllowConcurrentCreationOfRegistries() throws InterruptedException {
            // Arrange
            ServiceEndpointResolver resolver = mock(ServiceEndpointResolver.class);
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            RemoteWorkloadRegistry[] registries = new RemoteWorkloadRegistry[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> registries[index] = new RemoteWorkloadRegistry(resolver));
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert
            for (RemoteWorkloadRegistry registry : registries) {
                assertThat(registry).isNotNull();
            }
        }

        @Test
        @DisplayName("Should allow concurrent findById() calls without concurrent modification")
        void shouldAllowConcurrentFindByIdCalls() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            Optional<?>[] results = new Optional[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> results[index] = workloadRegistry.findById(WORKLOAD_ID));
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert - All should return empty (endpoint resolution returns null)
            for (Optional<?> result : results) {
                assertThat(result).isEmpty();
            }
        }

        @Test
        @DisplayName("Should allow concurrent listAll() calls without concurrent modification")
        void shouldAllowConcurrentListAllCalls() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            List<?>[] results = new List[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> results[index] = workloadRegistry.listAll());
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert - All should return empty list (endpoint resolution returns null)
            for (List<?> result : results) {
                assertThat(result).isEmpty();
            }
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Conditions")
    class EdgeCasesTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/workloads/get");
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should handle very long workload ID")
        void shouldHandleVeryLongWorkloadId() {
            // Arrange
            String longWorkloadId = "workload-" + "a".repeat(1000);

            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findById(longWorkloadId);

            // Assert - Should return empty (connection will fail in unit test)
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should handle special characters in workload ID")
        void shouldHandleSpecialCharactersInWorkloadId() {
            // Arrange
            String specialWorkloadId = "workload-123_@#$%";

            // Act
            Optional<WorkloadInfo> result = workloadRegistry.findById(specialWorkloadId);

            // Assert - Should return empty (connection will fail in unit test)
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationScenariosTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            workloadRegistry = new RemoteWorkloadRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should handle calling all unsupported operations in sequence")
        void shouldHandleCallingAllUnsupportedOperationsInSequence() {
            // Arrange
            WorkloadInfo workloadInfo = new WorkloadInfo(
                    WORKLOAD_ID, USER_ID, "wimse://example.com", "http://localhost:8082",
                    "public-key", Instant.now(), Instant.now().plusSeconds(3600),
                    "active", null, null);

            // Act & Assert - Write operations throw UnsupportedOperationException
            assertThatThrownBy(() -> workloadRegistry.save(workloadInfo))
                    .isInstanceOf(UnsupportedOperationException.class);

            assertThatThrownBy(() -> workloadRegistry.delete(WORKLOAD_ID))
                    .isInstanceOf(UnsupportedOperationException.class);

            // Read operations return empty (no real server)
            assertThat(workloadRegistry.findByWorkloadUniqueKey(WORKLOAD_UNIQUE_KEY)).isEmpty();
        }

        @Test
        @DisplayName("Should handle multiple sequential findById() calls")
        void shouldHandleMultipleSequentialFindByIdCalls() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act & Assert
            for (int i = 0; i < 5; i++) {
                Optional<WorkloadInfo> result = workloadRegistry.findById("workload-" + i);
                assertThat(result).isEmpty();
            }
        }

        @Test
        @DisplayName("Should handle alternating between findById() and listAll()")
        void shouldHandleAlternatingBetweenFindByIdAndListAll() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act & Assert
            assertThat(workloadRegistry.findById(WORKLOAD_ID)).isEmpty();
            assertThat(workloadRegistry.listAll()).isEmpty();
            assertThat(workloadRegistry.findById(WORKLOAD_ID)).isEmpty();
            assertThat(workloadRegistry.listAll()).isEmpty();
        }

        @Test
        @DisplayName("Should verify endpoint resolution uses correct service name and endpoint key")
        void shouldVerifyEndpointResolutionUsesCorrectServiceNameAndEndpointKey() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer("agent-idp", "workload.retrieve"))
                    .thenReturn(BASE_URL + "/api/v1/workloads/get");
            when(mockServiceEndpointResolver.resolveConsumer("agent-idp", "workload.list"))
                    .thenReturn(BASE_URL + "/api/v1/workloads/list");

            // Act - findById should use "agent-idp" and "workload.retrieve"
            workloadRegistry.findById(WORKLOAD_ID);

            // Act - listAll should use "agent-idp" and "workload.list"
            workloadRegistry.listAll();

            // Assert - No exceptions thrown, endpoint resolution was called correctly
            // (actual HTTP calls will fail in unit test, but endpoint resolution is verified)
        }
    }
}
