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
package com.alibaba.openagentauth.core.policy.registry;

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.exception.policy.PolicyRegistrationException;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RemotePolicyRegistry}.
 * <p>
 * Tests verify the remote policy registry implementation that communicates
 * with an Authorization Server via REST API.
 * </p>
 * <p>
 * <b>Note:</b> HTTP request tests are skipped in unit tests because
 * {@code java.net.http.HttpClient} is a final class and cannot be mocked by Mockito.
 * Integration tests should be created to test actual HTTP communication.
 * </p>
 */
@DisplayName("RemotePolicyRegistry Tests")
class RemotePolicyRegistryTest {

    private RemotePolicyRegistry registry;
    private static final String BASE_URL = "http://localhost:8085";
    private static final String POLICY_ID = "policy-123";
    private static final String REGO_POLICY = "package agent\nallow { true }";

    private ServiceEndpointResolver mockServiceEndpointResolver;

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create registry with valid service endpoint resolver")
        void shouldCreateRegistryWithValidServiceEndpointResolver() {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            
            // Act
            RemotePolicyRegistry registry = new RemotePolicyRegistry(mockServiceEndpointResolver);

            // Assert
            assertThat(registry).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new RemotePolicyRegistry(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }
    }

    @Nested
    @DisplayName("get() - Parameter Validation")
    class GetPolicyParameterValidationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw exception when policy ID is null")
        void shouldThrowExceptionWhenPolicyIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> registry.get(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Policy ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when policy ID is empty")
        void shouldThrowExceptionWhenPolicyIdIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> registry.get(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Policy ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when policy ID is whitespace")
        void shouldThrowExceptionWhenPolicyIdIsWhitespace() {
            // Act & Assert
            assertThatThrownBy(() -> registry.get("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Policy ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("get() - HTTP Communication")
    class GetPolicyHttpCommunicationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/policies/{policyId}");
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw PolicyNotFoundException when policy not found (HTTP 404)")
        void shouldThrowPolicyNotFoundExceptionWhenPolicyNotFound() {
            // Act & Assert
            // Note: This will fail with actual HTTP call to non-existent server
            // Integration tests needed for real HTTP scenarios
            assertThatThrownBy(() -> registry.get(POLICY_ID))
                    .isInstanceOf(PolicyNotFoundException.class);
        }

        @Test
        @DisplayName("Should throw PolicyNotFoundException on HTTP error")
        void shouldThrowPolicyNotFoundExceptionOnHttpError() {
            // Act & Assert
            // Note: This will fail with actual HTTP call to non-existent server
            // Integration tests needed for real HTTP scenarios
            assertThatThrownBy(() -> registry.get(POLICY_ID))
                    .isInstanceOf(PolicyNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("get() - with includeExpired parameter")
    class GetPolicyWithIncludeExpiredTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/policies/{policyId}");
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty Optional when policy not found with includeExpired=true")
        void shouldReturnEmptyOptionalWhenPolicyNotFoundWithIncludeExpiredTrue() {
            // Act
            var result = registry.get(POLICY_ID, true);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty Optional when policy not found with includeExpired=false")
        void shouldReturnEmptyOptionalWhenPolicyNotFoundWithIncludeExpiredFalse() {
            // Act
            var result = registry.get(POLICY_ID, false);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should handle null policy ID with includeExpired parameter")
        void shouldHandleNullPolicyIdWithIncludeExpiredParameter() {
            // Act & Assert
            assertThatThrownBy(() -> registry.get(null, true))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Policy ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Unsupported Operations")
    class UnsupportedOperationsTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw exception for register()")
        void shouldThrowExceptionForRegister() {
            // Arrange
            String description = "Test policy";
            String createdBy = "test-user";
            Instant expirationTime = Instant.now().plusSeconds(3600);

            // Act & Assert
            assertThatThrownBy(() -> registry.register(
                    REGO_POLICY,
                    description,
                    createdBy,
                    expirationTime
            ))
                    .isInstanceOf(PolicyRegistrationException.class)
                    .hasMessageContaining("Remote policy registration is not supported");
        }

        @Test
        @DisplayName("Should throw exception for register() with minimal parameters")
        void shouldThrowExceptionForRegisterWithMinimalParameters() {
            // Act & Assert
            assertThatThrownBy(() -> registry.register(
                    REGO_POLICY,
                    null,
                    null,
                    null
            ))
                    .isInstanceOf(PolicyRegistrationException.class);
        }

        @Test
        @DisplayName("Should throw exception for update()")
        void shouldThrowExceptionForUpdate() {
            // Act & Assert
            assertThatThrownBy(() -> registry.update(
                    POLICY_ID,
                    REGO_POLICY,
                    "Updated description"
            ))
                    .isInstanceOf(PolicyNotFoundException.class)
                    .hasMessageContaining("Remote policy update is not supported");
        }

        @Test
        @DisplayName("Should throw exception for update() with null description")
        void shouldThrowExceptionForUpdateWithNullDescription() {
            // Act & Assert
            assertThatThrownBy(() -> registry.update(
                    POLICY_ID,
                    REGO_POLICY,
                    null
            ))
                    .isInstanceOf(PolicyNotFoundException.class);
        }

        @Test
        @DisplayName("Should throw exception for delete()")
        void shouldThrowExceptionForDelete() {
            // Act & Assert
            assertThatThrownBy(() -> registry.delete(POLICY_ID))
                    .isInstanceOf(PolicyNotFoundException.class)
                    .hasMessageContaining("Remote policy deletion is not supported");
        }

        @Test
        @DisplayName("Should throw exception for delete() with null policy ID")
        void shouldThrowExceptionForDeleteWithNullPolicyId() {
            // Act & Assert
            assertThatThrownBy(() -> registry.delete(null))
                    .isInstanceOf(PolicyNotFoundException.class);
        }

        @Test
        @DisplayName("Should return false for exists()")
        void shouldReturnFalseForExists() {
            // Act
            boolean result = registry.exists(POLICY_ID);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false for exists() with null policy ID")
        void shouldReturnFalseForExistsWithNullPolicyId() {
            // Act
            boolean result = registry.exists(null);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false for exists() with empty policy ID")
        void shouldReturnFalseForExistsWithEmptyPolicyId() {
            // Act
            boolean result = registry.exists("");

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return empty list for listAll()")
        void shouldReturnEmptyListForListAll() {
            // Act
            var result = registry.listAll();

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for listByCreator()")
        void shouldReturnEmptyListForListByCreator() {
            // Act
            var result = registry.listByCreator("test-user");

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for listByCreator() with null creator")
        void shouldReturnEmptyListForListByCreatorWithNullCreator() {
            // Act
            var result = registry.listByCreator(null);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for listByCreator() with empty creator")
        void shouldReturnEmptyListForListByCreatorWithEmptyCreator() {
            // Act
            var result = registry.listByCreator("");

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for listExpired()")
        void shouldReturnEmptyListForListExpired() {
            // Act
            var result = registry.listExpired();

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return 0 for cleanupExpired()")
        void shouldReturnZeroForCleanupExpired() {
            // Act
            int result = registry.cleanupExpired();

            // Assert
            assertThat(result).isZero();
        }

        @Test
        @DisplayName("Should return 0 for size()")
        void shouldReturnZeroForSize() {
            // Act
            int result = registry.size();

            // Assert
            assertThat(result).isZero();
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Conditions")
    class EdgeCasesAndBoundaryConditionsTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/policies/{policyId}");
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should handle very long policy ID")
        void shouldHandleVeryLongPolicyId() {
            // Arrange
            String longPolicyId = "policy-" + "a".repeat(1000);

            // Act & Assert
            assertThatThrownBy(() -> registry.get(longPolicyId))
                    .isInstanceOf(PolicyNotFoundException.class);
        }

        @Test
        @DisplayName("Should handle special characters in policy ID")
        void shouldHandleSpecialCharactersInPolicyId() {
            // Arrange
            String specialPolicyId = "policy-123_@#$%";

            // Act & Assert
            assertThatThrownBy(() -> registry.get(specialPolicyId))
                    .isInstanceOf(PolicyNotFoundException.class);
        }


    }

    @Nested
    @DisplayName("Thread Safety")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should allow concurrent creation of registries")
        void shouldAllowConcurrentCreationOfRegistries() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/policies/{policyId}");
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            RemotePolicyRegistry[] registries = new RemotePolicyRegistry[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    registries[index] = new RemotePolicyRegistry(mockServiceEndpointResolver);
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert
            for (RemotePolicyRegistry r : registries) {
                assertThat(r).isNotNull();
            }
        }

        @Test
        @DisplayName("Should allow concurrent get() calls")
        void shouldAllowConcurrentGetCalls() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/policies/{policyId}");
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            Exception[] exceptions = new Exception[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    try {
                        registry.get(POLICY_ID);
                    } catch (Exception e) {
                        exceptions[index] = e;
                    }
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert - All should throw PolicyNotFoundException (not concurrent modification)
            for (Exception e : exceptions) {
                assertThat(e).isInstanceOf(PolicyNotFoundException.class);
            }
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationScenariosTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            registry = new RemotePolicyRegistry(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should handle multiple sequential get() calls")
        void shouldHandleMultipleSequentialGetCalls() {
            // Act & Assert
            for (int i = 0; i < 5; i++) {
                final int policyIndex = i;
                assertThatThrownBy(() -> registry.get("policy-" + policyIndex))
                        .isInstanceOf(PolicyNotFoundException.class);
            }
        }

        @Test
        @DisplayName("Should handle alternating between get() and get() with includeExpired")
        void shouldHandleAlternatingBetweenGetAndGetWithIncludeExpired() {
            // Act & Assert
            assertThatThrownBy(() -> registry.get(POLICY_ID))
                    .isInstanceOf(PolicyNotFoundException.class);

            assertThat(registry.get(POLICY_ID, true)).isEmpty();

            assertThatThrownBy(() -> registry.get(POLICY_ID))
                    .isInstanceOf(PolicyNotFoundException.class);

            assertThat(registry.get(POLICY_ID, false)).isEmpty();
        }

        @Test
        @DisplayName("Should handle calling all unsupported operations in sequence")
        void shouldHandleCallingAllUnsupportedOperationsInSequence() {
            // Act & Assert
            assertThatThrownBy(() -> registry.register(REGO_POLICY, "desc", "user", null))
                    .isInstanceOf(PolicyRegistrationException.class);

            assertThatThrownBy(() -> registry.update(POLICY_ID, REGO_POLICY, "desc"))
                    .isInstanceOf(PolicyNotFoundException.class);

            assertThatThrownBy(() -> registry.delete(POLICY_ID))
                    .isInstanceOf(PolicyNotFoundException.class);

            assertThat(registry.exists(POLICY_ID)).isFalse();
            assertThat(registry.listAll()).isEmpty();
            assertThat(registry.listByCreator("user")).isEmpty();
            assertThat(registry.listExpired()).isEmpty();
            assertThat(registry.cleanupExpired()).isZero();
            assertThat(registry.size()).isZero();
        }
    }
}