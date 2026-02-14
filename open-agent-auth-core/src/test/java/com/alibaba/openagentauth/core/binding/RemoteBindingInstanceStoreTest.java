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
package com.alibaba.openagentauth.core.binding;

import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RemoteBindingInstanceStore}.
 * <p>
 * This test class verifies the behavior of the remote binding instance store,
 * which communicates with an Authorization Server via HTTP.
 * </p>
 */
@DisplayName("RemoteBindingInstanceStore Tests")
class RemoteBindingInstanceStoreTest {

    private static final String BASE_URL = "http://localhost:8085";
    private static final String BINDING_INSTANCE_ID = "urn:uuid:test-binding-123";
    private static final String USER_ID = "https://idp.example.com|user-123";
    private static final String WORKLOAD_ID = "spiffe://example.com/ns/default/sa/agent-123";

    private ServiceEndpointResolver mockServiceEndpointResolver;

    private RemoteBindingInstanceStore remoteStore;

    @BeforeEach
    void setUp() {
        mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
        when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                .thenReturn(BASE_URL + "/api/v1/bindings/{bindingInstanceId}");
        remoteStore = new RemoteBindingInstanceStore(mockServiceEndpointResolver);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create store with valid service endpoint resolver")
        void shouldCreateStoreWithValidServiceEndpointResolver() {
            assertDoesNotThrow(() -> new RemoteBindingInstanceStore(mockServiceEndpointResolver));
        }

        @Test
        @DisplayName("Should throw exception with null service endpoint resolver")
        void shouldThrowExceptionWithNullServiceEndpointResolver() {
            assertThrows(IllegalArgumentException.class, () -> new RemoteBindingInstanceStore(null));
        }
    }

    @Nested
    @DisplayName("Retrieve Tests")
    class RetrieveTests {

        @Test
        @DisplayName("Should throw exception with null binding instance ID")
        void shouldThrowExceptionWithNullBindingInstanceId() {
            assertThrows(IllegalArgumentException.class, () -> remoteStore.retrieve(null));
        }

        @Test
        @DisplayName("Should throw exception with empty binding instance ID")
        void shouldThrowExceptionWithEmptyBindingInstanceId() {
            assertThrows(IllegalArgumentException.class, () -> remoteStore.retrieve(""));
        }

        @Test
        @DisplayName("Should return null when binding instance not found (404)")
        void shouldReturnNullWhenBindingInstanceNotFound() {
            // This test assumes the remote server returns 404 for non-existent bindings
            // In a real scenario, we would mock the HTTP client
            BindingInstance result = remoteStore.retrieve("urn:uuid:non-existent");
            // For now, we expect null because the server won't be running
            assertNull(result);
        }

        @Test
        @DisplayName("Should return null when remote server unavailable")
        void shouldReturnNullWhenRemoteServerUnavailable() {
            // This test assumes the remote server is not running
            BindingInstance result = remoteStore.retrieve(BINDING_INSTANCE_ID);
            // We expect null because the server won't be running
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Unsupported Operation Tests")
    class UnsupportedOperationTests {

        @Test
        @DisplayName("Should throw exception on store")
        void shouldThrowExceptionOnStore() {
            BindingInstance binding = BindingInstance.builder()
                    .bindingInstanceId(BINDING_INSTANCE_ID)
                    .userIdentity(USER_ID)
                    .workloadIdentity(WORKLOAD_ID)
                    .createdAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            assertThrows(UnsupportedOperationException.class, () -> remoteStore.store(binding));
        }

        @Test
        @DisplayName("Should return null on retrieveByUserIdentity")
        void shouldReturnNullOnRetrieveByUserIdentity() {
            assertNull(remoteStore.retrieveByUserIdentity(USER_ID));
        }

        @Test
        @DisplayName("Should return null on retrieveByWorkloadIdentity")
        void shouldReturnNullOnRetrieveByWorkloadIdentity() {
            assertNull(remoteStore.retrieveByWorkloadIdentity(WORKLOAD_ID));
        }

        @Test
        @DisplayName("Should throw exception on update")
        void shouldThrowExceptionOnUpdate() {
            BindingInstance binding = BindingInstance.builder()
                    .bindingInstanceId(BINDING_INSTANCE_ID)
                    .userIdentity(USER_ID)
                    .workloadIdentity(WORKLOAD_ID)
                    .createdAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build();

            assertThrows(UnsupportedOperationException.class, () -> remoteStore.update(binding));
        }

        @Test
        @DisplayName("Should throw exception on delete")
        void shouldThrowExceptionOnDelete() {
            assertThrows(UnsupportedOperationException.class, () -> remoteStore.delete(BINDING_INSTANCE_ID));
        }

        @Test
        @DisplayName("Should return 0 on deleteExpired")
        void shouldReturnZeroOnDeleteExpired() {
            assertEquals(0, remoteStore.deleteExpired());
        }
    }

    @Nested
    @DisplayName("Exists and Valid Tests")
    class ExistsAndValidTests {

        @Test
        @DisplayName("Should return false when binding instance does not exist")
        void shouldReturnFalseWhenBindingInstanceDoesNotExist() {
            assertFalse(remoteStore.exists("urn:uuid:non-existent"));
        }

        @Test
        @DisplayName("Should return false when binding instance is invalid")
        void shouldReturnFalseWhenBindingInstanceIsInvalid() {
            assertFalse(remoteStore.isValid("urn:uuid:non-existent"));
        }

        @Test
        @DisplayName("Should return false when remote server unavailable")
        void shouldReturnFalseWhenRemoteServerUnavailable() {
            assertFalse(remoteStore.exists(BINDING_INSTANCE_ID));
            assertFalse(remoteStore.isValid(BINDING_INSTANCE_ID));
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle special characters in binding instance ID")
        void shouldHandleSpecialCharactersInBindingInstanceId() {
            String specialId = "urn:uuid:test-123_special/chars";
            assertDoesNotThrow(() -> remoteStore.retrieve(specialId));
        }

        @Test
        @DisplayName("Should handle very long binding instance ID")
        void shouldHandleVeryLongBindingInstanceId() {
            String longId = "urn:uuid:" + "a".repeat(1000);
            assertDoesNotThrow(() -> remoteStore.retrieve(longId));
        }
    }
}
