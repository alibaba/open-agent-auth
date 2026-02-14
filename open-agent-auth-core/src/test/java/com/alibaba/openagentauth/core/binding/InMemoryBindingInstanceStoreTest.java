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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link InMemoryBindingInstanceStore}.
 */
@DisplayName("InMemoryBindingInstanceStore Tests")
class InMemoryBindingInstanceStoreTest {

    private InMemoryBindingInstanceStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryBindingInstanceStore();
    }

    @AfterEach
    void tearDown() {
        if (store != null) {
            store.clear();
        }
    }

    private BindingInstance createTestBinding(String id) {
        return BindingInstance.builder()
                .bindingInstanceId(id)
                .userIdentity("https://idp.example.com|user-" + id)
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent-" + id)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
    }

    @Test
    @DisplayName("Should store and retrieve binding instance by ID")
    void shouldStoreAndRetrieveBindingInstanceById() {
        String bindingId = "urn:uuid:binding-123";
        BindingInstance binding = createTestBinding(bindingId);

        store.store(binding);

        BindingInstance retrieved = store.retrieve(bindingId);
        assertNotNull(retrieved);
        assertEquals(binding.getBindingInstanceId(), retrieved.getBindingInstanceId());
        assertEquals(binding.getUserIdentity(), retrieved.getUserIdentity());
        assertEquals(binding.getWorkloadIdentity(), retrieved.getWorkloadIdentity());
    }

    @Test
    @DisplayName("Should return null when retrieving non-existent binding")
    void shouldReturnNullWhenRetrievingNonExistentBinding() {
        BindingInstance retrieved = store.retrieve("non-existent-id");
        assertNull(retrieved);
    }

    @Test
    @DisplayName("Should return null when retrieving with null ID")
    void shouldReturnNullWhenRetrievingWithNullId() {
        BindingInstance retrieved = store.retrieve(null);
        assertNull(retrieved);
    }

    @Test
    @DisplayName("Should retrieve binding by user identity")
    void shouldRetrieveBindingByUserIdentity() {
        String bindingId = "urn:uuid:binding-123";
        String userIdentity = "https://idp.example.com|user-456";
        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(bindingId)
                .userIdentity(userIdentity)
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent")
                .build();

        store.store(binding);

        BindingInstance retrieved = store.retrieveByUserIdentity(userIdentity);
        assertNotNull(retrieved);
        assertEquals(binding.getBindingInstanceId(), retrieved.getBindingInstanceId());
    }

    @Test
    @DisplayName("Should retrieve binding by workload identity")
    void shouldRetrieveBindingByWorkloadIdentity() {
        String bindingId = "urn:uuid:binding-123";
        String workloadIdentity = "spiffe://example.com/ns/default/sa/agent-789";
        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(bindingId)
                .userIdentity("https://idp.example.com|user-123")
                .workloadIdentity(workloadIdentity)
                .build();

        store.store(binding);

        BindingInstance retrieved = store.retrieveByWorkloadIdentity(workloadIdentity);
        assertNotNull(retrieved);
        assertEquals(binding.getBindingInstanceId(), retrieved.getBindingInstanceId());
    }

    @Test
    @DisplayName("Should update existing binding instance")
    void shouldUpdateExistingBindingInstance() {
        String bindingId = "urn:uuid:binding-123";
        BindingInstance original = createTestBinding(bindingId);
        store.store(original);

        Instant newExpiration = Instant.now().plusSeconds(7200);
        BindingInstance updated = BindingInstance.builder()
                .bindingInstanceId(bindingId)
                .userIdentity(original.getUserIdentity())
                .workloadIdentity(original.getWorkloadIdentity())
                .createdAt(original.getCreatedAt())
                .expiresAt(newExpiration)
                .build();

        store.update(updated);

        BindingInstance retrieved = store.retrieve(bindingId);
        assertNotNull(retrieved);
        assertEquals(newExpiration, retrieved.getExpiresAt());
    }

    @Test
    @DisplayName("Should not update when binding does not exist")
    void shouldNotUpdateWhenBindingDoesNotExist() {
        String bindingId = "urn:uuid:non-existent";
        BindingInstance binding = createTestBinding(bindingId);

        store.update(binding);

        BindingInstance retrieved = store.retrieve(bindingId);
        assertNull(retrieved);
    }

    @Test
    @DisplayName("Should delete binding instance")
    void shouldDeleteBindingInstance() {
        String bindingId = "urn:uuid:binding-123";
        BindingInstance binding = createTestBinding(bindingId);
        store.store(binding);

        assertTrue(store.exists(bindingId));

        store.delete(bindingId);

        assertFalse(store.exists(bindingId));
        assertNull(store.retrieve(bindingId));
    }

    @Test
    @DisplayName("Should handle delete with null ID gracefully")
    void shouldHandleDeleteWithNullIdGracefully() {
        assertDoesNotThrow(() -> store.delete(null));
    }

    @Test
    @DisplayName("Should check if binding exists")
    void shouldCheckIfBindingExists() {
        String bindingId = "urn:uuid:binding-123";
        BindingInstance binding = createTestBinding(bindingId);

        assertFalse(store.exists(bindingId));

        store.store(binding);

        assertTrue(store.exists(bindingId));
    }

    @Test
    @DisplayName("Should return false for exists with null ID")
    void shouldReturnFalseForExistsWithNullId() {
        assertFalse(store.exists(null));
    }

    @Test
    @DisplayName("Should check if binding is valid")
    void shouldCheckIfBindingIsValid() {
        String validBindingId = "urn:uuid:binding-valid";
        String expiredBindingId = "urn:uuid:binding-expired";

        BindingInstance validBinding = BindingInstance.builder()
                .bindingInstanceId(validBindingId)
                .userIdentity("https://idp.example.com|user-123")
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent")
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        BindingInstance expiredBinding = BindingInstance.builder()
                .bindingInstanceId(expiredBindingId)
                .userIdentity("https://idp.example.com|user-456")
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent-2")
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();

        store.store(validBinding);
        store.store(expiredBinding);

        assertTrue(store.isValid(validBindingId));
        assertFalse(store.isValid(expiredBindingId));
        assertFalse(store.isValid("non-existent"));
        assertFalse(store.isValid(null));
    }

    @Test
    @DisplayName("Should delete expired bindings")
    void shouldDeleteExpiredBindings() {
        String expired1 = "urn:uuid:expired-1";
        String expired2 = "urn:uuid:expired-2";
        String valid = "urn:uuid:valid-1";

        store.store(BindingInstance.builder()
                .bindingInstanceId(expired1)
                .userIdentity("https://idp.example.com|user-1")
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent-1")
                .createdAt(Instant.now())
                .expiresAt(Instant.now().minusSeconds(3600))
                .build());
        store.store(BindingInstance.builder()
                .bindingInstanceId(expired2)
                .userIdentity("https://idp.example.com|user-2")
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent-2")
                .createdAt(Instant.now())
                .expiresAt(Instant.now().minusSeconds(7200))
                .build());
        store.store(BindingInstance.builder()
                .bindingInstanceId(valid)
                .userIdentity("https://idp.example.com|user-3")
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent-3")
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals(3, store.size());

        int deletedCount = store.deleteExpired();

        assertEquals(2, deletedCount);
        assertEquals(1, store.size());
        assertTrue(store.exists(valid));
        assertFalse(store.exists(expired1));
        assertFalse(store.exists(expired2));
    }

    @Test
    @DisplayName("Should handle null binding gracefully when storing")
    void shouldHandleNullBindingGracefullyWhenStoring() {
        assertDoesNotThrow(() -> store.store(null));
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("Should handle null binding gracefully when updating")
    void shouldHandleNullBindingGracefullyWhenUpdating() {
        assertDoesNotThrow(() -> store.update(null));
    }

    @Test
    @DisplayName("Should return correct size")
    void shouldReturnCorrectSize() {
        assertEquals(0, store.size());

        store.store(createTestBinding("urn:uuid:binding-1"));
        assertEquals(1, store.size());

        store.store(createTestBinding("urn:uuid:binding-2"));
        assertEquals(2, store.size());

        store.store(createTestBinding("urn:uuid:binding-3"));
        assertEquals(3, store.size());

        store.delete("urn:uuid:binding-1");
        assertEquals(2, store.size());
    }

    @Test
    @DisplayName("Should clear all bindings")
    void shouldClearAllBindings() {
        store.store(createTestBinding("urn:uuid:binding-1"));
        store.store(createTestBinding("urn:uuid:binding-2"));
        store.store(createTestBinding("urn:uuid:binding-3"));

        assertEquals(3, store.size());

        store.clear();

        assertEquals(0, store.size());
        assertNull(store.retrieve("urn:uuid:binding-1"));
        assertNull(store.retrieve("urn:uuid:binding-2"));
        assertNull(store.retrieve("urn:uuid:binding-3"));
    }

    @Test
    @DisplayName("Should overwrite existing binding when storing with same ID")
    void shouldOverwriteExistingBindingWhenStoringWithSameId() {
        String bindingId = "urn:uuid:binding-123";
        String originalUserIdentity = "https://idp.example.com|user-1";
        String newUserIdentity = "https://idp.example.com|user-2";

        BindingInstance original = BindingInstance.builder()
                .bindingInstanceId(bindingId)
                .userIdentity(originalUserIdentity)
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent")
                .build();

        store.store(original);

        BindingInstance updated = BindingInstance.builder()
                .bindingInstanceId(bindingId)
                .userIdentity(newUserIdentity)
                .workloadIdentity("spiffe://example.com/ns/default/sa/agent")
                .build();

        store.store(updated);

        BindingInstance retrieved = store.retrieve(bindingId);
        assertNotNull(retrieved);
        assertEquals(newUserIdentity, retrieved.getUserIdentity());
    }

    @Test
    @DisplayName("Should handle concurrent operations safely")
    void shouldHandleConcurrentOperationsSafely() throws InterruptedException {
        int threadCount = 10;
        int bindingsPerThread = 100;
        Thread[] threads = new Thread[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < bindingsPerThread; j++) {
                    String bindingId = "urn:uuid:binding-" + threadId + "-" + j;
                    store.store(createTestBinding(bindingId));
                }
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        int expectedSize = threadCount * bindingsPerThread;
        assertEquals(expectedSize, store.size());
    }
}