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
package com.alibaba.openagentauth.framework.web.store.impl;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for InMemorySessionMappingStore.
 * <p>
 * This test class verifies the functionality of the in-memory session
 * mapping store.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("InMemorySessionMappingStore Tests")
class InMemorySessionMappingStoreTest {

    private InMemorySessionMappingStore store;

    @Mock
    private HttpSession mockSession1;

    @Mock
    private HttpSession mockSession2;

    @BeforeEach
    void setUp() {
        store = new InMemorySessionMappingStore();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create store successfully")
        void shouldCreateStoreSuccessfully() {
            assertThat(store).isNotNull();
        }
    }

    @Nested
    @DisplayName("Store Tests")
    class StoreTests {

        @Test
        @DisplayName("Should store session successfully")
        void shouldStoreSessionSuccessfully() {
            store.store("session-1", mockSession1);

            assertThat(store.retrieve("session-1")).isNotNull();
            assertThat(store.retrieve("session-1")).isEqualTo(mockSession1);
        }

        @Test
        @DisplayName("Should replace existing session")
        void shouldReplaceExistingSession() {
            store.store("session-1", mockSession1);
            store.store("session-1", mockSession2);

            assertThat(store.retrieve("session-1")).isEqualTo(mockSession2);
        }

        @Test
        @DisplayName("Should handle null session ID")
        void shouldHandleNullSessionId() {
            store.store(null, mockSession1);

            assertThat(store.retrieve(null)).isNull();
        }

        @Test
        @DisplayName("Should handle null session")
        void shouldHandleNullSession() {
            store.store("session-1", null);

            assertThat(store.retrieve("session-1")).isNull();
        }
    }

    @Nested
    @DisplayName("Retrieve Tests")
    class RetrieveTests {

        @Test
        @DisplayName("Should retrieve stored session")
        void shouldRetrieveStoredSession() {
            store.store("session-1", mockSession1);

            HttpSession retrieved = store.retrieve("session-1");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved).isEqualTo(mockSession1);
        }

        @Test
        @DisplayName("Should return null for non-existent session")
        void shouldReturnNullForNonExistentSession() {
            HttpSession retrieved = store.retrieve("non-existent");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should handle null session ID")
        void shouldHandleNullSessionId() {
            HttpSession retrieved = store.retrieve(null);

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should handle empty session ID")
        void shouldHandleEmptySessionId() {
            HttpSession retrieved = store.retrieve("");

            assertThat(retrieved).isNull();
        }
    }

    @Nested
    @DisplayName("Remove Tests")
    class RemoveTests {

        @Test
        @DisplayName("Should remove session successfully")
        void shouldRemoveSessionSuccessfully() {
            store.store("session-1", mockSession1);
            assertThat(store.retrieve("session-1")).isNotNull();

            store.remove("session-1");
            assertThat(store.retrieve("session-1")).isNull();
        }

        @Test
        @DisplayName("Should handle removing non-existent session")
        void shouldHandleRemovingNonExistentSession() {
            assertThatCode(() -> store.remove("non-existent"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle null session ID")
        void shouldHandleNullSessionId() {
            assertThatCode(() -> store.remove(null))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle empty session ID")
        void shouldHandleEmptySessionId() {
            assertThatCode(() -> store.remove(""))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Clear All Tests")
    class ClearAllTests {

        @Test
        @DisplayName("Should clear all sessions")
        void shouldClearAllSessions() {
            store.store("session-1", mockSession1);
            store.store("session-2", mockSession2);

            assertThat(store.retrieve("session-1")).isNotNull();
            assertThat(store.retrieve("session-2")).isNotNull();

            store.clearAll();

            assertThat(store.retrieve("session-1")).isNull();
            assertThat(store.retrieve("session-2")).isNull();
        }

        @Test
        @DisplayName("Should handle clearing empty store")
        void shouldHandleClearingEmptyStore() {
            assertThatCode(() -> store.clearAll())
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Multiple Sessions Tests")
    class MultipleSessionsTests {

        @Test
        @DisplayName("Should handle multiple sessions")
        void shouldHandleMultipleSessions() {
            store.store("session-1", mockSession1);
            store.store("session-2", mockSession2);
            store.store("session-3", mockSession1);

            assertThat(store.retrieve("session-1")).isEqualTo(mockSession1);
            assertThat(store.retrieve("session-2")).isEqualTo(mockSession2);
            assertThat(store.retrieve("session-3")).isEqualTo(mockSession1);
        }

        @Test
        @DisplayName("Should remove specific session without affecting others")
        void shouldRemoveSpecificSessionWithoutAffectingOthers() {
            store.store("session-1", mockSession1);
            store.store("session-2", mockSession2);

            store.remove("session-1");

            assertThat(store.retrieve("session-1")).isNull();
            assertThat(store.retrieve("session-2")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle whitespace session ID")
        void shouldHandleWhitespaceSessionId() {
            store.store("   ", mockSession1);

            HttpSession retrieved = store.retrieve("   ");
            assertThat(retrieved).isNotNull();
        }

        @Test
        @DisplayName("Should handle long session ID")
        void shouldHandleLongSessionId() {
            String longSessionId = "a".repeat(1000);
            store.store(longSessionId, mockSession1);

            assertThat(store.retrieve(longSessionId)).isNotNull();
        }

        @Test
        @DisplayName("Should handle special characters in session ID")
        void shouldHandleSpecialCharactersInSessionId() {
            String specialSessionId = "session-1_2.3@4#5$6%7^8&9*0";
            store.store(specialSessionId, mockSession1);

            assertThat(store.retrieve(specialSessionId)).isNotNull();
        }
    }

    @Nested
    @DisplayName("TTL Expiration Tests")
    class TtlExpirationTests {

        @Test
        @DisplayName("Should return null for expired session")
        void shouldReturnNullForExpiredSession() throws InterruptedException {
            InMemorySessionMappingStore ttlStore = new InMemorySessionMappingStore(
                    Duration.ofMillis(100),
                    Duration.ofMinutes(5)
            );
            ttlStore.store("session-1", mockSession1);

            assertThat(ttlStore.retrieve("session-1")).isNotNull();

            Thread.sleep(150);

            HttpSession retrieved = ttlStore.retrieve("session-1");
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return session before expiration")
        void shouldReturnSessionBeforeExpiration() {
            InMemorySessionMappingStore ttlStore = new InMemorySessionMappingStore(
                    Duration.ofMillis(100),
                    Duration.ofMinutes(5)
            );
            ttlStore.store("session-1", mockSession1);

            HttpSession retrieved = ttlStore.retrieve("session-1");
            assertThat(retrieved).isNotNull();
            assertThat(retrieved).isEqualTo(mockSession1);
        }

        @Test
        @DisplayName("Should create store with default TTL")
        void shouldCreateStoreWithDefaultTtl() {
            InMemorySessionMappingStore defaultStore = new InMemorySessionMappingStore();

            assertThat(defaultStore).isNotNull();
        }

        @Test
        @DisplayName("Should create store with custom TTL")
        void shouldCreateStoreWithCustomTtl() {
            InMemorySessionMappingStore customStore = new InMemorySessionMappingStore(
                    Duration.ofSeconds(30),
                    Duration.ofMinutes(1)
            );

            assertThat(customStore).isNotNull();
        }
    }
}