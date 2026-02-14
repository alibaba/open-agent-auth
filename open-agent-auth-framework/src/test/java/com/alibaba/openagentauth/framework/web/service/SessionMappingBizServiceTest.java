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
package com.alibaba.openagentauth.framework.web.service;

import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SessionMappingBizService.
 * <p>
 * This test class verifies the functionality of the session mapping business service.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SessionMappingBizService Tests")
class SessionMappingBizServiceTest {

    @Mock
    private SessionMappingStore mockStore;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpSession mockSession;

    @Mock
    private HttpSession mockRestoredSession;

    private SessionMappingBizService service;

    @BeforeEach
    void setUp() {
        service = new SessionMappingBizService(mockStore);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create service with valid store")
        void shouldCreateServiceWithValidStore() {
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when store is null")
        void shouldThrowExceptionWhenStoreIsNull() {
            assertThatThrownBy(() -> new SessionMappingBizService(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("SessionMappingStore");
        }
    }

    @Nested
    @DisplayName("Store Session Tests")
    class StoreSessionTests {

        @Test
        @DisplayName("Should store session successfully")
        void shouldStoreSessionSuccessfully() {
            service.storeSession("session-123", mockSession);

            verify(mockStore).store("session-123", mockSession);
        }

        @Test
        @DisplayName("Should handle null session ID")
        void shouldHandleNullSessionId() {
            service.storeSession(null, mockSession);

            verify(mockStore, never()).store(anyString(), any());
        }

        @Test
        @DisplayName("Should handle null session")
        void shouldHandleNullSession() {
            service.storeSession("session-123", null);

            verify(mockStore, never()).store(anyString(), any());
        }
    }

    @Nested
    @DisplayName("Restore Session Tests")
    class RestoreSessionTests {

        @Test
        @DisplayName("Should restore existing session")
        void shouldRestoreExistingSession() {
            when(mockStore.retrieve("session-123")).thenReturn(mockSession);

            HttpSession restored = service.restoreSession("session-123", false, mockRequest);

            assertThat(restored).isNotNull();
            assertThat(restored).isEqualTo(mockSession);
            verify(mockStore).retrieve("session-123");
            verify(mockRequest, never()).getSession(anyBoolean());
        }

        @Test
        @DisplayName("Should create new session when not found and createIfNotFound is true")
        void shouldCreateNewSessionWhenNotFoundAndCreateIfNotFoundIsTrue() {
            when(mockStore.retrieve("session-123")).thenReturn(null);
            when(mockRequest.getSession(true)).thenReturn(mockSession);

            HttpSession restored = service.restoreSession("session-123", true, mockRequest);

            assertThat(restored).isNotNull();
            assertThat(restored).isEqualTo(mockSession);
            verify(mockStore).retrieve("session-123");
            verify(mockRequest).getSession(true);
        }

        @Test
        @DisplayName("Should return null when not found and createIfNotFound is false")
        void shouldReturnNullWhenNotFoundAndCreateIfNotFoundIsFalse() {
            when(mockStore.retrieve("session-123")).thenReturn(null);

            HttpSession restored = service.restoreSession("session-123", false, mockRequest);

            assertThat(restored).isNull();
            verify(mockStore).retrieve("session-123");
            verify(mockRequest, never()).getSession(anyBoolean());
        }

        @Test
        @DisplayName("Should create new session when session ID is null and createIfNotFound is true")
        void shouldCreateNewSessionWhenSessionIdIsNullAndCreateIfNotFoundIsTrue() {
            when(mockRequest.getSession(true)).thenReturn(mockSession);

            HttpSession restored = service.restoreSession(null, true, mockRequest);

            assertThat(restored).isNotNull();
            assertThat(restored).isEqualTo(mockSession);
            verify(mockStore, never()).retrieve(anyString());
            verify(mockRequest).getSession(true);
        }

        @Test
        @DisplayName("Should return null when session ID is null and createIfNotFound is false")
        void shouldReturnNullWhenSessionIdIsNullAndCreateIfNotFoundIsFalse() {
            HttpSession restored = service.restoreSession(null, false, mockRequest);

            assertThat(restored).isNull();
            verify(mockStore, never()).retrieve(anyString());
            verify(mockRequest, never()).getSession(anyBoolean());
        }
    }

    @Nested
    @DisplayName("Remove Session Tests")
    class RemoveSessionTests {

        @Test
        @DisplayName("Should remove session successfully")
        void shouldRemoveSessionSuccessfully() {
            service.removeSession("session-123");

            verify(mockStore).remove("session-123");
        }

        @Test
        @DisplayName("Should handle null session ID")
        void shouldHandleNullSessionId() {
            service.removeSession(null);

            verify(mockStore, never()).remove(anyString());
        }
    }

    @Nested
    @DisplayName("Sync Session Attributes Tests")
    class SyncSessionAttributesTests {

        @Test
        @DisplayName("Should sync attributes from source to target")
        void shouldSyncAttributesFromSourceToTarget() {
            when(mockSession.getAttributeNames())
                    .thenReturn(new java.util.Vector<>(java.util.List.of("attr1", "attr2")).elements());
            when(mockSession.getAttribute("attr1")).thenReturn("value1");
            when(mockSession.getAttribute("attr2")).thenReturn("value2");

            service.syncSessionAttributes(mockSession, mockRestoredSession);

            verify(mockRestoredSession).setAttribute("attr1", "value1");
            verify(mockRestoredSession).setAttribute("attr2", "value2");
        }

        @Test
        @DisplayName("Should handle null source session")
        void shouldHandleNullSourceSession() {
            service.syncSessionAttributes(null, mockRestoredSession);

            verify(mockRestoredSession, never()).setAttribute(anyString(), any());
        }

        @Test
        @DisplayName("Should handle null target session")
        void shouldHandleNullTargetSession() {
            service.syncSessionAttributes(mockSession, null);

            verify(mockSession, never()).getAttributeNames();
        }

        @Test
        @DisplayName("Should skip null attribute values")
        void shouldSkipNullAttributeValues() {
            when(mockSession.getAttributeNames())
                    .thenReturn(new java.util.Vector<>(java.util.List.of("attr1", "attr2")).elements());
            when(mockSession.getAttribute("attr1")).thenReturn("value1");
            when(mockSession.getAttribute("attr2")).thenReturn(null);

            service.syncSessionAttributes(mockSession, mockRestoredSession);

            verify(mockRestoredSession).setAttribute("attr1", "value1");
            verify(mockRestoredSession, never()).setAttribute(eq("attr2"), isNull());
        }

        @Test
        @DisplayName("Should handle empty attribute names")
        void shouldHandleEmptyAttributeNames() {
            when(mockSession.getAttributeNames())
                    .thenReturn(new java.util.Vector<String>().elements());

            service.syncSessionAttributes(mockSession, mockRestoredSession);

            verify(mockRestoredSession, never()).setAttribute(anyString(), any());
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle large number of attributes")
        void shouldHandleLargeNumberOfAttributes() {
            java.util.Vector<String> attributeNames = new java.util.Vector<>();
            for (int i = 0; i < 100; i++) {
                attributeNames.add("attr" + i);
            }
            when(mockSession.getAttributeNames()).thenReturn(attributeNames.elements());
            for (int i = 0; i < 100; i++) {
                when(mockSession.getAttribute("attr" + i)).thenReturn("value" + i);
            }

            service.syncSessionAttributes(mockSession, mockRestoredSession);

            verify(mockRestoredSession, times(100)).setAttribute(anyString(), any());
        }

        @Test
        @DisplayName("Should overwrite existing attributes in target session")
        void shouldOverwriteExistingAttributesInTargetSession() {
            when(mockSession.getAttributeNames())
                    .thenReturn(new java.util.Vector<>(java.util.List.of("attr1")).elements());
            when(mockSession.getAttribute("attr1")).thenReturn("new-value");

            service.syncSessionAttributes(mockSession, mockRestoredSession);

            verify(mockRestoredSession).setAttribute("attr1", "new-value");
        }
    }
}