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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.binding.BindingInstance;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.page.PageRequest;
import com.alibaba.openagentauth.core.model.page.PageResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BindingInstanceController}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("BindingInstanceController Tests")
class BindingInstanceControllerTest {

    @Mock
    private BindingInstanceStore bindingInstanceStore;

    private BindingInstanceController controller;

    private static final String BINDING_INSTANCE_ID = "urn:uuid:binding-123";
    private static final String USER_IDENTITY = "https://idp.example.com|user-12345";
    private static final String WORKLOAD_IDENTITY = "spiffe://example.com/ns/default/sa/agent";

    @BeforeEach
    void setUp() {
        controller = new BindingInstanceController(bindingInstanceStore);
    }

    private BindingInstance createTestBinding() {
        return createTestBinding(BINDING_INSTANCE_ID);
    }

    private BindingInstance createTestBinding(String bindingInstanceId) {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .id(bindingInstanceId)
                .issuer("https://as.example.com")
                .issuedTo(USER_IDENTITY)
                .build();

        return BindingInstance.builder()
                .bindingInstanceId(bindingInstanceId)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .agentIdentity(agentIdentity)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
    }

    @Test
    @DisplayName("Should return binding instance when found by ID")
    void shouldReturnBindingInstanceWhenFoundById() {
        BindingInstance binding = createTestBinding();
        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(binding);

        BindingInstanceController.BindingInstanceIdRequest request = new BindingInstanceController.BindingInstanceIdRequest();
        request.setBindingInstanceId(BINDING_INSTANCE_ID);
        ResponseEntity<BindingInstance> response = controller.getBinding(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(BINDING_INSTANCE_ID, response.getBody().getBindingInstanceId());
        verify(bindingInstanceStore).retrieve(BINDING_INSTANCE_ID);
    }

    @Test
    @DisplayName("Should return 404 when binding not found by ID")
    void shouldReturn404WhenBindingNotFoundById() {
        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(null);

        BindingInstanceController.BindingInstanceIdRequest request = new BindingInstanceController.BindingInstanceIdRequest();
        request.setBindingInstanceId(BINDING_INSTANCE_ID);
        ResponseEntity<BindingInstance> response = controller.getBinding(request);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
        verify(bindingInstanceStore).retrieve(BINDING_INSTANCE_ID);
    }

    @Test
    @DisplayName("Should return 400 when binding instance ID is null or empty")
    void shouldReturn400WhenBindingInstanceIdIsNullOrEmpty() {
        BindingInstanceController.BindingInstanceIdRequest nullRequest = new BindingInstanceController.BindingInstanceIdRequest();
        nullRequest.setBindingInstanceId(null);
        ResponseEntity<BindingInstance> response = controller.getBinding(nullRequest);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        BindingInstanceController.BindingInstanceIdRequest emptyRequest = new BindingInstanceController.BindingInstanceIdRequest();
        emptyRequest.setBindingInstanceId("");
        response = controller.getBinding(emptyRequest);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        verify(bindingInstanceStore, never()).retrieve(any());
    }

    @Test
    @DisplayName("Should create binding instance successfully")
    void shouldCreateBindingInstanceSuccessfully() {
        BindingInstanceController.BindingInstanceRequest request = new BindingInstanceController.BindingInstanceRequest();
        request.setBindingInstanceId(BINDING_INSTANCE_ID);
        request.setUserIdentity(USER_IDENTITY);
        request.setWorkloadIdentity(WORKLOAD_IDENTITY);
        request.setCreatedAt(Instant.now());
        request.setExpiresAt(Instant.now().plusSeconds(3600));

        doNothing().when(bindingInstanceStore).store(any(BindingInstance.class));

        ResponseEntity<BindingInstance> response = controller.createBinding(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(BINDING_INSTANCE_ID, response.getBody().getBindingInstanceId());
        verify(bindingInstanceStore).store(any(BindingInstance.class));
    }

    @Test
    @DisplayName("Should return 500 when creating binding fails")
    void shouldReturn500WhenCreatingBindingFails() {
        BindingInstanceController.BindingInstanceRequest request = new BindingInstanceController.BindingInstanceRequest();
        request.setBindingInstanceId(BINDING_INSTANCE_ID);
        request.setUserIdentity(USER_IDENTITY);
        request.setWorkloadIdentity(WORKLOAD_IDENTITY);

        doThrow(new RuntimeException("Database error")).when(bindingInstanceStore).store(any(BindingInstance.class));

        ResponseEntity<BindingInstance> response = controller.createBinding(request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        verify(bindingInstanceStore).store(any(BindingInstance.class));
    }

    @Test
    @DisplayName("Should delete binding instance successfully")
    void shouldDeleteBindingInstanceSuccessfully() {
        when(bindingInstanceStore.exists(BINDING_INSTANCE_ID)).thenReturn(true);
        doNothing().when(bindingInstanceStore).delete(BINDING_INSTANCE_ID);

        BindingInstanceController.BindingInstanceIdRequest request = new BindingInstanceController.BindingInstanceIdRequest();
        request.setBindingInstanceId(BINDING_INSTANCE_ID);
        ResponseEntity<Void> response = controller.deleteBinding(request);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(bindingInstanceStore).exists(BINDING_INSTANCE_ID);
        verify(bindingInstanceStore).delete(BINDING_INSTANCE_ID);
    }

    @Test
    @DisplayName("Should return 404 when deleting non-existent binding")
    void shouldReturn404WhenDeletingNonExistentBinding() {
        when(bindingInstanceStore.exists(BINDING_INSTANCE_ID)).thenReturn(false);

        BindingInstanceController.BindingInstanceIdRequest request = new BindingInstanceController.BindingInstanceIdRequest();
        request.setBindingInstanceId(BINDING_INSTANCE_ID);
        ResponseEntity<Void> response = controller.deleteBinding(request);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        verify(bindingInstanceStore).exists(BINDING_INSTANCE_ID);
        verify(bindingInstanceStore, never()).delete(any());
    }

    @Test
    @DisplayName("Should return 400 when deleting with null or empty ID")
    void shouldReturn400WhenDeletingWithNullOrEmptyId() {
        BindingInstanceController.BindingInstanceIdRequest nullRequest = new BindingInstanceController.BindingInstanceIdRequest();
        nullRequest.setBindingInstanceId(null);
        ResponseEntity<Void> response = controller.deleteBinding(nullRequest);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        BindingInstanceController.BindingInstanceIdRequest emptyRequest = new BindingInstanceController.BindingInstanceIdRequest();
        emptyRequest.setBindingInstanceId("");
        response = controller.deleteBinding(emptyRequest);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        verify(bindingInstanceStore, never()).exists(any());
        verify(bindingInstanceStore, never()).delete(any());
    }

    @Nested
    @DisplayName("List Bindings with Pagination Tests")
    class ListBindingsPaginationTests {

        @Test
        @DisplayName("Should return paginated bindings")
        void shouldReturnPaginatedBindings() {
            // Arrange
            List<BindingInstance> bindings = new ArrayList<>();
            bindings.add(createTestBinding("urn:uuid:binding-1"));
            bindings.add(createTestBinding("urn:uuid:binding-2"));
            bindings.add(createTestBinding("urn:uuid:binding-3"));
            when(bindingInstanceStore.listAll()).thenReturn(bindings);

            PageRequest pageRequest = new PageRequest(1, 2);

            // Act
            ResponseEntity<PageResponse<BindingInstance>> response = controller.listBindings(pageRequest);

            // Assert
            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(2, response.getBody().getItems().size());
            assertEquals(3, response.getBody().getTotalItems());
            assertEquals(2, response.getBody().getTotalPages());
            assertEquals(1, response.getBody().getPage());
        }

        @Test
        @DisplayName("Should return empty page when no bindings")
        void shouldReturnEmptyPageWhenNoBindings() {
            // Arrange
            when(bindingInstanceStore.listAll()).thenReturn(Collections.emptyList());
            PageRequest pageRequest = new PageRequest(1, 10);

            // Act
            ResponseEntity<PageResponse<BindingInstance>> response = controller.listBindings(pageRequest);

            // Assert
            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(0, response.getBody().getItems().size());
            assertEquals(0, response.getBody().getTotalItems());
        }

        @Test
        @DisplayName("Should return second page")
        void shouldReturnSecondPage() {
            // Arrange
            List<BindingInstance> bindings = new ArrayList<>();
            bindings.add(createTestBinding("urn:uuid:binding-1"));
            bindings.add(createTestBinding("urn:uuid:binding-2"));
            bindings.add(createTestBinding("urn:uuid:binding-3"));
            when(bindingInstanceStore.listAll()).thenReturn(bindings);
            PageRequest pageRequest = new PageRequest(2, 2);

            // Act
            ResponseEntity<PageResponse<BindingInstance>> response = controller.listBindings(pageRequest);

            // Assert
            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(1, response.getBody().getItems().size());
            assertEquals(3, response.getBody().getTotalItems());
            assertEquals(2, response.getBody().getPage());
        }

        @Test
        @DisplayName("Should return 500 when list fails")
        void shouldReturn500WhenListFails() {
            // Arrange
            when(bindingInstanceStore.listAll()).thenThrow(new RuntimeException("DB error"));
            PageRequest pageRequest = new PageRequest(1, 10);

            // Act
            ResponseEntity<PageResponse<BindingInstance>> response = controller.listBindings(pageRequest);

            // Assert
            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        }
    }
}
