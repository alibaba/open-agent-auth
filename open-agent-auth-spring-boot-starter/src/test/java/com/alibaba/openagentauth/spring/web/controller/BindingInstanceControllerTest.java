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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;

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
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .id(BINDING_INSTANCE_ID)
                .issuer("https://as.example.com")
                .issuedTo(USER_IDENTITY)
                .build();

        return BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
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

        ResponseEntity<BindingInstance> response = controller.getBinding(BINDING_INSTANCE_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(BINDING_INSTANCE_ID, response.getBody().getBindingInstanceId());
        verify(bindingInstanceStore).retrieve(BINDING_INSTANCE_ID);
    }

    @Test
    @DisplayName("Should return 404 when binding not found by ID")
    void shouldReturn404WhenBindingNotFoundById() {
        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(null);

        ResponseEntity<BindingInstance> response = controller.getBinding(BINDING_INSTANCE_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
        verify(bindingInstanceStore).retrieve(BINDING_INSTANCE_ID);
    }

    @Test
    @DisplayName("Should return 400 when binding instance ID is null or empty")
    void shouldReturn400WhenBindingInstanceIdIsNullOrEmpty() {
        ResponseEntity<BindingInstance> response = controller.getBinding(null);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        response = controller.getBinding("");
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

        ResponseEntity<Void> response = controller.deleteBinding(BINDING_INSTANCE_ID);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(bindingInstanceStore).exists(BINDING_INSTANCE_ID);
        verify(bindingInstanceStore).delete(BINDING_INSTANCE_ID);
    }

    @Test
    @DisplayName("Should return 404 when deleting non-existent binding")
    void shouldReturn404WhenDeletingNonExistentBinding() {
        when(bindingInstanceStore.exists(BINDING_INSTANCE_ID)).thenReturn(false);

        ResponseEntity<Void> response = controller.deleteBinding(BINDING_INSTANCE_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        verify(bindingInstanceStore).exists(BINDING_INSTANCE_ID);
        verify(bindingInstanceStore, never()).delete(any());
    }

    @Test
    @DisplayName("Should return 400 when deleting with null or empty ID")
    void shouldReturn400WhenDeletingWithNullOrEmptyId() {
        ResponseEntity<Void> response = controller.deleteBinding(null);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        response = controller.deleteBinding("");
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        verify(bindingInstanceStore, never()).exists(any());
        verify(bindingInstanceStore, never()).delete(any());
    }
}
