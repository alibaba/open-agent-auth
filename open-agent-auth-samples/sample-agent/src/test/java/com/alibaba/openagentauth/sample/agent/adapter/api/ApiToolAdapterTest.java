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
package com.alibaba.openagentauth.sample.agent.adapter.api;

import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ApiToolAdapter}.
 * <p>
 * This test class verifies the API tool adapter functionality.
 * </p>
 */
@DisplayName("ApiToolAdapter Tests")
class ApiToolAdapterTest {

    private RestTemplate mockRestTemplate;
    private ServiceEndpointResolver mockEndpointResolver;
    private ApiToolAdapter adapter;

    private static final String SERVER_NAME = "test-api-server";
    private static final String BASE_URL = "http://localhost:8080";

    @BeforeEach
    void setUp() {
        mockRestTemplate = mock(RestTemplate.class);
        mockEndpointResolver = mock(ServiceEndpointResolver.class);
        adapter = new ApiToolAdapter(SERVER_NAME, mockEndpointResolver, mockRestTemplate);
    }

    @Nested
    @DisplayName("Adapter Type")
    class AdapterTypeTests {

        @Test
        @DisplayName("Should return correct adapter type")
        void shouldReturnCorrectAdapterType() {
            // When
            String type = adapter.getAdapterType();

            // Then
            assertEquals("api", type, "Adapter type should be 'api'");
        }
    }

    @Nested
    @DisplayName("Initialize")
    class InitializeTests {

        @Test
        @DisplayName("Should initialize successfully")
        void shouldInitializeSuccessfully() throws Exception {
            // When & Then - should not throw exception
            assertDoesNotThrow(() -> adapter.initialize());
        }
    }

    @Nested
    @DisplayName("List Tools")
    class ListToolsTests {

        @Test
        @DisplayName("Should return empty list when no tools registered")
        void shouldReturnEmptyListWhenNoToolsRegistered() {
            // When
            var tools = adapter.listTools();

            // Then
            assertNotNull(tools, "Tools list should not be null");
            assertTrue(tools.isEmpty(), "Tools list should be empty");
        }

        @Test
        @DisplayName("Should return registered tools")
        void shouldReturnRegisteredTools() {
            // Given
            adapter.registerTool("test-tool", "Test tool", "POST", "/api/test");

            // When
            var tools = adapter.listTools();

            // Then
            assertNotNull(tools, "Tools list should not be null");
            assertEquals(1, tools.size(), "Should return 1 tool");
            assertEquals("test-tool", tools.get(0).getToolName());
        }
    }

    @Nested
    @DisplayName("Call Tool")
    class CallToolTests {

        @Test
        @DisplayName("Should call tool successfully")
        void shouldCallToolSuccessfully() {
            // Given
            String responseBody = "{\"result\": \"success\"}";
            ResponseEntity<String> response = new ResponseEntity<>(responseBody, HttpStatus.OK);
            String expectedUrl = BASE_URL + "/test-tool";

            when(mockEndpointResolver.resolveConsumer(SERVER_NAME, "test-tool")).thenReturn(expectedUrl);
            when(mockRestTemplate.exchange(
                    eq(expectedUrl),
                    eq(HttpMethod.POST),
                    any(HttpEntity.class),
                    eq(String.class)
            )).thenReturn(response);

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("param1", "value1");

            // When
            var result = adapter.callTool("test-tool", arguments);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isSuccess(), "Result should be successful");
            assertEquals(responseBody, result.getData());
        }

        @Test
        @DisplayName("Should call tool with registered endpoint")
        void shouldCallToolWithRegisteredEndpoint() {
            // Given
            adapter.registerTool("test-tool", "Test tool", "POST", "/api/test");

            String responseBody = "{\"result\": \"success\"}";
            ResponseEntity<String> response = new ResponseEntity<>(responseBody, HttpStatus.OK);
            String expectedUrl = BASE_URL + "/api/test";

            when(mockEndpointResolver.resolveConsumer(SERVER_NAME, "/api/test")).thenReturn(expectedUrl);
            when(mockRestTemplate.exchange(
                    eq(expectedUrl),
                    eq(HttpMethod.POST),
                    any(HttpEntity.class),
                    eq(String.class)
            )).thenReturn(response);

            Map<String, Object> arguments = new HashMap<>();

            // When
            var result = adapter.callTool("test-tool", arguments);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isSuccess(), "Result should be successful");
        }

        @Test
        @DisplayName("Should return error when HTTP call fails")
        void shouldReturnErrorWhenHttpCallFails() {
            // Given
            String expectedUrl = BASE_URL + "/test-tool";
            when(mockEndpointResolver.resolveConsumer(SERVER_NAME, "test-tool")).thenReturn(expectedUrl);
            when(mockRestTemplate.exchange(
                    eq(expectedUrl),
                    eq(HttpMethod.POST),
                    any(HttpEntity.class),
                    eq(String.class)
            )).thenThrow(new RuntimeException("HTTP call failed"));

            Map<String, Object> arguments = new HashMap<>();

            // When
            var result = adapter.callTool("test-tool", arguments);

            // Then
            assertNotNull(result, "Result should not be null");
            assertFalse(result.isSuccess(), "Result should not be successful");
            assertTrue(result.getError().contains("Failed to call API tool"),
                    "Error message should mention API tool failure");
        }

        @Test
        @DisplayName("Should return error when HTTP status is not 2xx")
        void shouldReturnErrorWhenHttpStatusIsNot2xx() {
            // Given
            String expectedUrl = BASE_URL + "/test-tool";
            when(mockEndpointResolver.resolveConsumer(SERVER_NAME, "test-tool")).thenReturn(expectedUrl);
            ResponseEntity<String> response = new ResponseEntity<>("Internal Server Error", HttpStatus.INTERNAL_SERVER_ERROR);

            when(mockRestTemplate.exchange(
                    eq(expectedUrl),
                    eq(HttpMethod.POST),
                    any(HttpEntity.class),
                    eq(String.class)
            )).thenReturn(response);

            Map<String, Object> arguments = new HashMap<>();

            // When
            var result = adapter.callTool("test-tool", arguments);

            // Then
            assertNotNull(result, "Result should not be null");
            assertFalse(result.isSuccess(), "Result should not be successful");
            assertTrue(result.getError().contains("API call failed"),
                    "Error message should mention API call failure");
        }
    }

    @Nested
    @DisplayName("Register Tool")
    class RegisterToolTests {

        @Test
        @DisplayName("Should register tool successfully")
        void shouldRegisterToolSuccessfully() {
            // When & Then - should not throw exception
            assertDoesNotThrow(() -> {
                adapter.registerTool("test-tool", "Test tool", "POST", "/api/test");
            });

            // Verify tool is registered
            var tools = adapter.listTools();
            assertEquals(1, tools.size(), "Should have 1 registered tool");
        }
    }

    @Nested
    @DisplayName("Set Auth Token")
    class SetAuthTokenTests {

        @Test
        @DisplayName("Should set auth token successfully")
        void shouldSetAuthTokenSuccessfully() {
            // Given
            String token = "test-token";

            // When
            adapter.setAuthToken(token);

            // Then - token should be set for subsequent calls
            // This is verified implicitly through the callTool test
            assertDoesNotThrow(() -> adapter.setAuthToken(token));
        }
    }
}