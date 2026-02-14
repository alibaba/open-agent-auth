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
package com.alibaba.openagentauth.mcp.client;

import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.http.HttpRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link AuthHeaderCustomizer}.
 *
 * @since 1.0
 */
@DisplayName("AuthHeaderCustomizer Tests")
class AuthHeaderCustomizerTest {

    private AuthHeaderCustomizer customizer;
    private HttpRequest.Builder builder;
    private McpTransportContext context;

    @BeforeEach
    void setUp() {
        customizer = new AuthHeaderCustomizer();
        builder = HttpRequest.newBuilder()
                .uri(URI.create("https://example.com/mcp"));
        context = mock(McpTransportContext.class);
    }

    @AfterEach
    void tearDown() {
        McpAuthContextHolder.clearContext();
    }

    @Test
    @DisplayName("Should add all authentication headers when context is valid")
    void shouldAddAllAuthenticationHeadersWhenContextIsValid() {
        McpAuthContext authContext = new McpAuthContext(
                "test-aoat-token",
                "test-wit-token",
                "test-wpt-token"
        );
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertTrue(headers.containsKey("Authorization"));
        assertTrue(headers.containsKey("X-Workload-Identity"));
        assertTrue(headers.containsKey("X-Workload-Proof"));
        assertEquals(java.util.List.of("Bearer test-aoat-token"), headers.get("Authorization"));
        assertEquals(java.util.List.of("test-wit-token"), headers.get("X-Workload-Identity"));
        assertEquals(java.util.List.of("test-wpt-token"), headers.get("X-Workload-Proof"));
    }

    @Test
    @DisplayName("Should add only AOAT header when WIT and WPT are null")
    void shouldAddOnlyAoatHeaderWhenWitAndWptAreNull() {
        McpAuthContext authContext = new McpAuthContext("test-aoat-token", null, null);
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertTrue(headers.containsKey("Authorization"));
        assertFalse(headers.containsKey("X-Workload-Identity"));
        assertFalse(headers.containsKey("X-Workload-Proof"));
    }

    @Test
    @DisplayName("Should not add headers when context is null")
    void shouldNotAddHeadersWhenContextIsNull() {
        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertFalse(headers.containsKey("Authorization"));
        assertFalse(headers.containsKey("X-Workload-Identity"));
        assertFalse(headers.containsKey("X-Workload-Proof"));
    }

    @Test
    @DisplayName("Should not add headers when context is invalid")
    void shouldNotAddHeadersWhenContextIsInvalid() {
        McpAuthContext authContext = new McpAuthContext(null, "wit", "wpt");
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertFalse(headers.containsKey("Authorization"));
        assertFalse(headers.containsKey("X-Workload-Identity"));
        assertFalse(headers.containsKey("X-Workload-Proof"));
    }

    @Test
    @DisplayName("Should not add headers when AOAT is empty")
    void shouldNotAddHeadersWhenAoatIsEmpty() {
        McpAuthContext authContext = new McpAuthContext("", "wit", "wpt");
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertFalse(headers.containsKey("Authorization"));
    }

    @Test
    @DisplayName("Should add Bearer prefix to AOAT")
    void shouldAddBearerPrefixToAoat() {
        McpAuthContext authContext = new McpAuthContext("test-aoat-token", null, null);
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertEquals(java.util.List.of("Bearer test-aoat-token"), headers.get("Authorization"));
    }

    @Test
    @DisplayName("Should handle complex token strings")
    void shouldHandleComplexTokenStrings() {
        String complexAoat = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        McpAuthContext authContext = new McpAuthContext(complexAoat, "wit", "wpt");
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                builder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        HttpRequest.Builder customizedBuilder = result.block();
        HttpRequest request = customizedBuilder.build();

        java.util.Map<String, java.util.List<String>> headers = request.headers().map();
        assertEquals(java.util.List.of("Bearer " + complexAoat), headers.get("Authorization"));
    }

    @Test
    @DisplayName("Should return Mono with unchanged builder when exception occurs")
    void shouldReturnMonoWithUnchangedBuilderWhenExceptionOccurs() {
        HttpRequest.Builder invalidBuilder = mock(HttpRequest.Builder.class);
        McpAuthContext authContext = new McpAuthContext("aoat", "wit", "wpt");
        McpAuthContextHolder.setContext(authContext);

        Mono<HttpRequest.Builder> result = customizer.customize(
                invalidBuilder,
                "POST",
                URI.create("https://example.com/mcp"),
                "{}",
                context
        );

        assertNotNull(result);
    }
}
