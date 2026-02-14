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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link McpAuthContext}.
 *
 * @since 1.0
 */
@DisplayName("McpAuthContext Tests")
class McpAuthContextTest {

    @Test
    @DisplayName("Should create context with valid tokens")
    void shouldCreateContextWithValidTokens() {
        String aoat = "aoat-token";
        String wit = "wit-token";
        String wpt = "wpt-token";

        McpAuthContext context = new McpAuthContext(aoat, wit, wpt);

        assertEquals(aoat, context.getAgentOaToken());
        assertEquals(wit, context.getWit());
        assertEquals(wpt, context.getWpt());
    }

    @Test
    @DisplayName("Should be valid when AOAT is present")
    void shouldBeValidWhenAoatIsPresent() {
        McpAuthContext context = new McpAuthContext("aoat-token", null, null);

        assertTrue(context.isValid());
    }

    @Test
    @DisplayName("Should be invalid when AOAT is null")
    void shouldBeInvalidWhenAoatIsNull() {
        McpAuthContext context = new McpAuthContext(null, "wit-token", "wpt-token");

        assertFalse(context.isValid());
    }

    @Test
    @DisplayName("Should be invalid when AOAT is empty")
    void shouldBeInvalidWhenAoatIsEmpty() {
        McpAuthContext context = new McpAuthContext("", "wit-token", "wpt-token");

        assertFalse(context.isValid());
    }

    @Test
    @DisplayName("Should return null for missing tokens")
    void shouldReturnNullForMissingTokens() {
        McpAuthContext context = new McpAuthContext("aoat-token", null, null);

        assertNull(context.getWit());
        assertNull(context.getWpt());
    }

    @Test
    @DisplayName("Should handle empty tokens")
    void shouldHandleEmptyTokens() {
        McpAuthContext context = new McpAuthContext("", "", "");

        assertTrue(context.getAgentOaToken().isEmpty());
        assertTrue(context.getWit().isEmpty());
        assertTrue(context.getWpt().isEmpty());
        assertFalse(context.isValid());
    }

    @Test
    @DisplayName("Should store complex token strings")
    void shouldStoreComplexTokenStrings() {
        String complexAoat = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String complexWit = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.complex-wit-payload";
        String complexWpt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.complex-wpt-payload";

        McpAuthContext context = new McpAuthContext(complexAoat, complexWit, complexWpt);

        assertEquals(complexAoat, context.getAgentOaToken());
        assertEquals(complexWit, context.getWit());
        assertEquals(complexWpt, context.getWpt());
        assertTrue(context.isValid());
    }
}
