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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link McpAuthContextHolder}.
 *
 * @since 1.0
 */
@DisplayName("McpAuthContextHolder Tests")
class McpAuthContextHolderTest {

    @BeforeEach
    @AfterEach
    void clearContext() {
        McpAuthContextHolder.clearContext();
    }

    @Test
    @DisplayName("Should set and get context")
    void shouldSetAndGetContext() {
        McpAuthContext context = new McpAuthContext("aoat", "wit", "wpt");

        McpAuthContextHolder.setContext(context);
        McpAuthContext retrieved = McpAuthContextHolder.getContext();

        assertNotNull(retrieved);
        assertEquals("aoat", retrieved.getAgentOaToken());
        assertEquals("wit", retrieved.getWit());
        assertEquals("wpt", retrieved.getWpt());
    }

    @Test
    @DisplayName("Should return null when context is not set")
    void shouldReturnNullWhenContextIsNotSet() {
        McpAuthContext context = McpAuthContextHolder.getContext();

        assertNull(context);
    }

    @Test
    @DisplayName("Should clear context")
    void shouldClearContext() {
        McpAuthContext context = new McpAuthContext("aoat", "wit", "wpt");
        McpAuthContextHolder.setContext(context);

        McpAuthContextHolder.clearContext();

        assertNull(McpAuthContextHolder.getContext());
    }

    @Test
    @DisplayName("Should clear context when setting null")
    void shouldClearContextWhenSettingNull() {
        McpAuthContext context = new McpAuthContext("aoat", "wit", "wpt");
        McpAuthContextHolder.setContext(context);

        McpAuthContextHolder.setContext(null);

        assertNull(McpAuthContextHolder.getContext());
    }

    @Test
    @DisplayName("Should return false when context is not set")
    void shouldReturnFalseWhenContextIsNotSet() {
        boolean hasContext = McpAuthContextHolder.hasContext();

        assertFalse(hasContext);
    }

    @Test
    @DisplayName("Should return true when valid context is set")
    void shouldReturnTrueWhenValidContextIsSet() {
        McpAuthContext context = new McpAuthContext("aoat", "wit", "wpt");
        McpAuthContextHolder.setContext(context);

        boolean hasContext = McpAuthContextHolder.hasContext();

        assertTrue(hasContext);
    }

    @Test
    @DisplayName("Should return false when invalid context is set")
    void shouldReturnFalseWhenInvalidContextIsSet() {
        McpAuthContext context = new McpAuthContext(null, "wit", "wpt");
        McpAuthContextHolder.setContext(context);

        boolean hasContext = McpAuthContextHolder.hasContext();

        assertFalse(hasContext);
    }

    @Test
    @DisplayName("Should maintain thread isolation")
    void shouldMaintainThreadIsolation() throws InterruptedException {
        McpAuthContext mainContext = new McpAuthContext("main-aoat", "main-wit", "main-wpt");
        McpAuthContextHolder.setContext(mainContext);

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<McpAuthContext> threadContextRef = new AtomicReference<>();

        Thread thread = new Thread(() -> {
            McpAuthContext threadContext = new McpAuthContext("thread-aoat", "thread-wit", "thread-wpt");
            McpAuthContextHolder.setContext(threadContext);
            threadContextRef.set(McpAuthContextHolder.getContext());
            latch.countDown();
        });

        thread.start();
        latch.await(5, TimeUnit.SECONDS);

        McpAuthContext mainThreadContext = McpAuthContextHolder.getContext();

        assertEquals("thread-aoat", threadContextRef.get().getAgentOaToken());
        assertEquals("main-aoat", mainThreadContext.getAgentOaToken());
    }

    @Test
    @DisplayName("Should handle concurrent context operations")
    void shouldHandleConcurrentContextOperations() throws InterruptedException {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                McpAuthContext context = new McpAuthContext(
                        "aoat-" + threadId,
                        "wit-" + threadId,
                        "wpt-" + threadId
                );
                McpAuthContextHolder.setContext(context);
                
                McpAuthContext retrieved = McpAuthContextHolder.getContext();
                assertEquals("aoat-" + threadId, retrieved.getAgentOaToken());
                
                McpAuthContextHolder.clearContext();
                latch.countDown();
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);

        assertNull(McpAuthContextHolder.getContext());
    }

    @Test
    @DisplayName("Should handle multiple set and clear operations")
    void shouldHandleMultipleSetAndClearOperations() {
        for (int i = 0; i < 100; i++) {
            McpAuthContext context = new McpAuthContext("aoat-" + i, "wit-" + i, "wpt-" + i);
            McpAuthContextHolder.setContext(context);

            assertNotNull(McpAuthContextHolder.getContext());
            assertEquals("aoat-" + i, McpAuthContextHolder.getContext().getAgentOaToken());

            McpAuthContextHolder.clearContext();
            assertNull(McpAuthContextHolder.getContext());
        }
    }
}
