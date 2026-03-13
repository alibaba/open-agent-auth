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
package com.alibaba.openagentauth.sample.authz.renderer;

import com.alibaba.openagentauth.core.audit.model.OperationTextRenderContext;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;
import com.alibaba.openagentauth.core.audit.model.SemanticExpansionLevel;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.qwen.code.cli.QwenCodeCli;
import com.alibaba.qwen.code.cli.session.event.consumers.AssistantContentSimpleConsumers;
import com.alibaba.qwen.code.cli.transport.TransportOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for {@link QwenLlmOperationTextRenderer}.
 * <p>
 * Uses {@code mockStatic} to mock the static {@link QwenCodeCli#simpleQuery} method,
 * avoiding actual LLM calls during testing.
 * </p>
 */
@DisplayName("QwenLlmOperationTextRenderer Tests")
class QwenLlmOperationTextRendererTest {

    private static final String TEST_MODEL = "qwen3-coder-flash";
    private static final long TEST_TIMEOUT = 30;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create renderer with valid parameters")
        void shouldCreateRendererWithValidParameters() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);
            assertThat(renderer).isNotNull();
        }

        @Test
        @DisplayName("Should reject null model name")
        void shouldRejectNullModelName() {
            assertThatThrownBy(() -> new QwenLlmOperationTextRenderer(null, TEST_TIMEOUT))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Model name must not be null");
        }
    }

    @Nested
    @DisplayName("Render Tests")
    class RenderTests {

        @Test
        @DisplayName("Should render operation text successfully via LLM")
        void shouldRenderOperationTextSuccessfully() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { input.action == \"search\" }")
                    .originalPrompt("Search for programming books")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            // Simulate text callback via mock AssistantContent
                            simulateTextResponse(consumers, "Search for programming books.");
                            return null;
                        });

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result).isNotNull();
                assertThat(result.getRenderedText()).isEqualTo("Search for programming books.");
                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.MEDIUM);
            }
        }

        @Test
        @DisplayName("Should return HIGH expansion level when original prompt is absent")
        void shouldReturnHighExpansionWhenOriginalPromptAbsent() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { input.action == \"search\" }")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Search for items.");
                            return null;
                        });

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.HIGH);
            }
        }

        @Test
        @DisplayName("Should return MEDIUM expansion level when original prompt is present")
        void shouldReturnMediumExpansionWhenOriginalPromptPresent() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { input.action == \"search\" }")
                    .originalPrompt("Find books about Java")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Rendered text");
                            return null;
                        });

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.MEDIUM);
            }
        }

        @Test
        @DisplayName("Should return HIGH expansion level when original prompt is empty")
        void shouldReturnHighExpansionWhenOriginalPromptEmpty() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { true }")
                    .originalPrompt("")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Rendered text");
                            return null;
                        });

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.HIGH);
            }
        }
    }

    @Nested
    @DisplayName("Fallback Tests")
    class FallbackTests {

        @Test
        @DisplayName("Should fall back when LLM call throws exception")
        void shouldFallBackWhenLlmCallThrows() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { input.action == \"search\" }")
                    .originalPrompt("Search for books")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenThrow(new RuntimeException("Network error"));

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result).isNotNull();
                assertThat(result.getRenderedText()).isEqualTo("Authorized: Search for books");
                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
            }
        }

        @Test
        @DisplayName("Should fall back to operation proposal when LLM fails and no original prompt")
        void shouldFallBackToOperationProposalWhenNoOriginalPrompt() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            String shortPolicy = "package agent\nallow { input.action == \"read\" }";
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(shortPolicy)
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenThrow(new RuntimeException("Timeout"));

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result).isNotNull();
                assertThat(result.getRenderedText()).startsWith("Authorized agent operation per policy:");
                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
            }
        }

        @Test
        @DisplayName("Should fall back to generic message when LLM fails and no proposal or prompt")
        void shouldFallBackToGenericMessageWhenNoProposalOrPrompt() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder().build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenThrow(new RuntimeException("Error"));

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result).isNotNull();
                assertThat(result.getRenderedText()).isEqualTo("Authorized agent operation");
                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
            }
        }

        @Test
        @DisplayName("Should truncate long operation proposal in fallback")
        void shouldTruncateLongOperationProposalInFallback() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            String longPolicy = "package agent\n" + "a".repeat(200);
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(longPolicy)
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenThrow(new RuntimeException("Error"));

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result.getRenderedText()).contains("...");
                assertThat(result.getRenderedText().length()).isLessThan(longPolicy.length());
            }
        }

        @Test
        @DisplayName("Should fall back when LLM returns empty content")
        void shouldFallBackWhenLlmReturnsEmptyContent() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { true }")
                    .originalPrompt("Do something")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                // Simulate empty response (no text callback invoked)
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> null);

                OperationTextRenderResult result = renderer.render(context);

                assertThat(result).isNotNull();
                assertThat(result.getRenderedText()).isEqualTo("Authorized: Do something");
                assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
            }
        }
    }

    @Nested
    @DisplayName("Prompt Building Tests")
    class PromptBuildingTests {

        @Test
        @DisplayName("Should include operation proposal in prompt sent to LLM")
        void shouldIncludeOperationProposalInPrompt() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            String policy = "package shopping\nallow { input.category == \"books\" }";
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(policy)
                    .originalPrompt("Buy books")
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            String prompt = invocation.getArgument(0);
                            assertThat(prompt).contains("Rego Policy:");
                            assertThat(prompt).contains(policy);
                            assertThat(prompt).contains("Buy books");

                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Rendered");
                            return null;
                        });

                renderer.render(context);
            }
        }

        @Test
        @DisplayName("Should include request context in prompt when available")
        void shouldIncludeRequestContextInPrompt() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                    .platform("web")
                    .client("test-client")
                    .build();

            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .language("en-US")
                    .agent(agentContext)
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { true }")
                    .requestContext(requestContext)
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            String prompt = invocation.getArgument(0);
                            assertThat(prompt).contains("Channel: web");
                            assertThat(prompt).contains("Language: en-US");
                            assertThat(prompt).contains("Platform: web");
                            assertThat(prompt).contains("Client: test-client");

                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Rendered");
                            return null;
                        });

                renderer.render(context);
            }
        }

        @Test
        @DisplayName("Should include token expiration in prompt when available")
        void shouldIncludeTokenExpirationInPrompt() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            java.time.Instant expiration = java.time.Instant.parse("2026-12-31T23:59:59Z");
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("package agent\nallow { true }")
                    .tokenExpiration(expiration)
                    .build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            String prompt = invocation.getArgument(0);
                            assertThat(prompt).contains("Authorization valid until:");

                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Rendered");
                            return null;
                        });

                renderer.render(context);
            }
        }

        @Test
        @DisplayName("Should handle context with null fields gracefully")
        void shouldHandleContextWithNullFieldsGracefully() {
            QwenLlmOperationTextRenderer renderer = new QwenLlmOperationTextRenderer(TEST_MODEL, TEST_TIMEOUT);

            OperationTextRenderContext context = OperationTextRenderContext.builder().build();

            try (MockedStatic<QwenCodeCli> mockedCli = mockStatic(QwenCodeCli.class)) {
                mockedCli.when(() -> QwenCodeCli.simpleQuery(
                        anyString(), any(TransportOptions.class), any(AssistantContentSimpleConsumers.class)))
                        .thenAnswer(invocation -> {
                            String prompt = invocation.getArgument(0);
                            assertThat(prompt).doesNotContain("Rego Policy:");
                            assertThat(prompt).doesNotContain("User's Original Request:");

                            AssistantContentSimpleConsumers consumers = invocation.getArgument(2);
                            simulateTextResponse(consumers, "Generic authorization");
                            return null;
                        });

                OperationTextRenderResult result = renderer.render(context);
                assertThat(result.getRenderedText()).isEqualTo("Generic authorization");
            }
        }
    }

    /**
     * Simulates a text response from the Qwen model by invoking the onText callback
     * with a mock TextAssistantContent.
     */
    private void simulateTextResponse(AssistantContentSimpleConsumers consumers, String text) {
        com.alibaba.qwen.code.cli.protocol.data.AssistantContent.TextAssistantContent textContent =
                org.mockito.Mockito.mock(
                        com.alibaba.qwen.code.cli.protocol.data.AssistantContent.TextAssistantContent.class);
        org.mockito.Mockito.when(textContent.getText()).thenReturn(text);
        consumers.onText(null, textContent);
    }
}
