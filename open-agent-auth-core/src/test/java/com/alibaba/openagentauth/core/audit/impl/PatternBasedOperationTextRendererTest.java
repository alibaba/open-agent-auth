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
package com.alibaba.openagentauth.core.audit.impl;

import com.alibaba.openagentauth.core.audit.model.OperationTextRenderContext;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;
import com.alibaba.openagentauth.core.audit.model.SemanticExpansionLevel;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Comprehensive unit tests for {@link PatternBasedOperationTextRenderer}.
 * <p>
 * Tests cover all rendering scenarios including:
 * - Original prompt rendering
 * - Operation proposal rendering with truncation
 * - Fallback rendering when both are absent
 * - Channel and platform information appending
 * - Token expiration formatting
 * - Semantic expansion level assignment
 * </p>
 */
@DisplayName("PatternBasedOperationTextRenderer Tests")
class PatternBasedOperationTextRendererTest {

    private final PatternBasedOperationTextRenderer renderer = new PatternBasedOperationTextRenderer();

    @Nested
    @DisplayName("Original Prompt Rendering")
    class OriginalPromptRendering {

        @Test
        @DisplayName("Should render with original prompt and LOW expansion level")
        void shouldRenderWithOriginalPrompt() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .agent(new OperationRequestContext.AgentContext(null, "slack", null))
                    .build();

            Instant expiration = ZonedDateTime.of(2026, 3, 7, 23, 59, 0, 0, ZoneId.systemDefault())
                    .toInstant();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Purchase items under $50 during the Nov 11 promotion")
                    .requestContext(requestContext)
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized: Purchase items under $50 during the Nov 11 promotion via web on slack (valid until 23:59)");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should render with empty original prompt and use operation proposal")
        void shouldUseOperationProposalWhenOriginalPromptIsEmpty() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile")
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("")
                    .operationProposal("allow read access to user profile")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized agent operation per policy: allow read access to user profile via mobile");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }
    }

    @Nested
    @DisplayName("Operation Proposal Rendering")
    class OperationProposalRendering {

        @Test
        @DisplayName("Should render with operation proposal when original prompt is null")
        void shouldRenderWithOperationProposal() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .agent(new OperationRequestContext.AgentContext(null, "teams", null))
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("allow write access to documents")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized agent operation per policy: allow write access to documents on teams");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should truncate operation proposal when exceeding 50 characters")
        void shouldTruncateLongOperationProposal() {
            String longProposal = "This is a very long operation proposal that definitely exceeds the fifty character limit";
            assertThat(longProposal.length()).isGreaterThan(50);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(longProposal)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized agent operation per policy: This is a very long operation proposal that defini...");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should render exactly 50 characters without truncation")
        void shouldRenderExactFiftyCharactersWithoutTruncation() {
            String exactFiftyProposal = "12345678901234567890123456789012345678901234567890";
            assertThat(exactFiftyProposal.length()).isEqualTo(50);

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(exactFiftyProposal)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized agent operation per policy: " + exactFiftyProposal);
            assertThat(result.getRenderedText()).doesNotContain("...");
        }

        @Test
        @DisplayName("Should render with empty operation proposal and use fallback")
        void shouldUseFallbackWhenOperationProposalIsEmpty() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("")
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized agent operation");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
        }
    }

    @Nested
    @DisplayName("Fallback Rendering")
    class FallbackRendering {

        @Test
        @DisplayName("Should render fallback message when both prompt and proposal are null")
        void shouldRenderFallbackWhenBothAreNull() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).isEqualTo("Authorized agent operation");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
        }

        @Test
        @DisplayName("Should render fallback message when both prompt and proposal are empty")
        void shouldRenderFallbackWhenBothAreEmpty() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("")
                    .operationProposal("")
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).isEqualTo("Authorized agent operation");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
        }
    }

    @Nested
    @DisplayName("Context Information Appending")
    class ContextInformationAppending {

        @Test
        @DisplayName("Should append channel information when present")
        void shouldAppendChannelInformation() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).contains(" via web");
        }

        @Test
        @DisplayName("Should append platform information when present")
        void shouldAppendPlatformInformation() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .agent(new OperationRequestContext.AgentContext(null, "slack", null))
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).contains(" on slack");
        }

        @Test
        @DisplayName("Should append both channel and platform when both are present")
        void shouldAppendBothChannelAndPlatform() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile")
                    .agent(new OperationRequestContext.AgentContext(null, "discord", null))
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).contains(" via mobile").contains(" on discord");
        }

        @Test
        @DisplayName("Should not append channel when it is null")
        void shouldNotAppendChannelWhenNull() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).doesNotContain(" via ");
        }

        @Test
        @DisplayName("Should not append channel when it is empty")
        void shouldNotAppendChannelWhenEmpty() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("")
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).doesNotContain(" via ");
        }

        @Test
        @DisplayName("Should not append platform when agent is null")
        void shouldNotAppendPlatformWhenAgentIsNull() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).doesNotContain(" on ");
        }

        @Test
        @DisplayName("Should not append platform when platform is null")
        void shouldNotAppendPlatformWhenPlatformIsNull() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .agent(new OperationRequestContext.AgentContext(null, null, null))
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .requestContext(requestContext)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).doesNotContain(" on ");
        }

        @Test
        @DisplayName("Should not append context information when requestContext is null")
        void shouldNotAppendContextWhenRequestContextIsNull() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized: Test prompt");
            assertThat(result.getRenderedText()).doesNotContain(" via ").doesNotContain(" on ");
        }
    }

    @Nested
    @DisplayName("Token Expiration Formatting")
    class TokenExpirationFormatting {

        @Test
        @DisplayName("Should append expiration time in HH:mm format")
        void shouldAppendExpirationTime() {
            Instant expiration = ZonedDateTime.of(2026, 3, 7, 15, 30, 0, 0, ZoneId.systemDefault())
                    .toInstant();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).contains("(valid until 15:30)");
        }

        @Test
        @DisplayName("Should format midnight correctly")
        void shouldFormatMidnightCorrectly() {
            Instant expiration = ZonedDateTime.of(2026, 3, 7, 0, 0, 0, 0, ZoneId.systemDefault())
                    .toInstant();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).contains("(valid until 00:00)");
        }

        @Test
        @DisplayName("Should format 23:59 correctly")
        void shouldFormatEndOfDayCorrectly() {
            Instant expiration = ZonedDateTime.of(2026, 3, 7, 23, 59, 0, 0, ZoneId.systemDefault())
                    .toInstant();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).contains("(valid until 23:59)");
        }

        @Test
        @DisplayName("Should not append expiration when tokenExpiration is null")
        void shouldNotAppendExpirationWhenNull() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).doesNotContain("(valid until");
        }
    }

    @Nested
    @DisplayName("Semantic Expansion Level Assignment")
    class SemanticExpansionLevelAssignment {

        @Test
        @DisplayName("Should assign NONE expansion level for fallback rendering")
        void shouldAssignNoneExpansionForFallback() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
        }

        @Test
        @DisplayName("Should assign LOW expansion level when original prompt is present")
        void shouldAssignLowExpansionForOriginalPrompt() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should assign LOW expansion level when operation proposal is present")
        void shouldAssignLowExpansionForOperationProposal() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("allow read access")
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should assign LOW expansion level even when proposal is truncated")
        void shouldAssignLowExpansionForTruncatedProposal() {
            String longProposal = "This is a very long operation proposal that definitely exceeds the fifty character limit";
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(longProposal)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }
    }

    @Nested
    @DisplayName("OperationTextRenderResult Equality")
    class OperationTextRenderResultEquality {

        @Test
        @DisplayName("Should be equal when both text and expansion level match")
        void shouldBeEqualWhenBothMatch() {
            OperationTextRenderResult result1 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);
            OperationTextRenderResult result2 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result1).isEqualTo(result2);
            assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when text differs")
        void shouldNotBeEqualWhenTextDiffers() {
            OperationTextRenderResult result1 = new OperationTextRenderResult("Text 1", SemanticExpansionLevel.LOW);
            OperationTextRenderResult result2 = new OperationTextRenderResult("Text 2", SemanticExpansionLevel.LOW);

            assertThat(result1).isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should not be equal when expansion level differs")
        void shouldNotBeEqualWhenExpansionLevelDiffers() {
            OperationTextRenderResult result1 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.NONE);
            OperationTextRenderResult result2 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result1).isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should be reflexive")
        void shouldBeReflexive() {
            OperationTextRenderResult result = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result).isEqualTo(result);
        }

        @Test
        @DisplayName("Should be symmetric")
        void shouldBeSymmetric() {
            OperationTextRenderResult result1 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);
            OperationTextRenderResult result2 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result1.equals(result2)).isEqualTo(result2.equals(result1));
        }

        @Test
        @DisplayName("Should be transitive")
        void shouldBeTransitive() {
            OperationTextRenderResult result1 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);
            OperationTextRenderResult result2 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);
            OperationTextRenderResult result3 = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result1.equals(result2) && result2.equals(result3) && result1.equals(result3)).isTrue();
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            OperationTextRenderResult result = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            OperationTextRenderResult result = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            assertThat(result).isNotEqualTo("Test text");
        }

        @Test
        @DisplayName("Should have consistent hashCode")
        void shouldHaveConsistentHashCode() {
            OperationTextRenderResult result = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            int hashCode1 = result.hashCode();
            int hashCode2 = result.hashCode();

            assertThat(hashCode1).isEqualTo(hashCode2);
        }
    }

    @Nested
    @DisplayName("OperationTextRenderContext Builder")
    class OperationTextRenderContextBuilder {

        @Test
        @DisplayName("Should build context with all fields")
        void shouldBuildContextWithAllFields() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .agent(new OperationRequestContext.AgentContext(null, "slack", null))
                    .build();

            Instant expiration = Instant.now();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("allow read access")
                    .originalPrompt("Read user profile")
                    .requestContext(requestContext)
                    .tokenExpiration(expiration)
                    .build();

            assertThat(context.getOperationProposal()).isEqualTo("allow read access");
            assertThat(context.getOriginalPrompt()).isEqualTo("Read user profile");
            assertThat(context.getRequestContext()).isEqualTo(requestContext);
            assertThat(context.getTokenExpiration()).isEqualTo(expiration);
        }

        @Test
        @DisplayName("Should build context with only required fields")
        void shouldBuildContextWithOnlyRequiredFields() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .build();

            assertThat(context.getOperationProposal()).isNull();
            assertThat(context.getOriginalPrompt()).isNull();
            assertThat(context.getRequestContext()).isNull();
            assertThat(context.getVerifiedCredential()).isNull();
            assertThat(context.getTokenExpiration()).isNull();
        }

        @Test
        @DisplayName("Should build context with single field")
        void shouldBuildContextWithSingleField() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Test prompt")
                    .build();

            assertThat(context.getOriginalPrompt()).isEqualTo("Test prompt");
            assertThat(context.getOperationProposal()).isNull();
            assertThat(context.getRequestContext()).isNull();
        }

        @Test
        @DisplayName("Should support builder chaining")
        void shouldSupportBuilderChaining() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal("allow read access")
                    .originalPrompt("Read user profile")
                    .requestContext(requestContext)
                    .build();

            assertThat(context.getOperationProposal()).isEqualTo("allow read access");
            assertThat(context.getOriginalPrompt()).isEqualTo("Read user profile");
            assertThat(context.getRequestContext()).isEqualTo(requestContext);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstances() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            OperationTextRenderContext.Builder builder = OperationTextRenderContext.builder()
                    .operationProposal("allow read access");

            OperationTextRenderContext context1 = builder.originalPrompt("Prompt 1").build();
            OperationTextRenderContext context2 = builder.originalPrompt("Prompt 2").build();

            assertThat(context1.getOriginalPrompt()).isEqualTo("Prompt 1");
            assertThat(context2.getOriginalPrompt()).isEqualTo("Prompt 2");
            assertThat(context1.getOperationProposal()).isEqualTo(context2.getOperationProposal());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should render complete scenario with all components")
        void shouldRenderCompleteScenario() {
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .agent(new OperationRequestContext.AgentContext(null, "slack", null))
                    .build();

            Instant expiration = ZonedDateTime.of(2026, 3, 7, 23, 59, 0, 0, ZoneId.systemDefault())
                    .toInstant();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Purchase items under $50 during the Nov 11 promotion")
                    .requestContext(requestContext)
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized: Purchase items under $50 during the Nov 11 promotion via web on slack (valid until 23:59)");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should render scenario with truncated proposal and all context")
        void shouldRenderWithTruncatedProposalAndAllContext() {
            String longProposal = "This is a very long operation proposal that definitely exceeds the fifty character limit for testing purposes";
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile")
                    .agent(new OperationRequestContext.AgentContext(null, "discord", null))
                    .build();

            Instant expiration = ZonedDateTime.of(2026, 3, 7, 18, 30, 0, 0, ZoneId.systemDefault())
                    .toInstant();

            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(longProposal)
                    .requestContext(requestContext)
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText())
                    .isEqualTo("Authorized agent operation per policy: This is a very long operation proposal that defini... via mobile on discord (valid until 18:30)");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("Should render minimal scenario with only fallback")
        void shouldRenderMinimalScenario() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .build();

            OperationTextRenderResult result = renderer.render(context);

            assertThat(result.getRenderedText()).isEqualTo("Authorized agent operation");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
        }
    }

    @Nested
    @DisplayName("SemanticExpansionLevel Enum")
    class SemanticExpansionLevelTests {

        @Test
        @DisplayName("Should have correct string values for all levels")
        void shouldHaveCorrectStringValues() {
            assertThat(SemanticExpansionLevel.NONE.getValue()).isEqualTo("none");
            assertThat(SemanticExpansionLevel.LOW.getValue()).isEqualTo("low");
            assertThat(SemanticExpansionLevel.MEDIUM.getValue()).isEqualTo("medium");
            assertThat(SemanticExpansionLevel.HIGH.getValue()).isEqualTo("high");
        }

        @Test
        @DisplayName("Should return value from toString")
        void shouldReturnValueFromToString() {
            assertThat(SemanticExpansionLevel.NONE.toString()).isEqualTo("none");
            assertThat(SemanticExpansionLevel.LOW.toString()).isEqualTo("low");
            assertThat(SemanticExpansionLevel.MEDIUM.toString()).isEqualTo("medium");
            assertThat(SemanticExpansionLevel.HIGH.toString()).isEqualTo("high");
        }

        @Test
        @DisplayName("Should have exactly four enum constants")
        void shouldHaveFourEnumConstants() {
            assertThat(SemanticExpansionLevel.values()).hasSize(4);
        }

        @Test
        @DisplayName("Should resolve from name via valueOf")
        void shouldResolveFromNameViaValueOf() {
            assertThat(SemanticExpansionLevel.valueOf("NONE")).isEqualTo(SemanticExpansionLevel.NONE);
            assertThat(SemanticExpansionLevel.valueOf("LOW")).isEqualTo(SemanticExpansionLevel.LOW);
            assertThat(SemanticExpansionLevel.valueOf("MEDIUM")).isEqualTo(SemanticExpansionLevel.MEDIUM);
            assertThat(SemanticExpansionLevel.valueOf("HIGH")).isEqualTo(SemanticExpansionLevel.HIGH);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for invalid name")
        void shouldThrowForInvalidName() {
            assertThatThrownBy(() -> SemanticExpansionLevel.valueOf("INVALID"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("OperationTextRenderResult Static Factories and Validation")
    class OperationTextRenderResultFactories {

        @Test
        @DisplayName("withNoExpansion should create result with NONE level")
        void withNoExpansionShouldCreateResultWithNoneLevel() {
            OperationTextRenderResult result = OperationTextRenderResult.withNoExpansion("Test text");

            assertThat(result.getRenderedText()).isEqualTo("Test text");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.NONE);
        }

        @Test
        @DisplayName("withLowExpansion should create result with LOW level")
        void withLowExpansionShouldCreateResultWithLowLevel() {
            OperationTextRenderResult result = OperationTextRenderResult.withLowExpansion("Test text");

            assertThat(result.getRenderedText()).isEqualTo("Test text");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.LOW);
        }

        @Test
        @DisplayName("withMediumExpansion should create result with MEDIUM level")
        void withMediumExpansionShouldCreateResultWithMediumLevel() {
            OperationTextRenderResult result = OperationTextRenderResult.withMediumExpansion("Test text");

            assertThat(result.getRenderedText()).isEqualTo("Test text");
            assertThat(result.getSemanticExpansionLevel()).isEqualTo(SemanticExpansionLevel.MEDIUM);
        }

        @Test
        @DisplayName("Should throw NullPointerException when renderedText is null")
        void shouldThrowWhenRenderedTextIsNull() {
            assertThatThrownBy(() -> new OperationTextRenderResult(null, SemanticExpansionLevel.LOW))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("renderedText");
        }

        @Test
        @DisplayName("Should throw NullPointerException when semanticExpansionLevel is null")
        void shouldThrowWhenSemanticExpansionLevelIsNull() {
            assertThatThrownBy(() -> new OperationTextRenderResult("text", null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("semanticExpansionLevel");
        }

        @Test
        @DisplayName("toString should contain rendered text and expansion level")
        void toStringShouldContainRenderedTextAndExpansionLevel() {
            OperationTextRenderResult result = new OperationTextRenderResult("Test text", SemanticExpansionLevel.LOW);

            String stringRepresentation = result.toString();

            assertThat(stringRepresentation).contains("Test text");
            assertThat(stringRepresentation).contains("low");
        }
    }

    @Nested
    @DisplayName("OperationTextRenderContext Equality and ToString")
    class OperationTextRenderContextEqualityAndToString {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            Instant expiration = Instant.now();
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            OperationTextRenderContext context1 = OperationTextRenderContext.builder()
                    .operationProposal("policy")
                    .originalPrompt("prompt")
                    .requestContext(requestContext)
                    .tokenExpiration(expiration)
                    .build();

            OperationTextRenderContext context2 = OperationTextRenderContext.builder()
                    .operationProposal("policy")
                    .originalPrompt("prompt")
                    .requestContext(requestContext)
                    .tokenExpiration(expiration)
                    .build();

            assertThat(context1).isEqualTo(context2);
            assertThat(context1.hashCode()).isEqualTo(context2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when operationProposal differs")
        void shouldNotBeEqualWhenOperationProposalDiffers() {
            OperationTextRenderContext context1 = OperationTextRenderContext.builder()
                    .operationProposal("policy1")
                    .build();
            OperationTextRenderContext context2 = OperationTextRenderContext.builder()
                    .operationProposal("policy2")
                    .build();

            assertThat(context1).isNotEqualTo(context2);
        }

        @Test
        @DisplayName("Should not be equal when originalPrompt differs")
        void shouldNotBeEqualWhenOriginalPromptDiffers() {
            OperationTextRenderContext context1 = OperationTextRenderContext.builder()
                    .originalPrompt("prompt1")
                    .build();
            OperationTextRenderContext context2 = OperationTextRenderContext.builder()
                    .originalPrompt("prompt2")
                    .build();

            assertThat(context1).isNotEqualTo(context2);
        }

        @Test
        @DisplayName("Should not be equal when tokenExpiration differs")
        void shouldNotBeEqualWhenTokenExpirationDiffers() {
            OperationTextRenderContext context1 = OperationTextRenderContext.builder()
                    .tokenExpiration(Instant.ofEpochSecond(1000))
                    .build();
            OperationTextRenderContext context2 = OperationTextRenderContext.builder()
                    .tokenExpiration(Instant.ofEpochSecond(2000))
                    .build();

            assertThat(context1).isNotEqualTo(context2);
        }

        @Test
        @DisplayName("Should be reflexive")
        void shouldBeReflexive() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("test")
                    .build();

            assertThat(context).isEqualTo(context);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            OperationTextRenderContext context = OperationTextRenderContext.builder().build();

            assertThat(context).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            OperationTextRenderContext context = OperationTextRenderContext.builder().build();

            assertThat(context).isNotEqualTo("not a context");
        }

        @Test
        @DisplayName("Should have consistent hashCode")
        void shouldHaveConsistentHashCode() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("test")
                    .operationProposal("policy")
                    .build();

            assertThat(context.hashCode()).isEqualTo(context.hashCode());
        }

        @Test
        @DisplayName("toString should contain key fields")
        void toStringShouldContainKeyFields() {
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .originalPrompt("Buy books")
                    .operationProposal("allow read access to bookstore")
                    .build();

            String stringRepresentation = context.toString();

            assertThat(stringRepresentation).contains("Buy books");
            assertThat(stringRepresentation).contains("operationProposal");
        }

        @Test
        @DisplayName("toString should truncate long operationProposal")
        void toStringShouldTruncateLongOperationProposal() {
            String longProposal = "This is a very long operation proposal that definitely exceeds the fifty character limit for display";
            OperationTextRenderContext context = OperationTextRenderContext.builder()
                    .operationProposal(longProposal)
                    .build();

            String stringRepresentation = context.toString();

            assertThat(stringRepresentation).contains("...");
            assertThat(stringRepresentation).doesNotContain(longProposal);
        }

        @Test
        @DisplayName("toString should handle null operationProposal")
        void toStringShouldHandleNullOperationProposal() {
            OperationTextRenderContext context = OperationTextRenderContext.builder().build();

            String stringRepresentation = context.toString();

            assertThat(stringRepresentation).contains("null");
        }

        @Test
        @DisplayName("Two empty contexts should be equal")
        void twoEmptyContextsShouldBeEqual() {
            OperationTextRenderContext context1 = OperationTextRenderContext.builder().build();
            OperationTextRenderContext context2 = OperationTextRenderContext.builder().build();

            assertThat(context1).isEqualTo(context2);
            assertThat(context1.hashCode()).isEqualTo(context2.hashCode());
        }
    }
}
