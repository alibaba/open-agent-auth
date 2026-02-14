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
package com.alibaba.openagentauth.core.model.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AuditTrail Tests")
class AuditTrailTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build AuditTrail with no fields")
        void shouldBuildAuditTrailWithNoFields() {
            AuditTrail trail = AuditTrail.builder().build();

            assertNotNull(trail);
            assertNull(trail.getOriginalPromptText());
            assertNull(trail.getRenderedOperationText());
            assertNull(trail.getSemanticExpansionLevel());
            assertNull(trail.getUserAcknowledgeTimestamp());
            assertNull(trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should build AuditTrail with originalPromptText")
        void shouldBuildAuditTrailWithOriginalPromptText() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Buy something cheap on Nov 11 night")
                    .build();

            assertEquals("Buy something cheap on Nov 11 night", trail.getOriginalPromptText());
        }

        @Test
        @DisplayName("Should build AuditTrail with renderedOperationText")
        void shouldBuildAuditTrailWithRenderedOperationText() {
            AuditTrail trail = AuditTrail.builder()
                    .renderedOperationText("Purchase under $50 during 00:00-06:00")
                    .build();

            assertEquals("Purchase under $50 during 00:00-06:00", trail.getRenderedOperationText());
        }

        @Test
        @DisplayName("Should build AuditTrail with semanticExpansionLevel")
        void shouldBuildAuditTrailWithSemanticExpansionLevel() {
            AuditTrail trail = AuditTrail.builder()
                    .semanticExpansionLevel("medium")
                    .build();

            assertEquals("medium", trail.getSemanticExpansionLevel());
        }

        @Test
        @DisplayName("Should build AuditTrail with userAcknowledgeTimestamp")
        void shouldBuildAuditTrailWithUserAcknowledgeTimestamp() {
            AuditTrail trail = AuditTrail.builder()
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .build();

            assertEquals("2025-11-11T10:33:00Z", trail.getUserAcknowledgeTimestamp());
        }

        @Test
        @DisplayName("Should build AuditTrail with consentInterfaceVersion")
        void shouldBuildAuditTrailWithConsentInterfaceVersion() {
            AuditTrail trail = AuditTrail.builder()
                    .consentInterfaceVersion("1.0")
                    .build();

            assertEquals("1.0", trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should build AuditTrail with all fields")
        void shouldBuildAuditTrailWithAllFields() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Buy winter clothes")
                    .renderedOperationText("Purchase items under $100")
                    .semanticExpansionLevel("low")
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .consentInterfaceVersion("2.0")
                    .build();

            assertEquals("Buy winter clothes", trail.getOriginalPromptText());
            assertEquals("Purchase items under $100", trail.getRenderedOperationText());
            assertEquals("low", trail.getSemanticExpansionLevel());
            assertEquals("2025-11-11T10:33:00Z", trail.getUserAcknowledgeTimestamp());
            assertEquals("2.0", trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Prompt")
                    .renderedOperationText("Operation")
                    .semanticExpansionLevel("high")
                    .build();

            assertEquals("high", trail.getSemanticExpansionLevel());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return null for optional fields not set")
        void shouldReturnNullForOptionalFieldsNotSet() {
            AuditTrail trail = AuditTrail.builder().build();

            assertNull(trail.getOriginalPromptText());
            assertNull(trail.getRenderedOperationText());
            assertNull(trail.getSemanticExpansionLevel());
            assertNull(trail.getUserAcknowledgeTimestamp());
            assertNull(trail.getConsentInterfaceVersion());
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            AuditTrail trail1 = AuditTrail.builder()
                    .originalPromptText("Buy winter clothes")
                    .renderedOperationText("Purchase under $100")
                    .semanticExpansionLevel("low")
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .consentInterfaceVersion("1.0")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .originalPromptText("Buy winter clothes")
                    .renderedOperationText("Purchase under $100")
                    .semanticExpansionLevel("low")
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .consentInterfaceVersion("1.0")
                    .build();

            assertEquals(trail1, trail2);
            assertEquals(trail1.hashCode(), trail2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when originalPromptText differs")
        void shouldNotBeEqualWhenOriginalPromptTextDiffers() {
            AuditTrail trail1 = AuditTrail.builder()
                    .originalPromptText("Prompt 1")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .originalPromptText("Prompt 2")
                    .build();

            assertNotEquals(trail1, trail2);
        }

        @Test
        @DisplayName("Should not be equal when renderedOperationText differs")
        void shouldNotBeEqualWhenRenderedOperationTextDiffers() {
            AuditTrail trail1 = AuditTrail.builder()
                    .renderedOperationText("Operation 1")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .renderedOperationText("Operation 2")
                    .build();

            assertNotEquals(trail1, trail2);
        }

        @Test
        @DisplayName("Should not be equal when semanticExpansionLevel differs")
        void shouldNotBeEqualWhenSemanticExpansionLevelDiffers() {
            AuditTrail trail1 = AuditTrail.builder()
                    .semanticExpansionLevel("low")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .semanticExpansionLevel("high")
                    .build();

            assertNotEquals(trail1, trail2);
        }

        @Test
        @DisplayName("Should not be equal when userAcknowledgeTimestamp differs")
        void shouldNotBeEqualWhenUserAcknowledgeTimestampDiffers() {
            AuditTrail trail1 = AuditTrail.builder()
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .userAcknowledgeTimestamp("2025-11-11T11:33:00Z")
                    .build();

            assertNotEquals(trail1, trail2);
        }

        @Test
        @DisplayName("Should not be equal when consentInterfaceVersion differs")
        void shouldNotBeEqualWhenConsentInterfaceVersionDiffers() {
            AuditTrail trail1 = AuditTrail.builder()
                    .consentInterfaceVersion("1.0")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .consentInterfaceVersion("2.0")
                    .build();

            assertNotEquals(trail1, trail2);
        }

        @Test
        @DisplayName("Should be equal when both have all null fields")
        void shouldBeEqualWhenBothHaveAllNullFields() {
            AuditTrail trail1 = AuditTrail.builder().build();
            AuditTrail trail2 = AuditTrail.builder().build();

            assertEquals(trail1, trail2);
            assertEquals(trail1.hashCode(), trail2.hashCode());
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Test")
                    .build();

            assertEquals(trail, trail);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Test")
                    .build();

            assertNotEquals(trail, null);
        }

        @Test
        @DisplayName("Should not be equal to different class")
        void shouldNotBeEqualToDifferentClass() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Test")
                    .build();

            assertNotEquals(trail, "string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Buy winter clothes")
                    .renderedOperationText("Purchase under $100")
                    .semanticExpansionLevel("low")
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .consentInterfaceVersion("1.0")
                    .build();

            String toString = trail.toString();

            assertTrue(toString.contains("Buy winter clothes"));
            assertTrue(toString.contains("Purchase under $100"));
            assertTrue(toString.contains("low"));
            assertTrue(toString.contains("2025-11-11T10:33:00Z"));
            assertTrue(toString.contains("1.0"));
        }

        @Test
        @DisplayName("Should include non-null fields only")
        void shouldIncludeNonNullFieldsOnly() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Test prompt")
                    .build();

            String toString = trail.toString();

            assertTrue(toString.contains("Test prompt"));
            assertFalse(toString.contains("renderedOperationText=null"));
        }
    }

    @Nested
    @DisplayName("Semantic Expansion Level Tests")
    class SemanticExpansionLevelTests {

        @Test
        @DisplayName("Should support low semantic expansion level")
        void shouldSupportLowSemanticExpansionLevel() {
            AuditTrail trail = AuditTrail.builder()
                    .semanticExpansionLevel("low")
                    .build();

            assertEquals("low", trail.getSemanticExpansionLevel());
        }

        @Test
        @DisplayName("Should support medium semantic expansion level")
        void shouldSupportMediumSemanticExpansionLevel() {
            AuditTrail trail = AuditTrail.builder()
                    .semanticExpansionLevel("medium")
                    .build();

            assertEquals("medium", trail.getSemanticExpansionLevel());
        }

        @Test
        @DisplayName("Should support high semantic expansion level")
        void shouldSupportHighSemanticExpansionLevel() {
            AuditTrail trail = AuditTrail.builder()
                    .semanticExpansionLevel("high")
                    .build();

            assertEquals("high", trail.getSemanticExpansionLevel());
        }

        @Test
        @DisplayName("Should support none semantic expansion level")
        void shouldSupportNoneSemanticExpansionLevel() {
            AuditTrail trail = AuditTrail.builder()
                    .semanticExpansionLevel("none")
                    .build();

            assertEquals("none", trail.getSemanticExpansionLevel());
        }
    }

    @Nested
    @DisplayName("Timestamp Format Tests")
    class TimestampFormatTests {

        @Test
        @DisplayName("Should accept ISO 8601 UTC timestamp format")
        void shouldAcceptISO8601UTCTimestampFormat() {
            AuditTrail trail = AuditTrail.builder()
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .build();

            assertEquals("2025-11-11T10:33:00Z", trail.getUserAcknowledgeTimestamp());
        }

        @Test
        @DisplayName("Should accept ISO 8601 timestamp with milliseconds")
        void shouldAcceptISO8601TimestampWithMilliseconds() {
            AuditTrail trail = AuditTrail.builder()
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00.123Z")
                    .build();

            assertEquals("2025-11-11T10:33:00.123Z", trail.getUserAcknowledgeTimestamp());
        }

        @Test
        @DisplayName("Should accept ISO 8601 timestamp with timezone offset")
        void shouldAcceptISO8601TimestampWithTimezoneOffset() {
            AuditTrail trail = AuditTrail.builder()
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00+08:00")
                    .build();

            assertEquals("2025-11-11T10:33:00+08:00", trail.getUserAcknowledgeTimestamp());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should create complete audit trail for shopping scenario")
        void shouldCreateCompleteAuditTrailForShoppingScenario() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("I want to buy winter clothes, please give me some suggestions")
                    .renderedOperationText("Search and recommend winter clothing items under $100")
                    .semanticExpansionLevel("medium")
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .consentInterfaceVersion("1.0")
                    .build();

            assertNotNull(trail);
            assertEquals("I want to buy winter clothes, please give me some suggestions", 
                        trail.getOriginalPromptText());
            assertEquals("Search and recommend winter clothing items under $100", 
                        trail.getRenderedOperationText());
            assertEquals("medium", trail.getSemanticExpansionLevel());
            assertEquals("2025-11-11T10:33:00Z", trail.getUserAcknowledgeTimestamp());
            assertEquals("1.0", trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should create minimal audit trail")
        void shouldCreateMinimalAuditTrail() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Simple request")
                    .build();

            assertNotNull(trail);
            assertEquals("Simple request", trail.getOriginalPromptText());
            assertNull(trail.getRenderedOperationText());
            assertNull(trail.getSemanticExpansionLevel());
            assertNull(trail.getUserAcknowledgeTimestamp());
            assertNull(trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should handle empty strings")
        void shouldHandleEmptyStrings() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("")
                    .renderedOperationText("")
                    .semanticExpansionLevel("")
                    .userAcknowledgeTimestamp("")
                    .consentInterfaceVersion("")
                    .build();

            assertEquals("", trail.getOriginalPromptText());
            assertEquals("", trail.getRenderedOperationText());
            assertEquals("", trail.getSemanticExpansionLevel());
            assertEquals("", trail.getUserAcknowledgeTimestamp());
            assertEquals("", trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should handle long text in prompt and operation")
        void shouldHandleLongTextInPromptAndOperation() {
            String longPrompt = "This is a very long prompt that contains a lot of text " +
                               "representing a complex user request that requires detailed " +
                               "interpretation and semantic expansion to properly understand " +
                               "the user's intent and provide accurate operation suggestions.";

            String longOperation = "This is a very long rendered operation text that contains " +
                                  "detailed interpretation of the user's request with specific " +
                                  "parameters and constraints that will be used to execute the " +
                                  "operation safely and correctly.";

            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText(longPrompt)
                    .renderedOperationText(longOperation)
                    .build();

            assertEquals(longPrompt, trail.getOriginalPromptText());
            assertEquals(longOperation, trail.getRenderedOperationText());
        }
    }

    @Nested
    @DisplayName("Consent Interface Version Tests")
    class ConsentInterfaceVersionTests {

        @Test
        @DisplayName("Should support version 1.0")
        void shouldSupportVersion10() {
            AuditTrail trail = AuditTrail.builder()
                    .consentInterfaceVersion("1.0")
                    .build();

            assertEquals("1.0", trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should support version 2.0")
        void shouldSupportVersion20() {
            AuditTrail trail = AuditTrail.builder()
                    .consentInterfaceVersion("2.0")
                    .build();

            assertEquals("2.0", trail.getConsentInterfaceVersion());
        }

        @Test
        @DisplayName("Should support semantic versioning")
        void shouldSupportSemanticVersioning() {
            AuditTrail trail = AuditTrail.builder()
                    .consentInterfaceVersion("1.2.3")
                    .build();

            assertEquals("1.2.3", trail.getConsentInterfaceVersion());
        }
    }
}
